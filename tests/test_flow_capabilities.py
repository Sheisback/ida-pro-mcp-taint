"""Capability contracts without an IDA license; actual IDA tests live in api_flow."""

import importlib.util
import json
import sys
import types
from dataclasses import replace
from pathlib import Path

import pytest
from _mcp_spec_support import McpServer

from ida_pro_mcp import idalib_supervisor as supmod
from ida_pro_mcp.flow_core.profile_registry import REGISTRY
from ida_pro_mcp.flow_core.profile_routing import (
    FROZEN_PROFILE_EVIDENCE,
    REGISTRY_PROFILE_EVIDENCE,
    OpenDatabaseEvidence,
    resolve_open_database_profile,
)
from ida_pro_mcp.flow_core.serialization import ContractError

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src/ida_pro_mcp/ida_mcp"
DEFAULT_ROUTE = next(
    row
    for row in FROZEN_PROFILE_EVIDENCE
    if row.profile_id == "X64-LE" and row.format_id == "FMT-MACHO"
)
FILE_TYPES = {
    "FMT-ELF": "f_ELF",
    "FMT-PE": "f_PE",
    "FMT-MACHO": "f_MACHO",
    "FMT-RAW": "f_BIN",
}


@pytest.fixture
def flow(monkeypatch, tmp_path):
    server = McpServer("flow-test")
    package = types.ModuleType("_flow_test_package")
    package.__path__ = [str(PACKAGE)]
    monkeypatch.setitem(sys.modules, package.__name__, package)
    monkeypatch.setitem(
        sys.modules, package.__name__ + ".rpc", types.SimpleNamespace(tool=server.tool)
    )
    monkeypatch.setitem(
        sys.modules,
        package.__name__ + ".sync",
        types.SimpleNamespace(idasync=lambda f: f),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_hexrays",
        types.SimpleNamespace(
            init_hexrays_plugin=lambda: True,
            get_hexrays_version=lambda: "9.3.0.260213",
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_kernwin",
        types.SimpleNamespace(get_kernel_version=lambda: "9.3"),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_ida",
        types.SimpleNamespace(
            f_ELF=1,
            f_PE=2,
            f_BIN=3,
            f_MACHO=7,
            inf_get_procname=lambda: "metapc",
            inf_is_64bit=lambda: True,
            inf_is_32bit_exactly=lambda: False,
            inf_is_be=lambda: False,
            inf_get_filetype=lambda: 7,
            inf_get_database_change_count=lambda: 0,
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_loader",
        types.SimpleNamespace(
            PATH_TYPE_IDB=1, get_path=lambda _kind: str(tmp_path / "current.i64")
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_nalt",
        types.SimpleNamespace(
            retrieve_input_file_sha256=lambda: bytes.fromhex(
                DEFAULT_ROUTE.binary_digest.removeprefix("sha256-v1:")
            )
        ),
    )
    monkeypatch.setenv("IDA_MCP_FLOW_STATE_ROOT", str(tmp_path / "state"))
    name = package.__name__ + ".api_flow"
    spec = importlib.util.spec_from_file_location(name, PACKAGE / "api_flow.py")
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    return module, server


@pytest.mark.parametrize("ready", [True, False])
def test_initialization_is_not_analysis_support(flow, monkeypatch, ready):
    module, _ = flow
    monkeypatch.setattr(module.ida_hexrays, "init_hexrays_plugin", lambda: ready)
    result = module.flow_get_capabilities()
    assert result["environment"]["hexrays_initialization"]["status"] == (
        "available" if ready else "unavailable"
    )
    assert result["environment"]["hexrays_version"] == (
        "9.3.0.260213" if ready else None
    )
    assert result["supported_profiles"] == (["X64-LE"] if ready else [])
    assert all(
        v["status"] != "available"
        for k, v in result["features"].items()
        if k != "capability_discovery"
        and (
            not ready
            or k
            not in {
                "snapshot",
                "value_ssa",
                "memory_ssa",
                "taint",
                "interprocedural",
                "implicit_flow",
                "path_proof",
                "durable_jobs",
                "microcode_extraction",
            }
        )
    )
    assert result["features"]["microcode_extraction"]["status"] == (
        "available" if ready else "unavailable"
    )


def test_probe_failure_remains_unknown(flow, monkeypatch):
    module, _ = flow

    def fail():
        raise RuntimeError("license probe unavailable")

    monkeypatch.setattr(module.ida_hexrays, "init_hexrays_plugin", fail)
    result = module.flow_get_capabilities()
    assert result["environment"]["hexrays_initialization"]["status"] == "unverified"
    assert (
        "license probe unavailable"
        in result["environment"]["hexrays_initialization"]["reason"]
    )
    assert result["supported_profiles"] == []
    assert result["features"]["microcode_extraction"]["status"] == "unverified"


def test_unsupported_current_database_is_not_advertised(flow, monkeypatch):
    module, _ = flow
    monkeypatch.setattr(module.ida_ida, "inf_get_filetype", lambda: -1)
    result = module.flow_get_capabilities()
    assert result["supported_profiles"] == []
    for name in (
        "snapshot",
        "value_ssa",
        "memory_ssa",
        "taint",
        "interprocedural",
        "implicit_flow",
        "path_proof",
        "durable_jobs",
        "microcode_extraction",
    ):
        assert result["features"][name]["status"] == "unavailable"


def test_rv32_fallback_is_never_promoted_to_runtime_support(flow, monkeypatch):
    module, _ = flow
    build = json.loads(
        (ROOT / "tests/flow_fixtures/manifests/profiles/build.json").read_text()
    )
    rv32 = next(row for row in build["profiles"] if row["profile_id"] == "RV32-LE")
    monkeypatch.setattr(module.ida_ida, "inf_get_procname", lambda: "riscv")
    monkeypatch.setattr(module.ida_ida, "inf_is_64bit", lambda: False)
    monkeypatch.setattr(module.ida_ida, "inf_is_32bit_exactly", lambda: True)
    monkeypatch.setattr(
        module.ida_ida, "inf_get_filetype", lambda: module.ida_ida.f_ELF
    )
    monkeypatch.setattr(
        module.ida_nalt,
        "retrieve_input_file_sha256",
        lambda: bytes.fromhex(rv32["binary_sha256"]),
    )
    result = module.flow_get_capabilities()
    assert result["environment"]["processor"] == "riscv"
    assert result["supported_profiles"] == []
    assert all(
        result["features"][name]["status"] == "unavailable"
        for name in ("implicit_flow", "path_proof", "interprocedural")
    )
    assert (
        "experimental_profile_unavailable" in result["features"]["snapshot"]["reason"]
    )


@pytest.mark.parametrize(
    "route",
    FROZEN_PROFILE_EVIDENCE,
    ids=lambda row: row.profile_id + "-" + row.format_id,
)
def test_capabilities_route_every_exact_frozen_identity(flow, monkeypatch, route):
    module, _ = flow
    spec = REGISTRY.get(route.profile_id)
    monkeypatch.setattr(module.ida_ida, "inf_get_procname", lambda: route.processor)
    monkeypatch.setattr(module.ida_ida, "inf_is_64bit", lambda: spec.bitness == 64)
    monkeypatch.setattr(
        module.ida_ida, "inf_is_32bit_exactly", lambda: spec.bitness == 32
    )
    monkeypatch.setattr(module.ida_ida, "inf_is_be", lambda: spec.data_endian == "big")
    monkeypatch.setattr(
        module.ida_ida,
        "inf_get_filetype",
        lambda: getattr(module.ida_ida, FILE_TYPES[route.format_id]),
    )
    monkeypatch.setattr(
        module.ida_nalt,
        "retrieve_input_file_sha256",
        lambda: bytes.fromhex(route.binary_digest.removeprefix("sha256-v1:")),
    )
    result = module.flow_get_capabilities()
    assert result["supported_profiles"] == [route.profile_id]
    assert result["routing"]["mode"] == "exact_fixture"
    assert result["features"]["snapshot"]["status"] == "available"
    assert route.abi_id in result["features"]["snapshot"]["reason"]
    assert route.format_id in result["features"]["snapshot"]["reason"]


@pytest.mark.parametrize("route", REGISTRY_PROFILE_EVIDENCE)
def test_capabilities_do_not_infer_profile_for_unpinned_macho(flow, monkeypatch, route):
    module, _ = flow
    processor, bits, endian, format_id, _ida_build, _hexrays_build = (
        route.observed_identity
    )
    monkeypatch.setattr(module.ida_ida, "inf_get_procname", lambda: processor)
    monkeypatch.setattr(module.ida_ida, "inf_is_64bit", lambda: bits == 64)
    monkeypatch.setattr(module.ida_ida, "inf_is_32bit_exactly", lambda: bits == 32)
    monkeypatch.setattr(module.ida_ida, "inf_is_be", lambda: endian == "big")
    monkeypatch.setattr(
        module.ida_ida,
        "inf_get_filetype",
        lambda: getattr(module.ida_ida, FILE_TYPES[format_id]),
    )
    monkeypatch.setattr(
        module.ida_nalt,
        "retrieve_input_file_sha256",
        lambda: bytes.fromhex("f" * 64),
    )
    result = module.flow_get_capabilities()
    assert result["supported_profiles"] == []
    assert (
        "experimental_profile_unavailable" in result["features"]["snapshot"]["reason"]
    )


def test_runtime_context_uses_exact_measured_registry_profile(
    flow, monkeypatch, tmp_path
):
    from ida_pro_mcp.flow_core.profile_registry import REGISTRY

    module, _ = flow
    binary = tmp_path / "fixture"
    binary.write_bytes(b"static input; never executed")
    package = module.__package__
    funcs = types.SimpleNamespace(
        get_func=lambda ea: types.SimpleNamespace(start_ea=ea)
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_funcs",
        funcs,
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_loader",
        types.SimpleNamespace(
            PATH_TYPE_IDB=1, get_path=lambda _kind: str(binary) + ".i64"
        ),
    )
    nalt = types.SimpleNamespace(
        retrieve_input_file_sha256=lambda: bytes.fromhex(
            DEFAULT_ROUTE.binary_digest.removeprefix("sha256-v1:")
        )
    )
    monkeypatch.setitem(sys.modules, "ida_nalt", nalt)
    monkeypatch.setattr(module, "ida_nalt", nalt)
    monkeypatch.setitem(
        sys.modules,
        package + ".utils",
        types.SimpleNamespace(parse_address=lambda _selector: 0x1000),
    )
    monkeypatch.setattr(
        module.ida_ida, "inf_get_database_change_count", lambda: 0, raising=False
    )
    service = module._service()
    for route in FROZEN_PROFILE_EVIDENCE:
        spec = REGISTRY.get(route.profile_id)
        monkeypatch.setattr(
            module.ida_ida, "inf_get_procname", lambda route=route: route.processor
        )
        monkeypatch.setattr(
            module.ida_ida, "inf_is_64bit", lambda spec=spec: spec.bitness == 64
        )
        monkeypatch.setattr(
            module.ida_ida,
            "inf_is_32bit_exactly",
            lambda spec=spec: spec.bitness == 32,
        )
        monkeypatch.setattr(
            module.ida_ida,
            "inf_is_be",
            lambda spec=spec: spec.data_endian == "big",
        )
        monkeypatch.setattr(
            module.ida_ida,
            "inf_get_filetype",
            lambda route=route: getattr(module.ida_ida, FILE_TYPES[route.format_id]),
        )
        nalt.retrieve_input_file_sha256 = lambda route=route: bytes.fromhex(
            route.binary_digest.removeprefix("sha256-v1:")
        )
        info = service._context("0x1000", route.profile_id)
        assert info["profile"] == route.extraction_profile()[0]
        assert (
            info["registry"].validate_extraction_profile(info["profile"]).profile_id
            == spec.profile_id
        )


def test_runtime_context_retains_explicit_analyst_selection_and_rejects_staleness(
    flow, monkeypatch, tmp_path
):
    module, _ = flow
    route = next(
        row
        for row in FROZEN_PROFILE_EVIDENCE
        if row.profile_id == "X64-LE" and row.format_id == "FMT-ELF"
    )
    spec = __import__(
        "ida_pro_mcp.flow_core.profile_registry", fromlist=["REGISTRY"]
    ).REGISTRY.get(route.profile_id)
    dbpath = str(tmp_path / "analyst.i64")
    current_digest = "a" * 64
    package = module.__package__
    funcs = types.SimpleNamespace(
        get_func=lambda ea: types.SimpleNamespace(start_ea=ea)
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_funcs",
        funcs,
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_loader",
        types.SimpleNamespace(PATH_TYPE_IDB=1, get_path=lambda _kind: dbpath),
    )
    nalt = types.SimpleNamespace(
        retrieve_input_file_sha256=lambda: bytes.fromhex(current_digest)
    )
    monkeypatch.setitem(sys.modules, "ida_nalt", nalt)
    monkeypatch.setitem(
        sys.modules,
        package + ".utils",
        types.SimpleNamespace(parse_address=lambda _selector: 0x1000),
    )
    monkeypatch.setattr(module.ida_ida, "inf_get_procname", lambda: route.processor)
    monkeypatch.setattr(module.ida_ida, "inf_is_64bit", lambda: spec.bitness == 64)
    monkeypatch.setattr(
        module.ida_ida, "inf_is_32bit_exactly", lambda: spec.bitness == 32
    )
    monkeypatch.setattr(module.ida_ida, "inf_is_be", lambda: spec.data_endian == "big")
    monkeypatch.setattr(
        module.ida_ida,
        "inf_get_filetype",
        lambda: getattr(module.ida_ida, FILE_TYPES[route.format_id]),
    )
    monkeypatch.setattr(
        module.ida_ida, "inf_get_database_change_count", lambda: 0, raising=False
    )

    service = module._service()
    funcs.get_func = lambda _ea: None
    with pytest.raises(ContractError, match="function_entry_required"):
        service._context("0x1000", route.profile_id, route.abi_id, "analyst_selected")
    assert not service._state_root().exists()
    funcs.get_func = lambda ea: types.SimpleNamespace(start_ea=ea)
    info = service._context(
        "0x1000", route.profile_id, route.abi_id, "analyst_selected"
    )
    assert info["routing"] == {
        "routing_mode": "analyst_selected",
        "profile_id": route.profile_id,
        "abi_id": route.abi_id,
        "binary_digest": "sha256-v1:" + current_digest,
    }
    assert info["profile"]["abi_provenance"]["observed_binary_digest"] == (
        "sha256-v1:" + current_digest
    )
    engine = service.get_runtime(info)
    service.runtime.persist_routing_selection(
        engine.store,
        info["dbpath"],
        service._routing_selection(info, engine.store.scope),
    )
    replay = service._context()
    assert replay["routing"] == info["routing"]
    assert replay["profile"] == info["profile"]

    stale_request = {
        "routing": {**info["routing"], "binary_digest": "sha256-v1:" + "b" * 64}
    }
    with pytest.raises(ContractError, match="stale_profile_selection"):
        service._context_for_request(stale_request)
    nalt.retrieve_input_file_sha256 = lambda: bytes.fromhex("b" * 64)
    with pytest.raises(ContractError, match="stale_profile_selection"):
        service._context()


def test_create_publishes_selection_only_after_runtime_admission(flow, monkeypatch):
    module, _ = flow
    service = module._service()
    route = next(
        row
        for row in FROZEN_PROFILE_EVIDENCE
        if row.profile_id == "X64-LE" and row.format_id == "FMT-ELF"
    )
    current = "sha256-v1:" + "e" * 64
    resolved = resolve_open_database_profile(
        OpenDatabaseEvidence(
            current,
            route.processor,
            64,
            "little",
            route.format_id,
            route.ida_build,
            route.hexrays_build,
        ),
        route.profile_id,
        route.abi_id,
        "analyst_selected",
    )
    info = {
        "dbpath": "/tmp/selected.i64",
        "profile": resolved.profile,
        "registry": resolved.registry,
        "binary": current,
        "count": 0,
        "ida": route.ida_build,
        "hexrays": route.hexrays_build,
        "routing": {
            "routing_mode": "analyst_selected",
            "profile_id": route.profile_id,
            "abi_id": route.abi_id,
            "binary_digest": current,
        },
        "persist_selection": True,
        "ea": 0x1000,
    }
    scope = service._runtime_scope(info, "database_" + "f" * 48)
    events = []
    store = types.SimpleNamespace(scope=scope)
    engine = types.SimpleNamespace(
        store=store,
        submit=lambda *_args, **_kwargs: events.append("submit") or "job",
    )
    monkeypatch.setattr(service, "context", lambda *_args: info)
    monkeypatch.setattr(service, "get_runtime", lambda actual: engine)
    monkeypatch.setattr(
        service.runtime,
        "persist_routing_selection",
        lambda *_args: events.append("persist"),
    )

    assert (
        service.create(
            "0x1000", route.profile_id, "request", route.abi_id, "analyst_selected"
        )["job_id"]
        == "job"
    )
    assert events == ["persist", "submit"]


def test_durable_selection_restores_after_restart_and_fences_foreign_database(
    flow, monkeypatch, tmp_path
):
    module, _ = flow
    service = module._service()
    route = next(
        row
        for row in FROZEN_PROFILE_EVIDENCE
        if row.profile_id == "X64-LE" and row.format_id == "FMT-ELF"
    )
    spec = REGISTRY.get(route.profile_id)
    current_digest = "a" * 64
    dbpath = str(tmp_path / "selected.i64")
    package = module.__package__
    monkeypatch.setitem(
        sys.modules,
        "ida_funcs",
        types.SimpleNamespace(get_func=lambda ea: types.SimpleNamespace(start_ea=ea)),
    )
    loader = types.SimpleNamespace(PATH_TYPE_IDB=1, get_path=lambda _kind: dbpath)
    monkeypatch.setitem(sys.modules, "ida_loader", loader)
    monkeypatch.setattr(module, "ida_loader", loader)
    nalt = types.SimpleNamespace(
        retrieve_input_file_sha256=lambda: bytes.fromhex(current_digest)
    )
    monkeypatch.setitem(sys.modules, "ida_nalt", nalt)
    monkeypatch.setattr(module, "ida_nalt", nalt)
    monkeypatch.setitem(
        sys.modules,
        package + ".utils",
        types.SimpleNamespace(parse_address=lambda _selector: 0x1000),
    )
    monkeypatch.setattr(module.ida_ida, "inf_get_procname", lambda: route.processor)
    monkeypatch.setattr(module.ida_ida, "inf_is_64bit", lambda: spec.bitness == 64)
    monkeypatch.setattr(
        module.ida_ida, "inf_is_32bit_exactly", lambda: spec.bitness == 32
    )
    monkeypatch.setattr(module.ida_ida, "inf_is_be", lambda: spec.data_endian == "big")
    monkeypatch.setattr(
        module.ida_ida,
        "inf_get_filetype",
        lambda: getattr(module.ida_ida, FILE_TYPES[route.format_id]),
    )
    change_count = 7
    monkeypatch.setattr(
        module.ida_ida,
        "inf_get_database_change_count",
        lambda: change_count,
        raising=False,
    )

    info = service._context(
        "0x1000", route.profile_id, route.abi_id, "analyst_selected"
    )
    engine = service.get_runtime(info)
    service.runtime.persist_routing_selection(
        engine.store,
        info["dbpath"],
        service._routing_selection(info, engine.store.scope),
    )
    job_id = engine.store.create_job(
        "snapshot_ssa_v1", {"routing": info["routing"]}, "restart-job"
    )
    artifact_id = engine.store.put_artifact(
        "analysis", {"kind": "restart-artifact", "target_executed": False}
    )
    namespace = engine.store.scope.namespace
    scope_digest = engine.store.scope.scope_digest
    selection_path = engine.store.root / "routing-selection.json"

    engine.shutdown(0)
    engine.store.close()
    del service.runtime._runtimes[namespace]

    restored = service._context()
    assert restored["routing"] == info["routing"]
    assert restored["restored_selection"]["scope_digest"] == scope_digest
    reopened = service.get_runtime(restored)
    assert service.job(job_id)["state"] == "interrupted"
    assert reopened.store.artifact(artifact_id) == {
        "kind": "restart-artifact",
        "target_executed": False,
    }

    change_count = 8
    with pytest.raises(ContractError, match="stale_profile_selection"):
        service._context()
    reattached = service._context(
        "0x1000", route.profile_id, route.abi_id, "analyst_selected"
    )
    replacement = service.get_runtime(reattached)
    service.runtime.persist_routing_selection(
        replacement.store,
        reattached["dbpath"],
        service._routing_selection(reattached, replacement.store.scope),
    )
    assert service._context()["routing"] == info["routing"]
    with pytest.raises(ContractError, match="stale_context"):
        replacement.store.artifact(artifact_id)

    loader.get_path = lambda _kind: str(tmp_path / "foreign.i64")
    foreign_namespace, _owner = service.identity(
        service._state_root(), str(tmp_path / "foreign.i64")
    )
    foreign_root = service._state_root() / foreign_namespace
    foreign_root.mkdir(mode=0o700)
    foreign_selection = foreign_root / "routing-selection.json"
    foreign_selection.write_bytes(selection_path.read_bytes())
    foreign_selection.chmod(0o600)
    with pytest.raises(ContractError, match="invalid_routing_selection"):
        service._context()


def test_capabilities_follow_durable_analyst_selection_and_invalidation(
    flow, monkeypatch, tmp_path
):
    module, _ = flow
    service = module._service()
    route = next(
        row
        for row in FROZEN_PROFILE_EVIDENCE
        if row.profile_id == "X64-LE" and row.format_id == "FMT-ELF"
    )
    spec = REGISTRY.get(route.profile_id)
    current_digest = "c" * 64
    dbpath = str(tmp_path / "capabilities.i64")
    loader = types.SimpleNamespace(PATH_TYPE_IDB=1, get_path=lambda _kind: dbpath)
    monkeypatch.setitem(sys.modules, "ida_loader", loader)
    monkeypatch.setattr(module, "ida_loader", loader)
    nalt = types.SimpleNamespace(
        retrieve_input_file_sha256=lambda: bytes.fromhex(current_digest)
    )
    monkeypatch.setitem(sys.modules, "ida_nalt", nalt)
    monkeypatch.setattr(module, "ida_nalt", nalt)
    monkeypatch.setattr(module.ida_ida, "inf_get_procname", lambda: route.processor)
    monkeypatch.setattr(module.ida_ida, "inf_is_64bit", lambda: spec.bitness == 64)
    monkeypatch.setattr(
        module.ida_ida, "inf_is_32bit_exactly", lambda: spec.bitness == 32
    )
    monkeypatch.setattr(module.ida_ida, "inf_is_be", lambda: spec.data_endian == "big")
    monkeypatch.setattr(
        module.ida_ida,
        "inf_get_filetype",
        lambda: getattr(module.ida_ida, FILE_TYPES[route.format_id]),
    )
    change_count = 3
    monkeypatch.setattr(
        module.ida_ida,
        "inf_get_database_change_count",
        lambda: change_count,
        raising=False,
    )

    before = module.flow_get_capabilities()
    assert before["routing"]["mode"] is None
    assert before["supported_profiles"] == []
    assert not service._state_root().exists()

    observed = service.observe_open_database(
        module.ida_ida,
        nalt,
        ida_build=module.ida_kernwin.get_kernel_version(),
        hexrays_build=module.ida_hexrays.get_hexrays_version(),
    )
    info = service.resolve_observed_context(
        dbpath,
        observed,
        change_count,
        route.profile_id,
        route.abi_id,
        "analyst_selected",
    )
    engine = service.get_runtime(info)
    service.runtime.persist_routing_selection(
        engine.store,
        dbpath,
        service._routing_selection(info, engine.store.scope),
    )

    selected = module.flow_get_capabilities()
    assert selected["routing"] == {
        "mode": "analyst_selected",
        "profile_id": route.profile_id,
        "abi_id": route.abi_id,
        "binary_digest": "sha256-v1:" + current_digest,
    }
    assert selected["supported_profiles"] == [route.profile_id]
    assert "analyst-selected" in selected["features"]["snapshot"]["reason"]

    change_count = 4
    invalidated = module.flow_get_capabilities()
    assert invalidated["routing"]["mode"] is None
    assert invalidated["supported_profiles"] == []
    assert "stale_profile_selection" in invalidated["features"]["snapshot"]["reason"]


def test_runtime_extraction_rechecks_profile_and_passes_ephemeral_registry(
    flow, monkeypatch
):
    module, _ = flow
    service = module._service()
    profile, registry = DEFAULT_ROUTE.extraction_profile()
    info = {
        "dbpath": "/tmp/static.i64",
        "profile": profile,
        "registry": registry,
        "binary": DEFAULT_ROUTE.binary_digest,
        "count": 0,
        "ida": "test-ida",
        "hexrays": DEFAULT_ROUTE.hexrays_build,
    }
    monkeypatch.setattr(service, "_context", lambda: info)
    observed = {}

    def extract_snapshot(ea, **kwargs):
        observed.update({"ea": ea, **kwargs})
        return object()

    monkeypatch.setattr(service.extractor, "extract_snapshot", extract_snapshot)
    request = {
        "ea": 0x1000,
        "profile": profile,
        "namespace": "test",
        "function_key": "function-entry:4096",
        "fingerprint": service._fingerprint(info),
        "summary_digest": service.reviewed_catalog(info).catalog_digest,
    }
    context = types.SimpleNamespace(
        deadline=None, cancel=types.SimpleNamespace(is_set=lambda: False)
    )
    extracted, returned = service._extract(context, request)
    assert extracted is not None and returned is request
    assert observed["registry"] is registry
    assert observed["profile"] == profile

    with pytest.raises(ContractError, match="stale_profile_evidence"):
        service._extract(
            context, {**request, "profile": {**profile, "profile_id": "A64-LE"}}
        )


def test_runtime_extraction_rehydrates_explicit_selection(flow, monkeypatch):
    module, _ = flow
    service = module._service()
    route = next(
        row
        for row in FROZEN_PROFILE_EVIDENCE
        if row.profile_id == "X64-LE" and row.format_id == "FMT-ELF"
    )
    current = "sha256-v1:" + "c" * 64
    resolved = resolve_open_database_profile(
        OpenDatabaseEvidence(
            current,
            route.processor,
            64,
            "little",
            route.format_id,
            route.ida_build,
            route.hexrays_build,
        ),
        route.profile_id,
        route.abi_id,
        "analyst_selected",
    )
    info = {
        "dbpath": "/tmp/selected.i64",
        "profile": resolved.profile,
        "registry": resolved.registry,
        "binary": current,
        "count": 0,
        "ida": route.ida_build,
        "hexrays": route.hexrays_build,
        "routing": {
            "routing_mode": "analyst_selected",
            "profile_id": route.profile_id,
            "abi_id": route.abi_id,
            "binary_digest": current,
        },
    }
    calls = []
    monkeypatch.setattr(
        service,
        "_context",
        lambda **kwargs: calls.append(kwargs) or info,
    )
    monkeypatch.setattr(
        service.extractor, "extract_snapshot", lambda *_args, **_kwargs: object()
    )
    request = {
        "ea": 0x1000,
        "profile": resolved.profile,
        "namespace": "test",
        "function_key": "function-entry:4096",
        "fingerprint": service._fingerprint(info),
        "summary_digest": service.reviewed_catalog(info).catalog_digest,
        "routing": info["routing"],
    }
    context = types.SimpleNamespace(
        deadline=None, cancel=types.SimpleNamespace(is_set=lambda: False)
    )
    service._extract(context, request)
    assert calls == [
        {
            "requested_profile": route.profile_id,
            "requested_abi": route.abi_id,
            "routing_mode": "analyst_selected",
            "retain_selection": False,
        },
        {
            "requested_profile": route.profile_id,
            "requested_abi": route.abi_id,
            "routing_mode": "analyst_selected",
            "retain_selection": False,
        },
    ]


def test_background_routing_rehydration_uses_synchronized_context(flow, monkeypatch):
    module, _ = flow
    service = module._service()
    routing = {
        "routing_mode": "analyst_selected",
        "profile_id": "X64-LE",
        "abi_id": "sysv-amd64",
        "binary_digest": "sha256-v1:" + "d" * 64,
    }
    calls = []
    monkeypatch.setattr(
        service,
        "_context",
        lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("background work called raw IDA context")
        ),
    )
    monkeypatch.setattr(
        service,
        "context",
        lambda **kwargs: calls.append(kwargs) or {"binary": routing["binary_digest"]},
    )
    assert (
        service._context_for_request({"routing": routing}, synchronized=True)["binary"]
        == routing["binary_digest"]
    )
    assert calls == [
        {
            "requested_profile": "X64-LE",
            "requested_abi": "sysv-amd64",
            "routing_mode": "analyst_selected",
            "retain_selection": False,
        }
    ]


def test_supervisor_schema_and_forwarding(flow, monkeypatch):
    _, server = flow
    local = server._mcp_tools_list()["tools"][0]
    sup = supmod.IdalibSupervisor(supmod.McpServer("test"), max_workers=1)
    external = sup._inject_database_arg(local)
    assert "database" not in local["inputSchema"].get("properties", {})
    assert external["inputSchema"]["required"] == ["database"]
    forwarded = []
    monkeypatch.setattr(sup, "resolve_session", lambda database: database)
    monkeypatch.setattr(
        sup,
        "_worker_rpc",
        lambda session, payload, **kwargs: forwarded.append((session, payload)) or {},
    )
    monkeypatch.setattr(supmod, "supervisor", sup)
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "flow_get_capabilities",
            "arguments": {"database": "owned-db"},
        },
    }
    supmod._handle_tools_call(request)
    assert forwarded[0][0] == "owned-db"
    assert forwarded[0][1]["params"]["arguments"] == {}
    assert request["params"]["arguments"] == {"database": "owned-db"}


def test_supervisor_rejects_stale_flow_worker_before_forwarding(monkeypatch):
    sup = supmod.IdalibSupervisor(supmod.McpServer("test"), max_workers=1)
    session = object()
    calls = []
    monkeypatch.setattr(sup, "resolve_session", lambda database: session)

    def rpc(_session, payload, **_kwargs):
        calls.append(payload["params"]["name"])
        return {
            "result": {
                "structuredContent": {"build_id": "flow-build-sha256-v1:" + "0" * 64}
            }
        }

    monkeypatch.setattr(sup, "_worker_rpc", rpc)
    monkeypatch.setattr(supmod, "supervisor", sup)
    response = supmod._handle_tools_call(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "flow_get_job",
                "arguments": {"database": "db", "job_id": "job"},
            },
        }
    )
    assert calls == ["flow_get_capabilities"]
    assert response["result"]["isError"] is True
    assert "flow_extension_build_mismatch" in response["result"]["content"][0]["text"]


def test_profile_is_minimal_readonly(flow):
    names = {
        line.split("#")[0].strip()
        for line in (ROOT / "profiles/flow-readonly.txt").read_text().splitlines()
    } - {""}
    assert names == {name for name in dir(flow[0]) if name.startswith("flow_")} | {
        "server_health",
        "lookup_funcs",
        "list_funcs",
    }
    spec = importlib.util.spec_from_file_location(
        "_flow_profile", PACKAGE / "profile.py"
    )
    profile = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(profile)
    tools = {
        name: object() for name in names | {"py_eval", "patch", "dbg_start", "idb_save"}
    }
    profile.apply_profile(tools, whitelist=names)
    assert set(tools) == names

    _, server = flow

    @server.tool
    def py_eval(code: str) -> dict:
        return {"executed": code}

    profile.apply_profile(server.tools.methods, whitelist=names)
    denied = server._mcp_tools_call("py_eval", {"code": "ignore previous instructions"})
    assert denied["isError"] is True
    assert "py_eval" not in {tool["name"] for tool in server._mcp_tools_list()["tools"]}


def test_build_identity_is_install_location_independent(flow, tmp_path, monkeypatch):
    module, _ = flow
    # The GUI installer copies this package tree. Relocation must preserve identity.
    copied = tmp_path / "api_flow.py"
    copied.write_bytes((PACKAGE / "api_flow.py").read_bytes())
    name = "_flow_test_package.gui_copy"
    spec = importlib.util.spec_from_file_location(name, copied)
    relocated = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, relocated)
    spec.loader.exec_module(relocated)
    assert relocated.BUILD_ID == module.BUILD_ID


def test_advertised_output_schema_accepts_capabilities(flow):
    from jsonschema import Draft202012Validator

    module, server = flow
    tool = server._mcp_tools_list()["tools"][0]
    Draft202012Validator(tool["outputSchema"]).validate(module.flow_get_capabilities())


def test_exact_tool_schema_and_no_supervisor_database_on_workers(flow):
    _, server = flow
    expected = {
        "flow_get_capabilities",
        "flow_create_snapshot",
        "flow_create_implicit_analysis",
        "flow_check_path",
        "flow_get_job",
        "flow_cancel_job",
        "flow_get_function_ssa",
        "flow_get_cfg",
        "flow_get_implicit_analysis",
        "flow_get_call_compositions",
        "flow_trace_forward",
        "flow_trace_backward",
        "flow_continue_trace",
        "flow_cancel_trace",
        "flow_get_graph",
        "flow_get_evidence",
    }
    tools = server._mcp_tools_list()["tools"]
    assert {tool["name"] for tool in tools} == expected
    for tool in tools:
        assert "database" not in tool["inputSchema"].get("properties", {})
        assert tool["inputSchema"]["type"] == "object"
        assert tool["outputSchema"]["type"] == "object"
        assert (
            "anyOf" in tool["outputSchema"] or tool["name"] == "flow_get_capabilities"
        )
    by_name = {tool["name"]: tool for tool in tools}
    for name in ("flow_trace_forward", "flow_trace_backward"):
        source = by_name[name]["inputSchema"]["properties"]["source"]
        variants = source["anyOf"]
        assert {variant["properties"]["kind"]["enum"][0] for variant in variants} == {
            "value",
            "memory",
        }
        assert all(variant["additionalProperties"] is False for variant in variants)
    implicit = by_name["flow_create_implicit_analysis"]["inputSchema"]
    seed = implicit["properties"]["seeds"]["items"]
    assert seed["additionalProperties"] is False
    assert set(seed["required"]) == {"node_id", "labels"}
    assert seed["properties"]["labels"]["additionalProperties"] is False


def test_public_analysis_tools_forward_exact_owned_artifact_contracts(
    flow, monkeypatch
):
    module, _ = flow
    calls = []
    service = types.SimpleNamespace(
        create_implicit=lambda *args: (
            calls.append(("implicit", args))
            or {"schema_version": "flow-job/1", "job_id": "i", "experimental": True}
        ),
        create_path_proof=lambda *args: (
            calls.append(("proof", args))
            or {"schema_version": "flow-job/1", "job_id": "p", "experimental": True}
        ),
        analysis_page=lambda *args: (
            calls.append(("page", args))
            or {
                "schema_version": "flow-page/1",
                "artifact_id": args[0],
                "section": args[1],
                "metadata": {},
                "items": [],
                "next_cursor": None,
            }
        ),
    )
    monkeypatch.setattr(module, "_service", lambda: service)
    labels = {
        "explicit": ["source"],
        "control": [],
        "unknown_provenance": False,
        "any_explicit_source": False,
        "any_control_source": False,
    }
    assert (
        module.flow_create_implicit_analysis(
            "ssa", [{"node_id": "node-v1:" + "1" * 64, "labels": labels}], "key", 9
        )["job_id"]
        == "i"
    )
    assert (
        module._flow_create_path_proof("graph", {"query": "exact"}, "key")["job_id"]
        == "p"
    )
    assert (
        module.flow_get_implicit_analysis("i-result", "cursor", 7)["section"]
        == "implicit"
    )
    assert module._flow_get_path_proof("p-result")["section"] == "path_proof"
    assert module.flow_get_call_compositions("c-result")["section"] == (
        "interprocedural"
    )
    assert calls == [
        (
            "implicit",
            (
                "ssa",
                [{"node_id": "node-v1:" + "1" * 64, "labels": labels}],
                "key",
                9,
            ),
        ),
        ("proof", ("graph", {"query": "exact"}, "key")),
        ("page", ("i-result", "implicit", "cursor", 7)),
        ("page", ("p-result", "path_proof", None, 50)),
        ("page", ("c-result", "interprocedural", None, 50)),
    ]


def test_public_snapshot_forwards_explicit_profile_abi_mode(flow, monkeypatch):
    module, server = flow
    calls = []
    monkeypatch.setattr(
        module,
        "_service",
        lambda: types.SimpleNamespace(
            create=lambda *args: (
                calls.append(args)
                or {
                    "schema_version": "flow-job/1",
                    "job_id": "selected",
                    "experimental": True,
                }
            )
        ),
    )
    result = module.flow_create_snapshot(
        "0x1000", "X64-LE", "request", "sysv-amd64", "analyst_selected"
    )
    assert result["job_id"] == "selected"
    assert calls == [("0x1000", "X64-LE", "request", "sysv-amd64", "analyst_selected")]
    schema = {
        tool["name"]: tool["inputSchema"] for tool in server._mcp_tools_list()["tools"]
    }["flow_create_snapshot"]
    assert schema["properties"]["routing_mode"] == {
        "default": "exact_fixture",
        "type": "string",
    }
    assert "abi" not in schema["required"]


def test_analysis_adapter_preserves_partiality_proof_bounds_and_artifact_binding(flow):
    from ida_pro_mcp.flow_core import ContractError, digest
    from ida_pro_mcp.flow_core.constraints import (
        ConstraintExpression,
        ConstraintQuery,
        ConstraintVariable,
        DeclaredCoverage,
        PathConstraint,
        ProofBounds,
        ProofBudget,
        variable_domain_digest,
    )
    from ida_pro_mcp.flow_core.contracts import Snapshot
    from ida_pro_mcp.flow_core.implicit_analysis import analyze_implicit
    from ida_pro_mcp.flow_core.proof import ReferenceProofEngine, classify_proof
    from ida_pro_mcp.flow_core.ssa import build_ssa

    module, _ = flow
    service = module._service()
    snapshot = Snapshot.from_data(
        json.loads(
            (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
        )["snapshot"]
    )
    program = build_ssa(snapshot)
    implicit = analyze_implicit(program)
    items, metadata = service._implicit_page(
        {
            "schema_version": "flow-implicit-artifact/1",
            "source_artifact": "ssa",
            "result": implicit.to_data(),
            "target_executed": False,
            "no_auto_vulnerability_verdict": True,
        }
    )
    assert metadata["status"] == "partial"
    assert metadata["frontier_count"] == len(implicit.frontier) > 0
    assert any(item["type"] == "frontier" for item in items)
    assert metadata["no_auto_vulnerability_verdict"] is True
    assert "vulnerability_verdict" not in json.dumps(items)

    graph = program.graph
    evidence_id = graph.evidence[0].evidence_id
    variables = (ConstraintVariable("x", 1, (0, 1)),)
    constraint = PathConstraint(
        "c-eq",
        ConstraintExpression("variable", 1, variable="x"),
        "eq",
        ConstraintExpression("constant", 1, value=1),
        None,
        True,
        "rule:declared-path-v1",
        "origin:owned-static-evidence",
        (evidence_id,),
    )
    query = ConstraintQuery(
        service._expected_path_bindings(graph),
        variables,
        (constraint,),
        (),
        ProofBounds(1, 0),
        ProofBudget(2, 8, 1000),
        DeclaredCoverage(
            "fixed_width_bitvectors",
            ("x",),
            variable_domain_digest(variables),
            ("c-eq",),
            ("eq",),
        ),
    )
    with pytest.raises(ContractError, match="path_query_not_program_derived"):
        service._validate_path_query(graph, query)
    proof = classify_proof(query, ReferenceProofEngine())
    proof_items, proof_metadata = service._proof_page(
        {
            "schema_version": "flow-path-proof-artifact/1",
            "source_artifact": "graph",
            "query": query.to_data(),
            "proof": proof.to_data(),
            "target_executed": False,
            "no_auto_vulnerability_verdict": True,
        }
    )
    assert proof_metadata["status"] == "feasible"
    assert proof_metadata["scope"] == "within_bounds"
    assert proof_metadata["witness_valid"] is True
    assert any(item["type"] == "witness_assignment" for item in proof_items)
    stale = replace(
        query,
        bindings=replace(query.bindings, graph_digest=digest("stale-graph")),
    )
    with pytest.raises(ContractError, match="path_query_artifact_mismatch"):
        service._validate_path_query(graph, stale)
    foreign = replace(
        query,
        constraints=(replace(constraint, evidence_ids=("evidence-v1:" + "0" * 64,)),),
    )
    with pytest.raises(ContractError, match="path_query_foreign_evidence"):
        service._validate_path_query(graph, foreign)


def test_public_pagers_reject_tamper_and_malformed_evidence_filter(flow, monkeypatch):
    from ida_pro_mcp.flow_core import ContractError
    from ida_pro_mcp.flow_core.contracts import Snapshot
    from ida_pro_mcp.flow_core.ssa import build_ssa

    module, _ = flow
    service = module._service()
    snapshot = Snapshot.from_data(
        json.loads(
            (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
        )["snapshot"]
    )
    graph = build_ssa(snapshot).graph
    engine = types.SimpleNamespace(
        store=types.SimpleNamespace(artifact=lambda _identifier: graph.to_data())
    )
    monkeypatch.setattr(service, "get_runtime", lambda *_args: engine)
    with pytest.raises(ContractError, match="invalid_evidence_ids"):
        service.page("graph", "evidence", evidence_ids=[{"nested": "bad"}])
    with pytest.raises(ContractError, match="invalid_call_composition_artifact"):
        service._interprocedural_page(
            {
                "schema_version": "flow-call-compositions/1",
                "catalog_digest": "sha256-v1:" + "1" * 64,
                "calls": [{"binding": {}, "composition": {}, "extra": True}],
            }
        )


def test_success_and_error_envelopes_match_advertised_schemas(flow):
    from jsonschema import Draft202012Validator

    _, server = flow
    schemas = {
        tool["name"]: tool["outputSchema"] for tool in server._mcp_tools_list()["tools"]
    }
    examples = {
        "flow_create_snapshot": {
            "schema_version": "flow-job/1",
            "job_id": "job_1",
            "experimental": True,
        },
        "flow_get_job": {
            "schema_version": "flow-job/1",
            "id": "job_1",
            "state": "complete",
            "revision": 1,
            "progress": {},
            "budget": {},
            "error": None,
            "result": {},
        },
        "flow_get_graph": {
            "schema_version": "flow-page/1",
            "artifact_id": "artifact_1",
            "section": "graph",
            "metadata": {},
            "items": [],
            "next_cursor": None,
        },
        "flow_trace_forward": {
            "schema_version": "flow-trace-page/1",
            "trace_id": "trace_1",
            "revision": 1,
            "cursor": "cursor",
            "items": [],
            "status": "frontier_exhausted",
            "frontier_remaining": 0,
            "pending_remaining": 0,
            "unresolved_count": 0,
        },
    }
    error = {"schema_version": "flow-error/1", "error": {"code": "bad"}}
    for name, payload in examples.items():
        Draft202012Validator(schemas[name]).validate(payload)
        Draft202012Validator(schemas[name]).validate(error)


def test_public_errors_are_structured_without_tracebacks(flow, monkeypatch):
    from ida_pro_mcp.flow_core.persistence import PersistenceError

    module, _ = flow

    def fail(*args):
        raise PersistenceError("wrong_database")

    monkeypatch.setattr(module, "_service", lambda: types.SimpleNamespace(job=fail))
    assert module.flow_get_job("other") == {
        "schema_version": "flow-error/1",
        "error": {"code": "wrong_database"},
    }
    monkeypatch.setattr(
        module,
        "_service",
        lambda: types.SimpleNamespace(
            job=lambda *_: (_ for _ in ()).throw(PersistenceError("not_found"))
        ),
    )
    assert module.flow_get_job("foreign") == {
        "schema_version": "flow-error/1",
        "error": {"code": "wrong_database_or_unknown_id"},
    }


@pytest.mark.parametrize("phase", ["cfg", "explicit", "implicit"])
@pytest.mark.parametrize("stop", ["cancel", "deadline"])
def test_implicit_analysis_stops_during_computation_without_publication(
    flow, monkeypatch, phase, stop
):
    from threading import Event

    from ida_pro_mcp.flow_core.contracts import Snapshot
    from ida_pro_mcp.flow_core.implicit_analysis import ImplicitPolicy
    from ida_pro_mcp.flow_core.runtime import JobCancelled, JobContext, JobDeadline
    from ida_pro_mcp.flow_core.ssa import build_ssa

    module, _ = flow
    service = module._service()
    snapshot = Snapshot.from_data(
        json.loads(
            (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
        )["snapshot"]
    )
    program = build_ssa(snapshot)
    published = []
    monkeypatch.setattr(
        service,
        "_request_runtime",
        lambda request: types.SimpleNamespace(
            store=types.SimpleNamespace(
                put_artifact=lambda *args: published.append(args)
            )
        ),
    )
    cancelled = Event()
    now = [0.0]
    reached = []

    class Context(JobContext):
        def check(self):
            # Observe actual work, not just entry/exit calls or a mocked engine.
            caller = sys._getframe(1)
            name = caller.f_code.co_name
            local = caller.f_locals
            in_phase = (
                (phase == "cfg" and name == "tick" and local["self"].used > 0)
                or (
                    phase == "explicit"
                    and name == "analyze"
                    and local.get("evaluations", 0) > 0
                )
                or (
                    phase == "implicit"
                    and name == "_analyze_regions"
                    and local.get("evaluations", 0) > 0
                )
            )
            if in_phase:
                reached.append(phase)
                if stop == "cancel":
                    cancelled.set()
                else:
                    now[0] = 10.0
            super().check()

    context = Context(cancelled, 10.0, lambda: now[0], lambda *args: None)
    with pytest.raises(JobCancelled if stop == "cancel" else JobDeadline):
        service._analyze_implicit(
            context, (program, (), ImplicitPolicy(), {"ssa_artifact": "source"})
        )
    assert reached == [phase]
    assert published == []


def test_check_path_public_selector_schema_and_equation_rejection(flow, monkeypatch):
    module, server = flow
    schema = next(
        t["inputSchema"]
        for t in server._mcp_tools_list()["tools"]
        if t["name"] == "flow_check_path"
    )
    assert set(schema["properties"]) == {
        "graph_artifact",
        "path",
        "request_key",
        "artifact_id",
        "cursor",
        "limit",
    }
    calls = []
    monkeypatch.setattr(
        module,
        "_service",
        lambda: types.SimpleNamespace(
            create_path_proof=lambda *args: calls.append(args) or {"job_id": "path-job"}
        ),
    )
    assert (
        module.flow_check_path("graph", {"blocks": [0, 1]}, "key")["job_id"]
        == "path-job"
    )
    assert calls == [("graph", {"blocks": [0, 1]}, "key")]


def test_path_service_rejects_equations_before_runtime_access(flow, monkeypatch):
    from ida_pro_mcp.flow_core import ContractError

    module, _ = flow
    service = module._service()
    monkeypatch.setattr(
        service, "context", lambda: pytest.fail("must reject before runtime access")
    )
    with pytest.raises(ContractError):
        service.create_path_proof("graph", {"variables": [], "constraints": []}, "key")


def test_check_path_pages_evidence_and_rejects_mixed_modes(flow, monkeypatch):
    module, _ = flow
    calls = []
    monkeypatch.setattr(
        module,
        "_service",
        lambda: types.SimpleNamespace(
            analysis_page=lambda *args: calls.append(args) or {"section": "path_proof"}
        ),
    )
    assert (
        module.flow_check_path(artifact_id="proof", cursor="cursor", limit=1)["section"]
        == "path_proof"
    )
    assert calls == [("proof", "path_proof", "cursor", 1)]
    assert (
        module.flow_check_path(artifact_id="proof", path={})["error"]["code"]
        == "mixed_path_request"
    )
    assert module.flow_check_path()["error"]["code"] == "invalid_path_submission"


def test_program_path_artifact_paging_is_bounded_and_replayable(flow, monkeypatch):
    import threading
    from ida_pro_mcp.flow_core.contracts import Snapshot
    from ida_pro_mcp.flow_core.path_conditions import PathSelector, path_bindings
    from ida_pro_mcp.flow_core.ssa import build_ssa

    module, _ = flow
    service = module._service()
    snapshot = Snapshot.from_data(
        json.loads(
            (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
        )["snapshot"]
    )
    graph = build_ssa(snapshot).graph
    selector = PathSelector(path_bindings(graph), (snapshot.function.entry_block,))
    saved = {}

    def put(_kind, artifact):
        saved["artifact"] = artifact
        return "artifact-v1:" + "0" * 64

    runtime = types.SimpleNamespace(
        store=types.SimpleNamespace(
            put_artifact=put, artifact=lambda _id: saved["artifact"]
        )
    )
    monkeypatch.setattr(service, "_request_runtime", lambda _request: runtime)
    monkeypatch.setattr(service, "get_runtime", lambda: runtime)
    ctx = types.SimpleNamespace(check=lambda: None, cancel=threading.Event())
    result = service._analyze_path_proof(
        ctx, (graph, selector, {"graph_artifact": "owned-graph"})
    )
    assert result["status"] == "unknown"
    assert result["target_executed"] is False
    first = module.flow_check_path(artifact_id=result["path_proof_artifact"], limit=1)
    assert len(first["items"]) == 1
    assert first == module.flow_check_path(
        artifact_id=result["path_proof_artifact"], limit=1
    )
    assert first["metadata"]["model_kind"] == "incomplete"
    assert len(json.dumps(first)) < 40000
    assert any(
        item["type"] == "path_constraint"
        for item in service._proof_page(saved["artifact"])[0]
    )


def test_check_path_requires_explicit_selector_version_before_runtime(
    flow, monkeypatch
):
    module, _ = flow
    service = module._service()
    monkeypatch.setattr(
        service, "context", lambda: pytest.fail("invalid selector reached runtime")
    )
    result = module.flow_check_path("graph", {"bindings": {}, "blocks": [0]}, "key")
    assert result["error"]["code"] == "Wrong fields for PathSelector"
