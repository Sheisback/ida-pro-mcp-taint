"""Capability contracts without an IDA license; actual IDA tests live in api_flow."""

import importlib.util
import json
import sqlite3
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
    # The sidecar probe only checks configuration (interpreter + vendored
    # runner); the test interpreter satisfies both without importing angr.
    monkeypatch.setenv("IDA_MCP_ANGR_PYTHON", sys.executable)
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
                "symbolic_refinement",
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
    assert selected["supported_profiles"] == []
    assert "analyst-selected" in selected["features"]["snapshot"]["reason"]
    assert "flow_get_job" in selected["features"]["snapshot"]["reason"]
    for name in (
        "snapshot",
        "value_ssa",
        "memory_ssa",
        "taint",
        "implicit_flow",
        "path_proof",
        "microcode_extraction",
    ):
        assert selected["features"][name]["status"] == "unverified"

    pending = engine.store.create_job("snapshot_ssa_v1", {}, "pending-capability")
    assert module.flow_get_capabilities()["features"]["snapshot"]["status"] == (
        "unverified"
    )
    engine.store.transition_job(
        pending, "queued", "failed", error={"code": "MERR_LICENSE"}
    )
    failed = module.flow_get_capabilities()
    assert failed["supported_profiles"] == []
    assert failed["features"]["microcode_extraction"]["status"] == "unverified"

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
    derived = []
    monkeypatch.setattr(
        service,
        "extract_local_direct_callees",
        lambda context, extracted, observed: (
            derived.append((context, extracted, observed)) or ({}, {"boundaries": []})
        ),
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
    assert len(derived) == 1 and derived[0][0] is context
    assert derived[0][2] is info
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
        "flow_get_pointee_evidence",
        "flow_check_store",
        "flow_check_path",
        "flow_refine_path_proof",
        "flow_refine_memory_proof",
        "flow_get_job",
        "flow_cancel_job",
        "flow_get_function_ssa",
        "flow_get_cfg",
        "flow_get_implicit_analysis",
        "flow_explain_implicit_analysis",
        "flow_get_memory_analysis",
        "flow_get_derived_call_evidence",
        "flow_get_call_compositions",
        "flow_trace_forward",
        "flow_trace_backward",
        "flow_continue_trace",
        "flow_cancel_trace",
        "flow_get_graph",
        "flow_get_graph_digest_bytes",
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
    assert "Load" in by_name["flow_create_implicit_analysis"]["description"]
    assert "pointee" in by_name["flow_create_implicit_analysis"]["description"]
    assert "pointer value" in by_name["flow_get_function_ssa"]["description"]
    assert "unknown_provenance" in by_name["flow_get_implicit_analysis"]["description"]
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
    assert len(seed["anyOf"]) == 3
    whole, bit_range, pointee = seed["anyOf"]
    assert pointee["additionalProperties"] is False
    assert set(pointee["required"]) == {
        "kind", "schema_version", "pointer_node_id", "interval", "labels",
        "binding_mode", "point",
    }
    assert pointee["properties"]["kind"]["enum"] == ["pointee_range"]
    assert whole["additionalProperties"] is False
    assert set(whole["required"]) == {"node_id", "labels"}
    assert bit_range["additionalProperties"] is False
    assert set(bit_range["required"]) == {
        "kind",
        "schema_version",
        "node_id",
        "labels",
        "bit_offset",
        "width_bits",
    }
    assert bit_range["properties"]["kind"]["enum"] == ["bit_range"]
    version_variants = bit_range["properties"]["schema_version"]["anyOf"]
    assert any(item.get("enum") == [1] for item in version_variants)
    assert any("$int" in item.get("properties", {}) for item in version_variants)
    assert all(
        variant["properties"]["labels"]["additionalProperties"] is False
        for variant in (whole, bit_range)
    )


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
        explain_implicit=lambda *args: (
            calls.append(("explain", args))
            or {
                "schema_version": "flow-page/1",
                "artifact_id": args[0],
                "section": "implicit_explanation",
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
    assert (
        module.flow_explain_implicit_analysis(
            "i-result", "node-v1:" + "2" * 64, "cursor", 7, 99, 11
        )["section"]
        == "implicit_explanation"
    )
    assert module.flow_get_memory_analysis("m-result")["section"] == "memory"
    assert module.flow_get_derived_call_evidence("d-result")["section"] == (
        "derived_call"
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
        (
            "explain",
            ("i-result", "node-v1:" + "2" * 64, "cursor", 7, 99, 11),
        ),
        ("page", ("m-result", "memory", None, 50)),
        ("page", ("d-result", "derived_call", None, 50)),
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


def test_public_snapshot_forwards_wire_v2_opt_in(flow, monkeypatch):
    module, _ = flow
    calls = []
    monkeypatch.setattr(
        module,
        "_service",
        lambda: types.SimpleNamespace(
            create=lambda *args: (
                calls.append(args)
                or {
                    "schema_version": "flow-job/1",
                    "job_id": "v2-job",
                    "experimental": True,
                }
            )
        ),
    )
    result = module.flow_create_snapshot(
        "0x1000", "X64-LE", "request", wire_version="flow-wire/2"
    )
    assert result["job_id"] == "v2-job"
    assert calls == [
        ("0x1000", "X64-LE", "request", None, "exact_fixture", "flow-wire/2")
    ]


def test_v1_label_does_not_change_public_integer_encoding(flow):
    module, _ = flow

    @module._flow_api
    def view():
        return {
            "metadata": {"snapshot_id": "snapshot-v1:" + "a" * 64},
            "items": [{"width_bits": 64, "labels": ["flow-wire/2"]}],
        }

    assert view()["items"][0]["width_bits"] == 64


def test_wire_v2_rejects_reviewed_catalog_before_submission(flow, monkeypatch):
    from ida_pro_mcp.flow_core.serialization import ContractError

    module, _ = flow
    service = module._service()
    monkeypatch.setattr(
        service,
        "context",
        lambda *args: {"ea": 0x1000, "profile": {"bitness": 64}},
    )
    monkeypatch.setattr(
        service,
        "reviewed_catalog",
        lambda info: types.SimpleNamespace(summaries=(object(),)),
    )
    monkeypatch.setattr(
        service, "get_runtime", lambda *args: pytest.fail("no job should be submitted")
    )
    with pytest.raises(ContractError, match="wire_v2_reviewed_summary_unavailable"):
        service.create("0x1000", "X64-LE", "key", wire_version="flow-wire/2")


def test_memory_page_exposes_bounded_access_precision_without_verdict(flow):
    from ida_pro_mcp.flow_core.contracts import Snapshot
    from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
    from ida_pro_mcp.flow_core.query import artifact_page

    module, _ = flow
    service = module._service()
    raw = json.loads(
        (
            ROOT / "tests/flow_fixtures/manifests/memory/x86_64_memory_alias.json"
        ).read_text()
    )
    bundle = build_memory_graph(Snapshot.from_data(raw["snapshot"]))
    items, metadata = service._memory_page(bundle.result.to_data())
    accesses = [item for item in items if item["type"] == "access"]
    assert accesses and all(
        "precision" in item and "candidates" in item and "reasons" in item
        for item in accesses
    )
    assert all(
        (not item["reasons"]) if not item["unresolved"] else bool(item["reasons"])
        for item in accesses
    )
    assert metadata["status"] == bundle.result.status
    assert metadata["diagnostics"] == list(bundle.result.diagnostics)
    assert metadata["target_executed"] is False
    assert metadata["no_auto_vulnerability_verdict"] is True
    assert metadata["alias_policy"]["untyped_input_current_frame"] == (
        "may_alias_unknown"
    )
    assert metadata["untyped_current_frame_alias_dependency_count"] == sum(
        item.get("alias_boundary") is not None for item in items
    )
    assert "vulnerability_verdict" not in metadata
    assert all("vulnerability_verdict" not in item for item in items)
    page = artifact_page("owned", "memory", items, metadata, limit=1)
    assert page["items"] and page["next_cursor"]
    with pytest.raises(ContractError):
        service._memory_page({"schema_version": 1, "facts": []})


def test_memory_page_identifies_cross_object_may_alias_without_promoting_status(flow):
    from ida_pro_mcp.flow_core.contracts import Snapshot
    from ida_pro_mcp.flow_core.memory_graph import build_memory_graph

    module, _ = flow
    service = module._service()
    raw = json.loads(
        (
            ROOT
            / "tests/flow_fixtures/manifests/memory/x86_64_memory_global_roundtrip.json"
        ).read_text()
    )
    bundle = build_memory_graph(Snapshot.from_data(raw["snapshot"]))
    items, metadata = service._memory_page(bundle.result.to_data())
    uncertain = [
        item
        for item in items
        if item["type"] == "dependency" and item["reason"] == "cross_object_may_alias"
    ]
    assert uncertain
    assert all(
        item["object_id"] not in item["source_candidate_object_ids"]
        and item["impact"]
        == {
            "node_id": item["target"],
            "scope": "direct_target_load",
            "downstream": "trace_from_target_node",
        }
        for item in uncertain
    )
    assert metadata["status"] == bundle.result.status == "complete_in_scope"
    assert not any(item.get("reason") == "no_alias" for item in items)
    assert metadata["untyped_current_frame_alias_dependency_count"] == sum(
        item.get("alias_boundary") is not None for item in items
    )


def test_type_backed_argument_binding_exposes_exact_entry_atoms(flow):
    from ida_pro_mcp.flow_core import digest
    from ida_pro_mcp.flow_core.contracts import (
        Block,
        FunctionInput,
        Instruction,
        Operand,
        Snapshot,
    )
    from ida_pro_mcp.flow_core.ssa import build_ssa
    from ida_pro_mcp.flow_core.states import StorageLocation

    module, _ = flow
    base = Snapshot.from_data(
        json.loads(
            (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
        )["snapshot"]
    )
    storage = StorageLocation("microregister", "microregister", 448, 32)
    annotation = Instruction(
        0,
        "m_arg",
        (
            Operand("constant", 32, constant=0, role="left"),
            Operand("storage", 32, storage=storage, role="argument", synthetic=True),
        ),
        synthetic=True,
    )
    returned = Instruction(1, "m_ret", (Operand("storage", 32, storage=storage),))
    function = FunctionInput(
        "typed-argument-test", 0, (Block(0, (), (annotation, returned)),)
    )
    identity = replace(
        base.identity, function_id=function.function_id, input_digest=digest(function)
    )
    program = build_ssa(Snapshot(identity, function, identity.snapshot_id))
    binding = module._service()._argument_bindings(program)
    assert len(binding) == 1 and binding[0]["argument_index"] == 0
    assert binding[0]["storage"] == storage.to_data()
    assert binding[0]["entry_node_ids"] == [
        item.node_id for item in program.entry_storage
    ]
    assert binding[0]["type_correctness"] == "analyst_assumption"
    assert binding[0]["idb_pointer_type_assumption"] is False


def _entry_register_program():
    from ida_pro_mcp.flow_core import digest
    from ida_pro_mcp.flow_core.contracts import (
        Block,
        FunctionInput,
        Instruction,
        Operand,
        Snapshot,
    )
    from ida_pro_mcp.flow_core.ssa import build_ssa
    from ida_pro_mcp.flow_core.states import StorageLocation

    base = Snapshot.from_data(
        json.loads(
            (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
        )["snapshot"]
    )
    read_a = StorageLocation("microregister", "microregister", 0, 8)
    read_b = StorageLocation("microregister", "microregister", 64, 8)
    written = StorageLocation("microregister", "microregister", 128, 8)
    add = Instruction(
        0,
        "m_add",
        (
            Operand("storage", 8, storage=read_a),
            Operand("storage", 8, storage=read_b),
            Operand("storage", 8, storage=written, role="destination"),
        ),
    )
    returned = Instruction(
        1, "m_ret", (Operand("storage", 8, storage=written),)
    )
    function = FunctionInput(
        "entry-register-test", 0, (Block(0, (), (add, returned)),)
    )
    identity = replace(
        base.identity, function_id=function.function_id, input_digest=digest(function)
    )
    return build_ssa(Snapshot(identity, function, identity.snapshot_id))


def test_entry_register_table_lists_only_exact_aliases(flow, monkeypatch):
    hx = sys.modules["ida_hexrays"]
    bases = {100: 0, 101: 8}
    monkeypatch.setattr(
        hx, "reg2mreg", lambda regno: bases.get(regno, -1), raising=False
    )
    monkeypatch.setattr(
        hx,
        "mreg2reg",
        lambda mreg, size: (100 if (mreg, size) == (0, 1) else -1),
        raising=False,
    )
    monkeypatch.setattr(
        hx, "get_mreg_name", lambda mreg, size: "al", raising=False
    )
    module, _ = flow
    table, status = module._service().entry_register_table()
    assert status == "resolved"
    assert table == {"0/1": "al"}


def test_entry_register_table_degrades_explicitly_without_hexrays(
    flow, monkeypatch
):
    monkeypatch.setitem(sys.modules, "ida_hexrays", None)
    module, _ = flow
    table, status = module._service().entry_register_table()
    assert table == {}
    assert status == "hexrays_unavailable"


def test_resolve_entry_registers_names_atoms_and_marks_the_rest(flow):
    module, _ = flow
    program = _entry_register_program()
    resolved = module._service()._resolve_entry_registers(
        program.entry_storage, {"table": {"0/1": "al"}, "status": "resolved"}
    )
    by_offset = {entry["bit_offset"]: entry for entry in resolved}
    assert {0, 64} <= set(by_offset)
    assert by_offset[0]["register"] == "al"
    assert by_offset[0]["reason"] is None
    assert by_offset[0]["width_bits"] == 8
    assert by_offset[64]["register"] is None
    assert by_offset[64]["reason"] == "no_exact_alias"
    assert all(entry["node_id"] for entry in resolved)
    degraded = module._service()._resolve_entry_registers(
        program.entry_storage, {"table": {}, "status": "hexrays_unavailable"}
    )
    assert all(
        entry["register"] is None and entry["reason"] == "hexrays_unavailable"
        for entry in degraded
    )


def test_derived_call_evidence_page_checks_caller_callee_binding(flow):
    from ida_pro_mcp.flow_core import digest, stable_id
    from ida_pro_mcp.flow_core.contracts import Snapshot
    from ida_pro_mcp.flow_core.derived_calls import DerivedReturnEffect
    from ida_pro_mcp.flow_core.persistence import PersistenceError
    from ida_pro_mcp.flow_core.states import StorageLocation

    module, _ = flow
    service = module._service()
    callee = Snapshot.from_data(
        json.loads(
            (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
        )["snapshot"]
    )
    effect = DerivedReturnEffect(
        stable_id("snapshot", "caller"),
        callee.snapshot_id,
        0x1000,
        0,
        0,
        StorageLocation("microregister", "microregister", 64, 32),
        (),
        digest("bounded-return-proof"),
    )
    raw = {
        "schema_version": "flow-derived-call-evidence/1",
        "caller_snapshot_id": effect.caller_snapshot_id,
        "callee_snapshot": callee.to_data(),
        "effect": effect.to_data(),
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
    }
    items, metadata = service._derived_call_page(raw)
    assert [item["type"] for item in items] == [
        "derived_return_effect",
        "callee_snapshot",
    ]
    assert metadata["provenance"] == "derived_static_unreviewed"
    assert metadata["proof_digest"] == effect.proof_digest
    assert metadata["memory_effects"] == "unknown"
    assert metadata["target_executed"] is False
    with pytest.raises(
        PersistenceError, match="derived_call_evidence_binding_mismatch"
    ):
        service._derived_call_page(
            {**raw, "caller_snapshot_id": stable_id("snapshot", "foreign")}
        )


def test_derived_memory_free_evidence_is_rechecked_against_callee(flow):
    from ida_pro_mcp.flow_core import digest, stable_id
    from ida_pro_mcp.flow_core.contracts import (
        Block,
        FunctionInput,
        Instruction,
        Operand,
        Snapshot,
    )
    from ida_pro_mcp.flow_core.derived_calls import DerivedReturnEffect
    from ida_pro_mcp.flow_core.persistence import PersistenceError
    from ida_pro_mcp.flow_core.states import StorageLocation

    module, _ = flow
    service = module._service()
    base = Snapshot.from_data(
        json.loads(
            (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
        )["snapshot"]
    )

    def callee(*instructions):
        function = FunctionInput("static-callee", 0, (Block(0, (), instructions),))
        identity = replace(
            base.identity,
            function_id=function.function_id,
            input_digest=digest(function),
        )

        return Snapshot(identity, function, identity.snapshot_id)

    returned = Instruction(
        1, "m_ret", (Operand("constant", 32, constant=7, role="left"),)
    )
    pure = callee(replace(returned, index=0))
    effect = DerivedReturnEffect(
        stable_id("snapshot", "caller"),
        pure.snapshot_id,
        0x1000,
        0,
        0,
        StorageLocation("microregister", "microregister", 64, 32),
        (),
        digest("bounded-pure-proof"),
        "none",
    )
    raw = {
        "schema_version": "flow-derived-call-evidence/1",
        "caller_snapshot_id": effect.caller_snapshot_id,
        "callee_snapshot": pure.to_data(),
        "effect": effect.to_data(),
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
    }
    _, metadata = service._derived_call_page(raw)
    assert metadata["memory_effects"] == "none"
    assert "no modeled memory effects" in metadata["limitation"]

    writer = callee(
        Instruction(
            0,
            "m_mov",
            (
                Operand("constant", 32, constant=9, role="left"),
                Operand("global", 32, address=0x2000, role="destination"),
            ),
        ),
        returned,
    )
    with pytest.raises(
        PersistenceError, match="derived_call_memory_effect_proof_mismatch"
    ):
        service._derived_call_page(
            {
                **raw,
                "callee_snapshot": writer.to_data(),
                "effect": replace(
                    effect, callee_snapshot_id=writer.snapshot_id
                ).to_data(),
            }
        )


def test_derived_output_write_evidence_rejects_tampered_effect(flow, monkeypatch):
    from ida_pro_mcp.flow_core import digest
    from ida_pro_mcp.flow_core.derived_calls import derive_direct_memory_write
    from ida_pro_mcp.flow_core.persistence import PersistenceError

    monkeypatch.syspath_prepend(str(ROOT / "tests/flow_core"))
    from test_derived_calls import callee_write_output, caller_write_output

    module, _ = flow
    service = module._service()
    caller, call = caller_write_output()
    callee = callee_write_output()
    effect = derive_direct_memory_write(caller, callee, call, 0, 2)
    assert effect is not None
    raw = {
        "schema_version": "flow-derived-call-memory-evidence/1",
        "caller_snapshot": caller.to_data(),
        "callee_snapshot": callee.to_data(),
        "call_info": call.to_data(),
        "effect": effect.to_data(),
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
    }
    items, metadata = service._derived_call_page(raw)
    assert {item["type"] for item in items} == {
        "derived_memory_write_effect",
        "caller_snapshot",
        "callee_snapshot",
        "call_info",
    }
    assert metadata["memory_effects"] == "single_typed_output_write"
    assert metadata["proof_digest"] == effect.proof_digest
    assert metadata["target_executed"] is False
    with pytest.raises(
        PersistenceError, match="derived_call_memory_effect_proof_mismatch"
    ):
        service._derived_call_page(
            {
                **raw,
                "effect": replace(effect, proof_digest=digest("forged")).to_data(),
            }
        )
    with pytest.raises(
        PersistenceError, match="derived_call_memory_evidence_binding_mismatch"
    ):
        service._derived_call_page(
            {**raw, "callee_snapshot": callee_write_output(global_write=True).to_data()}
        )
    with pytest.raises(
        PersistenceError, match="derived_call_memory_effect_proof_mismatch"
    ):
        service._derived_call_page(
            {**raw, "call_info": replace(call, arguments=()).to_data()}
        )


def test_derived_fixed_global_write_evidence_replays_and_rejects_tamper(
    flow, monkeypatch
):
    from ida_pro_mcp.flow_core import digest
    from ida_pro_mcp.flow_core.derived_calls import derive_direct_global_write
    from ida_pro_mcp.flow_core.persistence import PersistenceError

    monkeypatch.syspath_prepend(str(ROOT / "tests/flow_core"))
    from test_derived_calls import caller, fixed_global_callee

    module, _ = flow
    service = module._service()
    source = caller()
    call = source.function.blocks[0].instructions[1].operands[-1].call
    target = fixed_global_callee()
    effect = derive_direct_global_write(source, target, call, 0, 1)
    assert effect is not None
    raw = {
        "schema_version": "flow-derived-call-global-memory-evidence/1",
        "caller_snapshot": source.to_data(),
        "callee_snapshot": target.to_data(),
        "call_info": call.to_data(),
        "effect": effect.to_data(),
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
    }
    items, metadata = service._derived_call_page(raw)
    assert {item["type"] for item in items} == {
        "derived_global_write_effect",
        "caller_snapshot",
        "callee_snapshot",
        "call_info",
    }
    assert metadata["memory_effects"] == "single_fixed_global_write"
    assert metadata["global_address"] == effect.global_address
    assert metadata["proof_digest"] == effect.proof_digest
    with pytest.raises(
        PersistenceError, match="derived_call_global_memory_effect_proof_mismatch"
    ):
        service._derived_call_page(
            {
                **raw,
                "effect": replace(effect, proof_digest=digest("forged")).to_data(),
            }
        )
    with pytest.raises(
        PersistenceError, match="derived_call_global_memory_evidence_binding_mismatch"
    ):
        service._derived_call_page(
            {**raw, "callee_snapshot": fixed_global_callee(constant=True).to_data()}
        )


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


def test_implicit_explanation_page_binds_owned_graph_and_global_reasons(
    flow, monkeypatch
):
    from ida_pro_mcp.flow_core import ContractError, digest
    from ida_pro_mcp.flow_core.contracts import Snapshot
    from ida_pro_mcp.flow_core.implicit_analysis import analyze_implicit
    from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
    from ida_pro_mcp.flow_core.persistence import PersistenceError

    module, _ = flow
    service = module._service()
    source = Snapshot.from_data(
        json.loads(
            (
                ROOT / "tests/flow_fixtures/manifests/memory/x86_64_memory_alias.json"
            ).read_text()
        )["snapshot"]
    )
    bundle = build_memory_graph(source)
    result = analyze_implicit(bundle.program, memory_model=bundle)
    raw = {
        "schema_version": "flow-implicit-artifact/1",
        "source_artifact": "ssa",
        "result": result.to_data(),
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
    }
    records = {"implicit": raw, "ssa": bundle.program.to_data()}
    monkeypatch.setattr(
        service,
        "get_runtime",
        lambda: types.SimpleNamespace(
            store=types.SimpleNamespace(artifact=lambda identifier: records[identifier])
        ),
    )
    target = result.facts[0].node_id
    page = service.explain_implicit("implicit", target, limit=1, max_nodes=8)
    assert page["schema_version"] == "flow-page/1"
    assert page["metadata"]["source_artifact"] == "ssa"
    assert page["metadata"]["observation_node_id"] == target
    assert page["metadata"]["no_auto_vulnerability_verdict"] is True
    assert page["metadata"]["analysis_status"] == result.status
    if page["next_cursor"] is not None:
        continued = service.explain_implicit(
            "implicit", target, page["next_cursor"], limit=1, max_nodes=8
        )
        assert continued["items"]
        with pytest.raises(PersistenceError, match="invalid_cursor"):
            service.explain_implicit(
                "implicit", target, page["next_cursor"], limit=1, max_nodes=9
            )
    with pytest.raises(ContractError, match="Unknown observation node"):
        service.explain_implicit("implicit", "node-v1:" + "0" * 64)
    records["implicit"] = {
        **raw,
        "result": replace(result, graph_digest=digest("foreign")).to_data(),
    }
    with pytest.raises(ContractError, match="Explanation graph mismatch"):
        service.explain_implicit("implicit", target)
    from ida_pro_mcp.flow_core.memory_graph import replay_memory_graph

    replay = replay_memory_graph(bundle.program)
    records.update(
        {
            "implicit": {
                **raw,
                "schema_version": "flow-implicit-artifact/2",
                "memory_plan_artifact": "plan",
                "memory_result_artifact": "memory",
            },
            "plan": replay.plan.to_data(),
            "memory": replay.result.to_data(),
        }
    )
    monkeypatch.setattr(
        service,
        "replay_memory_graph",
        lambda *_args: pytest.fail(
            "v2 page must reuse its verified memory certificate"
        ),
    )
    page = service.explain_implicit("implicit", target)
    assert page["metadata"]["memory_plan_artifact"] == "plan"
    assert page["metadata"]["memory_result_artifact"] == "memory"
    records["memory"] = replace(replay.result, dependencies=()).to_data()
    with pytest.raises(ContractError, match="Stored memory dependency replay mismatch"):
        service.explain_implicit("implicit", target)


def test_mcp_pages_name_untyped_input_current_frame_unknown(flow, monkeypatch):
    from ida_pro_mcp.flow_core import digest
    from ida_pro_mcp.flow_core.analysis import seeds_for_entry
    from ida_pro_mcp.flow_core.contracts import (
        Block,
        FunctionInput,
        Instruction,
        Operand,
        Snapshot,
    )
    from ida_pro_mcp.flow_core.implicit_analysis import analyze_implicit
    from ida_pro_mcp.flow_core.memory_graph import (
        build_memory_graph,
        replay_memory_graph,
    )
    from ida_pro_mcp.flow_core.states import Labels, StorageLocation

    module, _ = flow
    service = module._service()
    original = Snapshot.from_data(
        json.loads(
            (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
        )["snapshot"]
    )
    value = StorageLocation("microregister", "microregister", 0, 32)
    pointer = StorageLocation("microregister", "microregister", 64, 64)
    spill = StorageLocation("stack", "stack", 0, 32)
    output = StorageLocation("microregister", "microregister", 128, 32)
    function = FunctionInput(
        "mcp-untyped-frame-alias",
        0,
        (
            Block(
                0,
                (),
                (
                    Instruction(
                        0,
                        "m_mov",
                        (
                            Operand("storage", 32, storage=value, role="left"),
                            Operand("storage", 32, storage=spill, role="destination"),
                        ),
                    ),
                    Instruction(
                        1,
                        "m_ldx",
                        (
                            Operand("constant", 16, constant=0, role="left"),
                            Operand("storage", 64, storage=pointer, role="right"),
                            Operand("storage", 32, storage=output, role="destination"),
                        ),
                    ),
                    Instruction(2, "m_ret", (Operand("storage", 32, storage=output),)),
                ),
            ),
        ),
    )
    identity = replace(
        original.identity,
        function_id=function.function_id,
        input_digest=digest(function),
    )
    snapshot = Snapshot(identity, function, identity.snapshot_id)
    bundle = build_memory_graph(snapshot)
    replay = replay_memory_graph(bundle.program)
    seeds = seeds_for_entry(bundle.program, value, Labels(("X",)))
    analysis = analyze_implicit(bundle.program, seeds, memory_model=bundle)
    returned = next(node for node in bundle.graph.nodes if node.kind == "Return")
    records = {
        "ssa": bundle.program.to_data(),
        "plan": replay.plan.to_data(),
        "memory": replay.result.to_data(),
        "implicit": {
            "schema_version": "flow-implicit-artifact/2",
            "source_artifact": "ssa",
            "memory_plan_artifact": "plan",
            "memory_result_artifact": "memory",
            "result": analysis.to_data(),
            "target_executed": False,
            "no_auto_vulnerability_verdict": True,
        },
    }
    monkeypatch.setattr(
        service,
        "get_runtime",
        lambda: types.SimpleNamespace(
            store=types.SimpleNamespace(artifact=lambda key: records[key])
        ),
    )

    first_memory_page = module.flow_get_memory_analysis("memory", limit=1)
    assert first_memory_page["next_cursor"] is not None
    assert first_memory_page["metadata"]["untyped_current_frame_alias_dependency_count"]
    memory_page = module.flow_get_memory_analysis("memory", limit=100)
    boundary = next(
        item["alias_boundary"]
        for item in memory_page["items"]
        if item.get("alias_boundary") is not None
    )
    assert boundary["reason_code"] == "untyped_input_current_frame_noalias_unproven"
    assert boundary["status"] == "unknown"
    assert boundary["alias_relation"] == "may_alias"
    assert boundary["source_target_pairs"]
    object_by_id = {obj.object_id: obj for obj in replay.result.objects}
    pair = boundary["source_target_pairs"][0]
    typed_objects = {
        object_id: replace(obj, kind="typed_entry") if obj.kind == "argument" else obj
        for object_id, obj in object_by_id.items()
    }
    assert (
        service._untyped_frame_alias_boundary(
            pair["target_object_id"], (pair["source_object_id"],), typed_objects
        )
        is None
    )
    assert memory_page["metadata"]["alias_policy"]["untyped_input_current_frame"] == (
        "may_alias_unknown"
    )
    assert memory_page["metadata"]["untyped_current_frame_alias_dependency_count"]
    assert memory_page["metadata"]["target_executed"] is False

    first_explanation_page = module.flow_explain_implicit_analysis(
        "implicit", returned.node_id, limit=1
    )
    assert first_explanation_page["next_cursor"] is not None
    assert first_explanation_page["metadata"]["untyped_current_frame_alias_cause_count"]
    explanation = module.flow_explain_implicit_analysis(
        "implicit", returned.node_id, limit=100
    )
    assert explanation["metadata"]["untyped_current_frame_alias_cause_count"]
    assert explanation["metadata"]["observation_labels"]["unknown_provenance"]
    assert any(
        item.get("alias_boundary", {}).get("reason_code")
        == "untyped_input_current_frame_noalias_unproven"
        for item in explanation["items"]
        if item.get("alias_boundary") is not None
    )
    assert explanation["metadata"]["no_auto_vulnerability_verdict"] is True


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


def test_public_failed_job_exposes_allowlisted_phase_not_native_path(
    flow, monkeypatch, tmp_path
):
    from ida_pro_mcp.flow_core.persistence import Store
    from ida_pro_mcp.flow_core.runtime import Handler, Runtime
    from ida_pro_mcp.flow_core.runtime_contracts import RuntimeScope
    from ida_pro_mcp.flow_core.serialization import digest

    module, _ = flow
    binding = digest("public-error-cause")
    scope = RuntimeScope("public-job-error-test", *(binding for _ in range(6)))
    store = Store(tmp_path / "store", scope, "public-job-owner-secret-0001-long")

    def fail(ctx, value):
        raise RuntimeError(
            "gen_microcode failed: code=9, ea=0x401000 /Users/private/secret.i64"
        )

    engine = Runtime(store, {"native": Handler(fail, lambda ctx, value: value)})
    monkeypatch.setattr(module._service(), "get_runtime", lambda: engine)
    identifier = engine.submit("native", {}, "native")
    assert engine.wait(identifier)
    response = module.flow_get_job(identifier)
    assert response["state"] == "failed"
    assert response["error"] == {
        "code": "handler_failed",
        "phase": "extract",
        "reason": "microcode_generation_failed",
        "type": "RuntimeError",
    }
    assert "secret" not in json.dumps(response)
    assert "401000" not in json.dumps(response)
    engine.shutdown()
    store.close()


@pytest.mark.parametrize("cancel", (False, True))
def test_public_job_poll_reconciles_finished_worker_after_sqlite_lock(
    flow, monkeypatch, tmp_path, cancel
):
    from ida_pro_mcp.flow_core.persistence import Store
    from ida_pro_mcp.flow_core.runtime import Runtime
    from ida_pro_mcp.flow_core.runtime_contracts import RuntimeScope
    from ida_pro_mcp.flow_core.serialization import digest

    module, _ = flow
    binding = digest("public-job-lock")
    scope = RuntimeScope("public-job-test", *(binding for _ in range(6)))
    store = Store(tmp_path / "store", scope, "public-job-owner-secret-0001-long")
    engine = Runtime(store, {})
    monkeypatch.setattr(module._service(), "get_runtime", lambda: engine)
    job = engine.store.create_job("snapshot_ssa_v1", {}, "public-finish-lock")
    engine.store.transition_job(job, "queued", "extracting", owner=engine.owner)
    engine.store.transition_job(job, "extracting", "analyzing", owner=engine.owner)
    with sqlite3.connect(engine.store.db, isolation_level=None) as connection:
        connection.execute("BEGIN IMMEDIATE")
        engine._finish(job, "failed", {"code": "handler_failed"}, nonblocking=True)
        connection.execute("ROLLBACK")
    response = module.flow_cancel_job(job) if cancel else module.flow_get_job(job)
    assert response["state"] == "failed"
    assert response["error"] == {"code": "handler_failed"}
    store.close()


@pytest.mark.parametrize("phase", ["cfg", "explicit", "implicit"])
@pytest.mark.parametrize("stop", ["cancel", "deadline"])
def test_implicit_analysis_stops_during_computation_without_publication(
    flow, monkeypatch, phase, stop
):
    from threading import Event

    from ida_pro_mcp.flow_core.contracts import Snapshot
    from ida_pro_mcp.flow_core.implicit_analysis import ImplicitPolicy
    from ida_pro_mcp.flow_core.runtime import JobCancelled, JobContext, JobDeadline
    from ida_pro_mcp.flow_core.memory_graph import build_memory_graph

    module, _ = flow
    service = module._service()
    snapshot = Snapshot.from_data(
        json.loads(
            (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
        )["snapshot"]
    )
    program = build_memory_graph(snapshot).program
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
                    and name == "run"
                    and local.get("processed", 0) > 0
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
