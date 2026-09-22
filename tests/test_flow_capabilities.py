"""Capability contracts without an IDA license; actual IDA tests live in api_flow."""

import importlib.util
import sys
import types
from pathlib import Path

import pytest

from _mcp_spec_support import McpServer
from ida_pro_mcp import idalib_supervisor as supmod

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src/ida_pro_mcp/ida_mcp"


@pytest.fixture
def flow(monkeypatch):
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
            init_hexrays_plugin=lambda: True, get_hexrays_version=lambda: "test-hexrays"
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_kernwin",
        types.SimpleNamespace(get_kernel_version=lambda: "test-ida"),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_ida",
        types.SimpleNamespace(
            f_MACHO=7,
            inf_get_procname=lambda: "metapc",
            inf_is_64bit=lambda: True,
            inf_is_32bit_exactly=lambda: False,
            inf_is_be=lambda: False,
            inf_get_filetype=lambda: 7,
        ),
    )
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
        "test-hexrays" if ready else None
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
        "durable_jobs",
        "microcode_extraction",
    ):
        assert result["features"][name]["status"] == "unavailable"


def test_runtime_context_uses_exact_measured_registry_profile(
    flow, monkeypatch, tmp_path
):
    from ida_pro_mcp.flow_core.profile_registry import REGISTRY

    module, _ = flow
    binary = tmp_path / "fixture"
    binary.write_bytes(b"static input; never executed")
    package = module.__package__
    monkeypatch.setitem(
        sys.modules,
        "ida_funcs",
        types.SimpleNamespace(get_func=lambda ea: types.SimpleNamespace(start_ea=ea)),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_loader",
        types.SimpleNamespace(
            PATH_TYPE_IDB=1, get_path=lambda _kind: str(binary) + ".i64"
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_nalt",
        types.SimpleNamespace(get_input_file_path=lambda: str(binary)),
    )
    monkeypatch.setitem(
        sys.modules,
        package + ".utils",
        types.SimpleNamespace(parse_address=lambda _selector: 0x1000),
    )
    monkeypatch.setattr(
        module.ida_ida, "inf_get_database_change_count", lambda: 0, raising=False
    )
    service = module._service()
    for processor, profile_id in (("metapc", "X64-LE"), ("ARM", "A64-LE")):
        monkeypatch.setattr(module.ida_ida, "inf_get_procname", lambda: processor)
        info = service._context("0x1000", profile_id)
        assert info["profile"] == REGISTRY.measured_extraction_profile(profile_id)
        assert REGISTRY.validate_extraction_profile(info["profile"]) == REGISTRY.get(
            profile_id
        )


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
        "flow_get_job",
        "flow_cancel_job",
        "flow_get_function_ssa",
        "flow_get_cfg",
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
