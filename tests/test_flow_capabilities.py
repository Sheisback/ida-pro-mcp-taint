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
            inf_get_procname=lambda: "metapc",
            inf_is_64bit=lambda: True,
            inf_is_32bit_exactly=lambda: False,
            inf_is_be=lambda: False,
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
    assert result["supported_profiles"] == []
    assert all(
        v["status"] != "available"
        for k, v in result["features"].items()
        if k != "capability_discovery"
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
