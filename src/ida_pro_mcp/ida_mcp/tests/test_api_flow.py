"""Runtime contract tests shared by GUI/plugin and headless imports."""

import inspect

from .. import api_flow, trace
from ..api_flow import BUILD_ID, SCHEMA_VERSION
from ..framework import test
from ..rpc import MCP_SERVER, MCP_UNSAFE


@test()
def test_flow_capabilities_honest():
    # Resolve through the API module: mcp_mode patches this attribute, not aliases.
    from .mcp_mode import _instance

    before = list(trace.iter_idb_records()) if _instance is not None else []
    result = api_flow.flow_get_capabilities()
    if _instance is not None:
        added = list(trace.iter_idb_records())[len(before):]
        assert len(added) == 1, "Expected one real tools/call trace record"
        assert added[0]["tool"] == "flow_get_capabilities"
        assert added[0]["arguments"] == {}
        assert added[0]["isError"] is False
        assert added[0]["structuredContent"]["build_id"] == BUILD_ID
    assert result["schema_version"] == SCHEMA_VERSION
    assert result["build_id"] == BUILD_ID
    assert len(BUILD_ID.split(":")[-1]) == 64
    assert set(result["supported_profiles"]) <= {"X64-LE", "A64-LE"}
    assert result["features"]["capability_discovery"]["status"] == "available"
    for name, feature in result["features"].items():
        if name not in {
            "capability_discovery",
            "snapshot",
            "value_ssa",
            "memory_ssa",
            "taint",
            "interprocedural",
            "implicit_flow",
            "path_proof",
            "durable_jobs",
            "microcode_extraction",
        }:
            assert feature["status"] in ("unverified", "unavailable")
    supported = bool(result["supported_profiles"])
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
        assert (result["features"][name]["status"] == "available") == supported
    assert result["environment"]["bits"] in (16, 32, 64)
    assert any("netnode" in item and "save" in item for item in result["limitations"])


@test()
def test_flow_registration_and_local_schema():
    tools = {tool["name"]: tool for tool in MCP_SERVER._mcp_tools_list()["tools"]}
    assert {name for name in tools if name.startswith("flow_")} == {
        name for name in dir(api_flow) if name.startswith("flow_")
    }
    assert "trace_data_flow" in tools and "decompile" in tools
    assert "database" not in tools["flow_get_capabilities"]["inputSchema"].get("properties", {})
    assert not inspect.signature(api_flow.flow_get_capabilities).parameters
    assert "flow_get_capabilities" not in MCP_UNSAFE
