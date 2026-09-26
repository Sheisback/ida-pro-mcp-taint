"""Keep distributed usage examples aligned with the real MCP input schemas."""

import hashlib
import json
from pathlib import Path
import re
import shutil

from jsonschema import Draft202012Validator
import pytest

from ida_pro_mcp import idalib_supervisor
from ida_pro_mcp.flow_core.angr_client import ANGR_INTERPRETER_ENV
from ida_pro_mcp.flow_core.query import wire_safe_node_item
from ida_pro_mcp.flow_core.serialization import (
    ensure_wire_v1_safe,
    from_wire_v2,
    to_wire_v2,
)
from test_flow_capabilities import flow  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/ida-flow"
REFERENCE = SKILL / "references/requests.md"
EXAMPLES = [
    json.loads(block)
    for block in re.findall(r"```json\n(.*?)\n```", REFERENCE.read_text(), re.S)
]


@pytest.mark.parametrize("example", EXAMPLES, ids=lambda value: value["name"])
def test_skill_requests_match_supervisor_tool_schemas(flow, example):  # noqa: F811
    _, server = flow
    supervisor = idalib_supervisor.IdalibSupervisor(
        idalib_supervisor.McpServer("usage-schema-check"), max_workers=1
    )
    schemas = {
        tool["name"]: supervisor._inject_database_arg(tool)["inputSchema"]
        for tool in server._mcp_tools_list()["tools"]
    }
    schemas.update({
        tool["name"]: tool["inputSchema"]
        for tool in idalib_supervisor.mcp._mcp_tools_list()["tools"]
    })
    profile = {
        line.strip()
        for line in (ROOT / "profiles/flow-readonly.txt").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }
    assert example["name"] in profile | {"idb_open", "idb_close"}
    Draft202012Validator(schemas[example["name"]]).validate(example["arguments"])


def test_documented_profile_checksum_matches_distributed_profile():
    text = (ROOT / "docs/flow-installation.md").read_text()
    pin = re.search(r"^FLOW_REF=([0-9a-f]{40})$", text, re.M)
    checksum = re.search(r"printf '([0-9a-f]{64})  %s", text)
    assert pin is not None and checksum is not None
    assert checksum[1] == hashlib.sha256(
        (ROOT / "profiles/flow-readonly.txt").read_bytes()
    ).hexdigest()


def test_optional_engine_environment_is_forwarded_by_plugin():
    config = json.loads((ROOT / ".codex-plugin/mcp.json").read_text())
    variables = config["mcpServers"]["idalib"]["env_vars"]
    assert ANGR_INTERPRETER_ENV in variables
    assert len(variables) == len(set(variables))


def test_skill_reference_survives_standalone_installation(tmp_path):
    installed = tmp_path / "ida-flow"
    shutil.copytree(SKILL, installed)
    text = (installed / "SKILL.md").read_text()
    references = re.findall(r"\]\((references/[^)#]+)\)", text)
    assert references
    for reference in references:
        assert (installed / reference).is_file()
    assert EXAMPLES, "The request reference must contain schema-checkable examples"


def test_aasystem_constant_examples_match_actual_wire_renderers():
    contract = (ROOT / "docs/aasystem-g02-contract-draft.ko.txt").read_text()
    examples = [
        json.loads(block)
        for block in re.findall(r"```json\n(.*?)\n```", contract, re.S)
    ]
    value = {"constant": (1 << 53) + 1}
    v1 = next(item for item in examples if "constant_hex" in item)
    v2 = next(item for item in examples if isinstance(item.get("constant"), dict))
    assert wire_safe_node_item(value) == v1
    ensure_wire_v1_safe(v1)
    assert int(v1["constant_hex"], 16) == value["constant"]
    assert to_wire_v2(value) == v2
    assert from_wire_v2(v2) == value
