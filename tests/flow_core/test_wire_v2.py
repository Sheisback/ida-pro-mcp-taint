"""Lossless wire integers and independently reproducible identity preimages."""

from dataclasses import dataclass, field, replace
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from ida_pro_mcp.flow_core.contracts import Snapshot
from ida_pro_mcp.flow_core.ssa import build_ssa
from ida_pro_mcp.flow_core.wire_contracts import (
    validate_model_wire_v2,
    wire_v2_scope,
)
from ida_pro_mcp.flow_core.serialization import (
    ContractError,
    Model,
    canonical_json,
    canonical_json_v2,
    digest,
    digest_v2,
    ensure_wire_v1_safe,
    from_wire_v2,
    graph_digest_bytes_v2,
    stable_id_v2,
    to_wire_v2,
    validate_bit_pattern,
    validate_ea,
    validate_signed,
    validate_structural_int,
    validate_unsigned,
)


@pytest.mark.parametrize(
    "address", [(1 << 53) - 1, 1 << 53, (1 << 53) + 1, (1 << 64) - 2]
)
def test_large_addresses_roundtrip_without_number_conversion(address):
    data = {"address": address, "evidence": [{"source_eas": [address]}], "ok": True}
    encoded = json.loads(canonical_json_v2(data))
    assert encoded["address"] == {"$int": str(address)}
    assert encoded["ok"] is True
    assert from_wire_v2(encoded) == data
    assert validate_ea(address) == address


def test_adjacent_large_addresses_have_distinct_ids():
    for kind in ("snapshot", "node", "evidence", "edge", "object", "memory"):
        assert stable_id_v2(kind, {"ea": 1 << 53}) != stable_id_v2(
            kind, {"ea": (1 << 53) + 1}
        )


def _snapshot_with_ea(ea: int) -> Snapshot:
    fixture = json.loads(
        Path("tests/flow_fixtures/manifests/extraction_x64.json").read_text()
    )["snapshot"]
    original = Snapshot.from_data(fixture)
    function = original.function
    block = function.blocks[1]
    instruction = replace(
        block.instructions[0],
        source_eas=tuple(sorted(set(block.instructions[0].source_eas) | {ea})),
    )
    block = replace(block, instructions=(instruction,) + block.instructions[1:])
    function = replace(
        function, blocks=(function.blocks[0], block) + function.blocks[2:]
    )
    identity = replace(
        original.identity,
        input_digest=digest(function),
        wire_version="flow-wire/2",
    )
    return Snapshot(identity, function, identity.snapshot_id)


def test_actual_snapshot_graph_identities_preserve_adjacent_large_eas():
    graphs = [
        build_ssa(_snapshot_with_ea(ea)).graph
        for ea in (1 << 53, (1 << 53) + 1, (1 << 64) - 2)
    ]
    assert len({graph.snapshot.snapshot_id for graph in graphs}) == 3
    assert len({graph.nodes[0].node_id for graph in graphs}) == 3
    assert len({graph.graph_digest for graph in graphs}) == 3
    for graph in graphs:
        assert graph.graph_digest.startswith("sha256-v2:")
        assert all(
            item.evidence_id.startswith("evidence-v2:") for item in graph.evidence
        )
    for invalid in (-1, (1 << 64) - 1, 1 << 64):
        if invalid < 0:
            with pytest.raises(ContractError):
                _snapshot_with_ea(invalid)
        else:
            with pytest.raises(ContractError, match="integer_out_of_range"):
                _snapshot_with_ea(invalid)


@pytest.mark.parametrize(
    "value", ["+1", " 1", "1 ", "1\n", "01", "-0", "1e3", "1.0", "", "١", 1, True, None]
)
def test_noncanonical_tag_rejected(value):
    with pytest.raises(ContractError):
        from_wire_v2({"$int": value})


@pytest.mark.parametrize(
    "value",
    [0, 1 << 53, (1 << 53) + 1, 0.0, 1.5, float("nan"), {"$int": "1", "extra": False}],
)
def test_numeric_leaves_and_extended_tags_rejected(value):
    with pytest.raises(ContractError):
        from_wire_v2({"nested": [value]})


@pytest.mark.parametrize("value", [-1, 1 << 64, (1 << 64) - 1, True, 1.0])
def test_invalid_ea_rejected(value):
    with pytest.raises(ContractError, match="integer_out_of_range"):
        validate_ea(value)


def test_integer_category_limits():
    assert validate_ea((1 << 16) - 2, 16) == (1 << 16) - 2
    with pytest.raises(ContractError):
        validate_ea(1 << 16, 16)
    assert validate_unsigned((1 << 64) - 1) == (1 << 64) - 1  # RVA permits all ones.
    for value in (-(1 << 63), (1 << 63) - 1):
        assert validate_signed(value) == value
    for value in (-(1 << 63) - 1, 1 << 63, True):
        with pytest.raises(ContractError):
            validate_signed(value)
    assert validate_bit_pattern((1 << 4096) - 1, 4096) == (1 << 4096) - 1
    for value, width in ((256, 8), (-1, 8), (1, 0), (1, 4097), (True, 8)):
        with pytest.raises(ContractError):
            validate_bit_pattern(value, width)
    assert validate_structural_int((1 << 53) - 1) == (1 << 53) - 1
    with pytest.raises(ContractError):
        validate_structural_int(1 << 53)
    assert from_wire_v2(to_wire_v2((1 << 4096) - 1)) == (1 << 4096) - 1
    with pytest.raises(ContractError):
        from_wire_v2({"$int": "9" * 1235})


def test_public_integer_field_limits_cover_signed_offsets_and_plural_addresses():
    pointer = {"object_id": "object-v2:" + "a" * 64, "offset": -(1 << 63)}
    targets = {"target_node_id": "node-v2:" + "b" * 64, "targets": [(1 << 64) - 2]}
    closure = {"visited_rvas": [(1 << 64) - 1], "candidate_rvas": [1 << 53]}
    validate_model_wire_v2(
        {"pointer": pointer, "targets": targets, "closure": closure}, 64
    )
    for invalid in (
        {"object_id": pointer["object_id"], "offset": -(1 << 63) - 1},
        {"target_node_id": targets["target_node_id"], "targets": [(1 << 64) - 1]},
        {"visited_rvas": [1 << 64]},
    ):
        with pytest.raises(ContractError, match="integer_out_of_range"):
            validate_model_wire_v2(invalid, 64)


def test_user_labels_do_not_select_wire_version():
    response = {
        "metadata": {"snapshot_id": "snapshot-v1:" + "a" * 64},
        "items": [{"labels": {"explicit": ["flow-wire/2", "snapshot-v2:" + "b" * 64]}}],
    }
    assert wire_v2_scope(response) == (False, None)
    response["metadata"]["wire_version"] = "flow-wire/2"
    assert wire_v2_scope(response) == (True, None)


def test_v1_safe_guard_preserves_existing_canonicalization():
    value = {"n": (1 << 53) - 1, "ok": True}
    before = canonical_json(value), digest(value)
    ensure_wire_v1_safe(value)
    assert before == (canonical_json(value), digest(value))
    for number in (1 << 53, -(1 << 53), float(1 << 53)):
        with pytest.raises(ContractError, match="unsafe_integer_for_wire_v1"):
            ensure_wire_v1_safe({"items": [number]})


def test_graph_digest_hashes_complete_domain_wrapper():
    graph = {
        "nodes": [{"constant": 1 << 127}],
        "evidence": [{"source_eas": [(1 << 64) - 2]}],
    }
    preimage = graph_digest_bytes_v2(graph)
    wrapper = json.loads(preimage)
    assert wrapper == {
        "domain": "graph",
        "identity_version": 2,
        "value": to_wire_v2(graph),
    }
    assert digest_v2(graph) == "sha256-v2:" + hashlib.sha256(preimage).hexdigest()
    assert from_wire_v2(wrapper["value"]) == graph


def test_js_bigint_identity_parity():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js not installed")
    data = {"z": [True, None, "한글"], "a": [(1 << 53) + 1, (1 << 64) - 2, 1 << 127]}
    script = r"""
const crypto = require('crypto');
const fs = require('fs');
const tree = JSON.parse(fs.readFileSync(0, 'utf8'));
function canonical(x) {
  if (Array.isArray(x)) return '[' + x.map(canonical).join(',') + ']';
  if (x !== null && typeof x === 'object') {
    if ('$int' in x && BigInt(x.$int).toString() !== x.$int) throw Error('noncanonical');
    return '{' + Object.keys(x).sort().map(k => JSON.stringify(k)+':'+canonical(x[k])).join(',') + '}';
  }
  return JSON.stringify(x);
}
const result = {};
for (const kind of ['snapshot', 'node', 'evidence', 'graph']) {
  result[kind] = crypto.createHash('sha256').update(canonical({domain:kind,identity_version:2,value:tree})).digest('hex');
}
process.stdout.write(JSON.stringify(result));
"""
    result = subprocess.run(
        [node, "-e", script],
        input=canonical_json_v2(data),
        text=True,
        capture_output=True,
        check=True,
    )
    hashes = json.loads(result.stdout)
    for kind in ("snapshot", "node", "evidence"):
        assert stable_id_v2(kind, data) == f"{kind}-v2:" + hashes[kind]
    assert digest_v2(data) == "sha256-v2:" + hashes["graph"]


def test_reserved_keys_floats_and_cycles_fail_closed():
    for value in ({"$int": "1"}, 1.5, {"\ud800": None}):
        with pytest.raises(ContractError):
            to_wire_v2(value)
    cycle = []
    cycle.append(cycle)
    for operation in (to_wire_v2, from_wire_v2, ensure_wire_v1_safe):
        with pytest.raises(ContractError):
            operation(cycle)


def test_version_default_omission_preserves_legacy_model_bytes():
    @dataclass(frozen=True)
    class Versioned(Model):
        value: int
        wire_version: str = field(
            default="flow-wire/1", metadata={"omit_if_default": True}
        )

    assert Versioned(1).to_data() == {"value": 1}
    assert Versioned.from_data({"value": 1}) == Versioned(1)
    assert Versioned(1, "flow-wire/2").to_data() == {
        "value": 1,
        "wire_version": "flow-wire/2",
    }
    for value in ({}, {"value": 1, "extra": 0}):
        with pytest.raises(ContractError):
            Versioned.from_data(value)
