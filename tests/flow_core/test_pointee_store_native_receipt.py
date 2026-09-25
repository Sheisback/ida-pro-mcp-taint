"""Check recorded native observations, not independent binary/driver proofs.

Regenerate with native_pointee_store_probe.py after implementation changes;
never replace build/digest labels without rerunning licensed static IDA.
"""

import hashlib
import json
from pathlib import Path

import pytest

from ida_pro_mcp.flow_core.build_identity import BUILD_ID, extension_build_id
from ida_pro_mcp.flow_core.serialization import digest

ROOT = Path(__file__).resolve().parents[2]
RECEIPT = ROOT / "tests/flow_fixtures/manifests/pointee_store_native.json"


@pytest.fixture(scope="module")
def receipt():
    return json.loads(RECEIPT.read_text())


def one(items, kind):
    selected = [item for item in items if item["type"] == kind]
    assert len(selected) == 1
    return selected[0]


def test_recorded_native_inputs_and_implementation_are_current(receipt):
    assert receipt["schema_version"] == "flow-pointee-store-probe/1"
    assert receipt["passed"] is True
    assert receipt["target_executed"] is False
    assert receipt["build_id"] == BUILD_ID == extension_build_id()
    for key, path in (
        ("source_sha256", "tests/flow_fixtures/pointee_store.c"),
        ("runner_sha256", "tests/flow_core/native_pointee_store_probe.py"),
    ):
        assert receipt[key] == hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
    assert len(receipt["runs"]) == 2
    assert {row["arch"] for row in receipt["runs"]} == {"x86_64", "arm64"}
    assert (
        "Darwin Mach-O fixture is not Windows driver validation"
        in receipt["limitations"]
    )


@pytest.mark.parametrize("arch", ["x86_64", "arm64"])
def test_native_environment_and_disposable_session_boundaries(receipt, arch):
    row = next(row for row in receipt["runs"] if row["arch"] == arch)
    profile, abi, processor = (
        ("X64-LE", "darwin-x86_64-sysv-derived", "metapc")
        if arch == "x86_64"
        else ("A64-LE", "darwin-aarch64", "ARM")
    )
    assert (row["profile"], row["abi"]) == (profile, abi)
    assert row["format"] == "FMT-MACHO"
    assert row["optimization"] == "O1"
    assert row["compiler_flags"][:3] == ["-arch", arch, "-O1"]
    assert row["worker_build_id"] == receipt["build_id"]
    env = row["environment"]
    assert env["ida_version"] == "9.3"
    assert env["hexrays_version"] == "9.3.0.260213"
    assert (env["processor"], env["bits"], env["endian"]) == (processor, 64, "little")
    assert env["hexrays_initialization"]["status"] == "available"
    assert row["closed_save_false"] is True
    assert row["input_preserved"] is True
    for key in ("binary_sha256", "dwarf_sha256"):
        assert len(row[key]) == 64
        assert int(row[key], 16) > 0
    assert {case["function"] for case in row["functions"]} == {
        "pointee_partial_clear",
        "register_callback",
        "register_truncated",
        "register_changed",
    }
    for case in row["functions"]:
        assert case["passed"] is True
        assert case["snapshot"]["target_executed"] is False
        assert case["snapshot"]["snapshot_id"] == case["ssa_metadata"]["snapshot_id"]
        assert case["snapshot"]["graph_digest"] == case["ssa_metadata"]["graph_digest"]
        assert all(
            node["key"]["snapshot_id"] == case["snapshot"]["snapshot_id"]
            for node in case["nodes"]
        )


@pytest.mark.parametrize("arch", ["x86_64", "arm64"])
def test_pointee_partial_clear_observations_and_certificate_bindings(receipt, arch):
    row = next(row for row in receipt["runs"] if row["arch"] == arch)
    case = next(
        case for case in row["functions"] if case["function"] == "pointee_partial_clear"
    )
    nodes = {node["node_id"]: node for node in case["nodes"]}
    for key, kind in (("load_fact", "Load"), ("return_fact", "Return")):
        fact = case[key]
        assert fact in case["implicit_items"]
        assert nodes[fact["node_id"]]["kind"] == kind
        assert nodes[fact["node_id"]]["width_bits"] == 64
        assert fact["labels"] == {
            "explicit": ["BUFFER"],
            "control": [],
            "unknown_provenance": True,
            "any_explicit_source": False,
            "any_control_source": False,
        }
        assert fact["explicit_bit_ranges"] == [
            {"label": "BUFFER", "bit_offset": 32, "width_bits": 32}
        ]
    source = one(case["certificate_items"], "source")
    assert {key: value for key, value in source.items() if key != "type"} == case[
        "seed"
    ]
    assert nodes[source["pointer_node_id"]]["kind"] == "Load"
    assert source["interval"] == {"start": 0, "end": 8}
    assert source["binding_mode"] == "analyst_assumed_exact"
    assert source["point"] == "after_pointer_definition"
    binding = one(case["certificate_items"], "binding")
    seed = one(case["certificate_items"], "content_seed")
    assert seed["node_id"] == binding["source_node_id"]
    assert binding["pointer_node_id"] == source["pointer_node_id"]
    cert, meta, result = (
        case["certificate_metadata"],
        case["implicit_metadata"],
        case["implicit_result"],
    )
    assert (
        cert["implicit_source_digest"]
        == meta["source_digest"]
        == digest([{key: value for key, value in seed.items() if key != "type"}])
    )
    assert cert["snapshot_id"] == case["snapshot"]["snapshot_id"]
    assert cert["base_graph_digest"] == case["snapshot"]["graph_digest"]
    assert (
        cert["graph_digest"]
        == meta["graph_digest"]
        == case["explanation_metadata"]["graph_digest"]
    )
    assert (
        cert["base_ssa_artifact"]
        == meta["base_source_artifact"]
        == case["snapshot"]["ssa_artifact"]
    )
    assert (
        cert["bound_ssa_artifact"] == meta["source_artifact"] == result["ssa_artifact"]
    )
    assert cert["graph_artifact"] == result["graph_artifact"]
    assert (
        meta["pointee_certificate_artifact"] == result["pointee_certificate_artifact"]
    )
    assert any(
        item.get("reason_code") == "pointee_source"
        for item in case["explanation_items"]
    )
    for data in (cert, meta, result, case["explanation_metadata"]):
        assert data["target_executed"] is False
        assert data["no_auto_vulnerability_verdict"] is True


@pytest.mark.parametrize("arch", ["x86_64", "arm64"])
@pytest.mark.parametrize(
    "function,status,reasons",
    [
        ("register_callback", "proven_in_scope", []),
        ("register_truncated", "unknown", ["non_pointer_width_expression"]),
        ("register_changed", "mismatch", ["observed_relation_differs_from_request"]),
    ],
)
def test_store_observations_distinguish_exact_truncated_and_changed_targets(
    receipt, arch, function, status, reasons
):
    row = next(row for row in receipt["runs"] if row["arch"] == arch)
    case = next(case for case in row["functions"] if case["function"] == function)
    observation = one(case["store_items"], "observation")
    target = observation["function_observation"]
    assert target["status"] == "observed"
    assert target["exact_entry"] is True
    assert target["name"] == "callback_target"
    layout = observation["layout_observation"]
    assert layout["status"] == "observed"
    assert layout["member_path"] == ["slots", 14]
    assert (layout["byte_offset"], layout["width_bits"]) == (120, 64)
    assert [
        (step["relative_byte_offset"], step["width_bits"]) for step in layout["steps"]
    ] == [(8, 1024), (112, 64)]
    proof = one(case["store_items"], "proof")
    result, meta = case["store_result"], case["store_metadata"]
    assert proof["status"] == meta["status"] == result["status"] == status
    assert proof["reasons"] == reasons
    assert proof["target_ea"] == target["target_ea"]
    assert proof["base_node_id"] == layout["base_node_id"]
    assert (
        proof["snapshot_id"] == meta["snapshot_id"] == case["snapshot"]["snapshot_id"]
    )
    assert (
        proof["graph_digest"]
        == meta["graph_digest"]
        == case["snapshot"]["graph_digest"]
    )
    assert meta["source_artifact"] == case["snapshot"]["ssa_artifact"]
    assert meta["evidence_digest"] == result["evidence_digest"]
    assert meta["scope"] == "store_site_if_reached_not_final_registration_or_path_proof"
    for data in (result, meta):
        assert data["target_executed"] is False
        assert data["no_auto_vulnerability_verdict"] is True
    if status == "proven_in_scope":
        assert proof["observed_target_ea"] == target["target_ea"]
        assert proof["observed_byte_offset"] == 120
        assert proof["observed_base_node_id"] == proof["base_node_id"]
