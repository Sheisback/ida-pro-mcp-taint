"""Independent integrity and safety gates for the public BinCAT x64 corpus."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import cast

import pytest


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "tests/flow_fixtures/public/bincat_x64"
FLOW_RECEIPT = BASE / "flow_receipt.json"


def load_json(name: str):
    return json.loads((BASE / name).read_text())


def load_script(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def acquisition():
    return load_script("acquire_bincat_x64.py")


@pytest.fixture(scope="module")
def recorder():
    return load_script("record_bincat_x64_static.py")


@pytest.fixture(scope="module")
def flow_recorder():
    return load_script("record_bincat_x64_flow.py")


def test_provenance_manifest_is_exact_and_fetch_only(acquisition):
    manifest = load_json("provenance.json")
    acquisition.validate_manifest(manifest)
    assert manifest["upstream"] == {
        "commit": acquisition.PINNED_COMMIT,
        "commit_date": "2025-02-25T17:53:49+01:00",
        "repository": acquisition.PINNED_REPOSITORY,
    }
    assert {
        row["path"]: (row["size"], row["sha256"]) for row in manifest["files"]
    } == acquisition.PINNED_FILES
    assert manifest["artifact_policy"]["binary_and_pdb"] == (
        "fetch_only_not_redistributed"
    )
    assert manifest["acquisition"]["target_executed"] is False
    assert manifest["acquisition"]["ordinary_tests_require_network"] is False


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda value: value["upstream"].update(repository="https://example.test"),
            "URL",
        ),
        (lambda value: value["upstream"].update(commit="0" * 40), "commit"),
        (lambda value: value["files"][0].update(url="https://example.test/x"), "URL"),
        (lambda value: value["files"][0].update(sha256="0" * 64), "allowlist"),
    ],
)
def test_sc01_manifest_mismatch_fails_closed(acquisition, mutation, message):
    manifest = copy.deepcopy(load_json("provenance.json"))
    mutation(manifest)
    with pytest.raises(acquisition.CorpusError, match=message):
        acquisition.validate_manifest(manifest)


def test_sc01_download_substitution_leaves_no_output(
    acquisition, monkeypatch, tmp_path
):
    monkeypatch.setattr(acquisition, "_download", lambda _url: b"silent substitute")
    output = tmp_path / "isolated-cache"
    with pytest.raises(acquisition.CorpusError, match="Downloaded content mismatch"):
        acquisition.acquire(BASE / "provenance.json", output)
    assert not output.exists()


def test_license_and_notice_identity_is_pinned():
    manifest = load_json("provenance.json")
    evidence = {row["path"]: row["conclusion"] for row in manifest["license_evidence"]}
    assert evidence == {
        "README.md": "BinCAT repository statement: GNU AGPL",
        "doc/Apache-license-2.0": (
            "Apache License 2.0 text for the bundled SHA-1 source"
        ),
        "doc/COPYING": "GNU Affero General Public License version 3 text",
        "doc/get_key/sha1.c": "Direct SPDX Apache-2.0 header",
        "doc/get_key/sha1.h": "Direct SPDX Apache-2.0 header",
    }
    files = {row["path"]: row for row in manifest["files"]}
    assert files["doc/COPYING"]["sha256"] == (
        "57c8ff33c9c0cfc3ef00e650a1cc910d7ee479a8bc509f6c9209a7c2a11399d6"
    )
    assert files["doc/Apache-license-2.0"]["sha256"] == (
        "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
    )


def test_pe_pdb_identity_is_proven_but_source_is_not():
    identity = load_json("identity.json")
    assert identity["binary"]["format"] == "PE32+"
    assert identity["binary"]["machine"] == "x86_64"
    assert identity["binary"]["codeview"] == {
        "age": 1,
        "guid": "5c16eb2b-ccd3-4c03-bc8e-ec38c0e718ad",
        "pdb_path": (
            "C:\\Users\\abouh\\source\\repos\\Bincat_get_key\\x64\\Release\\"
            "Bincat_get_key.pdb"
        ),
        "record_file_offset": 12512,
    }
    assert identity["pdb"]["guid"] == identity["binary"]["codeview"]["guid"]
    assert identity["pdb"]["age"] == identity["binary"]["codeview"]["age"]
    assert identity["binary_pdb_correspondence"]["status"] == "proven"
    assert identity["source_correspondence"]["status"] == "unproven"
    assert identity["source_correspondence"]["source_authority"] == "reference_only"
    assert identity["source_correspondence"]["binary_observations"] == "authoritative"


def test_sc03_mismatched_pdb_is_downgraded(acquisition):
    identity = load_json("identity.json")
    pdb = copy.deepcopy(identity["pdb"])
    pdb["age"] += 1
    report = acquisition.compare_identities(identity["binary"], pdb)
    assert report == {
        "pdb_authority": "reference_only",
        "reason": "PE CodeView GUID-age does not match PDB info-stream GUID-age",
        "status": "mismatched",
    }


def test_static_ida_receipt_uses_snapshot_local_x64_selectors(recorder):
    receipt = load_json("ida_static_receipt.json")
    recorder.validate_snapshot_receipt(receipt)
    assert receipt["ida_version"] == "9.3"
    assert receipt["input_preserved"] is True
    assert receipt["target_executed"] is False
    assert receipt["debugger_attached"] is False
    assert receipt["identity"]["binary_pdb_correspondence"]["status"] == "proven"
    assert receipt["identity"]["source_correspondence"]["status"] == "unproven"
    assert receipt["selector_source"] == "PDB names plus snapshot-local x64 RVAs"
    assert receipt["command"][0] == "idat"
    assert receipt["command_kind"] == "static_ida_load_and_snapshot"


def test_sc02_x86_tutorial_address_is_rejected(recorder):
    receipt = copy.deepcopy(load_json("ida_static_receipt.json"))
    receipt["functions"][0]["rva"] = recorder.LEGACY_X86_TUTORIAL_ANALYSIS_EP
    with pytest.raises(ValueError, match="x86 tutorial address"):
        recorder.validate_snapshot_receipt(receipt)


def test_receipt_retains_unresolved_indirect_calls_as_unknown():
    receipt = load_json("ida_static_receipt.json")
    functions = {row["name"]: row for row in receipt["functions"]}
    unresolved = [
        call
        for call in functions["main"]["calls"]
        if call["resolution"] == "unresolved_indirect"
    ]
    assert [(row["site_rva"], row["targets"]) for row in unresolved] == [
        (0x138E, []),
        (0x1397, []),
    ]
    assert functions["custom_crc32"]["rva"] == 0x10EC
    assert functions["compute_hash"]["rva"] == 0x1134
    assert functions["main"]["rva"] == 0x1258


def test_hand_authored_oracle_covers_bounded_required_observables():
    oracle = load_json("oracle.json")
    assert "hand-authored independently" in oracle["oracle_origin"]
    assert oracle["authority"] == {
        "binary_observations": "authoritative",
        "pdb_symbols": "authoritative only after GUID-age proof",
        "source": "reference_only_unproven_correspondence",
    }
    cases = {row["case_id"]: row for row in oracle["cases"]}
    assert set(cases) == {
        "pointer-value-versus-pointed-bytes",
        "user-info-field-range",
        "caller-callee-pointer-boundary",
        "buffer-write-dependency",
        "unresolved-call-conservatism",
    }
    pointer = cases["pointer-value-versus-pointed-bytes"]
    assert set(pointer["seed_domains"]) == {"pointer_value", "pointed_bytes"}
    fields = cases["user-info-field-range"]
    assert fields["field_ranges"]["company"] == [0, 8]
    assert any("whole-struct" in row for row in fields["forbidden_relations"])
    unknown = cases["unresolved-call-conservatism"]
    assert any("partial or unknown" in row for row in unknown["expected_relations"])
    assert any("no-flow" in row for row in unknown["forbidden_relations"])
    assert "not_vulnerability_or_safety_verdict" in oracle["status"]


def test_actual_structured_flow_receipt_is_static_fresh_and_roundtrippable(
    flow_recorder,
):
    from ida_pro_mcp.flow_core.contracts import Snapshot

    receipt = json.loads(FLOW_RECEIPT.read_text())
    assert receipt["schema_version"] == "bincat-x64-flow-static/1"
    assert receipt["environment"] == {
        "hexrays_version": "9.3.0.260213",
        "ida_version": "9.3",
    }
    assert receipt["target_executed"] is False
    assert receipt["debugger_attached"] is False
    assert receipt["input_preserved"] is True
    assert receipt["binary_sha256"] == (
        "687a36f98a8b62fc0411e0e9e8d09c42608f201a7fe68d2e3ea4272b98fe0a70"
    )
    assert receipt["pdb_sha256"] == (
        "dde5e815e9c7c25f7b73319b9a491aa9ac2c860317164fbe067353993ab0563d"
    )
    assert receipt["identity"]["binary_pdb_correspondence"]["status"] == "proven"
    assert receipt["identity"]["source_correspondence"]["status"] == "unproven"
    assert receipt["profile"]["format_id"] == "FMT-PE"
    assert receipt["profile"]["abi"] == "windows-x64"
    assert (
        receipt["generator_sha256"]
        == hashlib.sha256(
            (ROOT / "scripts/flow_bincat_x64_extract.py").read_bytes()
        ).hexdigest()
    )
    assert (
        receipt["recorder_sha256"]
        == hashlib.sha256(
            (ROOT / "scripts/record_bincat_x64_flow.py").read_bytes()
        ).hexdigest()
    )
    assert [(row["name"], row["function_rva"]) for row in receipt["functions"]] == [
        ("custom_crc32", 0x10EC),
        ("compute_hash", 0x1134),
        ("main", 0x1258),
    ]
    for function in receipt["functions"]:
        assert function["repeat_equal"] is True
        assert function["roundtrip_equal"] is True
        Snapshot.from_data(function["snapshot"])
    assert flow_recorder.replay(receipt["functions"]) == receipt["core_replay"]


def test_actual_core_keeps_pointer_value_separate_from_pointed_bytes():
    from ida_pro_mcp.flow_core.contracts import Snapshot
    from ida_pro_mcp.flow_core.ssa import build_ssa

    receipt = json.loads(FLOW_RECEIPT.read_text())
    function = next(
        row for row in receipt["functions"] if row["name"] == "custom_crc32"
    )
    program = build_ssa(cast(Snapshot, Snapshot.from_data(function["snapshot"])))
    load = next(node for node in program.graph.nodes if node.kind == "Load")
    incoming = [edge for edge in program.graph.edges if edge.target == load.node_id]
    assert {edge.kind for edge in incoming} == {"address_dependency"}
    probe = next(
        row
        for row in receipt["core_replay"]["functions"]
        if row["function_key"] == "bincat-custom-crc32"
    )["pointer_value_probe"]
    assert probe["separation_proven"] is True
    assert probe["address_labels"]["explicit"] == ["pointer_value"]
    assert probe["load_labels"]["explicit"] == []
    assert probe["pointed_bytes_status"] == "unknown_without_memory_object_seed"
    assert probe["memory_status"] == "partial"


def test_actual_core_retains_four_distinct_user_info_field_loads():
    receipt = json.loads(FLOW_RECEIPT.read_text())
    replay = next(
        row
        for row in receipt["core_replay"]["functions"]
        if row["function_key"] == "bincat-compute-hash"
    )
    fields = replay["user_info_fields"]
    assert fields["offsets"] == [0, 8, 16, 24]
    assert fields["width_bytes"] == 8
    assert len(set(fields["load_nodes"])) == 4
    assert fields["whole_struct_collapsed"] is False
    assert replay["node_kinds"]["Load"] >= 4
    assert replay["edge_kinds"]["address_dependency"] >= 8


def test_actual_core_preserves_unresolved_buffer_and_indirect_call_boundaries():
    receipt = json.loads(FLOW_RECEIPT.read_text())
    core = receipt["core_replay"]
    assert core["status"] == "partial"
    assert core["buffer_write_status"] == "partial_unresolved_boundary"
    assert "no reviewed summary" in core["buffer_write_reason"]
    assert core["vulnerability_or_safety_verdict"] is False
    rows = {row["function_key"]: row for row in core["functions"]}
    for key in ("bincat-compute-hash", "bincat-main"):
        row = rows[key]
        assert row["scalar_status"] == "partial"
        assert row["memory_status"] == "partial"
        assert row["unresolved_call_count"] > 0
        assert "call_effects_unresolved" in row["program_diagnostics"]
        assert "unknown_call_or_write" in row["memory_diagnostics"]
        assert row["memory_dependency_count"] == 0
    assert receipt["invocation"][0] == "idat"
    assert "-A" in receipt["invocation"] and "-c" in receipt["invocation"]
    assert receipt["invocation"][-1] == "$BINARY"


def test_no_upstream_binary_archive_or_pdb_is_committed():
    forbidden_suffixes = {".exe", ".pdb", ".zip", ".tar", ".gz", ".7z"}
    assert not [
        path
        for path in BASE.rglob("*")
        if path.is_file() and path.suffix.lower() in forbidden_suffixes
    ]
