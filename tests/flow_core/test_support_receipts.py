"""Support-receipt completeness and no-promotion regression tests."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path

import pytest

from ida_pro_mcp.flow_core import ContractError, digest
from ida_pro_mcp.flow_core.profile_registry import PROFILE_IDS
from ida_pro_mcp.flow_core.support_receipts import (
    build_support_receipt_manifest,
    validate_support_receipt_manifest,
)

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/audit_flow_support.py"
MANIFEST = ROOT / "tests/flow_fixtures/manifests/support_receipts.json"


def _load_script():
    spec = importlib.util.spec_from_file_location("audit_flow_support_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


audit = _load_script()


def _read(path: Path):
    return json.loads(path.read_text())


def _sources():
    return (
        _read(ROOT / audit.INVENTORY),
        _read(ROOT / audit.P0_ROOT / "matrix.json"),
        _read(ROOT / audit.SEMANTIC_MATRIX),
    )


def test_committed_support_manifest_is_complete_reproducible_and_static_only():
    committed = _read(MANIFEST)
    assert committed == audit.build(ROOT)
    validate_support_receipt_manifest(committed)
    assert tuple(row["profile_id"] for row in committed["profiles"]) == PROFILE_IDS
    assert committed["profile_count"] == 17
    assert committed["normal_observation_count"] == 16
    assert committed["fallback_observation_count"] == 1
    assert committed["format_variant_count"] == 4
    assert committed["status"] == "complete_with_explicit_fallbacks"
    assert committed["target_executed"] is False
    assert committed["support_promoted"] is False
    assert {row["support_status"] for row in committed["profiles"]} == {"unverified"}


def test_rv32_remains_an_explicit_partial_fallback_not_a_support_promotion():
    receipt = _read(MANIFEST)
    rv32 = next(row for row in receipt["profiles"] if row["profile_id"] == "RV32-LE")
    assert rv32 == {
        "profile_id": "RV32-LE",
        "p0_status": "failed",
        "semantic_evidence_path": "fallback",
        "semantic_status": "accepted_candidate_partial_normal_failed",
        "support_status": "unverified",
    }


@pytest.mark.parametrize(
    "mutation",
    [
        lambda receipt: receipt.update(target_executed=True),
        lambda receipt: receipt.update(support_promoted=True),
        lambda receipt: receipt["source_digests"].update(inventory="sha256-v1:"),
        lambda receipt: receipt["profiles"][0].update(support_status="supported"),
        lambda receipt: receipt["profiles"].pop(),
    ],
)
def test_support_manifest_rejects_promotion_and_coverage_drift(mutation):
    receipt = deepcopy(_read(MANIFEST))
    mutation(receipt)
    with pytest.raises(ContractError):
        validate_support_receipt_manifest(receipt)


def test_builder_rejects_p0_status_that_contradicts_semantic_availability():
    inventory, p0_matrix, semantic_matrix = _sources()
    row = next(row for row in p0_matrix["rows"] if row["profile_id"] == "RV32-LE")
    row["status"] = "success"
    with pytest.raises(ContractError, match="P0/semantic availability mismatch"):
        build_support_receipt_manifest(inventory, p0_matrix, semantic_matrix)


def test_builder_derives_normal_and_fallback_eligibility_from_rows_not_names():
    inventory, p0_matrix, semantic_matrix = _sources()
    rv32_semantic = next(
        row for row in semantic_matrix["profiles"] if row["profile_id"] == "RV32-LE"
    )
    x86_semantic = next(
        row
        for row in semantic_matrix["profiles"]
        if row["profile_id"] == "X86-LE" and row["evidence_path"] == "normal"
    )
    rv32_semantic.update(
        evidence_path="normal", status="success_partial_with_named_limitations"
    )
    x86_semantic.update(
        evidence_path="fallback", status="accepted_candidate_partial_normal_failed"
    )
    semantic_matrix["rv32_normal_failure_count"] = 0
    semantic_matrix["rv32_fallback_count"] = 0
    semantic_matrix["receipt_digest"] = digest(
        {
            key: value
            for key, value in semantic_matrix.items()
            if key != "receipt_digest"
        }
    )
    next(row for row in p0_matrix["rows"] if row["profile_id"] == "RV32-LE")[
        "status"
    ] = "success"
    next(row for row in p0_matrix["rows"] if row["profile_id"] == "X86-LE")[
        "status"
    ] = "failed"

    result = build_support_receipt_manifest(inventory, p0_matrix, semantic_matrix)
    by_profile = {row["profile_id"]: row for row in result["profiles"]}
    assert by_profile["RV32-LE"]["semantic_evidence_path"] == "normal"
    assert by_profile["RV32-LE"]["p0_status"] == "success"
    assert by_profile["X86-LE"]["semantic_evidence_path"] == "fallback"
    assert by_profile["X86-LE"]["p0_status"] == "failed"


def test_audit_rejects_p0_body_tamper_with_copied_digest_label(monkeypatch):
    _, p0_matrix, semantic_matrix = _sources()
    result_file = p0_matrix["rows"][0]["result_file"]
    target = (ROOT / audit.P0_ROOT / result_file).resolve()
    original_read_json = audit.read_json

    def tampered_read_json(path: Path):
        value = original_read_json(path)
        if path.resolve() == target:
            value["binary"]["copied_sha256"] = "0" * 64
        return value

    monkeypatch.setattr(audit, "read_json", tampered_read_json)
    with pytest.raises(ValueError, match="receipt digest"):
        audit.validate_referenced_receipts(ROOT, p0_matrix, semantic_matrix)


def test_audit_rejects_semantic_body_tamper_with_copied_digest_label(monkeypatch):
    _, p0_matrix, semantic_matrix = _sources()
    row = next(
        item
        for item in semantic_matrix["profiles"]
        if item["evidence_path"] == "normal"
    )
    target = (ROOT / row["receipt_file"]).resolve()
    original_read_json = audit.SEMANTIC_RECEIPTS.read_json

    def tampered_read_json(path: Path):
        value = original_read_json(path)
        if path.resolve() == target:
            value["environment"]["processor"] = "tampered"
        return value

    monkeypatch.setattr(audit.SEMANTIC_RECEIPTS, "read_json", tampered_read_json)
    with pytest.raises(ValueError, match="receipt digest"):
        audit.validate_referenced_receipts(ROOT, p0_matrix, semantic_matrix)


def test_support_manifest_rejects_semantic_status_tamper():
    receipt = deepcopy(_read(MANIFEST))
    receipt["profiles"][0]["semantic_status"] = "success"
    body = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    receipt["receipt_digest"] = digest(body)
    with pytest.raises(ContractError, match="semantic status"):
        validate_support_receipt_manifest(receipt)


def test_docs_name_every_profile_and_the_static_only_boundary():
    compatibility = (ROOT / "docs/flow-compatibility.md").read_text()
    operator = (ROOT / "docs/flow-operator.md").read_text()
    for profile_id in PROFILE_IDS:
        assert f"`{profile_id}`" in compatibility
    assert "does not promote runtime support" in compatibility
    assert "does not establish distribution release readiness" in compatibility
    assert (
        "protected Linux runner or an official licensed 5×30 benchmark" in compatibility
    )
    assert "separate strict distribution gate" in compatibility
    assert "recomputes every referenced receipt body" in compatibility
    assert "Never execute the target" in operator
    assert "target_executed: false" in operator
    assert "copied digest labels" in operator
