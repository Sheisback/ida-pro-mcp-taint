"""Pure completeness contract for the committed static support receipts.

Completeness means that every required profile has a reviewed observation.  It
does not promote the profile registry or turn partial evidence into a runtime
support guarantee.
"""

from typing import Any

from .profile_registry import PROFILE_IDS, REGISTRY
from .profile_semantic_receipts import validate_complete_matrix_receipt
from .serialization import ContractError, digest
from .states import check_digest, require

SUPPORT_RECEIPT_SCHEMA = "flow-support-receipts/1"
P0_MATRIX_SCHEMA = "flow-profile-receipt-matrix/1"

_SEMANTIC_STATUS = {
    "normal": "success_partial_with_named_limitations",
    "fallback": "accepted_candidate_partial_normal_failed",
}


def _rows(value: Any, key: str, message: str) -> list[dict[str, Any]]:
    rows = value.get(key) if type(value) is dict else None
    if type(rows) is not list or any(type(row) is not dict for row in rows):
        raise ContractError(message)
    return rows


def _canonical_p0_rows(matrix: dict[str, Any]) -> dict[str, dict[str, Any]]:
    require(matrix.get("schema_version") == P0_MATRIX_SCHEMA, "Unsupported P0 matrix")
    require(matrix.get("target_executed") is False, "P0 matrix executed target")
    require(matrix.get("support_status") == "unverified", "P0 support promoted")
    rows = [
        row
        for row in _rows(matrix, "rows", "Invalid P0 matrix rows")
        if row.get("format") == "FMT-ELF"
    ]
    require(len(rows) == len(PROFILE_IDS), "P0 profile coverage mismatch")
    by_profile: dict[str, dict[str, Any]] = {}
    for row in rows:
        profile_id = row.get("profile_id")
        if type(profile_id) is not str:
            raise ContractError("Invalid P0 profile identifier")
        by_profile[profile_id] = row
    require(tuple(by_profile) == PROFILE_IDS, "P0 profile rows/order mismatch")
    require(len(by_profile) == len(rows), "Duplicate P0 profile row")
    require(
        all(row.get("status") in {"success", "failed"} for row in by_profile.values()),
        "P0 observation status mismatch",
    )
    return by_profile


def _canonical_semantic_rows(matrix: dict[str, Any]) -> dict[str, dict[str, Any]]:
    validate_complete_matrix_receipt(matrix)
    rows = [
        row
        for row in _rows(matrix, "profiles", "Invalid semantic matrix rows")
        if row.get("evidence_path") in {"normal", "fallback"}
    ]
    require(len(rows) == len(PROFILE_IDS), "Semantic profile coverage mismatch")
    by_profile: dict[str, dict[str, Any]] = {}
    for row in rows:
        profile_id = row.get("profile_id")
        if type(profile_id) is not str:
            raise ContractError("Invalid semantic profile identifier")
        by_profile[profile_id] = row
    require(set(by_profile) == set(PROFILE_IDS), "Semantic profile rows mismatch")
    require(len(by_profile) == len(rows), "Duplicate semantic profile row")
    for row in by_profile.values():
        evidence_path = row.get("evidence_path")
        expected_status = _SEMANTIC_STATUS.get(
            evidence_path if type(evidence_path) is str else ""
        )
        require(
            expected_status is not None,
            "Semantic evidence path mismatch",
        )
        require(
            row.get("status") == expected_status,
            "Semantic partial status mismatch",
        )
    return by_profile


def build_support_receipt_manifest(
    inventory: dict[str, Any],
    p0_matrix: dict[str, Any],
    semantic_matrix: dict[str, Any],
) -> dict[str, Any]:
    """Build the deterministic 17-row summary from existing static evidence."""

    REGISTRY.validate_inventory(inventory)
    p0_rows = _canonical_p0_rows(p0_matrix)
    semantic_rows = _canonical_semantic_rows(semantic_matrix)
    rows = []
    for spec in REGISTRY.profiles:
        require(
            spec.normal_status == spec.fallback_status == "unverified",
            "Registry support was promoted",
        )
        semantic = semantic_rows[spec.profile_id]
        expected_p0 = "success" if semantic["evidence_path"] == "normal" else "failed"
        require(
            p0_rows[spec.profile_id]["status"] == expected_p0,
            "P0/semantic availability mismatch",
        )
        rows.append(
            {
                "profile_id": spec.profile_id,
                "p0_status": p0_rows[spec.profile_id]["status"],
                "semantic_evidence_path": semantic["evidence_path"],
                "semantic_status": semantic["status"],
                "support_status": "unverified",
            }
        )
    body = {
        "schema_version": SUPPORT_RECEIPT_SCHEMA,
        "profile_count": len(rows),
        "normal_observation_count": sum(
            row["semantic_evidence_path"] == "normal" for row in rows
        ),
        "fallback_observation_count": sum(
            row["semantic_evidence_path"] == "fallback" for row in rows
        ),
        "format_variant_count": semantic_matrix["format_variant_count"],
        "target_executed": False,
        "support_promoted": False,
        "status": "complete_with_explicit_fallbacks",
        "source_digests": {
            "inventory": digest(inventory),
            "p0_matrix": digest(p0_matrix),
            "semantic_matrix": digest(semantic_matrix),
        },
        "profiles": rows,
    }
    result = {**body, "receipt_digest": digest(body)}
    validate_support_receipt_manifest(result)
    return result


def validate_support_receipt_manifest(value: Any) -> None:
    """Fail closed on drift or accidental promotion in a support summary."""

    if type(value) is not dict:
        raise ContractError("Support receipt manifest must be an object")
    expected_keys = {
        "schema_version",
        "profile_count",
        "normal_observation_count",
        "fallback_observation_count",
        "format_variant_count",
        "target_executed",
        "support_promoted",
        "status",
        "source_digests",
        "profiles",
        "receipt_digest",
    }
    require(set(value) == expected_keys, "Support receipt fields mismatch")
    require(
        value["schema_version"] == SUPPORT_RECEIPT_SCHEMA,
        "Unsupported support receipt schema",
    )
    require(
        value["profile_count"] == len(PROFILE_IDS), "Support profile count mismatch"
    )
    require(
        type(value["format_variant_count"]) is int
        and value["format_variant_count"] >= 0,
        "Format variant count mismatch",
    )
    require(value["target_executed"] is False, "Support audit executed target")
    require(value["support_promoted"] is False, "Support audit promoted support")
    require(
        value["status"] == "complete_with_explicit_fallbacks",
        "Support audit status mismatch",
    )
    source_digests = value["source_digests"]
    require(
        type(source_digests) is dict
        and set(source_digests) == {"inventory", "p0_matrix", "semantic_matrix"},
        "Support source digests mismatch",
    )
    for source_digest in source_digests.values():
        if type(source_digest) is not str:
            raise ContractError("Support source digest must be a string")
        check_digest(source_digest)
    profiles = _rows(value, "profiles", "Invalid support profile rows")
    require(
        tuple(row.get("profile_id") for row in profiles) == PROFILE_IDS,
        "Support profile rows/order mismatch",
    )
    require(
        value["normal_observation_count"]
        == sum(row.get("semantic_evidence_path") == "normal" for row in profiles),
        "Normal observation count mismatch",
    )
    require(
        value["fallback_observation_count"]
        == sum(row.get("semantic_evidence_path") == "fallback" for row in profiles),
        "Fallback observation count mismatch",
    )
    for row in profiles:
        require(
            set(row)
            == {
                "profile_id",
                "p0_status",
                "semantic_evidence_path",
                "semantic_status",
                "support_status",
            },
            "Support profile fields mismatch",
        )
        require(row["support_status"] == "unverified", "Profile support promoted")
        evidence_path = row["semantic_evidence_path"]
        require(evidence_path in _SEMANTIC_STATUS, "Profile semantic path mismatch")
        require(
            row["p0_status"] == ("success" if evidence_path == "normal" else "failed"),
            "Profile P0 status mismatch",
        )
        require(
            row["semantic_status"] == _SEMANTIC_STATUS[evidence_path],
            "Profile semantic status mismatch",
        )
    body = {key: item for key, item in value.items() if key != "receipt_digest"}
    require(value["receipt_digest"] == digest(body), "Support receipt digest mismatch")


__all__ = [
    "SUPPORT_RECEIPT_SCHEMA",
    "build_support_receipt_manifest",
    "validate_support_receipt_manifest",
]
