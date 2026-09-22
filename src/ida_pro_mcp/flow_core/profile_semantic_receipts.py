"""Canonical pure-data contracts for G012 fallback and completeness evidence."""

from __future__ import annotations

from typing import Any, cast

from .contracts import StructuredSnapshot
from .profile_semantics import (
    FORMAT_VARIANT_KEYS,
    verify_receipt_digest,
)
from .profile_registry import PROFILE_IDS
from .serialization import ContractError, digest
from .states import require


RV32_RECEIPT_SCHEMA = "flow-profile-semantics-rv32-fallback/1"
RV32_EVALUATION_SCHEMA = "flow-profile-semantics-rv32-evaluation/1"
COMPLETE_MATRIX_SCHEMA = "flow-profile-semantics-complete/2"


def _exact_keys(value: Any, expected: set[str], label: str) -> None:
    if type(value) is not dict:
        raise ContractError(label + " must be an object")
    actual = set(value)
    require(
        actual == expected,
        f"{label} keys mismatch; missing={sorted(expected - actual)!r}, "
        f"extra={sorted(actual - expected)!r}",
    )


def validate_rv32_receipt(value: dict[str, Any]) -> None:
    """Validate the canonical RV32 fallback receipt contract."""

    _exact_keys(
        value,
        {
            "schema_version",
            "profile_id",
            "abi_id",
            "evidence_path",
            "status",
            "candidate_status",
            "support_status",
            "normal_backend",
            "capture",
            "oracles",
            "implementation",
            "functions",
            "evaluation",
            "limitations",
            "input_preserved",
            "target_executed",
            "registry_promoted",
            "service_promoted",
            "receipt_digest",
        },
        "RV32 fallback receipt",
    )
    require(
        value["schema_version"] == RV32_RECEIPT_SCHEMA, "RV32 receipt schema mismatch"
    )
    verify_receipt_digest(value)
    require(value["profile_id"] == "RV32-LE", "RV32 profile mismatch")
    require(value["abi_id"] == "riscv-ilp32", "RV32 ABI mismatch")
    require(value["evidence_path"] == "fallback", "RV32 evidence path mismatch")
    require(value["status"] == "partial", "RV32 receipt must remain partial")
    require(
        value["candidate_status"] == "accepted_candidate",
        "RV32 candidate status mismatch",
    )
    require(value["support_status"] == "unverified", "RV32 support promotion")
    require(value["input_preserved"] is True, "RV32 input preservation missing")
    require(value["target_executed"] is False, "RV32 receipt executed target")
    require(
        value["registry_promoted"] is False and value["service_promoted"] is False,
        "RV32 receipt promoted support",
    )
    require(
        value["limitations"]
        == [
            "normal_hexrays_unavailable",
            "implicit_flow_deferred_g013",
            "call_effects_partial",
            "memory_effects_unknown",
            "no_registry_service_or_capability_promotion",
        ],
        "RV32 limitations mismatch",
    )

    normal = value["normal_backend"]
    _exact_keys(
        normal,
        {
            "artifact",
            "artifact_digest",
            "schema_version",
            "probe_status",
            "support_status",
            "maturities",
            "probes",
            "target_executed",
        },
        "RV32 normal failure",
    )
    require(normal["probe_status"] == "failed", "RV32 normal failure missing")
    require(normal["support_status"] == "unverified", "RV32 normal support claim")
    require(
        normal["maturities"] == ["MMAT_CALLS", "MMAT_GLBOPT3"],
        "RV32 maturity mismatch",
    )
    require(normal["target_executed"] is False, "RV32 normal probe executed target")

    capture = value["capture"]
    _exact_keys(
        capture,
        {
            "artifact",
            "artifact_digest",
            "process_artifacts",
            "capture_digest",
            "fresh_process_repeat_equal",
            "json_roundtrip_equal",
            "input_preserved",
            "target_executed",
        },
        "RV32 capture evidence",
    )
    require(capture["fresh_process_repeat_equal"] is True, "RV32 capture drift")
    require(capture["json_roundtrip_equal"] is True, "RV32 capture roundtrip drift")
    require(capture["input_preserved"] is True, "RV32 capture changed input")
    require(capture["target_executed"] is False, "RV32 capture executed target")
    require(
        type(capture["process_artifacts"]) is list
        and len(capture["process_artifacts"]) == 2,
        "RV32 process evidence mismatch",
    )

    _exact_keys(
        value["oracles"],
        {"rv32_artifact", "rv32_digest", "isa_artifact", "isa_digest"},
        "RV32 oracle evidence",
    )
    _exact_keys(
        value["implementation"],
        {
            "capture_implementation_digest",
            "lowering_rule_digest",
            "lowering_artifact",
            "lowering_artifact_sha256",
            "evaluator_artifact",
            "evaluator_artifact_sha256",
        },
        "RV32 implementation evidence",
    )

    raw_functions = value["functions"]
    require(
        type(raw_functions) is list and len(raw_functions) == 6,
        "RV32 function count mismatch",
    )
    snapshots: list[StructuredSnapshot] = []
    for ordinal, item in enumerate(raw_functions):
        _exact_keys(
            item,
            {
                "oracle_id",
                "symbol",
                "selector_ordinal",
                "function_rva",
                "snapshot_id",
                "snapshot_digest",
                "snapshot",
            },
            "RV32 function receipt",
        )
        require(item["selector_ordinal"] == ordinal, "RV32 function order mismatch")
        snapshot = cast(
            StructuredSnapshot, StructuredSnapshot.from_data(item["snapshot"])
        )
        require(
            item["snapshot_id"] == snapshot.snapshot_id,
            "RV32 snapshot id mismatch",
        )
        require(
            item["snapshot_digest"] == digest(snapshot),
            "RV32 snapshot digest mismatch",
        )
        require(
            snapshot.identity.environment.backend_id == "ida-disasm-rv32"
            and snapshot.identity.environment.extraction_stage
            == "structured-disassembly",
            "RV32 fallback identity mismatch",
        )
        snapshots.append(snapshot)
    require(
        len({item.snapshot_id for item in snapshots}) == 6,
        "RV32 snapshot uniqueness mismatch",
    )

    evaluation = value["evaluation"]
    require(
        type(evaluation) is dict
        and evaluation.get("schema_version") == RV32_EVALUATION_SCHEMA
        and evaluation.get("status") == "partial",
        "RV32 evaluation contract mismatch",
    )


def validate_complete_matrix_receipt(value: dict[str, Any]) -> None:
    """Validate semantic completeness against the canonical identity sets."""

    _exact_keys(
        value,
        {
            "schema_version",
            "profile_count",
            "semantic_row_count",
            "normal_success_count",
            "format_variant_count",
            "format_success_count",
            "rv32_normal_failure_count",
            "rv32_fallback_count",
            "profiles",
            "build_manifest",
            "build_manifest_digest",
            "oracle_file",
            "oracle_digest",
            "normal_matrix_file",
            "normal_matrix_digest",
            "format_matrix_file",
            "format_matrix_digest",
            "target_executed",
            "input_preserved",
            "normal_fallback_separate",
            "registry_service_capabilities_promoted",
            "status",
            "receipt_digest",
        },
        "complete semantic matrix",
    )
    require(
        value["schema_version"] == COMPLETE_MATRIX_SCHEMA,
        "Complete matrix schema mismatch",
    )
    verify_receipt_digest(value)
    require(value["target_executed"] is False, "Complete matrix executed target")
    require(value["input_preserved"] is True, "Complete matrix input changed")
    require(
        value["normal_fallback_separate"] is True,
        "Normal/fallback evidence merged",
    )
    require(
        value["registry_service_capabilities_promoted"] is False,
        "Complete matrix promoted support",
    )
    require(
        value["status"] == "accepted_candidate_partial_with_named_limitations",
        "Complete matrix status mismatch",
    )
    raw_profiles = value["profiles"]
    require(type(raw_profiles) is list, "Complete matrix rows mismatch")
    profiles = cast(list[dict[str, Any]], raw_profiles)
    for item in profiles:
        _exact_keys(
            item,
            {
                "profile_id",
                "format",
                "evidence_path",
                "status",
                "receipt_file",
                "receipt_digest",
            },
            "complete semantic profile row",
        )
    identities = [
        (item.get("profile_id"), item.get("format"), item.get("evidence_path"))
        for item in profiles
    ]
    require(len(identities) == len(set(identities)), "Duplicate semantic matrix row")
    primary = [item for item in profiles if item.get("evidence_path") != "format"]
    formats = [item for item in profiles if item.get("evidence_path") == "format"]
    require(
        len(primary) == len(PROFILE_IDS)
        and {item.get("profile_id") for item in primary} == set(PROFILE_IDS)
        and all(
            item.get("format") == "FMT-ELF"
            and item.get("evidence_path") in {"normal", "fallback"}
            for item in primary
        ),
        "Complete primary profile coverage mismatch",
    )
    require(
        {(item.get("profile_id"), item.get("format")) for item in formats}
        == set(FORMAT_VARIANT_KEYS),
        "Complete format coverage mismatch",
    )
    for item in profiles:
        evidence_path = item.get("evidence_path")
        expected_status = {
            "normal": "success_partial_with_named_limitations",
            "format": "success_partial_with_named_limitations",
            "fallback": "accepted_candidate_partial_normal_failed",
        }.get(evidence_path if type(evidence_path) is str else "")
        require(
            expected_status is not None and item.get("status") == expected_status,
            "Complete semantic row status mismatch",
        )
    expected_backend_counts = {
        evidence_path: sum(
            item.get("evidence_path") == evidence_path for item in profiles
        )
        for evidence_path in ("normal", "format", "fallback")
    }
    rv32_fallback_count = sum(
        item.get("profile_id") == "RV32-LE" and item.get("evidence_path") == "fallback"
        for item in primary
    )
    require(
        value["profile_count"] == len(PROFILE_IDS),
        "Complete matrix profile count mismatch",
    )
    require(
        value["semantic_row_count"] == len(profiles),
        "Complete semantic row count mismatch",
    )
    require(
        value["normal_success_count"] == expected_backend_counts["normal"],
        "Normal semantic success count mismatch",
    )
    require(
        value["format_variant_count"] == expected_backend_counts["format"],
        "Format variant count mismatch",
    )
    require(
        value["format_success_count"] == expected_backend_counts["format"],
        "Format success count mismatch",
    )
    require(
        value["rv32_normal_failure_count"] == rv32_fallback_count,
        "RV32 normal failure count mismatch",
    )
    require(
        value["rv32_fallback_count"] == rv32_fallback_count,
        "RV32 fallback count mismatch",
    )


__all__ = [
    "COMPLETE_MATRIX_SCHEMA",
    "RV32_EVALUATION_SCHEMA",
    "RV32_RECEIPT_SCHEMA",
    "validate_complete_matrix_receipt",
    "validate_rv32_receipt",
]
