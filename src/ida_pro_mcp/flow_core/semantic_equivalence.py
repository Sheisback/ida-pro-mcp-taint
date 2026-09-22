"""Provenance-free comparison for normal semantic receipt envelopes."""

from __future__ import annotations

from typing import Any

from .serialization import ContractError, digest

_SEMANTIC_PROFILE_FIELDS = (
    "profile_id",
    "version",
    "mode",
    "processor",
    "bitness",
    "data_endian",
    "instruction_endian",
    "abi",
    "format_id",
    "platform_tag",
    "required_features",
    "maturity",
    "receipt_status",
    "normal_status",
    "fallback_status",
)


def normal_semantic_equivalence_view(value: dict[str, Any]) -> dict[str, Any]:
    """Return normal-profile meaning without run/build/image provenance."""

    profile = value.get("profile")
    environment = value.get("environment")
    functions = value.get("functions")
    evaluation = value.get("evaluation")
    oracle_binding = value.get("isa_oracle_binding")
    if type(profile) is not dict:
        raise ContractError("Normal semantic profile is missing")
    if type(environment) is not dict:
        raise ContractError("Normal semantic environment is missing")
    if type(functions) is not list:
        raise ContractError("Normal semantic functions are missing")
    if type(evaluation) is not dict:
        raise ContractError("Normal semantic evaluation is missing")
    if type(oracle_binding) is not dict:
        raise ContractError("Normal semantic oracle binding is missing")
    if set(_SEMANTIC_PROFILE_FIELDS) - set(profile):
        raise ContractError("Normal semantic profile fields are missing")
    semantic_environment = {
        key: item
        for key, item in environment.items()
        if key not in {"ida_build", "hexrays_build"}
    }
    return {
        "schema_version": value.get("schema_version"),
        "identity": {
            "profile_id": value.get("profile_id"),
            "abi_id": value.get("abi_id"),
            "bitness": value.get("bitness"),
            "data_endian": value.get("data_endian"),
            "instruction_endian": value.get("instruction_endian"),
            "maturity": value.get("maturity"),
            "evidence_path": value.get("evidence_path"),
        },
        "profile": {key: profile[key] for key in _SEMANTIC_PROFILE_FIELDS},
        "environment": semantic_environment,
        "functions": functions,
        "oracle": {
            "source": value.get("oracle_source"),
            "digest": value.get("oracle_digest"),
            "binding": oracle_binding,
        },
        "evaluation": evaluation,
        "result": {
            "status": value.get("status"),
            "support_status": value.get("support_status"),
            "target_executed": value.get("target_executed"),
            "input_preserved": value.get("input_preserved"),
            "registry_promoted": value.get("registry_promoted"),
            "service_promoted": value.get("service_promoted"),
            "capabilities_promoted": value.get("capabilities_promoted"),
        },
    }


def normal_semantic_equivalence_digest(value: dict[str, Any]) -> str:
    """Digest normalized meaning while full receipts retain provenance."""

    return digest(normal_semantic_equivalence_view(value))


__all__ = [
    "normal_semantic_equivalence_digest",
    "normal_semantic_equivalence_view",
]
