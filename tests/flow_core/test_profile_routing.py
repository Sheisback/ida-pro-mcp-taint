"""Exact public routing from frozen semantic evidence, never identity guesses."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from ida_pro_mcp.flow_core.profile_registry import REGISTRY
from ida_pro_mcp.flow_core.profile_routing import (
    FROZEN_PROFILE_EVIDENCE,
    REGISTRY_PROFILE_EVIDENCE,
    OpenDatabaseEvidence,
    resolve_open_database_profile,
)
from ida_pro_mcp.flow_core.serialization import ContractError, digest

ROOT = Path(__file__).resolve().parents[2]
SEMANTIC_MATRIX = ROOT / "tests/flow_fixtures/manifests/profile_semantics/matrix.json"
BUILD_MANIFEST = ROOT / "tests/flow_fixtures/manifests/profiles/build.json"


def read(path: Path) -> dict:
    return json.loads(path.read_text())


def observed(route) -> OpenDatabaseEvidence:
    spec = REGISTRY.get(route.profile_id)
    return OpenDatabaseEvidence(
        route.binary_digest,
        route.processor,
        spec.bitness,
        spec.data_endian,
        route.format_id,
        route.ida_build,
        route.hexrays_build,
    )


def test_frozen_routes_exactly_match_every_normal_semantic_identity():
    matrix = read(SEMANTIC_MATRIX)
    expected = tuple(
        (row["profile_id"], row["format"], row["evidence_path"])
        for row in matrix["profiles"]
        if row["evidence_path"] != "fallback"
    )
    assert (
        tuple(
            (route.profile_id, route.format_id, route.evidence_path)
            for route in FROZEN_PROFILE_EVIDENCE
        )
        == expected
    )
    assert len(FROZEN_PROFILE_EVIDENCE) == 20
    assert len({route.binary_digest for route in FROZEN_PROFILE_EVIDENCE}) == 20

    for route in FROZEN_PROFILE_EVIDENCE:
        receipt = read(ROOT / route.semantic_receipt_file)
        profile, registry = route.extraction_profile()
        assert receipt["schema_version"] == "flow-profile-semantics-normal/1"
        assert receipt["status"] == "success"
        assert receipt["input_preserved"] is True
        assert receipt["target_executed"] is False
        assert route.semantic_receipt_digest == receipt["receipt_digest"]
        assert route.binary_digest == "sha256-v1:" + receipt["binary_sha256"]
        assert route.profile_digest == receipt["profile_digest"] == digest(profile)
        assert profile == receipt["profile"]
        assert (
            registry.validate_extraction_profile(profile).profile_id == route.profile_id
        )


@pytest.mark.parametrize(
    "route",
    FROZEN_PROFILE_EVIDENCE,
    ids=lambda row: row.profile_id + "-" + row.format_id,
)
def test_every_frozen_route_resolves_only_its_exact_requested_profile(route):
    resolved = resolve_open_database_profile(observed(route), route.profile_id)
    assert resolved.evidence == route
    assert resolved.profile["profile_id"] == route.profile_id
    assert resolved.profile["abi"] == route.abi_id
    assert resolved.profile["format_id"] == route.format_id
    assert resolved.registry is not REGISTRY
    assert REGISTRY.get(route.profile_id).normal_status == "unverified"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("processor", "guessed"),
        ("bits", 32),
        ("data_endian", "big"),
        ("format_id", "FMT-PE"),
        ("ida_build", "9.2"),
        ("hexrays_build", "9.2.0"),
    ],
)
def test_route_rejects_substituted_open_database_identity(field, value):
    route = next(
        row
        for row in FROZEN_PROFILE_EVIDENCE
        if row.profile_id == "X64-LE" and row.format_id == "FMT-ELF"
    )
    with pytest.raises(ContractError, match="profile_evidence_mismatch"):
        resolve_open_database_profile(replace(observed(route), **{field: value}))


def test_route_rejects_profile_substitution_unknown_input_and_stale_pin():
    route = FROZEN_PROFILE_EVIDENCE[0]
    with pytest.raises(ContractError, match="profile_mismatch"):
        resolve_open_database_profile(observed(route), "A64-LE")
    with pytest.raises(ContractError, match="experimental_profile_unavailable"):
        resolve_open_database_profile(
            replace(observed(route), binary_digest="sha256-v1:" + "0" * 64)
        )
    with pytest.raises(ContractError, match="Frozen profile evidence is stale"):
        replace(route, profile_digest="sha256-v1:" + "0" * 64).extraction_profile()


@pytest.mark.parametrize("route", REGISTRY_PROFILE_EVIDENCE)
def test_existing_measured_macho_configuration_routes_remain_available(route):
    processor, bits, endian, format_id, ida_build, hexrays_build = (
        route.observed_identity
    )
    resolved = resolve_open_database_profile(
        OpenDatabaseEvidence(
            "sha256-v1:" + "f" * 64,
            processor,
            bits,
            endian,
            format_id,
            ida_build,
            hexrays_build,
        ),
        route.profile_id,
    )
    assert resolved.evidence == route
    assert resolved.registry is REGISTRY
    assert resolved.profile == REGISTRY.measured_extraction_profile(route.profile_id)


def test_rv32_remains_explicit_normal_failure_and_local_unpinned_elf_fails_closed():
    build = read(BUILD_MANIFEST)
    rv32 = next(row for row in build["profiles"] if row["profile_id"] == "RV32-LE")
    with pytest.raises(ContractError, match="rv32_normal_profile_unavailable"):
        resolve_open_database_profile(
            OpenDatabaseEvidence(
                "sha256-v1:" + rv32["binary_sha256"],
                rv32["processor"],
                rv32["bitness"],
                "little",
                rv32["format"],
                "9.3",
                "9.3.0.260213",
            ),
            "RV32-LE",
        )

    local = ROOT / "tests/typed_fixture.elf"
    with pytest.raises(ContractError, match="experimental_profile_unavailable"):
        resolve_open_database_profile(
            OpenDatabaseEvidence(
                "sha256-v1:" + hashlib.sha256(local.read_bytes()).hexdigest(),
                "metapc",
                64,
                "little",
                "FMT-ELF",
                "9.3",
                "9.3.0.260213",
            )
        )
