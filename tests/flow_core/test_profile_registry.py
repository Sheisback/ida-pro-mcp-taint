"""Exact, IDA-free profile registry and measured-receipt boundaries."""

import copy
import json
import re
from pathlib import Path

import pytest

from ida_pro_mcp.flow_core.profile_registry import (
    PROFILE_IDS,
    REGISTRY,
    REGISTRY_DIGEST,
    ProfileRegistry,
)
from ida_pro_mcp.flow_core.serialization import ContractError, canonical_json, digest

ROOT = Path(__file__).resolve().parents[2]
MANIFESTS = ROOT / "tests/flow_fixtures/manifests"


def read(name: str):
    return json.loads((MANIFESTS / name).read_text())


def test_registry_exactly_matches_canonical_inventory_and_roundtrips():
    inventory = read("p0_inventory.json")
    REGISTRY.validate_inventory(inventory)
    assert tuple(row.profile_id for row in REGISTRY.profiles) == PROFILE_IDS
    assert len(REGISTRY.profiles) == 17
    assert ProfileRegistry.from_json(canonical_json(REGISTRY)) == REGISTRY
    assert REGISTRY_DIGEST == digest(REGISTRY)
    assert re.fullmatch(r"sha256-v1:[0-9a-f]{64}", REGISTRY_DIGEST)


@pytest.mark.parametrize(
    ("profile_id", "receipt_name"), [("X64-LE", "x64.json"), ("A64-LE", "a64.json")]
)
def test_only_anchor_rows_have_exact_measured_receipts(profile_id, receipt_name):
    receipt = REGISTRY.validate_probe_receipt(profile_id, read(receipt_name))
    assert receipt.status == "success"
    assert receipt.repeat_equal and receipt.roundtrip_equal
    assert receipt.target_executed is False
    measured = {
        row.profile_id for row in REGISTRY.profiles if row.measured_receipt is not None
    }
    assert measured == {"X64-LE", "A64-LE"}


def test_unmeasured_rows_remain_fail_closed_and_honest():
    for row in REGISTRY.profiles:
        assert row.normal_status == row.fallback_status == "unverified"
        if row.profile_id not in {"X64-LE", "A64-LE"}:
            assert row.receipt_status == "unverified"
            assert row.measured_receipt is None
            assert row.maturity is None
            assert row.format_ids == ()
            with pytest.raises(ContractError, match="no measured"):
                REGISTRY.validate_probe_receipt(row.profile_id, {})


@pytest.mark.parametrize(
    ("profile_id", "processor", "abi"),
    [
        ("X64-LE", "metapc", "darwin-x86_64-sysv-derived"),
        ("A64-LE", "ARM", "darwin-aarch64"),
    ],
)
def test_measured_runtime_profile_is_exact_and_explicitly_not_abi_inference(
    profile_id, processor, abi
):
    profile = REGISTRY.measured_extraction_profile(profile_id)
    receipt = REGISTRY.get(profile_id).measured_receipt
    assert receipt is not None
    assert REGISTRY.validate_extraction_profile(profile) == REGISTRY.get(profile_id)
    assert profile["processor"] == processor
    assert profile["abi"] == abi
    assert profile["receipt_evidence"] == receipt.to_data()
    assert profile["abi_provenance"] == {
        "kind": "measured_anchor_build",
        "receipt_digest": receipt.digest,
        "binary_digest": receipt.binary_digest,
        "scope": "registry receipt configuration; not runtime binary or ABI inference",
    }


def test_runtime_profile_rejects_every_unmeasured_registry_row():
    for row in REGISTRY.profiles:
        if row.measured_receipt is None:
            with pytest.raises(
                ContractError, match="Unmeasured extraction profile configuration"
            ):
                REGISTRY.measured_extraction_profile(row.profile_id)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("mode",), "guessed"),
        (("bitness",), 32),
        (("normal_status",), "available"),
        (("probe_status",), "unverified"),
        (("artifacts", "processor", "artifact"), "procs/guess.dylib"),
    ],
)
def test_inventory_drift_is_rejected(path, value):
    inventory = copy.deepcopy(read("p0_inventory.json"))
    row = next(row for row in inventory["profiles"] if row["profile_id"] == "X64-LE")
    target = row
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ContractError, match="contract mismatch"):
        REGISTRY.validate_inventory(inventory)


def test_receipt_digest_roundtrip_and_environment_drift_are_rejected():
    for path, value in (
        (("probes", 0, "digest"), "0" * 64),
        (("lifetime", "json_roundtrip"), False),
        (("environment", "processor"), "guess"),
        (("target_executed",), True),
    ):
        document = copy.deepcopy(read("x64.json"))
        target = document
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        with pytest.raises(ContractError):
            REGISTRY.validate_probe_receipt("X64-LE", document)
