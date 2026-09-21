"""Pure contract checks plus recorded real IDA probe regression evidence."""

import importlib.util
import hashlib
import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = ROOT / "tests/flow_fixtures/manifests"
SPEC = importlib.util.spec_from_file_location(
    "p0_probe_test", ROOT / "src/ida_pro_mcp/ida_mcp/flow/p0_probe.py"
)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def read(name):
    return json.loads((MANIFESTS / name).read_text())


@pytest.mark.parametrize("anchor,processor", [("x64", "metapc"), ("a64", "ARM")])
def test_actual_receipt_contract(anchor, processor):
    receipt = read(anchor + ".json")
    assert receipt["schema_version"] == probe.SCHEMA
    assert (
        receipt["implementation_sha256"]
        == hashlib.sha256(Path(SPEC.origin).read_bytes()).hexdigest()
    )
    assert receipt["environment"]["processor"] == processor
    assert receipt["target_executed"] is False
    assert receipt["lifetime"]["repeat_after_gc"] is True
    assert receipt["lifetime"]["native_leak_freedom"] == "not_proven"
    assert receipt["cancellation"]["pre_cancel"] is True
    assert receipt["cancellation"]["expired_deadline"] is True
    assert receipt["cancellation"]["native_cancel_tested"] is False
    builds = read("build.json")
    build = next(b for b in builds if b["binary_sha256"] == receipt["binary"]["sha256"])
    assert (
        build["function_selector"]["value"] == receipt["function_name"] == "p0_anchor"
    )
    assert build["function_selector"]["kind"] == "ida_name"
    assert build["function_selector"]["requires_companion"] is True
    assert len(build["companion_artifacts"]) == 1
    companion = build["companion_artifacts"][0]
    assert (
        companion["path"]
        == f"{build['binary']}.dSYM/Contents/Resources/DWARF/{build['binary']}"
    )
    assert companion["bundle"] == build["binary"] + ".dSYM"
    assert companion["placement"] == "sibling_of_binary"
    assert companion["required"] is True
    assert companion["purpose"] == "function/source mapping"
    assert len(companion["sha256"]) == 64
    assert all(c in "0123456789abcdef" for c in companion["sha256"])
    assert [p["maturity"] for p in receipt["probes"]] == list(probe.MATURITIES)
    for p in receipt["probes"]:
        assert p["status"] == "success" and p["failure_code"] == 0
        assert p["python_owns_mba"] is True
        assert p["warnings"] == [] and p["repeat_equal"] is True
        payload = {k: v for k, v in p.items() if k not in ("digest", "repeat_equal")}
        assert probe.digest(payload) == p["digest"]
        assert p["block_count"] == len(p["blocks"])
        assert p["operand_kind_counts"]["mop_f"] > 0
        assert p["source_map"]["top_level_with_ea"] > 0
        for chain in p["chains"].values():
            assert chain["status"] == "available"
            assert chain["block_count"] == p["block_count"]
        for method in ("build_use_list", "build_def_list"):
            for access in ("MAY_ACCESS", "MUST_ACCESS"):
                assert (
                    p["use_def_checks"][method + ":" + access + ":ok"]
                    == p["instruction_count"]
                )
        for block in p["blocks"]:
            for successor in block["successors"]:
                assert block["id"] in p["blocks"][successor]["predecessors"]


def test_all_required_profiles_have_honest_blockers():
    inventory = read("p0_inventory.json")
    profiles = inventory["profiles"]
    expected = {
        "X86-LE",
        "X64-LE",
        "ARM32-LE",
        "ARM32-BE",
        "THUMB-LE",
        "THUMB-BE",
        "A64-LE",
        "MIPS32-LE",
        "MIPS32-BE",
        "MIPS64-LE",
        "MIPS64-BE",
        "PPC32-LE",
        "PPC32-BE",
        "PPC64-LE",
        "PPC64-BE",
        "RV32-LE",
        "RV64-LE",
    }
    assert {p["profile_id"] for p in profiles} == expected
    assert len(profiles) == 17
    for row in profiles:
        assert row["required"] is True
        assert row["normal_status"] == row["fallback_status"] == "unverified"
        assert row["blockers"] and all(
            set(b) == {"owner", "reason", "next_probe"} for b in row["blockers"]
        )
        if row["probe_status"] == "success":
            assert row["profile_id"] in ("X64-LE", "A64-LE")
            assert read(row["probe_receipt"])["initialization"] is True
            assert row["maturity"] == "MMAT_CALLS"
        else:
            assert row["entitlement"]["status"] == "unverified"
            assert row["maturity"] is None


@pytest.mark.parametrize("kwargs", [{"cancelled": lambda: True}, {"deadline": 0}])
def test_cancellation_precedes_any_native_generation(monkeypatch, kwargs):
    for name in ("ida_funcs", "ida_hexrays", "ida_idaapi"):
        monkeypatch.setitem(sys.modules, name, types.SimpleNamespace())
    with pytest.raises(InterruptedError):
        probe.probe(0, "MMAT_CALLS", **kwargs)


def test_digest_is_key_order_independent():
    assert probe.digest({"b": 1, "a": 2}) == probe.digest({"a": 2, "b": 1})
    assert probe.digest({"a": 2}) != probe.digest({"a": 1})
