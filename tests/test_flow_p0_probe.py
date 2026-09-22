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


def request(*, raw=False, sha256="a" * 64):
    return {
        "schema_version": probe.REQUEST_SCHEMA,
        "profile": {
            "profile_id": "ARM32-LE" if raw else "X64-LE",
            "profile_version": 1,
            "mode": "ARM32" if raw else "X64",
            "processor": "ARM" if raw else "metapc",
            "bits": 32 if raw else 64,
            "data_endian": "LE",
            "instruction_endian": "LE",
            "abi_id": "aapcs32" if raw else "sysv-amd64",
        },
        "binary": {
            "format": "RAW" if raw else "ELF",
            "filetype": "Binary file" if raw else "ELF64 for x86-64",
            "sha256": sha256,
        },
        "load": (
            {"kind": "raw", "file_offset": 0, "load_address": 0x10000}
            if raw
            else {"kind": "loader", "image_base": 0x400000}
        ),
        "entry": (
            {"kind": "address", "value": 0x10000}
            if raw
            else {"kind": "name", "value": "p0_anchor"}
        ),
        "probe": {"maturities": list(probe.MATURITIES)},
    }


def observation(*, raw=False, sha256="a" * 64):
    return {
        "binary_sha256": sha256,
        "format": "RAW" if raw else "ELF",
        "filetype": "Binary file" if raw else "ELF64 for x86-64",
        "processor": "ARM" if raw else "metapc",
        "bits": 32 if raw else 64,
        "data_endian": "LE",
        "instruction_endian": None,
        "image_base": 0x10000 if raw else 0x400000,
        "entry_ea": 0x10000 if raw else 0x401000,
    }


@pytest.mark.parametrize("anchor,processor", [("x64", "metapc"), ("a64", "ARM")])
def test_actual_receipt_contract(anchor, processor):
    receipt = read(anchor + ".json")
    assert receipt["schema_version"] == probe.SCHEMA
    assert receipt["implementation_sha256"] == probe.LEGACY_IMPLEMENTATION_SHA256
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


@pytest.mark.parametrize("raw", [False, True])
def test_explicit_versioned_request_roundtrips_and_pins_both_maturities(raw):
    value = request(raw=raw)
    detached = probe.validate_request(value)
    assert detached == value and detached is not value
    assert detached["probe"]["maturities"] == ["MMAT_CALLS", "MMAT_GLBOPT3"]
    assert probe.request_digest(value) == probe.digest(value)


@pytest.mark.parametrize(
    "mutate,match",
    [
        (
            lambda value: value.update(schema_version="flow-p0-probe-request/2"),
            "schema",
        ),
        (lambda value: value.update(extra=True), "keys mismatch"),
        (
            lambda value: value["probe"].update(maturities=["MMAT_CALLS"]),
            "maturities",
        ),
        (lambda value: value.update(entry=("name", "p0_anchor")), "non-JSON"),
    ],
)
def test_request_contract_rejects_drift_and_non_json_values(mutate, match):
    value = request()
    mutate(value)
    with pytest.raises(ValueError, match=match):
        probe.validate_request(value)


def test_raw_request_requires_explicit_instruction_endian_and_address_entry():
    value = request(raw=True)
    value["profile"]["instruction_endian"] = None
    with pytest.raises(ValueError, match="explicit instruction endian"):
        probe.validate_request(value)

    value = request(raw=True)
    value["entry"] = {"kind": "name", "value": "p0_anchor"}
    with pytest.raises(ValueError, match="address entry"):
        probe.validate_request(value)


def test_loader_observation_is_accepted_without_inventing_profile_evidence():
    report = probe.validate_observation(request(), observation())
    assert report["schema_version"] == probe.VALIDATION_SCHEMA
    assert report["status"] == "accepted"
    assert report["mismatches"] == []
    assert report["unverified"] == ["profile.instruction_endian"]
    assert report["declared_only"] == [
        "profile.profile_id",
        "profile.profile_version",
        "profile.mode",
        "profile.abi_id",
    ]
    assert report["raw_setup"]["status"] == "not_applicable"
    assert "support_status" not in report


def test_observation_mismatch_fails_closed():
    actual = observation()
    actual["processor"] = "ARM"
    actual["bits"] = 32
    report = probe.validate_observation(request(), actual)
    assert report["status"] == "mismatch"
    assert report["mismatches"] == ["profile.processor", "profile.bits"]


def test_raw_setup_is_required_before_entry_and_verified_by_exact_observation():
    value = request(raw=True)
    setup = probe.raw_setup_contract(value)
    assert setup == {
        "schema_version": probe.RAW_SETUP_SCHEMA,
        "status": "required",
        "owner": "external_ida_invocation",
        "stage": "before_idapython_entrypoint",
        "reason": (
            "Raw processor, load, and entry configuration must be applied before "
            "this IDAPython script starts; the probe does not mutate loader state"
        ),
        "required": {
            "processor": "ARM",
            "bits": 32,
            "data_endian": "LE",
            "instruction_endian": "LE",
            "file_offset": 0,
            "load_address": 0x10000,
            "entry_address": 0x10000,
        },
    }
    report = probe.validate_observation(value, observation(raw=True))
    assert report["status"] == "accepted"
    assert report["mismatches"] == []
    assert report["raw_setup"]["status"] == "verified_observable_fields"
    assert "observable" in report["raw_setup"]["reason"].lower()
    assert "instruction endian" in report["raw_setup"]["reason"].lower()
    assert "unverified" in report["raw_setup"]["reason"].lower()
    assert report["unverified"] == ["profile.instruction_endian"]
    assert "support_status" not in report


@pytest.mark.parametrize(
    "field,value,expected_mismatch",
    [
        ("binary_sha256", "b" * 64, "binary.sha256"),
        ("format", "ELF", "binary.format"),
        ("filetype", "ELF32 for ARM", "binary.filetype"),
        ("processor", "ARMB", "profile.processor"),
        ("bits", 64, "profile.bits"),
        ("data_endian", "BE", "profile.data_endian"),
        ("image_base", 0x11000, "load.address"),
        ("entry_ea", 0x10004, "entry"),
        ("entry_ea", None, "entry"),
    ],
)
def test_raw_setup_mismatch_is_never_verified(field, value, expected_mismatch):
    actual = observation(raw=True)
    actual[field] = value
    report = probe.validate_observation(request(raw=True), actual)
    assert report["status"] == "mismatch"
    assert report["mismatches"] == [expected_mismatch]
    assert report["raw_setup"]["status"] != "verified_observable_fields"
    assert "profile.instruction_endian" in report["unverified"]


@pytest.mark.parametrize(
    "observed_start,expected_status,expected_entry",
    [
        (0x10000, "accepted", 0x10000),
        (0x10004, "mismatch", None),
        (None, "mismatch", None),
    ],
    ids=["exact", "enclosing", "missing"],
)
def test_raw_runner_uses_actual_function_observation_before_hexrays(
    monkeypatch, tmp_path, observed_start, expected_status, expected_entry
):
    binary = tmp_path / "anchor.bin"
    binary.write_bytes(b"static analysis only")
    value = request(raw=True, sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    request_path = tmp_path / "request.json"
    output_path = tmp_path / "receipt.json"
    request_path.write_text(json.dumps(value))
    initialized = []
    function_lookups = []

    def get_func(ea):
        function_lookups.append(ea)
        if ea == 0x10000 and observed_start is not None:
            return types.SimpleNamespace(start_ea=observed_start)
        return None

    modules = {
        "ida_auto": types.SimpleNamespace(auto_wait=lambda: None),
        "ida_funcs": types.SimpleNamespace(get_func=get_func),
        "ida_hexrays": types.SimpleNamespace(
            init_hexrays_plugin=lambda: initialized.append(True) or False,
            get_hexrays_version=lambda: "test",
        ),
        "ida_ida": types.SimpleNamespace(
            f_BIN=1,
            f_PE=2,
            f_ELF=3,
            f_MACHO=4,
            inf_get_filetype=lambda: 1,
            inf_get_procname=lambda: "ARM",
            inf_is_64bit=lambda: False,
            inf_is_be=lambda: False,
            inf_get_min_ea=lambda: 0x10000,
        ),
        "ida_kernwin": types.SimpleNamespace(get_kernel_version=lambda: "test"),
        "ida_loader": types.SimpleNamespace(get_file_type_name=lambda: "Binary file"),
        "ida_nalt": types.SimpleNamespace(
            get_input_file_path=lambda: str(binary), get_imagebase=lambda: 0xDEAD0000
        ),
        "ida_name": types.SimpleNamespace(get_name_ea=lambda *_args: -1),
        "ida_pro": types.SimpleNamespace(qexit=lambda _code: None),
        "idc": types.SimpleNamespace(
            ARGV=["flow_p0_probe.py", str(ROOT), str(output_path), str(request_path)],
            BADADDR=-1,
        ),
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    runner_spec = importlib.util.spec_from_file_location(
        "flow_p0_probe_runner_test", ROOT / "scripts/flow_p0_probe.py"
    )
    runner = importlib.util.module_from_spec(runner_spec)
    runner_spec.loader.exec_module(runner)
    runner.main()

    receipt = json.loads(output_path.read_text())
    assert function_lookups == [0x10000]
    assert receipt["schema_version"] == probe.RECEIPT_SCHEMA
    assert receipt["support_status"] == "unverified"
    assert receipt["target_executed"] is False
    assert receipt["probes"] == []
    assert receipt["environment"]["image_base"] == 0x10000
    assert receipt["environment"]["entry_ea"] == expected_entry
    assert receipt["environment"]["instruction_endian"] is None
    assert receipt["validation"]["status"] == expected_status
    if expected_status == "accepted":
        assert initialized == [True]
        assert receipt["probe_status"] == "failed"
        assert receipt["initialization"] is False
        assert receipt["validation"]["mismatches"] == []
        assert (
            receipt["validation"]["raw_setup"]["status"]
            == "verified_observable_fields"
        )
        assert receipt["validation"]["unverified"] == [
            "profile.instruction_endian"
        ]
    else:
        assert initialized == []
        assert receipt["probe_status"] == "blocked"
        assert receipt["initialization"] is None
        assert receipt["validation"]["mismatches"] == ["entry"]
        assert (
            receipt["validation"]["raw_setup"]["status"]
            != "verified_observable_fields"
        )
    payload = {key: item for key, item in receipt.items() if key != "receipt_digest"}
    assert receipt["receipt_digest"] == probe.digest(payload)
