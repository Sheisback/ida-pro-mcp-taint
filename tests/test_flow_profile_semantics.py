"""Focused pure guards for the G012 normal semantic recorder and receipts."""

from __future__ import annotations

from copy import deepcopy
import importlib.util
import inspect
import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from ida_pro_mcp.flow_core.profile_registry import (
    REGISTRY,
    REGISTRY_DIGEST,
    ProfileRegistry,
)
from ida_pro_mcp.flow_core.profile_semantics import (
    FORMAT_MATRIX_SCHEMA,
    FORMAT_VARIANT_KEYS,
    FUNCTIONS,
    NORMAL_MATRIX_SCHEMA,
    NORMAL_PROFILE_IDS,
    _validate_entry_selection,
    ephemeral_registry,
    function_entry_proofs,
    receipt_digest,
    select_ida_extraction,
    semantic_entry_proofs,
    semantic_profile,
    validate_normal_receipt,
    validate_semantic_profile,
    verify_receipt_digest,
)
from ida_pro_mcp.flow_core.serialization import ContractError, digest

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "tests/flow_fixtures/manifests/profile_semantics/normal"
FORMAT_EVIDENCE = ROOT / "tests/flow_fixtures/manifests/profile_semantics/formats"
P0_ROOT = ROOT / "tests/flow_fixtures/manifests/profiles"
P0_EVIDENCE = P0_ROOT / "actual-p0"
BUILD = ROOT / "tests/flow_fixtures/manifests/profiles/build.json"
ORACLE = ROOT / "tests/flow_fixtures/oracles/isa_profiles.json"
ENTRY = ROOT / "scripts/flow_profile_semantics.py"
RUNNER = ROOT / "scripts/record_flow_profile_semantics.py"
EXTRACTOR = ROOT / "src/ida_pro_mcp/ida_mcp/flow/extractor.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load(RUNNER, "flow_profile_semantics_runner_test")
extractor = load(EXTRACTOR, "flow_profile_semantics_extractor_test")


def build_row() -> dict:
    row = {
        "profile_id": "X86-LE",
        "profile_version": 1,
        "target_triple": "i386-linux-musl",
        "abi_id": "sysv-i386",
        "bitness": 32,
        "data_endian": "LE",
        "instruction_endian": "LE",
        "mode": "X86",
        "processor": "metapc",
        "format": "FMT-ELF",
        "platform_tag": "linux",
        "binary": "fresh-1/profiles/X86-LE/x86_le.elf",
        "binary_sha256": "a" * 64,
        "binary_size": 4,
        "binary_header": {"kind": "ELF", "entry": 0, "image_base": 0x400000},
        "function_selectors": [
            {"kind": "debug_or_symbol_name", "value": name} for name in FUNCTIONS
        ],
        "target_executed": False,
    }
    row["function_entries"] = [
        {
            "name": name,
            "symbol_value": 0x401000 + index * 0x20,
            "logical_rva": 0x1000 + index * 0x20,
            "symbol_size": 0x20,
            "symbol_other": 0,
            "symbol_table": ".symtab",
            "proof_kind": "elf_symbol",
            "local_entry_offset": 0,
            "extraction_rva": 0x1000 + index * 0x20,
        }
        for index, name in enumerate(FUNCTIONS)
    ]
    row["binary_header"]["entry"] = row["function_entries"][-1]["symbol_value"]
    return row


def ppc64_build_row(endian: str = "LE") -> dict:
    row = build_row()
    little = endian == "LE"
    row.update(
        profile_id="PPC64-LE" if little else "PPC64-BE",
        target_triple=("powerpc64le-linux-gnu" if little else "powerpc64-linux-gnu"),
        abi_id="elfv2-ppc64",
        bitness=64,
        data_endian=endian,
        instruction_endian=endian,
        mode="PPC64",
        processor="PPCL" if little else "PPC",
    )
    for entry in row["function_entries"]:
        entry["proof_kind"] = "ppc64_elfv2_st_other"
        if entry["name"] in {"isa_call", "isa_profile_entry"}:
            entry["symbol_other"] = 0x60
            entry["local_entry_offset"] = 8
            entry["extraction_rva"] = entry["logical_rva"] + 8
    return row


@pytest.mark.parametrize("endian", ["LE", "BE"])
def test_ppc64_function_entries_bind_local_extraction_to_raw_st_other(endian):
    entries = function_entry_proofs(ppc64_build_row(endian))
    by_name = {entry["name"]: entry for entry in entries}
    assert (
        by_name["isa_scalar"]["extraction_rva"] == by_name["isa_scalar"]["logical_rva"]
    )
    for name in ("isa_call", "isa_profile_entry"):
        assert by_name[name]["symbol_other"] == 0x60
        assert by_name[name]["local_entry_offset"] == 8
        assert by_name[name]["extraction_rva"] == by_name[name]["logical_rva"] + 8


@pytest.mark.parametrize(
    "mutation",
    [
        lambda row: row["function_entries"][4].update(
            symbol_other=0, local_entry_offset=8
        ),
        lambda row: row["function_entries"][4].update(
            symbol_other=0x40, local_entry_offset=8
        ),
        lambda row: row["function_entries"][4].update(
            symbol_size=8, extraction_rva=row["function_entries"][4]["logical_rva"] + 8
        ),
        lambda row: row.update(abi_id="sysv-ppc64"),
        lambda row: row.update(profile_id="PPC32-LE"),
        lambda row: row.update(mode="PPC"),
        lambda row: row.update(format="FMT-PE"),
        lambda row: row.update(data_endian="BE"),
        lambda row: row.update(instruction_endian="BE"),
        lambda row: row.update(bitness=32),
        lambda row: row["function_entries"][4].update(proof_kind="elf_symbol"),
        lambda row: row["function_entries"][4].pop("symbol_other"),
        lambda row: row["function_entries"][4].update(symbol_value=0x500000),
        lambda row: row["binary_header"].update(image_base=0),
        lambda row: row["function_entries"].__setitem__(
            5, deepcopy(row["function_entries"][4])
        ),
    ],
)
def test_ppc64_function_entries_reject_unbound_or_ambiguous_local_proofs(mutation):
    row = ppc64_build_row()
    mutation(row)
    with pytest.raises(ContractError):
        function_entry_proofs(row)


def test_entry_script_does_not_infer_ppc64_local_entry_from_numeric_adjacency():
    for path in (
        ENTRY,
        ROOT / "src/ida_pro_mcp/flow_core/profile_semantics.py",
        ROOT / "scripts/evaluate_flow_profile_semantics.py",
    ):
        source = path.read_text()
        assert "expected_rva + 8" not in source
    assert "semantic_entry_proofs" in ENTRY.read_text()
    assert "extraction_rva" in ENTRY.read_text()


def _entry_selection(
    proof: dict, image_base: int = 0x1000000, *, containing: bool = False
) -> dict:
    logical_rva = proof["logical_rva"]
    manifest_extraction_rva = proof["extraction_rva"]
    symbol_end_rva = logical_rva + proof["symbol_size"]
    if containing:
        ida_extraction_rva = logical_rva
        logical_end_rva = symbol_end_rva
        selection_kind = "logical_function_contains_proven_local_entry"
    else:
        ida_extraction_rva = manifest_extraction_rva
        logical_end_rva = (
            manifest_extraction_rva if proof["local_entry_offset"] else symbol_end_rva
        )
        selection_kind = "exact_local_function"

    def bounds(start_rva: int, end_rva: int) -> dict:
        return {
            "start_ea": image_base + start_rva,
            "start_rva": start_rva,
            "end_ea": image_base + end_rva,
            "end_rva": end_rva,
        }

    return {
        "logical_rva": logical_rva,
        "manifest_extraction_rva": manifest_extraction_rva,
        "ida_extraction_rva": ida_extraction_rva,
        "selection_kind": selection_kind,
        "proof_kind": proof["proof_kind"],
        "manifest_entry": deepcopy(proof),
        "materialization": None,
        "named_ea": image_base + logical_rva,
        "named_rva": logical_rva,
        "logical_ida_bounds": bounds(logical_rva, logical_end_rva),
        "extraction_ida_bounds": bounds(ida_extraction_rva, symbol_end_rva),
    }


def test_ppc64_entry_selection_accepts_exact_manifest_and_ida_bounds():
    proof = function_entry_proofs(ppc64_build_row())[4]
    _validate_entry_selection(_entry_selection(proof), proof, 0x1000000)


def test_ppc64_entry_selection_accepts_logical_function_containing_proven_local():
    proof = function_entry_proofs(ppc64_build_row())[5]
    value = _entry_selection(proof, containing=True)
    _validate_entry_selection(value, proof, 0x1000000)
    assert select_ida_extraction(
        proof,
        value["extraction_ida_bounds"]["start_rva"],
        value["extraction_ida_bounds"]["end_rva"],
    ) == {
        "manifest_extraction_rva": proof["extraction_rva"],
        "ida_extraction_rva": proof["logical_rva"],
        "selection_kind": "logical_function_contains_proven_local_entry",
    }


@pytest.mark.parametrize(
    ("start_delta", "end_delta", "offset"),
    [(-4, 8, 8), (4, 20, 8), (0, 8, 8), (0, 40, 8), (8, 8, 8)],
)
def test_ppc64_two_case_selector_rejects_adjacent_arbitrary_or_unproven_ranges(
    start_delta, end_delta, offset
):
    proof = deepcopy(function_entry_proofs(ppc64_build_row())[5])
    proof["local_entry_offset"] = offset
    proof["extraction_rva"] = proof["logical_rva"] + offset
    with pytest.raises(ContractError):
        select_ida_extraction(
            proof,
            proof["logical_rva"] + start_delta,
            proof["logical_rva"] + end_delta,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["manifest_entry"].update(symbol_other=0),
        lambda value: value.update(named_ea=value["named_ea"] + 8),
        lambda value: value["logical_ida_bounds"].update(
            end_rva=value["logical_ida_bounds"]["end_rva"] + 4,
            end_ea=value["logical_ida_bounds"]["end_ea"] + 4,
        ),
        lambda value: value["extraction_ida_bounds"].update(
            start_rva=value["extraction_ida_bounds"]["start_rva"] + 4,
            start_ea=value["extraction_ida_bounds"]["start_ea"] + 4,
        ),
        lambda value: value["extraction_ida_bounds"].update(
            end_rva=value["extraction_ida_bounds"]["end_rva"] + 4,
            end_ea=value["extraction_ida_bounds"]["end_ea"] + 4,
        ),
    ],
)
def test_ppc64_entry_selection_rejects_manifest_and_ida_bound_tampering(mutation):
    proof = function_entry_proofs(ppc64_build_row())[4]
    value = _entry_selection(proof)
    mutation(value)
    with pytest.raises(ContractError):
        _validate_entry_selection(value, proof, 0x1000000)


def p0_documents(row: dict) -> tuple[dict, dict]:
    declared = {
        "profile_id": row["profile_id"],
        "profile_version": row["profile_version"],
        "mode": row["mode"],
        "processor": row["processor"],
        "bits": row["bitness"],
        "data_endian": row["data_endian"],
        "instruction_endian": row["instruction_endian"],
        "abi_id": row["abi_id"],
    }
    result = {
        "schema_version": "flow-profile-receipt-run/1",
        "profile_id": row["profile_id"],
        "format": "FMT-ELF",
        "declared_profile": declared,
        "binary": {
            "manifest_path": row["binary"],
            "expected_sha256": row["binary_sha256"],
            "copied_sha256": row["binary_sha256"],
        },
        "status": "success",
        "support_status": "unverified",
        "target_executed": False,
        "repeatability": {"performed": True, "semantic_equal": True},
    }
    receipt = {
        "schema_version": "flow-p0-probe/2",
        "request": {
            "profile": declared,
            "binary": {
                "format": "ELF",
                "sha256": row["binary_sha256"],
            },
        },
        "environment": {
            "ida_version": "9.3",
            "processor": row["processor"],
            "bits": row["bitness"],
            "data_endian": row["data_endian"],
            "binary_sha256": row["binary_sha256"],
            "format": "ELF",
        },
        "validation": {"status": "accepted"},
        "probe_status": "success",
        "support_status": "unverified",
        "target_executed": False,
        "initialization": True,
        "probes": [
            {
                "maturity": "MMAT_CALLS",
                "status": "success",
                "repeat_equal": True,
                "digest": "b" * 64,
            }
        ],
        "failures": [],
        "lifetime": {"json_roundtrip": True, "repeat_after_gc": True},
    }
    return result, receipt


def test_ephemeral_registry_is_exact_typed_and_does_not_promote_support():
    row = build_row()
    result, receipt = p0_documents(row)
    registry = ephemeral_registry(row, result, receipt, "actual-p0/x86/receipt.json")
    assert type(registry) is ProfileRegistry
    assert registry is not REGISTRY
    assert [item.profile_id for item in registry.profiles] == [
        item.profile_id for item in REGISTRY.profiles
    ]
    changed = registry.get("X86-LE")
    assert changed.receipt_status == "success"
    assert changed.maturity == "MMAT_CALLS"
    assert changed.format_ids == ("FMT-ELF",)
    assert changed.instruction_endian == "little"
    assert all(
        item.normal_status == item.fallback_status == "unverified"
        for item in registry.profiles
    )
    profile = semantic_profile(row, "c" * 64, registry)
    assert profile["registry_digest"] == digest(registry)
    assert profile["receipt_status"] == "success"
    assert profile["abi_provenance"]["binary_sha256"] == row["binary_sha256"]
    validate_semantic_profile(profile, row, "c" * 64, registry)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda result, _receipt: result["binary"].update(copied_sha256="0" * 64),
        lambda result, _receipt: result["declared_profile"].update(abi_id="wrong"),
        lambda result, _receipt: result["repeatability"].update(semantic_equal=False),
        lambda _result, receipt: receipt.update(target_executed=True),
        lambda _result, receipt: receipt["probes"][0].update(repeat_equal=False),
    ],
)
def test_ephemeral_registry_rejects_p0_tampering(mutation):
    row = build_row()
    result, receipt = p0_documents(row)
    mutation(result, receipt)
    with pytest.raises(ContractError):
        ephemeral_registry(row, result, receipt, "actual-p0/x86/receipt.json")


def test_canonical_registry_profile_remains_byte_compatible():
    profile = REGISTRY.measured_extraction_profile("X64-LE")
    assert profile["registry_digest"] == REGISTRY_DIGEST == digest(REGISTRY)
    REGISTRY.validate_extraction_profile(profile)


def test_extractor_uses_exact_typed_registry_seam_without_entry_monkeypatch():
    parameter = inspect.signature(extractor.extract_snapshot).parameters["registry"]
    assert parameter.annotation is ProfileRegistry
    assert parameter.default is REGISTRY
    source = ENTRY.read_text()
    assert "extractor.REGISTRY =" not in source
    assert "registry=registry" in source


def test_runner_invocation_is_shell_free_disposable_and_input_preserving(
    tmp_path, monkeypatch
):
    source = tmp_path / "original.elf"
    source.write_bytes(b"ELF\x00")
    ida = tmp_path / "idat"
    ida.write_bytes(b"static ida executable")
    request = {
        "build_row": {"profile_id": "X86-LE"},
        "manifest_sha256": "a" * 64,
    }
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        assert kwargs["shell"] is False
        assert command[1:3] == ["-c", "-A"]
        disposable = Path(command[-1])
        assert disposable != source
        assert disposable.read_bytes() == source.read_bytes()
        script_args = command[3][2:]
        output = Path(script_args.split()[2])
        output.write_text("{}")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    monkeypatch.setattr(runner, "validate_normal_process", lambda *_args: None)
    process, invocation = runner._run_process(
        root=ROOT,
        ida_executable=ida,
        source_binary=source,
        request=request,
        run_id="fresh-1",
        timeout_seconds=10,
    )
    assert process == {}
    assert invocation["shell"] is False
    assert invocation["target_executed"] is False
    assert invocation["input_preserved"] is True
    assert source.read_bytes() == b"ELF\x00"
    assert len(calls) == 1


def test_committed_normal_matrix_is_complete_and_replayable():
    matrix = json.loads((EVIDENCE / "matrix.json").read_text())
    assert matrix["schema_version"] == NORMAL_MATRIX_SCHEMA
    verify_receipt_digest(matrix)
    assert matrix["status"] == "success"
    assert matrix["success_count"] == 16
    assert matrix["failure_count"] == 0
    assert matrix["target_executed"] is False
    assert matrix["input_preserved"] is True
    assert [item["profile_id"] for item in matrix["profiles"]] == list(
        NORMAL_PROFILE_IDS
    )

    build = json.loads(BUILD.read_text())
    oracle = json.loads(ORACLE.read_text())
    builds = {item["profile_id"]: item for item in build["profiles"]}
    oracles = {item["profile_id"]: item for item in oracle["profiles"]}
    for item in matrix["profiles"]:
        receipt = json.loads((EVIDENCE / item["result_file"]).read_text())
        validate_normal_receipt(
            receipt, builds[item["profile_id"]], oracles[item["profile_id"]]
        )
        assert receipt["implementation"] == {
            relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            for relative in receipt["implementation"]
        }
        assert item["receipt_digest"] == receipt["receipt_digest"]
        assert [function["symbol"] for function in receipt["functions"]] == list(
            FUNCTIONS
        )
        p0_path = P0_ROOT / receipt["profile"]["abi_provenance"]["p0_receipt"]
        assert p0_path.is_file()
        p0 = json.loads(p0_path.read_text())
        assert p0["target_executed"] is False
        assert p0["request"]["binary"]["sha256"] == receipt["binary_sha256"]
        assert p0["request"]["profile"]["profile_id"] == item["profile_id"]


def test_committed_format_matrix_is_complete_replayable_and_p0_resolvable():
    matrix = json.loads((FORMAT_EVIDENCE / "matrix.json").read_text())
    assert matrix["schema_version"] == FORMAT_MATRIX_SCHEMA
    verify_receipt_digest(matrix)
    assert matrix["status"] == "success"
    assert matrix["success_count"] == 4
    assert matrix["failure_count"] == 0
    assert matrix["target_executed"] is False
    assert matrix["input_preserved"] is True
    assert [
        (item["profile_id"], item["format"]) for item in matrix["profiles"]
    ] == list(FORMAT_VARIANT_KEYS)

    build = json.loads(BUILD.read_text())
    oracle = json.loads(ORACLE.read_text())
    builds = {
        (item["profile_id"], item["format"]): item for item in build["format_variants"]
    }
    oracles = {item["profile_id"]: item for item in oracle["profiles"]}
    for item in matrix["profiles"]:
        key = (item["profile_id"], item["format"])
        receipt = json.loads((FORMAT_EVIDENCE / item["result_file"]).read_text())
        validate_normal_receipt(receipt, builds[key], oracles[item["profile_id"]])
        semantic_entry_proofs(builds[key])
        p0_path = P0_ROOT / receipt["profile"]["abi_provenance"]["p0_receipt"]
        assert p0_path.is_file()
        p0 = json.loads(p0_path.read_text())
        assert p0["target_executed"] is False
        assert p0["request"]["binary"]["sha256"] == receipt["binary_sha256"]
        assert p0["request"]["profile"]["profile_id"] == item["profile_id"]
        assert receipt["implementation"] == {
            relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            for relative in receipt["implementation"]
        }
        assert item["receipt_digest"] == receipt["receipt_digest"]
        assert [function["symbol"] for function in receipt["functions"]] == list(
            FUNCTIONS
        )


def test_committed_p0_matrix_is_resolvable_static_and_exactly_partial_for_rv32():
    matrix = json.loads((P0_EVIDENCE / "matrix.json").read_text())
    assert matrix["row_count"] == 21
    assert matrix["status_counts"] == {"blocked": 0, "failed": 1, "success": 20}
    assert matrix["status"] == "partial"
    assert matrix["target_executed"] is False
    failed = [item for item in matrix["rows"] if item["status"] == "failed"]
    assert [(item["profile_id"], item["format"]) for item in failed] == [
        ("RV32-LE", "FMT-ELF")
    ]
    for item in matrix["rows"]:
        result_path = P0_EVIDENCE / item["result_file"]
        assert result_path.is_file()
        result = json.loads(result_path.read_text())
        assert result["target_executed"] is False
        assert result["profile_id"] == item["profile_id"]
        assert result["format"] == item["format"]
        for stage in result["stages"].values():
            for key in ("request_file", "receipt_file"):
                if stage[key] is not None:
                    assert (result_path.parent / stage[key]).is_file()


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["profile"].update(abi="tampered"),
        lambda value: value.update(binary_sha256="0" * 64),
        lambda value: value["functions"][0].update(function_rva=0),
        lambda value: value.update(maturity="MMAT_GLBOPT3"),
        lambda value: value.update(target_executed=True),
        lambda value: value.update(registry_promoted=True),
        lambda value: value["functions"][4]["call_target_resolutions"][0].update(
            resolved_to_expected=(
                not value["functions"][4]["call_target_resolutions"][0][
                    "resolved_to_expected"
                ]
            )
        ),
    ],
)
def test_normal_receipt_rejects_tampering_even_with_recomputed_digest(mutation):
    build = json.loads(BUILD.read_text())
    oracle = json.loads(ORACLE.read_text())
    row = next(item for item in build["profiles"] if item["profile_id"] == "X64-LE")
    oracle_row = next(
        item for item in oracle["profiles"] if item["profile_id"] == "X64-LE"
    )
    value = json.loads((EVIDENCE / "x64-le.json").read_text())
    mutation(value)
    value["receipt_digest"] = receipt_digest(
        {key: item for key, item in value.items() if key != "receipt_digest"}
    )
    with pytest.raises((ContractError, KeyError, ValueError)):
        validate_normal_receipt(value, row, oracle_row)
