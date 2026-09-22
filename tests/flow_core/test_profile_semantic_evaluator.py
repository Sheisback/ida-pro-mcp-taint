"""Independent Phase-2 semantic receipt and oracle validation."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
from typing import Any, Callable

import pytest

from ida_pro_mcp.flow_core import ContractError, digest
from ida_pro_mcp.flow_core.profile_semantic_receipts import (
    COMPLETE_MATRIX_SCHEMA,
    RV32_RECEIPT_SCHEMA,
    validate_complete_matrix_receipt,
    validate_rv32_receipt,
)
from ida_pro_mcp.flow_core.profile_semantics import (
    FUNCTIONS,
    function_entry_proofs,
    select_ida_extraction,
    semantic_entry_proofs,
)


ROOT = Path(__file__).resolve().parents[2]
EVALUATOR_PATH = ROOT / "scripts/evaluate_flow_profile_semantics.py"
RECEIPT_PATH = (
    ROOT / "tests/flow_fixtures/manifests/profile_semantics/rv32-fallback.json"
)
ORACLE_PATH = ROOT / "tests/flow_fixtures/oracles/rv32_lowering.json"
CAPTURE_ROOT = ROOT / "tests/flow_fixtures/manifests/rv32_capture"
MATRIX_PATH = ROOT / "tests/flow_fixtures/manifests/profile_semantics/matrix.json"
NORMAL_ROOT = ROOT / "tests/flow_fixtures/manifests/profile_semantics/normal"
FORMAT_ROOT = ROOT / "tests/flow_fixtures/manifests/profile_semantics/formats"
BUILD_PATH = ROOT / "tests/flow_fixtures/manifests/profiles/build.json"
ISA_ORACLE_PATH = ROOT / "tests/flow_fixtures/oracles/isa_profiles.json"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


evaluator = _load(EVALUATOR_PATH, "profile_semantic_evaluator_test")


def _ppc64_build_row() -> dict[str, Any]:
    entries = [
        {
            "name": name,
            "symbol_value": 0x1010000 + index * 0x20,
            "symbol_size": 0x20,
            "symbol_other": 0x60 if name in {"isa_call", "isa_profile_entry"} else 0,
            "symbol_table": ".symtab",
            "logical_rva": 0x10000 + index * 0x20,
            "local_entry_offset": (
                8 if name in {"isa_call", "isa_profile_entry"} else 0
            ),
            "extraction_rva": 0x10000
            + index * 0x20
            + (8 if name in {"isa_call", "isa_profile_entry"} else 0),
            "proof_kind": "ppc64_elfv2_st_other",
        }
        for index, name in enumerate(FUNCTIONS)
    ]
    return {
        "profile_id": "PPC64-LE",
        "mode": "PPC64",
        "abi_id": "elfv2-ppc64",
        "bitness": 64,
        "format": "FMT-ELF",
        "platform_tag": "linux",
        "data_endian": "LE",
        "instruction_endian": "LE",
        "processor": "PPCL",
        "target_triple": "powerpc64le-linux-gnu",
        "binary_header": {
            "kind": "ELF",
            "entry": entries[-1]["symbol_value"],
            "image_base": 0x1000000,
        },
        "function_entries": entries,
    }


def test_core_and_independent_evaluator_share_exact_ppc64_entry_proof_contract():
    row = _ppc64_build_row()
    assert evaluator._function_entry_proofs(row) == function_entry_proofs(row)


@pytest.mark.parametrize(
    ("function", "start_kind"),
    [("isa_call", "manifest"), ("isa_profile_entry", "logical")],
)
def test_core_and_independent_evaluator_share_two_case_ida_selection(
    function, start_kind
):
    proof = next(
        item
        for item in function_entry_proofs(_ppc64_build_row())
        if item["name"] == function
    )
    start = (
        proof["extraction_rva"] if start_kind == "manifest" else proof["logical_rva"]
    )
    end = proof["logical_rva"] + proof["symbol_size"]
    assert evaluator._select_ida_extraction(proof, start, end) == select_ida_extraction(
        proof, start, end
    )


@pytest.mark.parametrize(
    ("start_delta", "end_delta"),
    [(-4, 8), (4, 20), (0, 8), (0, 40), (8, 8)],
)
def test_independent_two_case_selector_rejects_unapproved_ranges(
    start_delta, end_delta
):
    proof = function_entry_proofs(_ppc64_build_row())[-1]
    with pytest.raises(ValueError):
        evaluator._select_ida_extraction(
            proof,
            proof["logical_rva"] + start_delta,
            proof["logical_rva"] + end_delta,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda row: row["function_entries"][4].update(symbol_other=0),
        lambda row: row["function_entries"][4].update(extraction_rva=0x10000),
        lambda row: row.update(format="FMT-PE"),
        lambda row: row["function_entries"][5].update(
            name=row["function_entries"][4]["name"]
        ),
    ],
)
def test_independent_evaluator_rejects_forged_ppc64_entry_proofs(mutation):
    row = _ppc64_build_row()
    mutation(row)
    with pytest.raises(ValueError):
        evaluator._function_entry_proofs(row)


def _receipt() -> dict[str, Any]:
    return evaluator.read_json(RECEIPT_PATH)


def _redigest(receipt: dict[str, Any]) -> dict[str, Any]:
    body = dict(receipt)
    body.pop("receipt_digest", None)
    receipt["receipt_digest"] = digest(body)
    return receipt


def _raw_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_committed_rv32_fallback_receipt_is_pure_repeatable_and_replayable(
    tmp_path,
):
    immutable_inputs = [
        CAPTURE_ROOT / "receipt.json",
        CAPTURE_ROOT / "fresh-1/process-receipt.json",
        CAPTURE_ROOT / "fresh-2/process-receipt.json",
        CAPTURE_ROOT / "normal_microcode_unavailable.json",
        ORACLE_PATH,
    ]
    before = {path: _raw_sha256(path) for path in immutable_inputs}

    first = evaluator.build_rv32_fallback_receipt(ROOT)
    second = evaluator.build_rv32_fallback_receipt(ROOT)
    assert first == second == _receipt()
    evaluator.validate_rv32_fallback_receipt(ROOT, first)

    output = tmp_path / "rv32-fallback.json"
    assert evaluator.main(["--root", str(ROOT), "--output", str(output)]) == 0
    assert evaluator.read_json(output) == first
    assert {path: _raw_sha256(path) for path in immutable_inputs} == before
    assert first["target_executed"] is False
    assert first["input_preserved"] is True
    assert first["registry_promoted"] is first["service_promoted"] is False
    assert first["support_status"] == "unverified"
    assert first["status"] == "partial"
    assert first["candidate_status"] == "accepted_candidate"
    assert first["normal_backend"]["probe_status"] == "failed"
    assert first["normal_backend"]["target_executed"] is False


def test_core_contract_and_independent_rv32_validator_accept_the_same_receipt():
    receipt = _receipt()
    assert evaluator.RV32_RECEIPT_SCHEMA == RV32_RECEIPT_SCHEMA
    validate_rv32_receipt(receipt)
    evaluator.validate_rv32_fallback_receipt(ROOT, receipt)


def test_rv32_fallback_evaluation_matches_the_hand_authored_semantic_contract():
    receipt = _receipt()
    oracle = evaluator.read_json(ORACLE_PATH)
    evaluation = receipt["evaluation"]
    expected = oracle["semantic_contract"]

    assert evaluation["scalar"] == {
        "operations": expected["scalar"]["operations"],
        "a0_return_labels": ["rv32:a0"],
        "a1_return_labels": ["rv32:a1"],
        "unrelated_ra_return_labels": [],
    }
    assert evaluation["branch"] == {
        "cfg_successors": expected["branch"]["cfg_successors"],
        "phi_predecessors": expected["branch"]["phi_predecessors"],
        "value_return_labels": ["rv32:a0"],
        "selector_predicate_labels": ["rv32:a1"],
        "selector_return_labels": [],
        "implicit_flow_claimed": False,
    }
    assert evaluation["memory"] == expected["memory"]
    assert evaluation["isa_store_return"] == {"inputs": [], "width_bits": None}

    expected_targets = {
        item["symbol"]: item["entry_ea"] for item in oracle["functions"]
    }
    calls = evaluation["calls"]
    assert calls["all_effects_partial"] is True
    assert len(calls["calls"]) == 5
    for actual, expected_row in zip(calls["calls"], expected["calls"]["rows"]):
        assert actual["site_ea"] == expected_row["site_ea"]
        assert actual["callee_ea"] == expected_targets[expected_row["callee_symbol"]]
        assert actual["arguments"] == expected_row["arguments"]
        assert actual["returns"] == expected_row["returns"]
        assert actual["return_is_void"] is expected_row["return_is_void"]
        assert actual["return_width_bits"] == expected_row["return_width_bits"]
        assert actual["unresolved"] == expected["calls"]["unresolved"]
        assert (
            digest(actual["spoiled_locations"])
            == expected["calls"]["spoiled_locations_digest"]
        )


def test_all_normal_receipts_pass_independent_replay_and_oracle_validation():
    build = evaluator.read_json(BUILD_PATH)
    oracle = evaluator.read_json(ISA_ORACLE_PATH)
    build_rows = {item["profile_id"]: item for item in build["profiles"]}
    oracle_rows = {item["profile_id"]: item for item in oracle["profiles"]}

    for profile_id in evaluator.NORMAL_PROFILE_IDS:
        receipt = evaluator.read_json(NORMAL_ROOT / f"{profile_id.lower()}.json")
        evaluator.validate_normal_receipt(
            ROOT, receipt, build_rows[profile_id], oracle_rows[profile_id]
        )
        assert receipt["target_executed"] is False
        assert receipt["input_preserved"] is True
        assert receipt["registry_promoted"] is False
        assert receipt["service_promoted"] is False
        assert receipt["capabilities_promoted"] is False


def test_all_format_receipts_pass_independent_replay_and_oracle_validation():
    build = evaluator.read_json(BUILD_PATH)
    oracle = evaluator.read_json(ISA_ORACLE_PATH)
    build_rows = {
        (item["profile_id"], item["format"]): item for item in build["format_variants"]
    }
    oracle_rows = {item["profile_id"]: item for item in oracle["profiles"]}
    matrix = evaluator.read_json(FORMAT_ROOT / "matrix.json")
    for item in matrix["profiles"]:
        key = (item["profile_id"], item["format"])
        receipt = evaluator.read_json(FORMAT_ROOT / item["result_file"])
        assert evaluator._semantic_entry_proofs(
            build_rows[key]
        ) == semantic_entry_proofs(build_rows[key])
        evaluator.validate_normal_receipt(
            ROOT, receipt, build_rows[key], oracle_rows[item["profile_id"]]
        )
        assert receipt["target_executed"] is False
        assert receipt["input_preserved"] is True


def test_raw_format_receipt_rejects_materialization_tampering():
    receipt = evaluator.read_json(FORMAT_ROOT / "arm32-le--raw.json")
    build = evaluator.read_json(BUILD_PATH)
    oracle = evaluator.read_json(ISA_ORACLE_PATH)
    row = next(item for item in build["format_variants"] if item["format"] == "FMT-RAW")
    oracle_row = next(
        item for item in oracle["profiles"] if item["profile_id"] == "ARM32-LE"
    )
    receipt["functions"][0]["entry_selection"]["materialization"][
        "requested_end_rva"
    ] += 1
    _redigest(receipt)
    with pytest.raises((ValueError, ContractError)):
        evaluator.validate_normal_receipt(ROOT, receipt, row, oracle_row)


def test_committed_complete_matrix_is_reproducible_and_cross_validated():
    matrix = evaluator.read_json(MATRIX_PATH)
    assert matrix["schema_version"] == COMPLETE_MATRIX_SCHEMA
    assert matrix == evaluator.build_complete_matrix_receipt(ROOT)
    validate_complete_matrix_receipt(matrix)
    evaluator.validate_complete_matrix_artifacts(ROOT, matrix)
    assert matrix["profile_count"] == 17
    assert matrix["semantic_row_count"] == 21
    assert matrix["normal_success_count"] == 16
    assert matrix["format_variant_count"] == 4
    assert matrix["format_success_count"] == 4
    assert matrix["rv32_normal_failure_count"] == 1
    assert matrix["rv32_fallback_count"] == 1
    assert matrix["target_executed"] is False
    assert matrix["input_preserved"] is True
    assert matrix["normal_fallback_separate"] is True
    assert matrix["registry_service_capabilities_promoted"] is False


def test_artifact_validator_derives_normal_and_fallback_backends_from_rows(monkeypatch):
    matrix = deepcopy(evaluator.read_json(MATRIX_PATH))
    normal_matrix_path = ROOT / matrix["normal_matrix_file"]
    normal_matrix = deepcopy(evaluator.read_json(normal_matrix_path))
    x86 = next(
        row
        for row in matrix["profiles"]
        if row["profile_id"] == "X86-LE" and row["evidence_path"] == "normal"
    )
    rv32 = next(row for row in matrix["profiles"] if row["profile_id"] == "RV32-LE")

    rv32_normal = {
        "profile_id": "RV32-LE",
        "receipt_digest": "sha256-v1:" + "1" * 64,
    }
    fallback_body = {
        "schema_version": "flow-profile-semantics-fallback/1",
        "profile_id": "X86-LE",
        "evidence_path": "fallback",
        "status": "partial",
        "candidate_status": "accepted_candidate",
        "support_status": "unverified",
        "normal_backend": {
            "probe_status": "failed",
            "support_status": "unverified",
            "target_executed": False,
        },
        "limitations": ["normal_backend_unavailable"],
        "input_preserved": True,
        "target_executed": False,
        "registry_promoted": False,
        "service_promoted": False,
    }
    x86_fallback = {**fallback_body, "receipt_digest": digest(fallback_body)}
    x86.update(
        evidence_path="fallback",
        status="accepted_candidate_partial_normal_failed",
        receipt_file="tests/flow_fixtures/manifests/profile_semantics/x86-fallback.json",
        receipt_digest=x86_fallback["receipt_digest"],
    )
    rv32.update(
        evidence_path="normal",
        status="success_partial_with_named_limitations",
        receipt_file="tests/flow_fixtures/manifests/profile_semantics/normal/rv32-le.json",
        receipt_digest=rv32_normal["receipt_digest"],
    )
    matrix["rv32_normal_failure_count"] = 0
    matrix["rv32_fallback_count"] = 0

    normal_matrix["profiles"] = [
        row for row in normal_matrix["profiles"] if row["profile_id"] != "X86-LE"
    ] + [
        {
            "profile_id": "RV32-LE",
            "status": "success",
            "result_file": "rv32-le.json",
            "receipt_digest": rv32_normal["receipt_digest"],
        }
    ]
    normal_matrix["success_count"] = len(normal_matrix["profiles"])
    _redigest(normal_matrix)
    matrix["normal_matrix_digest"] = normal_matrix["receipt_digest"]
    _redigest(matrix)

    documents = {
        normal_matrix_path.resolve(): normal_matrix,
        (ROOT / x86["receipt_file"]).resolve(): x86_fallback,
        (ROOT / rv32["receipt_file"]).resolve(): rv32_normal,
    }
    original_read = evaluator.read_json

    def read(path: Path):
        resolved = path.resolve()
        return (
            deepcopy(documents[resolved])
            if resolved in documents
            else original_read(path)
        )

    validated = []
    monkeypatch.setattr(evaluator, "read_json", read)
    monkeypatch.setattr(
        evaluator,
        "validate_normal_receipt",
        lambda _root, value, _build, _oracle: validated.append(value["profile_id"]),
    )
    fallback_validated = []
    monkeypatch.setattr(
        evaluator,
        "_validate_fallback_receipt",
        lambda _root, value: fallback_validated.append(value["profile_id"]),
    )

    evaluator.validate_complete_matrix_artifacts(ROOT, matrix)
    assert "RV32-LE" in validated
    assert "X86-LE" not in validated
    assert fallback_validated == ["X86-LE"]


def test_fallback_dispatch_rejects_unbacked_generic_envelopes():
    with pytest.raises(
        ValueError, match="Unsupported fallback semantic receipt schema"
    ):
        evaluator._validate_fallback_receipt(
            ROOT,
            {
                "schema_version": "flow-profile-semantics-fallback/1",
                "profile_id": "X86-LE",
            },
        )


@pytest.mark.parametrize("endian", ["le", "be"])
def test_ppc64_closes_direct_target_argument_return_and_void_facts(endian):
    receipt = evaluator.read_json(NORMAL_ROOT / f"ppc64-{endian}.json")
    evaluation = receipt["evaluation"]
    assert (
        evaluation["generic_oracles"]["ISA-G05"]
        == "pass_direct_target_args_return_void_partial_effects"
    )
    assert (
        "direct_call_target_or_argument_metadata_unresolved"
        not in evaluation["limitations"]
    )
    assert "profile_entry_direct_target_set_unresolved" not in evaluation["limitations"]
    assert all(
        item["resolved_to_expected"] is True
        for item in evaluation["call_observation"]["profile_entry_target_resolutions"]
    )
    assert evaluation["call_observation"]["observed_isa_call_target_rvas"]


Mutation = Callable[[dict[str, Any]], None]


def _set_top(key: str, value: Any) -> Mutation:
    def mutate(receipt: dict[str, Any]) -> None:
        receipt[key] = value

    return mutate


def _set_nested(*path_and_value: Any) -> Mutation:
    *path, value = path_and_value

    def mutate(receipt: dict[str, Any]) -> None:
        current: Any = receipt
        for key in path[:-1]:
            current = current[key]
        current[path[-1]] = value

    return mutate


def _drop_function(receipt: dict[str, Any]) -> None:
    receipt["functions"].pop()


def _duplicate_function(receipt: dict[str, Any]) -> None:
    receipt["functions"][-1] = deepcopy(receipt["functions"][0])


def _tamper_snapshot_identity(receipt: dict[str, Any]) -> None:
    function = receipt["functions"][0]
    function["snapshot"]["identity"]["environment"]["abi"] = "wrong-abi"
    function["snapshot_digest"] = digest(function["snapshot"])


def _tamper_normal_snapshot_identity(receipt: dict[str, Any]) -> None:
    receipt["functions"][0]["structural_identity"]["function_rva"] += 4


def _drop_normal_function(receipt: dict[str, Any]) -> None:
    receipt["functions"].pop()


def _duplicate_normal_function(receipt: dict[str, Any]) -> None:
    receipt["functions"][-1] = deepcopy(receipt["functions"][0])


@pytest.mark.parametrize(
    "mutate",
    [
        _set_top("profile_id", "RV64-LE"),
        _set_top("abi_id", "riscv-lp64"),
        _set_top("evidence_path", "normal"),
        _set_top("status", "verified"),
        _set_top("candidate_status", "supported"),
        _set_top("support_status", "supported"),
        _set_top("target_executed", True),
        _set_top("input_preserved", False),
        _set_top("registry_promoted", True),
        _set_top("service_promoted", True),
        _set_nested("normal_backend", "probe_status", "success"),
        _set_nested("normal_backend", "target_executed", True),
        _set_nested("capture", "capture_digest", "sha256-v1:" + "0" * 64),
        _set_nested("capture", "input_preserved", False),
        _set_nested("oracles", "rv32_digest", "sha256-v1:" + "0" * 64),
        _drop_function,
        _duplicate_function,
        _tamper_snapshot_identity,
        _set_nested("evaluation", "branch", "implicit_flow_claimed", True),
        _set_nested("evaluation", "calls", "all_effects_partial", False),
    ],
    ids=[
        "profile",
        "abi",
        "fallback-path",
        "status-promotion",
        "candidate-promotion",
        "support-promotion",
        "target-executed",
        "input-mutated",
        "registry-promotion",
        "service-promotion",
        "normal-success",
        "normal-target-executed",
        "capture-digest",
        "capture-input-mutated",
        "oracle-digest",
        "missing-function",
        "duplicate-function",
        "snapshot-identity",
        "implicit-flow-claim",
        "call-completeness-claim",
    ],
)
def test_rv32_fallback_rejects_hostile_tampering_even_when_redigested(
    mutate: Mutation,
):
    receipt = deepcopy(_receipt())
    mutate(receipt)
    _redigest(receipt)
    with pytest.raises((ValueError, ContractError)):
        evaluator.validate_rv32_fallback_receipt(ROOT, receipt)


@pytest.mark.parametrize(
    "mutate",
    [
        _set_top("profile_id", "X64-LE"),
        _set_top("abi_id", "wrong-abi"),
        _set_top("maturity", "MMAT_GLBOPT3"),
        _set_top("status", "verified"),
        _set_top("target_executed", True),
        _set_top("input_preserved", False),
        _set_top("registry_promoted", True),
        _set_top("service_promoted", True),
        _set_top("capabilities_promoted", True),
        _set_nested("implementation", "scripts/flow_profile_semantics.py", "0" * 64),
        _set_nested("invocations", 0, "shell", True),
        _set_top(
            "fresh_process_receipt_digests",
            ["sha256-v1:" + "0" * 64, "sha256-v1:" + "0" * 64],
        ),
        _set_nested("evaluation", "status", "pass"),
        _drop_normal_function,
        _duplicate_normal_function,
        _tamper_normal_snapshot_identity,
    ],
    ids=[
        "profile",
        "abi",
        "maturity",
        "status-promotion",
        "target-executed",
        "input-mutated",
        "registry-promotion",
        "service-promotion",
        "capability-promotion",
        "implementation-digest",
        "shell-invocation",
        "process-digest-payload-mismatch",
        "partiality-removed",
        "missing-function",
        "duplicate-function",
        "structural-identity",
    ],
)
def test_normal_receipt_rejects_hostile_tampering_even_when_redigested(
    mutate: Mutation,
):
    profile_id = "X86-LE"
    receipt = evaluator.read_json(NORMAL_ROOT / "x86-le.json")
    build = evaluator.read_json(BUILD_PATH)
    oracle = evaluator.read_json(ISA_ORACLE_PATH)
    build_row = next(
        item for item in build["profiles"] if item["profile_id"] == profile_id
    )
    oracle_row = next(
        item for item in oracle["profiles"] if item["profile_id"] == profile_id
    )
    mutate(receipt)
    _redigest(receipt)
    with pytest.raises((ValueError, ContractError)):
        evaluator.validate_normal_receipt(ROOT, receipt, build_row, oracle_row)


@pytest.mark.parametrize(
    "mutate",
    [
        _set_top("profile_count", 16),
        _set_top("semantic_row_count", 20),
        _set_top("normal_success_count", 15),
        _set_top("format_variant_count", 3),
        _set_top("format_success_count", 3),
        _set_top("target_executed", True),
        _set_top("normal_fallback_separate", False),
        _set_top("registry_service_capabilities_promoted", True),
        _set_top("status", "supported"),
    ],
)
def test_complete_matrix_core_contract_rejects_hostile_tampering(mutate: Mutation):
    matrix = evaluator.read_json(MATRIX_PATH)
    mutate(matrix)
    _redigest(matrix)
    with pytest.raises((ValueError, ContractError)):
        validate_complete_matrix_receipt(matrix)


def test_complete_matrix_independent_validator_rejects_artifact_digest_tampering():
    matrix = evaluator.read_json(MATRIX_PATH)
    matrix["oracle_digest"] = "sha256-v1:" + "0" * 64
    _redigest(matrix)
    with pytest.raises(ValueError, match="mismatch"):
        evaluator.validate_complete_matrix_artifacts(ROOT, matrix)


def test_rv32_fallback_rejects_extension_fields_duplicate_keys_and_nonfinite_json(
    tmp_path,
):
    receipt = deepcopy(_receipt())
    receipt["claimed_support"] = True
    _redigest(receipt)
    with pytest.raises(ValueError, match="keys mismatch"):
        evaluator.validate_rv32_fallback_receipt(ROOT, receipt)

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":1,"schema_version":1}')
    with pytest.raises(ValueError, match="Duplicate JSON key"):
        evaluator.read_json(duplicate)

    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text('{"value":NaN}')
    with pytest.raises(ValueError, match="Non-finite JSON constant"):
        evaluator.read_json(nonfinite)
