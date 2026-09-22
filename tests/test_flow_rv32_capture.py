"""Independent Phase-0 guards for the RV32 structured-capture backend."""

import hashlib
import json
import struct
import sys
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from ida_pro_mcp.flow_core.profile_registry import REGISTRY
from ida_pro_mcp.flow_core.rv32_capture import (
    BACKEND_IDENTITY,
    CAPTURE_SCHEMA,
    PROCESS_SCHEMA,
    RECEIPT_SCHEMA,
    AddressRange,
    BackendIdentity,
    BlockCapture,
    CaptureBudgets,
    CaptureBundle,
    CaptureDiagnostic,
    CaptureReceipt,
    CaptureRequest,
    ElfIdentity,
    FixtureEvidence,
    FreshProcessEvidence,
    FunctionCapture,
    InstructionCapture,
    OperandCapture,
    ProcessReceipt,
    ProcessorAdapterIdentity,
    RegisterMetadata,
    function_stable_key,
    parse_elf32_riscv_header,
)
from ida_pro_mcp.flow_core.serialization import ContractError, canonical_json, digest


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_FILE = sys.modules[CaptureRequest.__module__].__file__
assert CONTRACT_FILE is not None
PRODUCT_ROOT = Path(CONTRACT_FILE).parents[3]
INVENTORY = ROOT / "tests/flow_fixtures/manifests/p0_inventory.json"
RV32_EVIDENCE = ROOT / "tests/flow_fixtures/manifests/rv32_capture"


def _sha(character: str) -> str:
    return "sha256-v1:" + character * 64


def _elf_header() -> bytes:
    value = bytearray(52)
    value[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<H", value, 18, 243)
    struct.pack_into("<I", value, 36, 1)
    return bytes(value)


def _fixture() -> FixtureEvidence:
    values = {
        "profile_id": "RV32-LE",
        "profile_version": 1,
        "mode": "RV32",
        "processor": "riscv",
        "bitness": 32,
        "data_endian": "LE",
        "instruction_endian": "LE",
        "format_id": "FMT-ELF",
        "abi_id": "riscv-ilp32",
        "target_triple": "riscv32-linux-gnu",
        "platform_tag": "linux",
        "source_sha256": _sha("1"),
        "build_manifest_sha256": _sha("2"),
        "command_sha256": _sha("3"),
        "binary_sha256": _sha("4"),
        "binary_size": 4096,
        "fresh_builds": 2,
        "binary_sha256_equal": True,
    }
    profile = {
        key: values[key]
        for key in (
            "profile_id",
            "profile_version",
            "mode",
            "processor",
            "bitness",
            "data_endian",
            "instruction_endian",
            "format_id",
            "platform_tag",
        )
    }
    abi = {
        key: values[key]
        for key in (
            "abi_id",
            "target_triple",
            "source_sha256",
            "build_manifest_sha256",
            "command_sha256",
            "binary_sha256",
            "fresh_builds",
            "binary_sha256_equal",
        )
    }
    return FixtureEvidence(
        **values,
        profile_evidence_digest=digest(profile),
        abi_evidence_digest=digest(abi),
    )


def _instruction(
    rva: int,
    *,
    size: int = 2,
    is_macro: bool = False,
    operands: tuple[OperandCapture, ...] = (),
) -> InstructionCapture:
    return InstructionCapture(
        rva,
        size,
        "00" * size,
        10 + rva,
        True,
        is_macro,
        0x100,
        0,
        0,
        0,
        0,
        operands,
    )


def _function(ordinal: int, *, rva: int | None = None) -> FunctionCapture:
    fixture = _fixture()
    rva = 0x100 + ordinal * 0x10 if rva is None else rva
    instruction = _instruction(rva)
    return FunctionCapture(
        ordinal,
        function_stable_key(
            binary_sha256=fixture.binary_sha256,
            source_sha256=fixture.source_sha256,
            command_sha256=fixture.command_sha256,
            function_rva=rva,
        ),
        rva,
        (AddressRange(rva, rva + instruction.size),),
        (BlockCapture(0, rva, rva + instruction.size, (), (), (instruction,)),),
    )


def _bundle() -> CaptureBundle:
    registers = (RegisterMetadata(0, "zero"), RegisterMetadata(1, "ra"))
    adapter = ProcessorAdapterIdentity(
        "riscv",
        15,
        1,
        0,
        8,
        8,
        _sha("5"),
        registers,
        digest({"registers": [item.to_data() for item in registers]}),
    )
    return CaptureBundle(
        CAPTURE_SCHEMA,
        BACKEND_IDENTITY,
        _fixture(),
        parse_elf32_riscv_header(_elf_header()),
        "9.3",
        "3.11.15",
        adapter,
        _sha("6"),
        0x10000,
        tuple(_function(index) for index in range(6)),
        (
            CaptureDiagnostic(
                "capture_only_unverified",
                "No lowering, SSA, or support claim",
                "information",
            ),
        ),
        CaptureBudgets(),
    )


def test_phase_zero_capture_does_not_promote_rv32_analysis_support():
    profile = REGISTRY.get("RV32-LE")
    assert profile.receipt_status == "unverified"
    assert profile.maturity is None
    assert profile.normal_status == "unverified"
    assert profile.fallback_status == "unverified"
    assert profile.measured_receipt is None
    assert profile.format_ids == ()
    with pytest.raises(ContractError, match="Unmeasured extraction profile"):
        REGISTRY.measured_extraction_profile("RV32-LE")

    inventory = json.loads(INVENTORY.read_text())
    row = next(
        item for item in inventory["profiles"] if item["profile_id"] == "RV32-LE"
    )
    assert row["normal_status"] == "unverified"
    assert row["fallback_status"] == "unverified"
    assert row["maturity"] is None


def test_normal_microcode_failure_remains_separate_unverified_evidence():
    receipt = json.loads(
        (RV32_EVIDENCE / "normal_microcode_unavailable.json").read_text()
    )
    assert receipt["schema_version"] == "flow-p0-probe/2"
    assert receipt["request"]["profile"] == {
        "profile_id": "RV32-LE",
        "profile_version": 1,
        "processor": "riscv",
        "bits": 32,
        "data_endian": "LE",
        "instruction_endian": "LE",
        "mode": "RV32",
        "abi_id": "riscv-ilp32",
    }
    assert receipt["probe_status"] == "failed"
    assert receipt["support_status"] == "unverified"
    assert receipt["target_executed"] is False
    assert [
        (probe["maturity"], probe["status"], probe["failure_code"], probe["repeat_equal"])
        for probe in receipt["probes"]
    ] == [
        ("MMAT_CALLS", "failed", -23, True),
        ("MMAT_GLBOPT3", "failed", -23, True),
    ]
    expected = digest(
        {key: value for key, value in receipt.items() if key != "receipt_digest"}
    )
    assert expected == "sha256-v1:" + receipt["receipt_digest"]


def test_backend_identity_is_capture_only_and_cannot_forge_microcode_identity():
    value = BACKEND_IDENTITY.to_data()
    assert value == {
        "backend_id": "ida-disasm-rv32",
        "backend_version": 1,
        "extraction_stage": "structured-disassembly",
        "maturity": None,
        "capture_schema": CAPTURE_SCHEMA,
        "decoder_rule_digest": value["decoder_rule_digest"],
        "abi_rule_digest": value["abi_rule_digest"],
    }
    assert all(
        forbidden not in canonical_json(value).lower()
        for forbidden in ("hexrays", "mmat_", "snapshot", "ssa", "normalized_ir")
    )
    for key, forged in (
        ("backend_id", "microcode"),
        ("extraction_stage", "MMAT_CALLS"),
        ("maturity", "MMAT_CALLS"),
        ("capture_schema", "flow-snapshot/1"),
    ):
        with pytest.raises(ContractError):
            BackendIdentity.from_data({**value, key: forged})
    with pytest.raises(ContractError, match="Wrong fields"):
        BackendIdentity.from_data({**value, "hexrays_version": "9.3"})


@pytest.mark.parametrize(
    ("offset", "replacement", "message"),
    [
        (0, b"NOPE", "Not an ELF"),
        (4, b"\x02", "ELFCLASS32"),
        (5, b"\x02", "ELFDATA2LSB"),
        (6, b"\x02", "identification version"),
        (18, struct.pack("<H", 62), "EM_RISCV"),
        (36, struct.pack("<I", 2), "soft-float"),
        (36, struct.pack("<I", 9), "RVE"),
        (36, struct.pack("<I", 0), "flags drift"),
    ],
)
def test_exact_elf32_riscv_identity_rejects_near_misses(offset, replacement, message):
    header = bytearray(_elf_header())
    header[offset : offset + len(replacement)] = replacement
    with pytest.raises(ContractError, match=message):
        parse_elf32_riscv_header(bytes(header))


def test_exact_elf32_riscv_identity_is_strict_and_roundtrips():
    identity = parse_elf32_riscv_header(_elf_header())
    assert identity == ElfIdentity.from_json(canonical_json(identity))
    assert identity.machine == 243
    assert identity.flags == 1
    assert identity.float_abi == "soft"
    assert identity.rve is False
    assert identity.rvc is True
    assert identity.header_digest == digest({"elf32_header_hex": _elf_header().hex()})


def test_capture_contract_roundtrip_separates_in_session_and_fresh_process_evidence():
    capture = _bundle()
    assert CaptureBundle.from_json(canonical_json(capture)) == capture
    capture_digest = digest(capture)
    process = ProcessReceipt(
        PROCESS_SCHEMA,
        capture,
        capture_digest,
        capture_digest,
        True,
        True,
    )
    assert ProcessReceipt.from_json(canonical_json(process)) == process
    process_digest = digest(process)
    runs = tuple(
        FreshProcessEvidence(
            run_id,
            f"{run_id}/process-receipt.json",
            process_digest,
            capture_digest,
            True,
            True,
        )
        for run_id in ("fresh-1", "fresh-2")
    )
    receipt = cast(
        CaptureReceipt,
        CaptureReceipt.from_data(
            {
                "schema_version": RECEIPT_SCHEMA,
                "backend": BACKEND_IDENTITY.to_data(),
                "binary_sha256": capture.fixture.binary_sha256,
                "entry_script_sha256": _sha("7"),
                "recorder_script_sha256": _sha("8"),
                "ida_executable_sha256": _sha("9"),
                "runs": [run.to_data() for run in runs],
                "fresh_process_repeat_equal": True,
                "input_preserved": True,
                "target_executed": False,
                "support_status": "unverified",
            }
        ),
    )
    assert CaptureReceipt.from_json(canonical_json(receipt)) == receipt
    assert receipt.target_executed is False
    assert receipt.support_status == "unverified"

    with pytest.raises(ContractError, match="ordered fresh processes"):
        replace(receipt, runs=tuple(reversed(runs)))
    with pytest.raises(ContractError, match="semantic capture drift"):
        replace(
            receipt,
            runs=(runs[0], replace(runs[1], capture_digest=_sha("6"))),
        )


def test_capture_models_reject_support_promotion_and_schema_extension():
    capture = _bundle()
    for model, data in (
        (CaptureBundle, capture.to_data()),
        (
            ProcessReceipt,
            ProcessReceipt(
                PROCESS_SCHEMA,
                capture,
                digest(capture),
                digest(capture),
                True,
                True,
            ).to_data(),
        ),
    ):
        with pytest.raises(ContractError):
            model.from_data({**data, "support_status": "available"})
        with pytest.raises(ContractError, match="Wrong fields"):
            model.from_data({**data, "lowered_snapshot": {}})


def test_typed_operands_and_macro_items_preserve_raw_structured_fields():
    operand = OperandCapture(
        0,
        7,
        2,
        1,
        0,
        0,
        0x11258,
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
    )
    instruction = _instruction(0x210, size=8, is_macro=True, operands=(operand,))
    assert instruction.size == 8
    assert instruction.is_macro is True
    assert instruction.is_canon is True
    assert instruction.canonical_feature_bits == 0x100
    assert InstructionCapture.from_json(canonical_json(instruction)) == instruction
    assert instruction.operands[0].to_data() == {
        "index": 0,
        "operand_type": 7,
        "dtype": 2,
        "reg": 1,
        "phrase": 0,
        "value": 0,
        "addr": 0x11258,
        "specval": 0,
        "specflag1": 1,
        "specflag2": 2,
        "specflag3": 3,
        "specflag4": 4,
        "flags": 5,
        "offb": 6,
        "offo": 7,
    }
    with pytest.raises(ContractError, match="dense and ordered"):
        replace(instruction, operands=(replace(operand, index=1),))
    with pytest.raises(ContractError, match="decoded instruction size"):
        replace(instruction, size=6, raw_bytes="00" * 6)
    with pytest.raises(ContractError, match="lowercase hex"):
        replace(instruction, raw_bytes="AA" * 8)
    with pytest.raises(ContractError, match="Canonical feature presence mismatch"):
        replace(instruction, is_canon=False)


def test_block_and_function_contracts_reject_cfg_and_decode_corruption():
    first = _instruction(0x100)
    second = _instruction(0x102)
    with pytest.raises(ContractError, match="gap or overlap"):
        BlockCapture(0, 0x100, 0x105, (), (), (first, replace(second, rva=0x103)))
    with pytest.raises(ContractError, match="sorted and unique"):
        BlockCapture(0, 0x100, 0x102, (), (1, 1), (first,))

    fixture = _fixture()
    stable_key = function_stable_key(
        binary_sha256=fixture.binary_sha256,
        source_sha256=fixture.source_sha256,
        command_sha256=fixture.command_sha256,
        function_rva=0x100,
    )
    block = BlockCapture(0, 0x100, 0x102, (), (1,), (first,))
    with pytest.raises(ContractError, match="Dangling CFG edge"):
        FunctionCapture(
            0,
            stable_key,
            0x100,
            (AddressRange(0x100, 0x102),),
            (block,),
        )

    successor = BlockCapture(1, 0x102, 0x104, (), (), (second,))
    with pytest.raises(ContractError, match="Asymmetric CFG successor"):
        FunctionCapture(
            0,
            stable_key,
            0x100,
            (AddressRange(0x100, 0x104),),
            (block, successor),
        )

    symmetric = replace(successor, predecessors=(0,))
    function = FunctionCapture(
        0,
        stable_key,
        0x100,
        (AddressRange(0x100, 0x104),),
        (block, symmetric),
    )
    assert function.blocks[0].successors == (1,)
    with pytest.raises(ContractError, match="overlap"):
        replace(
            function,
            chunks=(AddressRange(0x100, 0x103), AddressRange(0x102, 0x104)),
        )


def test_capture_bundle_rejects_drift_nondeterminism_and_budget_exhaustion():
    bundle = _bundle()
    with pytest.raises(ContractError, match="all six fixture functions"):
        replace(bundle, functions=bundle.functions[:-1])
    with pytest.raises(ContractError, match="RVA order"):
        replace(
            bundle,
            functions=(
                _function(0, rva=0x110),
                _function(1, rva=0x100),
                *bundle.functions[2:],
            ),
        )
    with pytest.raises(ContractError, match="stable-key drift"):
        replace(
            bundle,
            functions=(
                replace(bundle.functions[0], stable_key="rv32-function-v1:" + "0" * 64),
                *bundle.functions[1:],
            ),
        )
    with pytest.raises(ContractError, match="deterministically ordered"):
        replace(
            bundle,
            diagnostics=(
                CaptureDiagnostic("z", "last", "opaque"),
                CaptureDiagnostic("a", "first", "opaque"),
            ),
        )
    with pytest.raises(ContractError, match="Instruction budget exceeded"):
        replace(bundle, budgets=replace(bundle.budgets, max_instructions=1))


def test_function_stable_key_is_not_a_display_name_identity():
    fixture = _fixture()
    values = {
        "binary_sha256": fixture.binary_sha256,
        "source_sha256": fixture.source_sha256,
        "command_sha256": fixture.command_sha256,
        "function_rva": 0x100,
    }
    baseline = function_stable_key(**values)
    assert baseline.startswith("rv32-function-v1:")
    for key, replacement_value in (
        ("binary_sha256", _sha("a")),
        ("source_sha256", _sha("b")),
        ("command_sha256", _sha("c")),
        ("function_rva", 0x102),
    ):
        assert function_stable_key(**{**values, key: replacement_value}) != baseline


def test_actual_two_process_receipts_are_current_separate_and_nonexecuting():
    request = cast(
        CaptureRequest,
        CaptureRequest.from_json((RV32_EVIDENCE / "request.json").read_text()),
    )
    receipt = cast(
        CaptureReceipt,
        CaptureReceipt.from_json((RV32_EVIDENCE / "receipt.json").read_text()),
    )
    processes = tuple(
        cast(
            ProcessReceipt,
            ProcessReceipt.from_json(
                (RV32_EVIDENCE / run_id / "process-receipt.json").read_text()
            ),
        )
        for run_id in ("fresh-1", "fresh-2")
    )
    implementation_files = (
        Path("src/ida_pro_mcp/flow_core/rv32_capture.py"),
        Path("src/ida_pro_mcp/ida_mcp/flow/rv32_extractor.py"),
    )
    expected_implementation_digest = digest(
        {
            str(path): "sha256-v1:"
            + hashlib.sha256((PRODUCT_ROOT / path).read_bytes()).hexdigest()
            for path in implementation_files
        }
    )
    assert request.implementation_digest == expected_implementation_digest
    assert receipt.backend == request.backend == BACKEND_IDENTITY
    assert receipt.binary_sha256 == request.fixture.binary_sha256
    assert receipt.fresh_process_repeat_equal is True
    assert receipt.input_preserved is True
    assert receipt.target_executed is False
    assert receipt.support_status == "unverified"
    assert getattr(receipt, "entry_script_sha256") == (
        "sha256-v1:"
        + hashlib.sha256(
            (PRODUCT_ROOT / "scripts/flow_rv32_capture.py").read_bytes()
        ).hexdigest()
    )
    assert getattr(receipt, "recorder_script_sha256") == (
        "sha256-v1:"
        + hashlib.sha256(
            (PRODUCT_ROOT / "scripts/record_flow_rv32_capture.py").read_bytes()
        ).hexdigest()
    )
    idat = Path("/Applications/IDA Professional 9.3.app/Contents/MacOS/idat")
    assert getattr(receipt, "ida_executable_sha256") == (
        "sha256-v1:044e7d28a17ecaacaeb4e7d78147c11c7faaba79c6eec657f7924ec3d22a0380"
    )
    if idat.is_file():
        assert getattr(receipt, "ida_executable_sha256") == (
            "sha256-v1:" + hashlib.sha256(idat.read_bytes()).hexdigest()
        )
    assert canonical_json(processes[0].capture) == canonical_json(processes[1].capture)
    assert processes[0].capture_digest == processes[1].capture_digest
    assert processes[0].capture_digest == (
        "sha256-v1:32268d0833ca8f4b235d289f99c301ee9e7313ccde9e05d6ffe0244a91514d27"
    )
    for run, process in zip(receipt.runs, processes):
        assert run.process_receipt_digest == digest(process)
        assert run.capture_digest == process.capture_digest == digest(process.capture)
        assert run.in_session_repeat_equal is True
        assert run.json_roundtrip_equal is True
        assert process.in_session_repeat_equal is True
        assert process.json_roundtrip_equal is True
        assert process.target_executed is False
        assert process.support_status == "unverified"
        assert process.capture.fixture == request.fixture
        assert process.capture.implementation_digest == request.implementation_digest
        assert process.capture.processor_adapter.module_sha256 == (
            "sha256-v1:13b153cd2e9152f84a8a622fb75d83f62598fad00c493fb33c315fdb4904e076"
        )
        invocation = json.loads(
            (RV32_EVIDENCE / run.run_id / "invocation.json").read_text()
        )
        assert invocation == {
            "executable": "idat",
            "flags": ["-c", "-A", "-S<fixed-script-and-contract>"],
            "gui": False,
            "returncode": 0,
            "schema_version": "flow-rv32-static-invocation/1",
            "shell": False,
            "target_executed": False,
        }


def test_actual_receipt_pins_observed_macro_compressed_branch_and_operand_layouts():
    process = cast(
        ProcessReceipt,
        ProcessReceipt.from_json(
            (RV32_EVIDENCE / "fresh-1/process-receipt.json").read_text()
        ),
    )
    functions = process.capture.functions
    instructions = tuple(
        instruction
        for function in functions
        for block in function.blocks
        for instruction in block.instructions
    )
    assert [
        sum(len(block.instructions) for block in function.blocks)
        for function in functions
    ] == [15, 22, 11, 13, 12, 25]
    assert any(instruction.size == 2 for instruction in instructions)
    assert {instruction.size for instruction in instructions} == {2, 4, 8}
    li = next(instruction for instruction in instructions if instruction.rva == 0x1272)
    assert (
        li.size,
        li.itype,
        li.is_canon,
        li.is_macro,
        li.canonical_feature_bits,
    ) == (8, 122, True, True, 0x204)
    assert [
        (operand.operand_type, operand.dtype, operand.reg, operand.value, operand.addr)
        for operand in li.operands
    ] == [(1, 2, 11, 0, 0), (5, 2, 0, 20281789, 0)]
    call = next(instruction for instruction in instructions if instruction.rva == 0x1310)
    assert (
        call.size,
        call.itype,
        call.is_canon,
        call.is_macro,
        call.canonical_feature_bits,
    ) == (8, 163, True, True, 0x206)
    assert [
        (operand.operand_type, operand.dtype, operand.reg, operand.value, operand.addr)
        for operand in call.operands
    ] == [(1, 2, 1, 0, 0), (7, 2, 0, 0, 70232)]
    branch = next(
        instruction for instruction in instructions if instruction.rva == 0x1298
    )
    assert (
        branch.size,
        branch.itype,
        branch.is_canon,
        branch.is_macro,
        branch.canonical_feature_bits,
    ) == (2, 134, True, False, 0x300)
    assert [
        (operand.operand_type, operand.reg, operand.addr)
        for operand in branch.operands
    ] == [(1, 10, 0), (7, 0, 70312)]
    operand_fields = {
        "index",
        "operand_type",
        "dtype",
        "reg",
        "phrase",
        "value",
        "addr",
        "specval",
        "specflag1",
        "specflag2",
        "specflag3",
        "specflag4",
        "flags",
        "offb",
        "offo",
    }
    assert all(set(operand.to_data()) == operand_fields for item in instructions for operand in item.operands)
    assert all(
        not ({"mnemonic", "disassembly", "text"} & set(instruction.to_data()))
        for instruction in instructions
    )
    assert process.capture.diagnostics == (
        CaptureDiagnostic(
            "capture_only_unverified",
            "Structured decoder evidence only; no RV32 lowering, SSA, or support claim",
            "information",
        ),
    )
