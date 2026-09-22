"""Strict Phase-0 contracts for the RV32 structured-disassembly backend.

These models deliberately do not extend the microcode snapshot schema.  They
record decoder evidence only: no lowering, SSA, capability promotion, or
semantic dispatch on rendered assembly is represented here.
"""

from dataclasses import dataclass
import re
import struct
from typing import Literal

from .serialization import Model, canonical_json, digest
from .states import check_digest, nonempty, require

CAPTURE_SCHEMA = "flow-rv32-disassembly-capture/1"
PROCESS_SCHEMA = "flow-rv32-disassembly-process/1"
RECEIPT_SCHEMA = "flow-rv32-fallback-receipt/1"
REQUEST_SCHEMA = "flow-rv32-disassembly-request/1"

DECODER_RULES = {
    "version": 1,
    "source": "ida-ua-structured-fields",
    "advance": "decode-insn-returned-size",
    "allowed_sizes": [2, 4, 8],
    "display_text_semantics": False,
    "unsupported": "opaque-or-reject-control-effect-risk",
    "cfg": "flowchart-fc-noext-dense-rva-remap",
}
ABI_RULES = {
    "version": 1,
    "profile": "RV32-LE",
    "abi": "riscv-ilp32",
    "float_abi": "soft",
    "rve": False,
    "proof": "pinned-reproducible-build-and-elf-header",
}


def _sha256(value: str) -> None:
    check_digest(value)


def _hex_bytes(value: str, size: int) -> None:
    require(
        len(value) == size * 2 and re.fullmatch(r"[0-9a-f]*", value) is not None,
        "Instruction bytes must be lowercase hex of the decoded size",
    )


def function_stable_key(
    *, binary_sha256: str, source_sha256: str, command_sha256: str, function_rva: int
) -> str:
    """Bind fixture function identity to bytes/build/RVA, never a display name."""
    value = digest(
        {
            "domain": "rv32-fixture-function",
            "binary_sha256": binary_sha256,
            "source_sha256": source_sha256,
            "command_sha256": command_sha256,
            "function_rva": function_rva,
        }
    )
    return "rv32-function-v1:" + value.split(":", 1)[1]


@dataclass(frozen=True)
class BackendIdentity(Model):
    backend_id: Literal["ida-disasm-rv32"] = "ida-disasm-rv32"
    backend_version: Literal[1] = 1
    extraction_stage: Literal["structured-disassembly"] = "structured-disassembly"
    maturity: None = None
    capture_schema: Literal["flow-rv32-disassembly-capture/1"] = CAPTURE_SCHEMA
    decoder_rule_digest: str = digest(DECODER_RULES)
    abi_rule_digest: str = digest(ABI_RULES)

    def __post_init__(self):
        super().__post_init__()
        require(
            self.decoder_rule_digest == digest(DECODER_RULES),
            "Unknown RV32 decoder rules",
        )
        require(self.abi_rule_digest == digest(ABI_RULES), "Unknown RV32 ABI rules")


@dataclass(frozen=True)
class CaptureBudgets(Model):
    max_functions: int = 6
    max_blocks: int = 64
    max_instructions: int = 512
    max_operands: int = 2048
    max_instruction_bytes: int = 65536
    max_diagnostics: int = 256
    max_output_bytes: int = 2_000_000
    deadline_millis: int = 30_000

    def __post_init__(self):
        super().__post_init__()
        require(
            all(
                type(value) is int and value > 0
                for value in (
                    self.max_functions,
                    self.max_blocks,
                    self.max_instructions,
                    self.max_operands,
                    self.max_instruction_bytes,
                    self.max_diagnostics,
                    self.max_output_bytes,
                    self.deadline_millis,
                )
            ),
            "Capture budgets must be positive integers",
        )
        require(self.max_functions == 6, "The Phase-0 fixture captures six functions")


@dataclass(frozen=True)
class FixtureEvidence(Model):
    profile_id: Literal["RV32-LE"]
    profile_version: Literal[1]
    mode: Literal["RV32"]
    processor: Literal["riscv"]
    bitness: Literal[32]
    data_endian: Literal["LE"]
    instruction_endian: Literal["LE"]
    format_id: Literal["FMT-ELF"]
    abi_id: Literal["riscv-ilp32"]
    target_triple: Literal["riscv32-linux-gnu"]
    platform_tag: Literal["linux"]
    source_sha256: str
    build_manifest_sha256: str
    command_sha256: str
    binary_sha256: str
    binary_size: int
    fresh_builds: Literal[2]
    binary_sha256_equal: Literal[True]
    profile_evidence_digest: str
    abi_evidence_digest: str
    target_executed: Literal[False] = False
    support_status: Literal["unverified"] = "unverified"

    def __post_init__(self):
        super().__post_init__()
        for value in (
            self.source_sha256,
            self.build_manifest_sha256,
            self.command_sha256,
            self.binary_sha256,
            self.profile_evidence_digest,
            self.abi_evidence_digest,
        ):
            _sha256(value)
        require(self.binary_size > 0, "Fixture binary must be nonempty")
        profile = {
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "mode": self.mode,
            "processor": self.processor,
            "bitness": self.bitness,
            "data_endian": self.data_endian,
            "instruction_endian": self.instruction_endian,
            "format_id": self.format_id,
            "platform_tag": self.platform_tag,
        }
        abi = {
            "abi_id": self.abi_id,
            "target_triple": self.target_triple,
            "source_sha256": self.source_sha256,
            "build_manifest_sha256": self.build_manifest_sha256,
            "command_sha256": self.command_sha256,
            "binary_sha256": self.binary_sha256,
            "fresh_builds": self.fresh_builds,
            "binary_sha256_equal": self.binary_sha256_equal,
        }
        require(
            self.profile_evidence_digest == digest(profile), "Profile evidence drift"
        )
        require(self.abi_evidence_digest == digest(abi), "ABI evidence drift")


@dataclass(frozen=True)
class FunctionSelector(Model):
    ordinal: int
    symbol: str
    expected_rva: int

    def __post_init__(self):
        super().__post_init__()
        require(0 <= self.ordinal < 6, "Invalid fixture function ordinal")
        nonempty(self.symbol)
        require(self.expected_rva >= 0, "Invalid expected function RVA")


@dataclass(frozen=True)
class CaptureRequest(Model):
    schema_version: Literal["flow-rv32-disassembly-request/1"]
    backend: BackendIdentity
    fixture: FixtureEvidence
    functions: tuple[FunctionSelector, ...]
    budgets: CaptureBudgets
    expected_ida_kernel_version: Literal["9.3"]
    processor_adapter_sha256: str
    implementation_digest: str

    def __post_init__(self):
        super().__post_init__()
        _sha256(self.processor_adapter_sha256)
        _sha256(self.implementation_digest)
        require(
            tuple(selector.ordinal for selector in self.functions) == tuple(range(6)),
            "Fixture selectors must be in exact ordinal order",
        )
        require(
            len({selector.symbol for selector in self.functions}) == 6,
            "Fixture selectors must be unique",
        )


@dataclass(frozen=True)
class ElfIdentity(Model):
    elf_class: Literal[1]
    elf_data: Literal[1]
    osabi: int
    abi_version: int
    machine: Literal[243]
    flags: Literal[1]
    float_abi: Literal["soft"]
    rve: Literal[False]
    rvc: Literal[True]
    header_digest: str

    def __post_init__(self):
        super().__post_init__()
        require(0 <= self.osabi <= 255, "Invalid ELF OSABI")
        require(0 <= self.abi_version <= 255, "Invalid ELF ABI version")
        _sha256(self.header_digest)


def parse_elf32_riscv_header(data: bytes) -> ElfIdentity:
    """Validate the pinned ELF32 little-endian soft-float non-RVE boundary."""
    require(type(data) is bytes and len(data) >= 52, "Truncated ELF32 header")
    require(data[:4] == b"\x7fELF", "Not an ELF input")
    require(data[4] == 1, "Expected ELFCLASS32")
    require(data[5] == 1, "Expected ELFDATA2LSB")
    require(data[6] == 1, "Unsupported ELF identification version")
    machine = struct.unpack_from("<H", data, 18)[0]
    flags = struct.unpack_from("<I", data, 36)[0]
    require(machine == 243, "Expected EM_RISCV")
    require(flags & 0x6 == 0, "Expected RISC-V soft-float ABI")
    require(flags & 0x8 == 0, "RVE ABI is outside the reviewed ILP32 boundary")
    require(flags == 1, "Pinned fixture ELF flags drift")
    return ElfIdentity(
        1,
        1,
        data[7],
        data[8],
        243,
        1,
        "soft",
        False,
        True,
        digest({"elf32_header_hex": data[:52].hex()}),
    )


@dataclass(frozen=True)
class RegisterMetadata(Model):
    register_id: int
    name: str

    def __post_init__(self):
        super().__post_init__()
        require(self.register_id >= 0, "Negative register identifier")
        nonempty(self.name)


@dataclass(frozen=True)
class ProcessorAdapterIdentity(Model):
    processor: Literal["riscv"]
    module_id: int
    module_version: int
    module_flags: int
    code_bits: int
    data_bits: int
    module_sha256: str
    registers: tuple[RegisterMetadata, ...]
    registers_digest: str

    def __post_init__(self):
        super().__post_init__()
        require(self.module_id >= 0, "Invalid processor module identifier")
        require(self.module_version >= 0, "Invalid processor module version")
        require(
            self.code_bits == 8 and self.data_bits == 8, "Unexpected RISC-V byte widths"
        )
        _sha256(self.module_sha256)
        require(
            tuple(register.register_id for register in self.registers)
            == tuple(range(len(self.registers))),
            "Register metadata must be dense and ordered",
        )
        require(
            self.registers_digest
            == digest({"registers": [item.to_data() for item in self.registers]}),
            "Processor register metadata drift",
        )


@dataclass(frozen=True)
class OperandCapture(Model):
    index: int
    operand_type: int
    dtype: int
    reg: int
    phrase: int
    value: int
    addr: int
    specval: int
    specflag1: int
    specflag2: int
    specflag3: int
    specflag4: int
    flags: int
    offb: int
    offo: int

    def __post_init__(self):
        super().__post_init__()
        require(0 <= self.index < 8, "Invalid operand index")
        require(
            all(
                type(value) is int and value >= 0
                for value in (
                    self.operand_type,
                    self.dtype,
                    self.reg,
                    self.phrase,
                    self.value,
                    self.addr,
                    self.specval,
                    self.specflag1,
                    self.specflag2,
                    self.specflag3,
                    self.specflag4,
                    self.flags,
                    self.offb,
                    self.offo,
                )
            ),
            "Operand fields must be nonnegative structured integers",
        )


@dataclass(frozen=True)
class InstructionCapture(Model):
    rva: int
    size: int
    raw_bytes: str
    itype: int
    is_canon: bool
    is_macro: bool
    canonical_feature_bits: int | None
    auxpref: int
    segpref: int
    insnpref: int
    flags: int
    operands: tuple[OperandCapture, ...]

    def __post_init__(self):
        super().__post_init__()
        require(self.rva >= 0, "Negative instruction RVA")
        require(self.size in (2, 4, 8), "Unsupported decoded instruction size")
        _hex_bytes(self.raw_bytes, self.size)
        require(self.itype >= 0, "Negative instruction type")
        require(
            self.canonical_feature_bits is None or self.canonical_feature_bits >= 0,
            "Negative canonical feature bits",
        )
        require(
            self.is_canon == (self.canonical_feature_bits is not None),
            "Canonical feature presence mismatch",
        )
        require(
            tuple(operand.index for operand in self.operands)
            == tuple(range(len(self.operands))),
            "Operands must be dense and ordered",
        )


@dataclass(frozen=True)
class AddressRange(Model):
    start_rva: int
    end_rva: int

    def __post_init__(self):
        super().__post_init__()
        require(0 <= self.start_rva < self.end_rva, "Invalid RVA range")


@dataclass(frozen=True)
class BlockCapture(Model):
    index: int
    start_rva: int
    end_rva: int
    predecessors: tuple[int, ...]
    successors: tuple[int, ...]
    instructions: tuple[InstructionCapture, ...]

    def __post_init__(self):
        super().__post_init__()
        require(self.index >= 0, "Negative block index")
        require(0 <= self.start_rva < self.end_rva, "Invalid block range")
        for edges in (self.predecessors, self.successors):
            require(
                edges == tuple(sorted(set(edges))),
                "CFG edges must be sorted and unique",
            )
            require(all(edge >= 0 for edge in edges), "Negative CFG edge")
        require(bool(self.instructions), "Empty flow-chart block")
        require(
            self.instructions[0].rva == self.start_rva, "Block decode starts with a gap"
        )
        for before, after in zip(self.instructions, self.instructions[1:]):
            require(
                before.rva + before.size == after.rva, "Block decode has gap or overlap"
            )
        last = self.instructions[-1]
        require(
            last.rva + last.size == self.end_rva,
            "Block decode does not cover its range",
        )


@dataclass(frozen=True)
class FunctionCapture(Model):
    selector_ordinal: int
    stable_key: str
    function_rva: int
    chunks: tuple[AddressRange, ...]
    blocks: tuple[BlockCapture, ...]

    def __post_init__(self):
        super().__post_init__()
        require(0 <= self.selector_ordinal < 6, "Invalid function selector ordinal")
        require(
            re.fullmatch(r"rv32-function-v1:[0-9a-f]{64}", self.stable_key) is not None,
            "Invalid RV32 function stable key",
        )
        require(self.function_rva >= 0, "Negative function RVA")
        require(
            bool(self.chunks) and self.chunks[0].start_rva == self.function_rva,
            "Function entry/chunk mismatch",
        )
        require(
            self.chunks == tuple(sorted(self.chunks, key=lambda item: item.start_rva)),
            "Function chunks must be ordered",
        )
        for before, after in zip(self.chunks, self.chunks[1:]):
            require(before.end_rva <= after.start_rva, "Function chunks overlap")
        require(
            tuple(block.index for block in self.blocks)
            == tuple(range(len(self.blocks))),
            "Blocks must use a dense deterministic index",
        )
        require(
            self.blocks == tuple(sorted(self.blocks, key=lambda item: item.start_rva)),
            "Blocks must be ordered by RVA",
        )
        block_ids = set(range(len(self.blocks)))
        for block in self.blocks:
            require(
                set(block.predecessors) <= block_ids
                and set(block.successors) <= block_ids,
                "Dangling CFG edge",
            )
            require(
                any(
                    chunk.start_rva <= block.start_rva
                    and block.end_rva <= chunk.end_rva
                    for chunk in self.chunks
                ),
                "Block lies outside function chunks",
            )
            for successor in block.successors:
                require(
                    block.index in self.blocks[successor].predecessors,
                    "Asymmetric CFG successor",
                )
            for predecessor in block.predecessors:
                require(
                    block.index in self.blocks[predecessor].successors,
                    "Asymmetric CFG predecessor",
                )
        boundaries = {
            instruction.rva
            for block in self.blocks
            for instruction in block.instructions
        }
        require(
            all(block.start_rva in boundaries for block in self.blocks),
            "CFG target enters the interior of a decoded item",
        )
        block_ranges = tuple(
            AddressRange(block.start_rva, block.end_rva) for block in self.blocks
        )
        merged: list[AddressRange] = []
        for item in block_ranges:
            if merged and merged[-1].end_rva == item.start_rva:
                merged[-1] = AddressRange(merged[-1].start_rva, item.end_rva)
            else:
                merged.append(item)
        require(
            tuple(merged) == self.chunks, "Blocks do not exactly cover function chunks"
        )


@dataclass(frozen=True)
class CaptureDiagnostic(Model):
    code: str
    detail: str
    severity: Literal["information", "opaque"]

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.code)
        nonempty(self.detail)


@dataclass(frozen=True)
class CaptureBundle(Model):
    schema_version: Literal["flow-rv32-disassembly-capture/1"]
    backend: BackendIdentity
    fixture: FixtureEvidence
    elf: ElfIdentity
    ida_kernel_version: str
    python_version: str
    processor_adapter: ProcessorAdapterIdentity
    implementation_digest: str
    image_base: int
    functions: tuple[FunctionCapture, ...]
    diagnostics: tuple[CaptureDiagnostic, ...]
    budgets: CaptureBudgets
    target_executed: Literal[False] = False
    support_status: Literal["unverified"] = "unverified"

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.ida_kernel_version)
        nonempty(self.python_version)
        _sha256(self.implementation_digest)
        require(self.image_base >= 0, "Negative image base")
        require(
            tuple(function.selector_ordinal for function in self.functions)
            == tuple(range(6)),
            "Capture must contain all six fixture functions",
        )
        require(
            self.functions
            == tuple(sorted(self.functions, key=lambda item: item.function_rva)),
            "Functions must be in deterministic RVA order",
        )
        for function in self.functions:
            expected = function_stable_key(
                binary_sha256=self.fixture.binary_sha256,
                source_sha256=self.fixture.source_sha256,
                command_sha256=self.fixture.command_sha256,
                function_rva=function.function_rva,
            )
            require(function.stable_key == expected, "Function stable-key drift")
        require(
            self.diagnostics
            == tuple(
                sorted(self.diagnostics, key=lambda item: (item.code, item.detail))
            ),
            "Diagnostics must be deterministically ordered",
        )
        blocks = sum(len(function.blocks) for function in self.functions)
        instructions = sum(
            len(block.instructions)
            for function in self.functions
            for block in function.blocks
        )
        operands = sum(
            len(instruction.operands)
            for function in self.functions
            for block in function.blocks
            for instruction in block.instructions
        )
        byte_count = sum(
            instruction.size
            for function in self.functions
            for block in function.blocks
            for instruction in block.instructions
        )
        require(blocks <= self.budgets.max_blocks, "Block budget exceeded")
        require(
            instructions <= self.budgets.max_instructions, "Instruction budget exceeded"
        )
        require(operands <= self.budgets.max_operands, "Operand budget exceeded")
        require(
            byte_count <= self.budgets.max_instruction_bytes,
            "Instruction-byte budget exceeded",
        )
        require(
            len(self.diagnostics) <= self.budgets.max_diagnostics,
            "Diagnostic budget exceeded",
        )


@dataclass(frozen=True)
class ProcessReceipt(Model):
    schema_version: Literal["flow-rv32-disassembly-process/1"]
    capture: CaptureBundle
    capture_digest: str
    repeated_capture_digest: str
    in_session_repeat_equal: Literal[True]
    json_roundtrip_equal: Literal[True]
    target_executed: Literal[False] = False
    support_status: Literal["unverified"] = "unverified"

    def __post_init__(self):
        super().__post_init__()
        _sha256(self.capture_digest)
        _sha256(self.repeated_capture_digest)
        require(self.capture_digest == digest(self.capture), "Capture digest mismatch")
        require(
            self.repeated_capture_digest == self.capture_digest,
            "In-session capture drift",
        )
        require(
            CaptureBundle.from_json(canonical_json(self.capture)) == self.capture,
            "Capture JSON roundtrip mismatch",
        )


@dataclass(frozen=True)
class FreshProcessEvidence(Model):
    run_id: Literal["fresh-1", "fresh-2"]
    artifact: str
    process_receipt_digest: str
    capture_digest: str
    in_session_repeat_equal: Literal[True]
    json_roundtrip_equal: Literal[True]

    def __post_init__(self):
        super().__post_init__()
        require(
            self.artifact == self.run_id + "/process-receipt.json",
            "Fresh-process artifact path drift",
        )
        _sha256(self.process_receipt_digest)
        _sha256(self.capture_digest)


@dataclass(frozen=True)
class CaptureReceipt(Model):
    schema_version: Literal["flow-rv32-fallback-receipt/1"]
    backend: BackendIdentity
    binary_sha256: str
    entry_script_sha256: str
    recorder_script_sha256: str
    ida_executable_sha256: str
    runs: tuple[FreshProcessEvidence, ...]
    fresh_process_repeat_equal: Literal[True]
    input_preserved: Literal[True]
    target_executed: Literal[False] = False
    support_status: Literal["unverified"] = "unverified"

    def __post_init__(self):
        super().__post_init__()
        for value in (
            self.binary_sha256,
            self.entry_script_sha256,
            self.recorder_script_sha256,
            self.ida_executable_sha256,
        ):
            _sha256(value)
        require(
            tuple(run.run_id for run in self.runs) == ("fresh-1", "fresh-2"),
            "Receipt requires two ordered fresh processes",
        )
        require(
            len({run.capture_digest for run in self.runs}) == 1,
            "Fresh-process semantic capture drift",
        )


__all__ = [
    "ABI_RULES",
    "BACKEND_IDENTITY",
    "CAPTURE_SCHEMA",
    "DECODER_RULES",
    "PROCESS_SCHEMA",
    "RECEIPT_SCHEMA",
    "REQUEST_SCHEMA",
    "AddressRange",
    "BackendIdentity",
    "BlockCapture",
    "CaptureBudgets",
    "CaptureBundle",
    "CaptureDiagnostic",
    "CaptureReceipt",
    "CaptureRequest",
    "ElfIdentity",
    "FixtureEvidence",
    "FreshProcessEvidence",
    "FunctionCapture",
    "FunctionSelector",
    "InstructionCapture",
    "OperandCapture",
    "ProcessReceipt",
    "ProcessorAdapterIdentity",
    "RegisterMetadata",
    "function_stable_key",
    "parse_elf32_riscv_header",
]

BACKEND_IDENTITY = BackendIdentity()
