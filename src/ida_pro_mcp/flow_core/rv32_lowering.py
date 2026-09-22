"""Reviewed RV32 structured-disassembly lowering into shared flow contracts.

Only structured capture fields participate in dispatch.  Rendered assembly,
Hex-Rays state, and target execution are deliberately outside this module.
"""

from collections import deque
from dataclasses import dataclass
from typing import Literal, cast

from .contracts import (
    Block,
    CallInfo,
    Diagnostic,
    FunctionInput,
    Instruction,
    LocationSet,
    Operand,
    StructuredEnvironment,
    StructuredSnapshot,
    StructuredSnapshotIdentity,
)
from .rv32_capture import (
    CaptureBundle,
    FunctionCapture,
    InstructionCapture,
    OperandCapture,
)
from .serialization import ContractError, Model, digest
from .states import StorageLocation, nonempty, require


RV32_LOWERING_RULES = {
    "version": 1,
    "profile": "RV32-LE",
    "abi": "riscv-ilp32",
    "dispatch": "canonical-itype-feature-layout",
    "word_bits": 32,
    "frame": "bounded-entry-sp-affine-equality-join",
    "unknown": "opaque-data-reject-control-risk",
    "display_text_semantics": False,
}
RV32_LOWERING_RULE_DIGEST = digest(RV32_LOWERING_RULES)
RV32_EMPTY_SUMMARY_DIGEST = digest(
    {"version": 1, "profile": "RV32-LE", "summaries": []}
)


@dataclass(frozen=True)
class RV32LoweringPolicy(Model):
    max_blocks: int = 64
    max_instructions: int = 512
    max_diagnostics: int = 256
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        require(
            all(
                type(value) is int and value > 0
                for value in (
                    self.max_blocks,
                    self.max_instructions,
                    self.max_diagnostics,
                )
            ),
            "RV32 lowering budgets must be positive integers",
        )


DEFAULT_RV32_LOWERING_POLICY = RV32LoweringPolicy()


_REGISTER_NAMES = (
    "zero",
    "ra",
    "sp",
    "gp",
    "tp",
    "t0",
    "t1",
    "t2",
    "s0",
    "s1",
    "a0",
    "a1",
    "a2",
    "a3",
    "a4",
    "a5",
    "a6",
    "a7",
    "s2",
    "s3",
    "s4",
    "s5",
    "s6",
    "s7",
    "s8",
    "s9",
    "s10",
    "s11",
    "t3",
    "t4",
    "t5",
    "t6",
)

_FEATURES = {
    1: 0x204,  # lui
    13: 0x204,  # lw
    18: 0x108,  # sw
    19: 0x604,  # addi
    22: 0x604,  # xori
    28: 0x604,  # add
    33: 0x604,  # xor
    122: 0x204,  # li
    134: 0x300,  # beqz
    140: 0x101,  # j
    142: 0x001,  # ret
    163: 0x206,  # call
}
_SHAPES = {
    1: ((1, 2), (5, 2)),
    13: ((1, 2), (4, 2)),
    18: ((1, 2), (4, 2)),
    19: ((1, 2), (1, 2), (5, 2)),
    22: ((1, 2), (1, 2), (5, 2)),
    28: ((1, 2), (1, 2), (1, 2)),
    33: ((1, 2), (1, 2), (1, 2)),
    122: ((1, 2), (5, 2)),
    134: ((1, 2), (7, 0)),
    140: ((7, 0),),
    142: (),
    163: ((1, 2), (7, 2)),
}
_WIDTHS = {
    1: {(4, False)},
    13: {(2, False), (4, False)},
    18: {(2, False), (4, False)},
    19: {(2, False), (4, False)},
    22: {(4, False)},
    28: {(2, False), (4, False)},
    33: {(2, False), (4, False)},
    122: {(2, False), (8, True)},
    134: {(2, False)},
    140: {(2, False)},
    142: {(2, False)},
    163: {(8, True)},
}
_CONTROL_ITYPES = {134, 140, 142, 163}
_CONTROL_FEATURES = 0x1 | 0x2 | 0x800
_CALLER_SAVED = (1, 5, 6, 7, *range(10, 18), *range(28, 32))
_UNKNOWN = (None, None)
_OperandRole = Literal[
    "unspecified", "left", "right", "destination", "argument", "return"
]
_FIXTURE_ABI = {
    0: ((10, 11), (10,)),
    1: ((10, 11), (10,)),
    2: ((10,), (10,)),
    3: ((10, 11), ()),
    4: ((10,), (10,)),
    5: ((10, 11), (10,)),
}


def _word(value: int) -> int:
    """Accept canonical zero/sign extension and return the RV32 bit pattern."""
    require(0 <= value <= 0xFFFFFFFFFFFFFFFF, "RV32 scalar field exceeds 64 bits")
    word = value & 0xFFFFFFFF
    sign_extended = word | (0xFFFFFFFF00000000 if word & 0x80000000 else 0)
    require(value in {word, sign_extended}, "Non-canonical RV32 scalar extension")
    return word


def _signed(value: int) -> int:
    word = _word(value)
    return word - (1 << 32) if word & 0x80000000 else word


def _layout_error(instruction: InstructionCapture) -> str | None:
    expected_feature = _FEATURES.get(instruction.itype)
    if not instruction.is_canon or instruction.canonical_feature_bits is None:
        return "instruction is not canonical"
    if expected_feature is None:
        return "instruction itype is outside the reviewed table"
    if instruction.canonical_feature_bits != expected_feature:
        return "canonical feature bits do not match the reviewed table"
    if (instruction.size, instruction.is_macro) not in _WIDTHS[instruction.itype]:
        return "instruction width/macro layout is not reviewed"
    if instruction.flags != (1 if instruction.is_macro else 0):
        return "instruction flags do not match the reviewed macro layout"
    if any((instruction.auxpref, instruction.segpref, instruction.insnpref)):
        return "instruction prefix/spec fields are not reviewed"
    shape = _SHAPES[instruction.itype]
    if tuple((op.operand_type, op.dtype) for op in instruction.operands) != shape:
        return "operand count/type/dtype layout is not reviewed"
    for operand in instruction.operands:
        if any(
            (
                operand.specval,
                operand.specflag1,
                operand.specflag2,
                operand.specflag3,
                operand.specflag4,
                operand.offb,
                operand.offo,
            )
        ):
            return "operand spec/offset fields are not reviewed"
        if operand.operand_type == 1:
            expected_flags = 0 if instruction.itype == 163 else 8
            if not (
                0 <= operand.reg < 32
                and operand.phrase == operand.reg
                and operand.value == 0
                and operand.addr == 0
                and operand.flags == expected_flags
            ):
                return "register operand layout is not reviewed"
        elif operand.operand_type == 4:
            if not (
                0 <= operand.reg < 32
                and operand.phrase == operand.reg
                and operand.value == 0
                and operand.flags == 8
            ):
                return "displacement operand layout is not reviewed"
            try:
                _word(operand.addr)
            except ContractError:
                return "displacement is not canonical RV32 two's-complement"
        elif operand.operand_type == 5:
            if not (
                operand.reg == 0
                and operand.phrase == 0
                and operand.addr == 0
                and operand.flags == 8
            ):
                return "immediate operand layout is not reviewed"
            try:
                _word(operand.value)
            except ContractError:
                return "immediate is not canonical RV32 two's-complement"
        elif operand.operand_type == 7:
            if not (
                operand.reg == 0
                and operand.phrase == 0
                and operand.value == 0
                and operand.addr > 0
                and operand.flags == 8
            ):
                return "near operand layout is not reviewed"
    if instruction.itype == 163 and instruction.operands[0].reg != 1:
        return "reviewed call must explicitly define ra"
    return None


def _control_risk(instruction: InstructionCapture) -> bool:
    return (
        instruction.itype in _CONTROL_ITYPES
        or not instruction.is_canon
        or instruction.canonical_feature_bits is None
        or bool(instruction.canonical_feature_bits & _CONTROL_FEATURES)
    )


def _register(register_id: int, role: _OperandRole, ea: int) -> Operand:
    if register_id == 0:
        return Operand("constant", 32, constant=0, role=role, source_eas=(ea,))
    return Operand(
        "storage",
        32,
        storage=StorageLocation(
            "register", f"rv32:{_REGISTER_NAMES[register_id]}", 0, 32
        ),
        role=role,
        source_eas=(ea,),
    )


def _destination(register_id: int, ea: int) -> Operand | None:
    return None if register_id == 0 else _register(register_id, "destination", ea)


def _constant(value: int, role: _OperandRole, ea: int) -> Operand:
    return Operand("constant", 32, constant=_word(value), role=role, source_eas=(ea,))


def _frame(offset: int, role: _OperandRole, ea: int) -> Operand:
    sign = "+" if offset >= 0 else ""
    return Operand(
        "storage",
        32,
        storage=StorageLocation("frame", f"rv32:entry-sp:{sign}{offset}", 0, 32),
        role=role,
        source_eas=(ea,),
    )


def _address(base: int, displacement: int, role: _OperandRole, ea: int) -> Operand:
    return Operand(
        "expression",
        32,
        operation="m_add",
        children=(
            _register(base, "left", ea),
            _constant(displacement, "right", ea),
        ),
        role=role,
        source_eas=(ea,),
    )


def _block_operand(block: int, ea: int) -> Operand:
    return Operand(
        "block", None, block_index=block, role="destination", source_eas=(ea,)
    )


def _abi_bytes(registers: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(
        byte for register in registers for byte in range(register * 4, register * 4 + 4)
    )


def _call_info(
    capture: CaptureBundle, target: int, ea: int
) -> tuple[CallInfo, Operand | None]:
    target_ordinal = next(
        function.selector_ordinal
        for function in capture.functions
        if capture.image_base + function.function_rva == target
    )
    arguments, returns = _FIXTURE_ABI[target_ordinal]
    return_operands = tuple(_register(register, "return", ea) for register in returns)
    destination = _destination(returns[0], ea) if returns else None
    return CallInfo(
        callee_ea=target,
        convention=0,
        arguments=tuple(_register(register, "argument", ea) for register in arguments),
        return_operands=return_operands,
        return_width_bits=32 if returns else None,
        return_locations=LocationSet(register_bytes=_abi_bytes(returns)),
        spoiled_locations=LocationSet(register_bytes=_abi_bytes(_CALLER_SAVED)),
        return_type_code=0,
        return_is_void=not returns,
        unresolved=(
            "call_effects_partial",
            "memory_effects_unknown",
            "numeric_calling_convention_unavailable",
        ),
    ), destination


def _transfer_frame(
    state: tuple[int | None, int | None], instruction: InstructionCapture
) -> tuple[int | None, int | None]:
    if _layout_error(instruction) is not None:
        return _UNKNOWN
    sp, s0 = state
    if instruction.itype == 19:
        destination, source, immediate = instruction.operands
        if destination.reg not in {2, 8}:
            return state
        base = sp if source.reg == 2 else s0 if source.reg == 8 else None
        value = None if base is None else base + _signed(immediate.value)
        return (value, s0) if destination.reg == 2 else (sp, value)
    if instruction.itype in {1, 13, 22, 28, 33, 122}:
        destination = instruction.operands[0].reg
        if destination == 2:
            return None, s0
        if destination == 8:
            return sp, None
    return state


def _frame_states(
    function: FunctionCapture,
) -> dict[tuple[int, int], tuple[int | None, int | None]]:
    require(
        not function.blocks[0].predecessors, "RV32 entry block must not have a backedge"
    )
    incoming: dict[int, tuple[int | None, int | None]] = {0: (0, None)}
    outgoing: dict[int, tuple[int | None, int | None]] = {}
    queue: deque[int] = deque((0,))
    queued = {0}
    while queue:
        block_index = queue.popleft()
        queued.discard(block_index)
        state = incoming[block_index]
        for instruction in function.blocks[block_index].instructions:
            state = _transfer_frame(state, instruction)
        if outgoing.get(block_index) == state:
            continue
        outgoing[block_index] = state
        for successor in function.blocks[block_index].successors:
            available = [
                outgoing[pred]
                for pred in function.blocks[successor].predecessors
                if pred in outgoing
            ]
            if not available:
                continue
            joined: tuple[int | None, int | None] = (
                available[0][0]
                if all(value[0] == available[0][0] for value in available)
                else None,
                available[0][1]
                if all(value[1] == available[0][1] for value in available)
                else None,
            )
            if incoming.get(successor) != joined:
                incoming[successor] = joined
                if successor not in queued:
                    queue.append(successor)
                    queued.add(successor)
    before: dict[tuple[int, int], tuple[int | None, int | None]] = {}
    for block in function.blocks:
        state = incoming.get(block.index, _UNKNOWN)
        for instruction in block.instructions:
            before[(block.index, instruction.rva)] = state
            state = _transfer_frame(state, instruction)
    return before


def _frame_offset(
    operand: OperandCapture, state: tuple[int | None, int | None]
) -> int | None:
    base = state[0] if operand.reg == 2 else state[1] if operand.reg == 8 else None
    return None if base is None else base + _signed(operand.addr)


def _lower_reviewed(
    capture: CaptureBundle,
    function: FunctionCapture,
    block_index: int,
    instruction: InstructionCapture,
    state: tuple[int | None, int | None],
) -> Instruction:
    ea = capture.image_base + instruction.rva
    operands = instruction.operands
    destination = _destination(operands[0].reg, ea) if operands else None

    def result(opcode: str, values: tuple[Operand | None, ...]) -> Instruction:
        return Instruction(
            0,
            opcode,
            tuple(value for value in values if value is not None),
            (ea,),
        )

    if instruction.itype == 1:
        return (
            result(
                "m_mov",
                (
                    _constant(
                        (_word(operands[1].value) << 12) & 0xFFFFFFFF, "left", ea
                    ),
                    destination,
                ),
            )
            if destination is not None
            else result("m_nop", ())
        )
    if instruction.itype in {19, 22}:
        if destination is None:
            return result("m_nop", ())
        opcode = "m_add" if instruction.itype == 19 else "m_xor"
        return result(
            opcode,
            (
                _register(operands[1].reg, "left", ea),
                _constant(operands[2].value, "right", ea),
                destination,
            ),
        )
    if instruction.itype in {28, 33}:
        if destination is None:
            return result("m_nop", ())
        return result(
            "m_add" if instruction.itype == 28 else "m_xor",
            (
                _register(operands[1].reg, "left", ea),
                _register(operands[2].reg, "right", ea),
                destination,
            ),
        )
    if instruction.itype == 122:
        return (
            result("m_mov", (_constant(operands[1].value, "left", ea), destination))
            if destination is not None
            else result("m_nop", ())
        )
    if instruction.itype in {13, 18}:
        memory = operands[1]
        offset = _frame_offset(memory, state)
        if instruction.itype == 13:
            if offset is not None:
                return (
                    result("m_mov", (_frame(offset, "left", ea), destination))
                    if destination is not None
                    else result("m_nop", ())
                )
            address = _address(memory.reg, memory.addr, "right", ea)
            if destination is None:
                discarded = Operand(
                    "unknown",
                    32,
                    role="destination",
                    source_eas=(ea,),
                    diagnostic=Diagnostic(
                        "rv32_x0_discard", "load result is discarded by x0"
                    ),
                )
                destination = discarded
            return result("m_ldx", (_constant(0, "left", ea), address, destination))
        source = _register(operands[0].reg, "left", ea)
        if offset is not None:
            return result("m_mov", (source, _frame(offset, "destination", ea)))
        return result(
            "m_stx",
            (
                source,
                _constant(0, "right", ea),
                _address(memory.reg, memory.addr, "destination", ea),
            ),
        )
    block_eas = {
        capture.image_base + block.start_rva: block.index for block in function.blocks
    }
    if instruction.itype == 134:
        target_ea = operands[1].addr
        require(target_ea in block_eas, "RV32 branch target is not a captured block")
        target = block_eas[target_ea]
        successors = set(function.blocks[block_index].successors)
        fallthrough = block_eas.get(ea + instruction.size)
        require(
            target in successors
            and fallthrough in successors
            and target != fallthrough
            and len(successors) == 2,
            "RV32 conditional branch/CFG mismatch",
        )
        return result(
            "m_jz",
            (
                _register(operands[0].reg, "left", ea),
                _constant(0, "right", ea),
                _block_operand(target, ea),
            ),
        )
    if instruction.itype == 140:
        target_ea = operands[0].addr
        require(target_ea in block_eas, "RV32 jump target is not a captured block")
        target = block_eas[target_ea]
        require(
            function.blocks[block_index].successors == (target,),
            "RV32 jump/CFG mismatch",
        )
        return result("m_goto", (_block_operand(target, ea),))
    if instruction.itype == 142:
        require(
            not function.blocks[block_index].successors,
            "RV32 return has CFG successors",
        )
        return result(
            "m_ret",
            () if function.selector_ordinal == 3 else (_register(10, "return", ea),),
        )
    if instruction.itype == 163:
        target = operands[1].addr
        function_eas = {
            capture.image_base + candidate.function_rva
            for candidate in capture.functions
        }
        require(target in function_eas, "RV32 call target is not a captured function")
        info, call_destination = _call_info(capture, target, ea)
        call = Operand(
            "callinfo",
            info.return_width_bits,
            call=info,
            source_eas=(ea,),
        )
        target_operand = Operand(
            "global", 32, address=target, role="left", source_eas=(ea,)
        )
        return result("m_call", (target_operand, call, call_destination))
    raise ContractError("Reviewed RV32 dispatch table is incomplete")


def _validate_profile(capture: CaptureBundle) -> None:
    expected = tuple(enumerate(_REGISTER_NAMES))
    actual = tuple(
        (register.register_id, register.name)
        for register in capture.processor_adapter.registers[:32]
    )
    require(actual == expected, "RV32 native integer register metadata drift")
    require(
        capture.backend.backend_id == "ida-disasm-rv32"
        and capture.backend.backend_version == 1
        and capture.backend.extraction_stage == "structured-disassembly"
        and capture.backend.maturity is None,
        "Unexpected RV32 structured backend identity",
    )


def _resolve_function(
    capture: CaptureBundle, function: FunctionCapture | int
) -> FunctionCapture:
    if type(function) is int:
        matches = [
            item for item in capture.functions if item.selector_ordinal == function
        ]
        require(len(matches) == 1, "Missing RV32 function selector")
        return matches[0]
    require(type(function) is FunctionCapture, "Expected RV32 function capture")
    selected = cast(FunctionCapture, function)
    require(selected in capture.functions, "Function is not owned by capture bundle")
    return selected


def lower_function(
    capture: CaptureBundle,
    function: FunctionCapture | int,
    *,
    namespace: str = "rv32-structured",
    policy: RV32LoweringPolicy = DEFAULT_RV32_LOWERING_POLICY,
) -> StructuredSnapshot:
    """Lower one captured function through the reviewed Phase-1 RV32 table."""
    require(type(capture) is CaptureBundle, "Expected RV32 capture bundle")
    require(type(policy) is RV32LoweringPolicy, "Expected RV32 lowering policy")
    nonempty(namespace)
    _validate_profile(capture)
    selected = _resolve_function(capture, function)
    instruction_count = sum(len(block.instructions) for block in selected.blocks)
    require(
        len(selected.blocks) <= policy.max_blocks, "RV32 lowering block budget exceeded"
    )
    require(
        instruction_count <= policy.max_instructions,
        "RV32 lowering instruction budget exceeded",
    )
    states = _frame_states(selected)
    diagnostics: list[Diagnostic] = []
    blocks: list[Block] = []
    for block in selected.blocks:
        lowered: list[Instruction] = []
        for native in block.instructions:
            reason = _layout_error(native)
            ea = capture.image_base + native.rva
            if reason is not None:
                require(
                    not _control_risk(native),
                    f"Unreviewed RV32 control/effect layout at {ea:#x}: {reason}",
                )
                diagnostics.append(
                    Diagnostic(
                        "rv32_opaque_instruction",
                        f"ea={ea:#x};itype={native.itype};reason={reason}",
                    )
                )
                lowered.append(Instruction(0, "rv32_opaque", (), (ea,)))
                continue
            if native.itype in _CONTROL_ITYPES:
                require(
                    native is block.instructions[-1] or native.itype == 163,
                    "RV32 terminator is not the final block instruction",
                )
            lowered.append(
                _lower_reviewed(
                    capture,
                    selected,
                    block.index,
                    native,
                    states[(block.index, native.rva)],
                )
            )
            if native.itype == 163:
                diagnostics.append(
                    Diagnostic(
                        "rv32_call_effects_partial",
                        f"ea={ea:#x};target={native.operands[1].addr:#x}",
                        "information",
                    )
                )
        blocks.append(
            Block(
                block.index,
                block.predecessors,
                tuple(
                    Instruction(
                        index,
                        instruction.opcode,
                        instruction.operands,
                        instruction.source_eas,
                        instruction.synthetic,
                    )
                    for index, instruction in enumerate(lowered)
                ),
                block.successors,
            )
        )
    diagnostics.sort(key=lambda item: (item.code, item.detail, item.severity))
    require(
        len(diagnostics) <= policy.max_diagnostics,
        "RV32 lowering diagnostic budget exceeded",
    )
    lowered_function = FunctionInput(
        selected.stable_key, 0, tuple(blocks), tuple(diagnostics)
    )
    environment = StructuredEnvironment(
        ida_build=capture.ida_kernel_version,
        processor=capture.fixture.processor,
        abi=capture.fixture.abi_id,
        bitness=capture.fixture.bitness,
        data_endian="little",
        instruction_endian="little",
        address_space="flat-rv32",
        backend_id=capture.backend.backend_id,
        backend_version=capture.backend.backend_version,
        extraction_stage=capture.backend.extraction_stage,
        lowering_version="rv32-lowering/1",
        processor_adapter_digest=digest(capture.processor_adapter),
        format_id=capture.fixture.format_id,
        platform_tag=capture.fixture.platform_tag,
    )
    identity = StructuredSnapshotIdentity(
        namespace=namespace,
        binary_digest=capture.fixture.binary_sha256,
        semantic_digest=digest(
            {
                "function": lowered_function.to_data(),
                "interpretation": RV32_LOWERING_RULES,
            }
        ),
        function_id=lowered_function.function_id,
        backend_digest=digest(capture.backend),
        profile_digest=capture.fixture.profile_evidence_digest,
        capture_digest=digest(capture),
        lowering_rule_digest=RV32_LOWERING_RULE_DIGEST,
        summary_digest=RV32_EMPTY_SUMMARY_DIGEST,
        policy_digest=digest(policy),
        input_digest=digest(lowered_function),
        environment=environment,
    )
    return StructuredSnapshot(identity, lowered_function, identity.snapshot_id)


def lower_bundle(
    capture: CaptureBundle,
    *,
    namespace: str = "rv32-structured",
    policy: RV32LoweringPolicy = DEFAULT_RV32_LOWERING_POLICY,
) -> tuple[StructuredSnapshot, ...]:
    """Lower all six captured functions in deterministic selector order."""
    return tuple(
        lower_function(capture, function, namespace=namespace, policy=policy)
        for function in capture.functions
    )


lower_rv32_function = lower_function
lower_rv32_bundle = lower_bundle


__all__ = [
    "DEFAULT_RV32_LOWERING_POLICY",
    "RV32_EMPTY_SUMMARY_DIGEST",
    "RV32_LOWERING_RULE_DIGEST",
    "RV32_LOWERING_RULES",
    "RV32LoweringPolicy",
    "lower_bundle",
    "lower_function",
    "lower_rv32_bundle",
    "lower_rv32_function",
]
