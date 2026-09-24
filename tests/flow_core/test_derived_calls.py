"""Derived scalar returns separate proven memory-free from opaque calls."""

from dataclasses import replace

import pytest

from ida_pro_mcp.flow_core import ContractError, digest, stable_id
from ida_pro_mcp.flow_core.analysis import analyze, seeds_for_entry
from ida_pro_mcp.flow_core.contracts import (
    Block,
    CallInfo,
    Instruction,
    LocationSet,
    Operand,
)
from ida_pro_mcp.flow_core.derived_calls import (
    DerivedMemoryWriteEffect,
    DerivedReturnEffect,
    derive_direct_memory_write,
    derive_direct_return,
)
from ida_pro_mcp.flow_core.implicit_analysis import analyze_implicit
from ida_pro_mcp.flow_core.memory_graph import build_memory_graph, replay_memory_graph
from ida_pro_mcp.flow_core.ssa import build_ssa
from ida_pro_mcp.flow_core.states import Labels, StorageLocation
from test_ssa import snapshot


def caller(opcode="m_call", *, nested=False, call_argument=True):
    argument = StorageLocation("microregister", "microregister", 448, 32)
    returned = StorageLocation("microregister", "microregister", 64, 32)
    info = CallInfo(
        0x1000 if opcode == "m_call" else None,
        1,
        (Operand("storage", 32, storage=argument, role="argument"),)
        if call_argument
        else (),
        (),
        32,
        LocationSet((8, 9, 10, 11)),
        LocationSet(),
        1,
        False,
    )
    target = (
        Operand("global", None, role="left", address=0x1000)
        if opcode == "m_call"
        else Operand(
            "storage",
            64,
            role="left",
            storage=StorageLocation("microregister", "microregister", 512, 64),
        )
    )
    call_operands = (
        target,
        Operand("void", None, role="right"),
        Operand("callinfo", None, call=info, role="destination"),
    )
    call_instruction = (
        Instruction(
            1,
            "m_mov",
            (
                Operand(
                    "expression",
                    32,
                    operation="m_call",
                    children=call_operands,
                    role="left",
                ),
                Operand("void", None, role="right"),
                Operand("storage", 32, storage=returned, role="destination"),
            ),
        )
        if nested and opcode == "m_call"
        else Instruction(1, opcode, call_operands)
    )
    return snapshot(
        (
            Block(
                0,
                (),
                (
                    Instruction(
                        0,
                        "m_arg",
                        (
                            Operand("constant", 32, constant=0, role="left"),
                            Operand("storage", 32, storage=argument, role="argument"),
                        ),
                        synthetic=True,
                    ),
                    call_instruction,
                    Instruction(
                        2,
                        "m_ret",
                        (Operand("storage", 32, storage=returned, role="left"),),
                    ),
                ),
            ),
        )
    )


def effect(source):
    return DerivedReturnEffect(
        source.snapshot_id,
        stable_id("snapshot", "verified-static-callee"),
        0x1000,
        0,
        1,
        StorageLocation("microregister", "microregister", 64, 32),
        (0,),
        digest("complete-callee-return-certificate"),
    )


def callee(return_offset=448):
    argument = StorageLocation("microregister", "microregister", 448, 32)
    return snapshot(
        (
            Block(
                0,
                (),
                (
                    Instruction(
                        0,
                        "m_arg",
                        (
                            Operand("constant", 32, constant=0, role="left"),
                            Operand("storage", 32, storage=argument, role="argument"),
                        ),
                        synthetic=True,
                    ),
                    Instruction(
                        1,
                        "m_ret",
                        (
                            Operand(
                                "storage",
                                32,
                                storage=StorageLocation(
                                    "microregister", "microregister", return_offset, 32
                                ),
                                role="left",
                            ),
                        ),
                    ),
                ),
            ),
        )
    )


def constant_callee():
    return snapshot(
        (
            Block(
                0,
                (),
                (
                    Instruction(
                        0,
                        "m_ret",
                        (Operand("constant", 32, constant=7, role="left"),),
                    ),
                ),
            ),
        )
    )


def constant_callee_with_global_write():
    return snapshot(
        (
            Block(
                0,
                (),
                (
                    Instruction(
                        0,
                        "m_mov",
                        (
                            Operand("constant", 32, constant=9, role="left"),
                            Operand("global", 32, address=0x2000, role="destination"),
                        ),
                    ),
                    Instruction(
                        1,
                        "m_ret",
                        (Operand("constant", 32, constant=7, role="left"),),
                    ),
                ),
            ),
        )
    )


def caller_preserving_stack_across_call():
    argument = StorageLocation("microregister", "microregister", 448, 32)
    spill = StorageLocation("stack", "stack", 0, 32)
    restored = StorageLocation("microregister", "microregister", 256, 32)
    info = replace(observed_call(caller()), arguments=())
    return snapshot(
        (
            Block(
                0,
                (),
                (
                    Instruction(
                        0,
                        "m_arg",
                        (
                            Operand("constant", 32, constant=0, role="left"),
                            Operand("storage", 32, storage=argument, role="argument"),
                        ),
                        synthetic=True,
                    ),
                    Instruction(
                        1,
                        "m_mov",
                        (
                            Operand("storage", 32, storage=argument, role="left"),
                            Operand("storage", 32, storage=spill, role="destination"),
                        ),
                    ),
                    Instruction(
                        2,
                        "m_call",
                        (
                            Operand("global", None, address=0x1000, role="left"),
                            Operand("void", None, role="right"),
                            Operand("callinfo", None, call=info, role="destination"),
                        ),
                    ),
                    Instruction(
                        3,
                        "m_mov",
                        (
                            Operand("storage", 32, storage=spill, role="left"),
                            Operand(
                                "storage", 32, storage=restored, role="destination"
                            ),
                        ),
                    ),
                    Instruction(
                        4, "m_ret", (Operand("storage", 32, storage=restored),)
                    ),
                ),
            ),
        )
    ), info


def observed_call(source):
    def walk(value):
        if value.call is not None:
            yield value.call
        for child in value.children:
            yield from walk(child)

    instruction = source.function.blocks[0].instructions[1]
    calls = [info for operand in instruction.operands for info in walk(operand)]
    assert len(calls) == 1
    return calls[0]


def returned(program, result):
    target = next(node.node_id for node in program.graph.nodes if node.kind == "Return")
    return next(item for item in result.facts if item.node_id == target)


@pytest.mark.parametrize("nested", (False, True))
def test_derived_return_reaches_caller_without_clearing_unknown_call_effects(nested):
    source = caller(nested=nested)
    original = build_memory_graph(source)
    derived = build_memory_graph(source, derived_returns=(effect(source),))
    seeds = seeds_for_entry(
        derived.program,
        StorageLocation("microregister", "microregister", 448, 32),
        Labels(("X",)),
    )
    assert returned(
        original.program, analyze(original.graph, seeds)
    ).labels.unknown_provenance
    call_result = [node for node in derived.graph.nodes if node.kind == "CallResult"]
    assert len(call_result) == 1 and call_result[0].width_bits == 32
    assert call_result[0].operation == "derived_static_return"
    result = analyze_implicit(derived.program, seeds, memory_model=derived)
    fact = returned(derived.program, result)
    assert fact.labels.explicit == ("X",)
    assert fact.labels.unknown_provenance is False
    assert result.status == "partial"
    assert "unknown_call_or_write" in derived.result.diagnostics
    assert replay_memory_graph(derived.program).graph == derived.graph


@pytest.mark.parametrize("nested", (False, True))
def test_complete_local_callee_proof_drives_only_caller_return(nested):
    source = caller(nested=nested)
    target = callee()
    derived = derive_direct_return(source, target, observed_call(source), 0, 1)
    assert derived is not None and derived.provenance == "derived_static"
    assert derived.argument_indices == (0,)
    assert derived.memory_effects == "none"
    bundle = build_memory_graph(source, derived_returns=(derived,))
    seeds = seeds_for_entry(
        bundle.program,
        StorageLocation("microregister", "microregister", 448, 32),
        Labels(("X",)),
    )
    result = analyze_implicit(bundle.program, seeds, memory_model=bundle)
    assert returned(bundle.program, result).labels.explicit == ("X",)
    assert returned(bundle.program, result).labels.unknown_provenance is False
    assert result.status == "partial"  # Scalar call effects remain unresolved.
    assert "unknown_call_or_write" not in bundle.result.diagnostics


def test_untyped_extra_callee_input_cannot_get_clean_derived_return():
    source = caller()
    assert derive_direct_return(source, callee(96), observed_call(source), 0, 1) is None


def test_resolved_indirect_site_is_not_promoted_to_direct_return_certificate():
    source = caller(opcode="m_icall")
    block = source.function.blocks[0]
    instruction = block.instructions[1]
    callinfo = instruction.operands[2]
    updated = replace(
        instruction,
        operands=(
            *instruction.operands[:2],
            replace(callinfo, call=replace(callinfo.call, callee_ea=0x1000)),
        ),
    )
    source = snapshot(
        (
            replace(
                block,
                instructions=(block.instructions[0], updated, block.instructions[2]),
            ),
        )
    )
    assert derive_direct_return(source, callee(), observed_call(source), 0, 1) is None


def callee_write_output(*, global_write=False, read_first=False):
    value = StorageLocation("microregister", "microregister", 448, 32)
    pointer = StorageLocation("microregister", "microregister", 512, 64)
    instructions = [
        Instruction(
            0,
            "m_arg",
            (
                Operand("constant", 32, constant=0, role="left"),
                Operand("storage", 32, storage=value, role="argument"),
            ),
            synthetic=True,
        ),
        Instruction(
            1,
            "m_arg",
            (
                Operand("constant", 32, constant=1, role="left"),
                Operand(
                    "storage",
                    64,
                    storage=pointer,
                    role="argument",
                    native_kind="typed_pointer_argument_argloc",
                ),
            ),
            synthetic=True,
        ),
    ]
    if read_first:
        instructions.append(
            Instruction(
                2,
                "m_ldx",
                (
                    Operand("constant", 16, constant=0, role="left"),
                    Operand("storage", 64, storage=pointer, role="right"),
                    Operand(
                        "storage",
                        32,
                        storage=StorageLocation(
                            "microregister", "microregister", 640, 32
                        ),
                        role="destination",
                    ),
                ),
            )
        )
    instructions.append(
        Instruction(
            len(instructions),
            "m_mov" if global_write else "m_stx",
            (
                Operand("storage", 32, storage=value, role="left"),
                *(
                    (Operand("global", 32, address=0x2000, role="destination"),)
                    if global_write
                    else (
                        Operand("constant", 16, constant=0, role="right"),
                        Operand("storage", 64, storage=pointer, role="destination"),
                    )
                ),
            ),
        )
    )
    instructions.append(Instruction(len(instructions), "m_exit", (), synthetic=True))
    return snapshot((Block(0, (), tuple(instructions)),))


def caller_write_output():
    value = StorageLocation("microregister", "microregister", 448, 32)
    restored = StorageLocation("microregister", "microregister", 256, 32)
    local = StorageLocation("stack", "stack", 0, 32)
    info = CallInfo(
        0x1000,
        1,
        (
            Operand("storage", 32, storage=value, role="argument"),
            Operand("stack_address", 64, address=0, role="argument"),
        ),
        (),
        None,
        LocationSet(),
        LocationSet(),
        1,
        True,
    )
    source = snapshot(
        (
            Block(
                0,
                (),
                (
                    Instruction(
                        0,
                        "m_arg",
                        (
                            Operand("constant", 32, constant=0, role="left"),
                            Operand("storage", 32, storage=value, role="argument"),
                        ),
                        synthetic=True,
                    ),
                    Instruction(
                        1,
                        "m_mov",
                        (
                            Operand("constant", 32, constant=7, role="left"),
                            Operand("storage", 32, storage=local, role="destination"),
                        ),
                    ),
                    Instruction(
                        2,
                        "m_call",
                        (
                            Operand("global", None, address=0x1000, role="left"),
                            Operand("void", None, role="right"),
                            Operand("callinfo", None, call=info, role="destination"),
                        ),
                    ),
                    Instruction(
                        3,
                        "m_mov",
                        (
                            Operand("storage", 32, storage=local, role="left"),
                            Operand(
                                "storage", 32, storage=restored, role="destination"
                            ),
                        ),
                    ),
                    Instruction(
                        4, "m_ret", (Operand("storage", 32, storage=restored),)
                    ),
                ),
            ),
        )
    )
    return source, info


def test_exact_typed_single_output_write_derives_bounded_memory_effect():
    source, info = caller_write_output()
    callee = callee_write_output()
    effect = derive_direct_memory_write(source, callee, info, 0, 2)
    assert isinstance(effect, DerivedMemoryWriteEffect)
    assert effect.pointer_argument_index == 1
    assert effect.value_argument_index == 0
    assert effect.width_bits == 32 and effect.byte_offset == 0
    assert DerivedMemoryWriteEffect.from_data(effect.to_data()) == effect

    original = build_memory_graph(source)
    derived = build_memory_graph(source, derived_memory_writes=(effect,))
    seeds = seeds_for_entry(
        derived.program,
        StorageLocation("microregister", "microregister", 448, 32),
        Labels(("X",)),
    )
    before = analyze_implicit(original.program, seeds, memory_model=original)
    after = analyze_implicit(derived.program, seeds, memory_model=derived)
    assert returned(original.program, before).labels.unknown_provenance
    assert returned(derived.program, after).labels.explicit == ("X",)
    assert returned(derived.program, after).labels.unknown_provenance is False
    assert after.status == "partial"  # Scalar callinfo/spoilers are still opaque.
    assert "unknown_call_or_write" not in derived.result.diagnostics
    modeled = [
        node
        for node in derived.graph.nodes
        if node.kind == "Store"
        and any(
            "unreviewed_static_single_output_write" in evidence.assumptions
            for evidence in derived.graph.evidence
            if evidence.evidence_id in node.evidence_ids
        )
    ]
    assert len(modeled) == 1
    assert (
        replay_memory_graph(derived.program).result.dependencies
        == derived.result.dependencies
    )


def test_mismatched_memory_write_site_is_rejected_before_graph_construction():
    source, info = caller_write_output()
    effect = derive_direct_memory_write(source, callee_write_output(), info, 0, 2)
    assert effect is not None
    with pytest.raises(ContractError, match="Derived memory write"):
        build_memory_graph(
            source, derived_memory_writes=(replace(effect, instruction=1),)
        )


def test_direct_call_target_must_match_callinfo_before_any_derived_effect():
    source, info = caller_write_output()
    block = source.function.blocks[0]
    instruction = block.instructions[2]
    wrong_target = replace(
        instruction,
        operands=(
            replace(instruction.operands[0], address=0x2000),
            *instruction.operands[1:],
        ),
    )
    source = snapshot(
        (
            replace(
                block,
                instructions=(
                    *block.instructions[:2],
                    wrong_target,
                    *block.instructions[3:],
                ),
            ),
        )
    )
    assert derive_direct_memory_write(source, callee_write_output(), info, 0, 2) is None
    forged = DerivedMemoryWriteEffect(
        source.snapshot_id,
        callee_write_output().snapshot_id,
        0x1000,
        0,
        2,
        1,
        0,
        32,
        digest("forged-output-proof"),
    )
    with pytest.raises(ContractError, match="requires one direct call"):
        build_memory_graph(source, derived_memory_writes=(forged,))
    scalar = caller()
    block = scalar.function.blocks[0]
    instruction = block.instructions[1]
    wrong_target = replace(
        instruction,
        operands=(
            replace(instruction.operands[0], address=0x2000),
            *instruction.operands[1:],
        ),
    )
    scalar = snapshot(
        (
            replace(
                block,
                instructions=(
                    block.instructions[0],
                    wrong_target,
                    block.instructions[2],
                ),
            ),
        )
    )
    assert derive_direct_return(scalar, callee(), observed_call(scalar), 0, 1) is None
    with pytest.raises(ContractError, match="requires one direct call"):
        build_memory_graph(scalar, derived_returns=(effect(scalar),))


@pytest.mark.parametrize("global_write,read_first", ((True, False), (False, True)))
def test_output_write_proof_rejects_other_external_effects(global_write, read_first):
    source, info = caller_write_output()
    assert (
        derive_direct_memory_write(
            source,
            callee_write_output(global_write=global_write, read_first=read_first),
            info,
            0,
            2,
        )
        is None
    )


def test_output_write_proof_rejects_multiple_external_stores():
    source, info = caller_write_output()
    target = callee_write_output()
    block = target.function.blocks[0]
    write = block.instructions[2]
    duplicate = replace(write, index=3)
    exit_marker = replace(block.instructions[3], index=4)
    target = snapshot(
        (
            replace(
                block, instructions=(*block.instructions[:3], duplicate, exit_marker)
            ),
        )
    )
    assert derive_direct_memory_write(source, target, info, 0, 2) is None


@pytest.mark.parametrize("nested", (False, True))
def test_zero_argument_constant_callee_return_is_clean_with_proven_no_memory_effect(
    nested,
):
    source = caller(nested=nested, call_argument=False)
    target = constant_callee()
    derived = derive_direct_return(source, target, observed_call(source), 0, 1)
    assert derived is not None and derived.argument_indices == ()
    assert derived.memory_effects == "none"
    bundle = build_memory_graph(source, derived_returns=(derived,))
    seeds = seeds_for_entry(
        bundle.program,
        StorageLocation("microregister", "microregister", 448, 32),
        Labels(("X",)),
    )
    result = analyze_implicit(bundle.program, seeds, memory_model=bundle)
    out = returned(bundle.program, result)
    assert out.labels.explicit == ()
    assert out.labels.unknown_provenance is False
    assert result.status == "partial"
    assert "unknown_call_or_write" not in bundle.result.diagnostics


@pytest.mark.parametrize(
    "callee,expected_effect,unknown",
    (
        (constant_callee, "none", False),
        (constant_callee_with_global_write, "unknown", True),
    ),
)
def test_only_proven_memory_free_callee_preserves_caller_stack(
    callee, expected_effect, unknown
):
    source, info = caller_preserving_stack_across_call()
    derived = derive_direct_return(source, callee(), info, 0, 2)
    assert derived is not None and derived.memory_effects == expected_effect
    bundle = build_memory_graph(source, derived_returns=(derived,))
    seeds = seeds_for_entry(
        bundle.program,
        StorageLocation("microregister", "microregister", 448, 32),
        Labels(("X",)),
    )
    result = analyze_implicit(bundle.program, seeds, memory_model=bundle)
    assert returned(bundle.program, result).labels.explicit == ("X",)
    assert returned(bundle.program, result).labels.unknown_provenance is unknown
    assert ("unknown_call_or_write" in bundle.result.diagnostics) is unknown
    assert ("unknown_call_or_write" in result.diagnostics) is unknown


def test_zero_argument_callee_with_untyped_input_is_not_proven_constant():
    source = caller(call_argument=False)
    target = snapshot(
        (
            Block(
                0,
                (),
                (
                    Instruction(
                        0,
                        "m_ret",
                        (
                            Operand(
                                "storage",
                                32,
                                storage=StorageLocation(
                                    "microregister", "microregister", 96, 32
                                ),
                                role="left",
                            ),
                        ),
                    ),
                ),
            ),
        )
    )
    assert derive_direct_return(source, target, observed_call(source), 0, 1) is None


@pytest.mark.parametrize("spoil_temp", (False, True, None))
def test_call_spoiler_preserves_only_proven_unspoiled_microregisters(spoil_temp):
    argument = StorageLocation("microregister", "microregister", 448, 32)
    temporary = StorageLocation("microregister", "microregister", 256, 32)
    returned_storage = StorageLocation("microregister", "microregister", 64, 32)
    spoiled = (
        ()
        if spoil_temp is None
        else (8, 9, 10, 11, 32, 33, 34, 35)
        if spoil_temp
        else (8, 9, 10, 11)
    )
    info = replace(observed_call(caller()), spoiled_locations=LocationSet(spoiled))
    source = snapshot(
        (
            Block(
                0,
                (),
                (
                    Instruction(
                        0,
                        "m_arg",
                        (
                            Operand("constant", 32, constant=0, role="left"),
                            Operand("storage", 32, storage=argument, role="argument"),
                        ),
                        synthetic=True,
                    ),
                    Instruction(
                        1,
                        "m_mov",
                        (
                            Operand("storage", 32, storage=argument, role="left"),
                            Operand(
                                "storage", 32, storage=temporary, role="destination"
                            ),
                        ),
                    ),
                    Instruction(
                        2,
                        "m_call",
                        (
                            Operand("global", None, address=0x1000, role="left"),
                            Operand("void", None, role="right"),
                            Operand("callinfo", None, call=info, role="destination"),
                        ),
                    ),
                    Instruction(
                        3,
                        "m_mov",
                        (
                            Operand("storage", 32, storage=temporary, role="left"),
                            Operand(
                                "storage",
                                32,
                                storage=returned_storage,
                                role="destination",
                            ),
                        ),
                    ),
                    Instruction(
                        4,
                        "m_ret",
                        (
                            Operand(
                                "storage", 32, storage=returned_storage, role="left"
                            ),
                        ),
                    ),
                ),
            ),
        )
    )
    bundle = build_memory_graph(source)
    seeds = seeds_for_entry(bundle.program, argument, Labels(("X",)))
    result = analyze_implicit(bundle.program, seeds, memory_model=bundle)
    out = returned(bundle.program, result)
    assert result.status == "partial"
    assert "unknown_call_or_write" in bundle.result.diagnostics
    assert out.labels.explicit == ("X",)
    assert out.labels.unknown_provenance is (spoil_temp is not False)


@pytest.mark.parametrize(
    "mutation",
    (
        {"callee_ea": 0x2000},
        {"instruction": 2},
        {"return_storage": StorageLocation("microregister", "microregister", 96, 32)},
        {"argument_indices": (1,)},
    ),
)
def test_derived_return_rejects_unbound_call_claims(mutation):
    source = caller()
    with pytest.raises(ContractError):
        build_ssa(source, derived_returns=(replace(effect(source), **mutation),))


def test_indirect_call_cannot_be_masqueraded_as_direct_derived_effect():
    source = caller("m_icall")
    with pytest.raises(ContractError, match="one direct call"):
        build_ssa(source, derived_returns=(effect(source),))


def fixed_global_callee(*, constant=False):
    source = callee()
    original = source.function.blocks[0].instructions
    write = Instruction(
        1,
        "m_mov",
        (
            Operand("constant", 32, constant=7, role="left")
            if constant
            else original[1].operands[0],
            Operand("global", 32, address=0x2000, role="destination"),
        ),
    )
    function = replace(
        source.function,
        function_id="function-entry:4096",
        blocks=(Block(0, (), (original[0], write, replace(original[1], index=2))),),
    )
    identity = replace(
        source.identity, function_id=function.function_id, input_digest=digest(function)
    )
    return replace(
        source, function=function, identity=identity, snapshot_id=identity.snapshot_id
    )


@pytest.mark.parametrize("constant", [False, True])
def test_fixed_global_write_is_derived_without_claiming_purity(constant):
    from ida_pro_mcp.flow_core.derived_calls import (
        DerivedGlobalWriteEffect,
        derive_direct_global_write,
    )

    source = caller()
    info = source.function.blocks[0].instructions[1].operands[-1].call
    target = fixed_global_callee(constant=constant)
    effect = derive_direct_global_write(source, target, info, 0, 1)
    assert isinstance(effect, DerivedGlobalWriteEffect)
    assert effect.global_address == 0x2000
    assert effect.value_argument_index == (None if constant else 0)
    assert effect.constant_value == (7 if constant else None)
    assert DerivedGlobalWriteEffect.from_data(effect.to_data()) == effect
    derived = build_memory_graph(source, derived_memory_writes=(effect,))
    stores = [node for node in derived.program.graph.nodes if node.kind == "Store"]
    assert len(stores) == 1
    nodes = {node.node_id: node for node in derived.program.graph.nodes}
    assert nodes[stores[0].memory_operands.address].constant == 0x2000
    assert "unknown_call_or_write" not in derived.result.diagnostics
    result = analyze_implicit(derived.program, (), memory_model=derived)
    assert returned(derived.program, result).labels.unknown_provenance


def test_fixed_global_write_memory_replay_honors_checkpoint(monkeypatch):
    import ida_pro_mcp.flow_core.memory_graph as memory_graph
    from ida_pro_mcp.flow_core.derived_calls import derive_direct_global_write

    source = caller()
    call = source.function.blocks[0].instructions[1].operands[-1].call
    target = fixed_global_callee()
    in_memory = [False]

    def checkpoint():
        if in_memory[0]:
            raise RuntimeError("cancelled during memory replay")

    def replay(_plan, _policy, **kwargs):
        assert kwargs["checkpoint"] is checkpoint
        in_memory[0] = True
        kwargs["checkpoint"]()

    monkeypatch.setattr(memory_graph, "_analyze_plan", replay)
    with pytest.raises(RuntimeError, match="cancelled during memory replay"):
        derive_direct_global_write(
            source, target, call, 0, 1, checkpoint=checkpoint
        )


def test_fixed_global_write_rejects_wrong_callee_and_binary():
    from ida_pro_mcp.flow_core.derived_calls import derive_direct_global_write

    source = caller()
    info = source.function.blocks[0].instructions[1].operands[-1].call
    target = fixed_global_callee()
    assert derive_direct_global_write(source, callee(), info, 0, 1) is None
    identity = replace(target.identity, binary_digest=digest("different-binary"))
    wrong = replace(target, identity=identity, snapshot_id=identity.snapshot_id)
    assert derive_direct_global_write(source, wrong, info, 0, 1) is None


@pytest.mark.parametrize("overwrite", [False, True])
@pytest.mark.parametrize("constant", [False, True])
def test_fixed_global_write_reaches_caller_load_and_respects_overwrite(
    overwrite, constant
):
    from ida_pro_mcp.flow_core.derived_calls import derive_direct_global_write

    base = caller()
    instructions = list(base.function.blocks[0].instructions[:2])
    if overwrite:
        instructions.append(
            Instruction(
                len(instructions),
                "m_mov",
                (
                    Operand("constant", 32, constant=0, role="left"),
                    Operand("global", 32, address=0x2000, role="destination"),
                ),
            )
        )
    result_storage = StorageLocation("microregister", "microregister", 256, 32)
    instructions.append(
        Instruction(
            len(instructions),
            "m_mov",
            (
                Operand("global", 32, address=0x2000, role="left"),
                Operand("storage", 32, storage=result_storage, role="destination"),
            ),
        )
    )
    instructions.append(
        Instruction(
            len(instructions),
            "m_ret",
            (Operand("storage", 32, storage=result_storage, role="left"),),
        )
    )
    source = snapshot((Block(0, (), tuple(instructions)),))
    info = instructions[1].operands[-1].call
    effect = derive_direct_global_write(
        source, fixed_global_callee(constant=constant), info, 0, 1
    )
    assert effect is not None
    memory = build_memory_graph(source, derived_memory_writes=(effect,))
    seeds = seeds_for_entry(
        memory.program,
        StorageLocation("microregister", "microregister", 448, 32),
        Labels(("X",)),
    )
    result = analyze_implicit(memory.program, seeds, memory_model=memory)
    output = returned(memory.program, result).labels
    assert output.explicit == (() if overwrite or constant else ("X",))
    assert not output.unknown_provenance
    assert (
        replay_memory_graph(memory.program).result.dependencies
        == memory.result.dependencies
    )


def rebuild_global_callee(target, instructions):
    function = replace(
        target.function,
        blocks=(
            Block(
                0,
                (),
                tuple(
                    replace(item, index=index)
                    for index, item in enumerate(instructions)
                ),
            ),
        ),
    )
    identity = replace(target.identity, input_digest=digest(function))
    return replace(
        target, function=function, identity=identity, snapshot_id=identity.snapshot_id
    )


@pytest.mark.parametrize(
    "bad_effect", ["second_global", "load", "unknown", "namespace"]
)
def test_fixed_global_write_rejects_incomplete_effects(bad_effect):
    from ida_pro_mcp.flow_core.derived_calls import derive_direct_global_write

    source = caller()
    info = source.function.blocks[0].instructions[1].operands[-1].call
    target = fixed_global_callee()
    instructions = list(target.function.blocks[0].instructions)
    if bad_effect == "namespace":
        identity = replace(target.identity, namespace="another-address-map")
        target = replace(target, identity=identity, snapshot_id=identity.snapshot_id)
    else:
        extra = {
            "second_global": instructions[1],
            "load": Instruction(
                0,
                "m_mov",
                (
                    Operand("global", 32, address=0x3000, role="left"),
                    Operand(
                        "storage",
                        32,
                        storage=StorageLocation(
                            "microregister", "microregister", 256, 32
                        ),
                        role="destination",
                    ),
                ),
            ),
            "unknown": Instruction(0, "m_ext", ()),
        }[bad_effect]
        instructions.insert(1, extra)
        target = rebuild_global_callee(target, instructions)
    assert derive_direct_global_write(source, target, info, 0, 1) is None


def test_fixed_global_write_accepts_proven_local_stack_store_and_zero_extension():
    from ida_pro_mcp.flow_core.derived_calls import derive_direct_global_write

    source = caller()
    info = source.function.blocks[0].instructions[1].operands[-1].call
    target = fixed_global_callee()
    instructions = list(target.function.blocks[0].instructions)
    value = instructions[1].operands[0]
    extended = StorageLocation("microregister", "microregister", 256, 64)
    instructions[1:2] = [
        Instruction(
            1,
            "m_mov",
            (
                value,
                Operand(
                    "storage",
                    32,
                    storage=StorageLocation("stack", "stack", 0, 32),
                    role="destination",
                ),
            ),
        ),
        Instruction(
            2,
            "m_xdu",
            (value, Operand("storage", 64, storage=extended, role="destination")),
        ),
        Instruction(
            3,
            "m_mov",
            (
                Operand("storage", 64, storage=extended, role="left"),
                Operand("global", 64, address=0x2000, role="destination"),
            ),
        ),
    ]
    target = rebuild_global_callee(target, instructions)
    effect = derive_direct_global_write(source, target, info, 0, 1)
    assert effect is not None
    assert effect.width_bits == 64 and effect.value_width_bits == 32
    memory = build_memory_graph(source, derived_memory_writes=(effect,))
    store = next(node for node in memory.program.graph.nodes if node.kind == "Store")
    data = next(
        node
        for node in memory.program.graph.nodes
        if node.node_id == store.memory_operands.data
    )
    assert data.kind == "Unary" and data.operation == "zext" and data.width_bits == 64
    # Inspect the upper half after the call: zero-extension must not smear X
    # into the added high bytes.
    instructions = list(source.function.blocks[0].instructions[:2])
    restored = StorageLocation("microregister", "microregister", 384, 64)
    high = StorageLocation("microregister", "microregister", 640, 32)
    instructions.extend(
        (
            Instruction(
                2,
                "m_mov",
                (
                    Operand("global", 64, address=0x2000, role="left"),
                    Operand("storage", 64, storage=restored, role="destination"),
                ),
            ),
            Instruction(
                3,
                "m_high",
                (
                    Operand("storage", 64, storage=restored, role="left"),
                    Operand("storage", 32, storage=high, role="destination"),
                ),
            ),
            Instruction(
                4, "m_ret", (Operand("storage", 32, storage=high, role="left"),)
            ),
        )
    )
    upper_caller = snapshot((Block(0, (), tuple(instructions)),))
    upper_effect = derive_direct_global_write(upper_caller, target, info, 0, 1)
    assert upper_effect is not None
    upper_memory = build_memory_graph(
        upper_caller, derived_memory_writes=(upper_effect,)
    )
    seeds = seeds_for_entry(
        upper_memory.program,
        StorageLocation("microregister", "microregister", 448, 32),
        Labels(("X",)),
    )
    result = analyze_implicit(upper_memory.program, seeds, memory_model=upper_memory)
    assert returned(upper_memory.program, result).labels == Labels()


def test_fixed_global_write_rejects_store_after_normal_return():
    from ida_pro_mcp.flow_core.derived_calls import derive_direct_global_write

    source = caller()
    info = source.function.blocks[0].instructions[1].operands[-1].call
    target = fixed_global_callee()
    entry, store, returned_value = target.function.blocks[0].instructions
    target = rebuild_global_callee(target, [entry, returned_value, store])
    assert derive_direct_global_write(source, target, info, 0, 1) is None


@pytest.mark.parametrize("branch", [False, True])
def test_fixed_global_write_requires_all_blocks_in_single_acyclic_chain(branch):
    from ida_pro_mcp.flow_core.derived_calls import derive_direct_global_write

    source = caller()
    info = source.function.blocks[0].instructions[1].operands[-1].call
    target = fixed_global_callee()
    entry, store, returned_value = target.function.blocks[0].instructions
    blocks = (
        Block(0, (), (entry,), successors=(1, 2) if branch else (1,)),
        Block(1, (0,), (replace(store, index=0),), successors=(2,)),
        Block(2, (0, 1) if branch else (1,), (replace(returned_value, index=0),)),
    )
    function = replace(target.function, blocks=blocks)
    identity = replace(target.identity, input_digest=digest(function))
    target = replace(
        target, function=function, identity=identity, snapshot_id=identity.snapshot_id
    )
    effect = derive_direct_global_write(source, target, info, 0, 1)
    assert (effect is None) == branch


@pytest.mark.parametrize("write_kind", ["global", "output"])
def test_return_and_memory_write_require_same_callee_snapshot(write_kind):
    from ida_pro_mcp.flow_core.derived_calls import derive_direct_global_write

    if write_kind == "global":
        source = caller()
        target = fixed_global_callee()
        info = observed_call(source)
        write = derive_direct_global_write(source, target, info, 0, 1)
    else:
        original, info = caller_write_output()
        info = replace(
            info,
            return_width_bits=32,
            return_locations=LocationSet((8, 9, 10, 11)),
            return_is_void=False,
        )
        block = original.function.blocks[0]
        instructions = list(block.instructions)
        call = instructions[2]
        instructions[2] = replace(
            call,
            operands=(
                *call.operands[:-1],
                replace(call.operands[-1], call=info),
            ),
        )
        source = snapshot((replace(block, instructions=tuple(instructions)),))
        target = callee_write_output()
        write = derive_direct_memory_write(source, target, info, 0, 2)
    assert write is not None
    return_effect = DerivedReturnEffect(
        source.snapshot_id,
        write.callee_snapshot_id,
        write.callee_ea,
        write.block,
        write.instruction,
        StorageLocation("microregister", "microregister", 64, 32),
        (0,),
        digest("return-proof-same-snapshot"),
    )
    # Both certificates may legitimately describe different effects of one callee.
    build_memory_graph(
        source, derived_returns=(return_effect,), derived_memory_writes=(write,)
    )
    stale = replace(
        return_effect, callee_snapshot_id=stable_id("snapshot", "other-callee-version")
    )
    with pytest.raises(ContractError, match="callee snapshot"):
        build_memory_graph(
            source, derived_returns=(stale,), derived_memory_writes=(write,)
        )


def split_global_argument_fixture(
    *, high_atom=False, caller_offset=448, operation="m_xdu", direct_storage=False
):
    base = fixed_global_callee()
    original = list(base.function.blocks[0].instructions)
    full = StorageLocation("microregister", "microregister", 448, 64)
    low = StorageLocation(
        "microregister", "microregister", 480 if high_atom else 448, 32
    )
    temp = StorageLocation("microregister", "microregister", 640, 64)
    original[0] = replace(
        original[0],
        operands=(
            original[0].operands[0],
            Operand("storage", 64, storage=full, role="argument"),
        ),
    )
    original[1:2] = [
        Instruction(
            1,
            "m_xdu",
            (
                Operand("storage", 32, storage=low, role="left"),
                Operand("storage", 64, storage=temp, role="destination"),
            ),
        ),
        Instruction(
            2,
            "m_mov",
            (
                Operand("storage", 64, storage=temp, role="left"),
                Operand("global", 64, address=0x2000, role="destination"),
            ),
        ),
    ]
    target = rebuild_global_callee(base, original)
    caller_base = caller()
    instructions = list(caller_base.function.blocks[0].instructions)
    instructions[0] = replace(
        instructions[0],
        operands=(
            instructions[0].operands[0],
            Operand("storage", 64, storage=full, role="argument"),
        ),
    )
    info = observed_call(caller_base)
    info = replace(
        info,
        arguments=(
            Operand(
                "expression",
                64,
                operation=operation,
                children=(
                    Operand(
                        "storage",
                        32,
                        storage=StorageLocation(
                            "microregister", "microregister", caller_offset, 32
                        ),
                        role="left",
                    ),
                ),
                role="argument",
            ),
        ),
    )
    if direct_storage:
        info = replace(
            info,
            arguments=(
                Operand(
                    "storage",
                    64,
                    storage=StorageLocation(
                        "microregister", "microregister", caller_offset, 64
                    ),
                    role="argument",
                ),
            ),
        )
    instructions[1] = replace(
        instructions[1],
        operands=(
            *instructions[1].operands[:-1],
            replace(instructions[1].operands[-1], call=info),
        ),
    )
    instructions[2:] = [
        Instruction(
            2,
            "m_mov",
            (
                Operand("global", 64, address=0x2000, role="left"),
                Operand("storage", 64, storage=temp, role="destination"),
            ),
        ),
        Instruction(3, "m_ret", (Operand("storage", 64, storage=temp, role="left"),)),
    ]
    return snapshot((Block(0, (), tuple(instructions)),)), target, info


@pytest.mark.parametrize("direct_storage", [False, True])
def test_global_write_proves_exact_split_low_argument_and_ignores_high_only_seed(
    direct_storage,
):
    from ida_pro_mcp.flow_core.derived_calls import derive_direct_global_write

    source, target, info = split_global_argument_fixture(direct_storage=direct_storage)
    effect = derive_direct_global_write(source, target, info, 0, 1)
    assert effect is not None
    memory = build_memory_graph(source, derived_memory_writes=(effect,))
    for offset, expected in ((448, ("X",)), (480, ())):
        if direct_storage:
            from ida_pro_mcp.flow_core.analysis import BitSeed

            entry = next(
                item
                for item in memory.program.entry_storage
                if item.storage
                == StorageLocation("microregister", "microregister", 448, 64)
            )
            seeds = (BitSeed(entry.node_id, Labels(("X",)), offset - 448, 32),)
        else:
            seeds = seeds_for_entry(
                memory.program,
                StorageLocation("microregister", "microregister", offset, 32),
                Labels(("X",)),
            )
        result = analyze_implicit(memory.program, seeds, memory_model=memory)
        labels = returned(memory.program, result).labels
        assert labels.explicit == expected
        assert not labels.unknown_provenance


@pytest.mark.parametrize(
    "options",
    [
        {"high_atom": True},
        {"operation": "m_xds"},
        {"direct_storage": True, "caller_offset": 480},
        {"direct_storage": True, "high_atom": True},
    ],
)
def test_global_write_rejects_unproven_split_argument(options):
    from ida_pro_mcp.flow_core.derived_calls import derive_direct_global_write

    source, target, info = split_global_argument_fixture(**options)
    assert derive_direct_global_write(source, target, info, 0, 1) is None


@pytest.mark.parametrize("load_target", ["local", "external", "unknown"])
def test_global_write_allows_only_exact_local_stack_loads(load_target):
    from ida_pro_mcp.flow_core.derived_calls import derive_direct_global_write

    source = caller()
    info = observed_call(source)
    target = fixed_global_callee()
    instructions = list(target.function.blocks[0].instructions)
    value = instructions[1].operands[0]
    stack = StorageLocation("stack", "stack", 0, 32)
    address = {
        "local": Operand("stack_address", 64, address=0, role="right"),
        "external": Operand("address", 64, address=0x3000, role="right"),
        "unknown": Operand(
            "storage",
            64,
            storage=StorageLocation("microregister", "microregister", 768, 64),
            role="right",
        ),
    }[load_target]
    instructions[1:1] = [
        Instruction(
            0,
            "m_mov",
            (value, Operand("storage", 32, storage=stack, role="destination")),
        ),
        Instruction(
            0,
            "m_ldx",
            (
                Operand("constant", 16, constant=0, role="left"),
                address,
                Operand(
                    "storage",
                    32,
                    storage=StorageLocation("microregister", "microregister", 640, 32),
                    role="destination",
                ),
            ),
        ),
    ]
    target = rebuild_global_callee(target, instructions)
    effect = derive_direct_global_write(source, target, info, 0, 1)
    assert (effect is not None) == (load_target == "local")


def global_write_spill_data_fixture(*, fault=None):
    source, target, info = split_global_argument_fixture()
    instructions = list(target.function.blocks[0].instructions)
    low = instructions[1].operands[0]
    loaded = StorageLocation("microregister", "microregister", 704, 32)
    copied = StorageLocation("microregister", "microregister", 736, 32)
    instructions[1] = replace(
        instructions[1],
        operands=(
            Operand("storage", 32, storage=loaded, role="left"),
            instructions[1].operands[-1],
        ),
    )
    spill = [
        Instruction(
            0,
            "m_mov",
            (low, Operand("storage", 32, storage=copied, role="destination")),
        ),
        Instruction(
            0,
            "m_stx",
            (
                Operand("storage", 32, storage=copied, role="left"),
                Operand("constant", 16, constant=0, role="right"),
                Operand("stack_address", 64, address=12, role="destination"),
            ),
        ),
        Instruction(
            0,
            "m_ldx",
            (
                Operand("constant", 16, constant=0, role="left"),
                Operand("stack_address", 64, address=12, role="right"),
                Operand("storage", 32, storage=loaded, role="destination"),
            ),
        ),
    ]
    if fault == "load_before_store":
        spill[1], spill[2] = spill[2], spill[1]
    elif fault == "partial_overwrite":
        spill.insert(
            2,
            Instruction(
                0,
                "m_stx",
                (
                    Operand("constant", 16, constant=0, role="left"),
                    Operand("constant", 16, constant=0, role="right"),
                    Operand("stack_address", 64, address=14, role="destination"),
                ),
            ),
        )
    elif fault == "high_atom":
        spill[0] = replace(
            spill[0],
            operands=(
                Operand(
                    "storage",
                    32,
                    storage=StorageLocation("microregister", "microregister", 480, 32),
                    role="left",
                ),
                spill[0].operands[-1],
            ),
        )
    elif fault == "different_interval":
        spill[2] = replace(
            spill[2],
            operands=(
                spill[2].operands[0],
                Operand("stack_address", 64, address=14, role="right"),
                spill[2].operands[-1],
            ),
        )
    instructions[1:1] = spill
    return source, rebuild_global_callee(target, instructions), info


def test_global_write_recovers_one_exact_dominating_stack_data_spill():
    from ida_pro_mcp.flow_core.derived_calls import derive_direct_global_write

    source, target, info = global_write_spill_data_fixture()
    effect = derive_direct_global_write(source, target, info, 0, 1)
    assert effect is not None
    assert effect.value_width_bits == 32 and effect.width_bits == 64
    memory = build_memory_graph(source, derived_memory_writes=(effect,))
    for offset, expected in ((448, ("X",)), (480, ())):
        seeds = seeds_for_entry(
            memory.program,
            StorageLocation("microregister", "microregister", offset, 32),
            Labels(("X",)),
        )
        result = analyze_implicit(memory.program, seeds, memory_model=memory)
        labels = returned(memory.program, result).labels
        assert labels.explicit == expected
        assert not labels.unknown_provenance


@pytest.mark.parametrize(
    "fault",
    ["load_before_store", "partial_overwrite", "high_atom", "different_interval"],
)
def test_global_write_rejects_unproven_stack_data_spill(fault):
    from ida_pro_mcp.flow_core.derived_calls import derive_direct_global_write

    source, target, info = global_write_spill_data_fixture(fault=fault)
    assert derive_direct_global_write(source, target, info, 0, 1) is None


@pytest.mark.parametrize("stack_source", [False, True])
def test_global_write_split_argument_uses_actual_caller_operand_not_callee_location(
    stack_source,
):
    from ida_pro_mcp.flow_core.derived_calls import derive_direct_global_write

    source, target, info = split_global_argument_fixture(caller_offset=480)
    instructions = list(source.function.blocks[0].instructions)
    site = 1
    if stack_source:
        stack = StorageLocation("stack", "stack", 96, 32)
        argument = replace(
            info.arguments[0],
            children=(Operand("storage", 32, storage=stack, role="left"),),
        )
        info = replace(info, arguments=(argument,))
        instructions[1] = replace(
            instructions[1],
            operands=(
                *instructions[1].operands[:-1],
                replace(instructions[1].operands[-1], call=info),
            ),
        )
        instructions.insert(
            1,
            Instruction(
                1,
                "m_mov",
                (
                    Operand(
                        "storage",
                        32,
                        storage=StorageLocation(
                            "microregister", "microregister", 480, 32
                        ),
                        role="left",
                    ),
                    Operand("storage", 32, storage=stack, role="destination"),
                ),
            ),
        )
        source = snapshot(
            (
                Block(
                    0,
                    (),
                    tuple(
                        replace(ins, index=index)
                        for index, ins in enumerate(instructions)
                    ),
                ),
            )
        )
        site = 2
    effect = derive_direct_global_write(source, target, info, 0, site)
    assert effect is not None
    memory = build_memory_graph(source, derived_memory_writes=(effect,))
    for offset, expected in ((448, ()), (480, ("X",))):
        seeds = seeds_for_entry(
            memory.program,
            StorageLocation("microregister", "microregister", offset, 32),
            Labels(("X",)),
        )
        result = analyze_implicit(memory.program, seeds, memory_model=memory)
        labels = returned(memory.program, result).labels
        assert labels.explicit == expected
        assert not labels.unknown_provenance


@pytest.mark.parametrize(
    "fault", ["wrong_child_width", "sign_extension", "missing_binding"]
)
def test_global_write_rejects_invalid_relocated_actual_argument(fault):
    from ida_pro_mcp.flow_core.derived_calls import derive_direct_global_write

    source, target, info = split_global_argument_fixture(caller_offset=480)
    if fault == "missing_binding":
        target = rebuild_global_callee(
            target, target.function.blocks[0].instructions[1:]
        )
    else:
        argument = info.arguments[0]
        if fault == "wrong_child_width":
            argument = replace(
                argument,
                children=(
                    Operand(
                        "storage",
                        16,
                        storage=StorageLocation(
                            "microregister", "microregister", 480, 16
                        ),
                        role="left",
                    ),
                ),
            )
        else:
            argument = replace(argument, operation="m_xds")
        info = replace(info, arguments=(argument,))
        instructions = list(source.function.blocks[0].instructions)
        instructions[1] = replace(
            instructions[1],
            operands=(
                *instructions[1].operands[:-1],
                replace(instructions[1].operands[-1], call=info),
            ),
        )
        source = snapshot((Block(0, (), tuple(instructions)),))
    assert derive_direct_global_write(source, target, info, 0, 1) is None
