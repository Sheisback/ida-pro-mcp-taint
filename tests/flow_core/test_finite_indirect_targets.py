"""Complete SSA target-set proofs must fail closed at unknowns and budgets."""

from dataclasses import replace

import pytest

from ida_pro_mcp.flow_core import ContractError, digest
from ida_pro_mcp.flow_core.analysis import BitSeed, Seed, analyze, seeds_for_entry
from ida_pro_mcp.flow_core.contracts import Block, CallInfo, Instruction, LocationSet, Operand, Snapshot
from ida_pro_mcp.flow_core.derived_calls import (
    DerivedIndirectReturnEffect,
    derive_finite_indirect_return,
    resolve_finite_indirect_targets,
)
from ida_pro_mcp.flow_core.implicit_analysis import analyze_implicit
from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
from ida_pro_mcp.flow_core.ssa import build_ssa
from ida_pro_mcp.flow_core.states import Labels, StorageLocation
from test_derived_calls import callee
from test_ssa import snapshot


FIRST = 0x401000
SECOND = 0x401040
TARGET = StorageLocation("microregister", "microregister", 192, 64)
ARGUMENT = StorageLocation("microregister", "microregister", 448, 32)
CONDITION = StorageLocation("microregister", "microregister", 512, 32)
RETURNED = StorageLocation("microregister", "microregister", 64, 32)


def indirect_snapshot(second=SECOND, *, target_count=2, call_argument_width=32):
    argument_storage = StorageLocation(
        "microregister", "microregister", ARGUMENT.bit_offset, call_argument_width
    )
    call = CallInfo(
        None,
        1,
        (
            Operand(
                "storage",
                call_argument_width,
                storage=argument_storage,
                role="argument",
            ),
        ),
        (),
        32,
        LocationSet((8, 9, 10, 11)),
        LocationSet(),
        1,
        False,
    )
    expression = Operand(
        "expression",
        32,
        operation="m_icall",
        children=(
            Operand(
                "storage",
                16,
                storage=StorageLocation("microregister", "microregister", 1920, 16),
                role="left",
            ),
            Operand("storage", 64, storage=TARGET, role="right"),
            Operand("callinfo", None, call=call, role="destination"),
        ),
        role="left",
    )

    def target_block(index, address):
        source = (
            Operand("address", 64, address=address, role="left")
            if type(address) is int
            else Operand("storage", 64, storage=address, role="left")
        )
        return Block(
            index,
            (0,),
            (
                Instruction(
                    0,
                    "m_mov",
                    (source, Operand("storage", 64, storage=TARGET, role="destination")),
                ),
            ),
        )

    branches = (target_block(1, FIRST), target_block(2, second))
    if target_count == 1:
        branches = branches[:1]
    entry = Block(
        0,
        (),
        (
            Instruction(
                0,
                "m_jnz",
                (
                    Operand("storage", 32, storage=CONDITION, role="left"),
                    Operand("constant", 32, constant=0, role="right"),
                    Operand("block", None, block_index=2, role="destination"),
                ),
            ),
        ),
    )
    merge = Block(
        3,
        tuple(block.index for block in branches),
        (
            Instruction(
                0,
                "m_mov",
                (expression, Operand("storage", 32, storage=RETURNED, role="destination")),
            ),
            Instruction(1, "m_ret", (Operand("storage", 32, storage=RETURNED),)),
        ),
    )
    return snapshot((entry, *branches, merge))


def test_complete_two_target_phi_is_bound_to_exact_indirect_call_site():
    program = build_ssa(indirect_snapshot(), storage_model="memory")
    proof = resolve_finite_indirect_targets(program, 3, 0)
    assert proof is not None
    assert proof.targets == (FIRST, SECOND)
    assert proof.complete is True
    assert proof.reasons == ()
    assert proof.graph_digest == program.graph.graph_digest
    assert proof.caller_snapshot_id == program.graph.snapshot.snapshot_id
    assert proof.proof_digest.startswith("sha256-v1:")
    assert resolve_finite_indirect_targets(program, 3, 1) is None


def test_unknown_branch_retains_known_candidate_but_not_completeness():
    unknown = StorageLocation("microregister", "microregister", 2048, 64)
    program = build_ssa(indirect_snapshot(unknown), storage_model="memory")
    proof = resolve_finite_indirect_targets(program, 3, 0)
    assert proof is not None
    assert proof.targets == (FIRST,)
    assert proof.complete is False
    assert "unknown_target_value" in proof.reasons


def test_candidate_and_node_budgets_never_truncate_into_a_complete_set():
    program = build_ssa(indirect_snapshot(), storage_model="memory")
    candidate_limited = resolve_finite_indirect_targets(program, 3, 0, max_candidates=1)
    assert candidate_limited is not None
    assert candidate_limited.targets == (FIRST,)
    assert candidate_limited.complete is False
    assert "candidate_budget" in candidate_limited.reasons
    node_limited = resolve_finite_indirect_targets(program, 3, 0, max_nodes=2)
    assert node_limited is not None
    assert node_limited.complete is False
    assert "node_budget" in node_limited.reasons


def test_direct_call_metadata_is_not_reinterpreted_as_indirect_candidates():
    source = indirect_snapshot()
    block = source.function.blocks[3]
    instruction = block.instructions[0]
    expression = instruction.operands[0]
    info = expression.children[2].call
    assert info is not None
    altered = replace(
        expression,
        children=(
            *expression.children[:2],
            replace(expression.children[2], call=replace(info, callee_ea=FIRST)),
        ),
    )
    blocks = list(source.function.blocks)
    blocks[3] = replace(block, instructions=(replace(instruction, operands=(altered, *instruction.operands[1:])), *block.instructions[1:]))
    program = build_ssa(snapshot(tuple(blocks)), storage_model="memory")
    assert resolve_finite_indirect_targets(program, 3, 0) is None


def _callee_at(ea, *, constant=False):
    source = callee()
    if constant:
        block = source.function.blocks[0]
        source = snapshot(
            (
                replace(
                    block,
                    instructions=(
                        block.instructions[0],
                        Instruction(1, "m_ret", (Operand("constant", 32, constant=7),)),
                    ),
                ),
            )
        )
    function = replace(source.function, function_id="function-entry:" + str(ea))
    identity = replace(
        source.identity,
        function_id=function.function_id,
        input_digest=digest(function),
    )
    return Snapshot(identity, function, identity.snapshot_id)


def test_every_typed_candidate_return_is_joined_under_exact_identity():
    caller = indirect_snapshot()
    call = caller.function.blocks[3].instructions[0].operands[0].children[2].call
    assert call is not None
    targets = resolve_finite_indirect_targets(build_ssa(caller, storage_model="memory"), 3, 0)
    assert targets is not None and targets.complete
    callees = {FIRST: _callee_at(FIRST), SECOND: _callee_at(SECOND, constant=True)}
    effect = derive_finite_indirect_return(caller, callees, call, targets)
    assert effect is not None
    assert effect.target_eas == (FIRST, SECOND)
    assert effect.argument_indices == (0,)
    assert effect.memory_effects == "none"
    assert DerivedIndirectReturnEffect.from_data(effect.to_data()) == effect
    program = build_ssa(
        caller, storage_model="memory", derived_indirect_returns=(effect,)
    )
    entry = next(
        item for item in program.entry_storage if item.storage == ARGUMENT
    )
    result = analyze(program.graph, (Seed(entry.node_id, Labels(("X",))),))
    returned = next(node for node in program.graph.nodes if node.kind == "Return")
    fact = next(item for item in result.facts if item.node_id == returned.node_id)
    assert fact.labels.explicit == ("X",)
    assert not fact.labels.unknown_provenance
    assert any(
        node.kind == "CallResult"
        and node.operation == "derived_static_finite_indirect_return"
        for node in program.graph.nodes
    )
    with pytest.raises(ContractError, match="target proof"):
        build_ssa(
            caller,
            storage_model="memory",
            derived_indirect_returns=(
                replace(effect, target_proof_digest=digest("forged")),
            ),
        )


def test_all_constant_candidates_produce_no_argument_label():
    caller = indirect_snapshot()
    call = caller.function.blocks[3].instructions[0].operands[0].children[2].call
    targets = resolve_finite_indirect_targets(build_ssa(caller, storage_model="memory"), 3, 0)
    assert call is not None and targets is not None
    callees = {
        FIRST: _callee_at(FIRST, constant=True),
        SECOND: _callee_at(SECOND, constant=True),
    }
    effect = derive_finite_indirect_return(caller, callees, call, targets)
    assert effect is not None and effect.argument_indices == ()
    program = build_ssa(caller, storage_model="memory", derived_indirect_returns=(effect,))
    entry = next(item for item in program.entry_storage if item.storage == ARGUMENT)
    result = analyze(program.graph, (Seed(entry.node_id, Labels(("X",))),))
    returned = next(node for node in program.graph.nodes if node.kind == "Return")
    fact = next(item for item in result.facts if item.node_id == returned.node_id)
    assert "X" not in fact.labels.explicit
    assert not fact.labels.unknown_provenance


def test_selector_controls_joined_constant_return_without_false_clean():
    caller = indirect_snapshot()
    call = caller.function.blocks[3].instructions[0].operands[0].children[2].call
    targets = resolve_finite_indirect_targets(build_ssa(caller, storage_model="memory"), 3, 0)
    assert call is not None and targets is not None
    effect = derive_finite_indirect_return(
        caller,
        {
            FIRST: _callee_at(FIRST, constant=True),
            SECOND: _callee_at(SECOND, constant=True),
        },
        call,
        targets,
    )
    assert effect is not None
    bundle = build_memory_graph(caller, derived_indirect_returns=(effect,))
    seeds = seeds_for_entry(bundle.program, CONDITION, Labels(("SELECTOR",)))
    result = analyze_implicit(bundle.program, seeds, memory_model=bundle)
    returned = next(node for node in bundle.graph.nodes if node.kind == "Return")
    labels = next(item.labels for item in result.facts if item.node_id == returned.node_id)
    assert labels.explicit == ()
    assert labels.control == ("SELECTOR",)
    assert not labels.unknown_provenance


def test_unknown_seed_on_dispatch_value_is_not_silently_discarded():
    caller = indirect_snapshot()
    call = caller.function.blocks[3].instructions[0].operands[0].children[2].call
    targets = resolve_finite_indirect_targets(build_ssa(caller, storage_model="memory"), 3, 0)
    assert call is not None and targets is not None
    effect = derive_finite_indirect_return(
        caller,
        {
            FIRST: _callee_at(FIRST, constant=True),
            SECOND: _callee_at(SECOND, constant=True),
        },
        call,
        targets,
    )
    assert effect is not None
    bundle = build_memory_graph(caller, derived_indirect_returns=(effect,))
    seeds = (
        *seeds_for_entry(bundle.program, CONDITION, Labels(("SELECTOR",))),
        Seed(targets.target_node_id, Labels(unknown_provenance=True)),
    )
    result = analyze_implicit(bundle.program, seeds, memory_model=bundle)
    returned = next(node for node in bundle.graph.nodes if node.kind == "Return")
    labels = next(item.labels for item in result.facts if item.node_id == returned.node_id)
    assert labels.control == ("SELECTOR",)
    assert labels.unknown_provenance


def test_wider_call_register_maps_only_proven_low_formal_bits():
    caller = indirect_snapshot(call_argument_width=64)
    call = caller.function.blocks[3].instructions[0].operands[0].children[2].call
    targets = resolve_finite_indirect_targets(build_ssa(caller, storage_model="memory"), 3, 0)
    assert call is not None and targets is not None
    callees = {FIRST: _callee_at(FIRST), SECOND: _callee_at(SECOND, constant=True)}
    effect = derive_finite_indirect_return(caller, callees, call, targets)
    assert effect is not None
    assert [item.to_data() for item in effect.argument_slices] == [
        {"argument_index": 0, "bit_offset": 0, "width_bits": 32}
    ]
    bundle = build_memory_graph(caller, derived_indirect_returns=(effect,))
    entry = next(
        item for item in bundle.program.entry_storage
        if item.storage.bit_offset == ARGUMENT.bit_offset
        and item.storage.width_bits == 64
    )
    result = analyze_implicit(
        bundle.program,
        (
            BitSeed(entry.node_id, Labels(("LOW",)), 0, 32),
            BitSeed(entry.node_id, Labels(("HIGH",)), 32, 32),
        ),
        memory_model=bundle,
    )
    returned = next(node for node in bundle.graph.nodes if node.kind == "Return")
    labels = next(item.labels for item in result.facts if item.node_id == returned.node_id)
    assert labels.explicit == ("LOW",)
    assert not labels.unknown_provenance


def test_missing_stale_or_incomplete_candidate_never_yields_joined_effect():
    caller = indirect_snapshot()
    call = caller.function.blocks[3].instructions[0].operands[0].children[2].call
    assert call is not None
    targets = resolve_finite_indirect_targets(build_ssa(caller, storage_model="memory"), 3, 0)
    assert targets is not None
    first = _callee_at(FIRST)
    second = _callee_at(SECOND)
    assert derive_finite_indirect_return(caller, {FIRST: first}, call, targets) is None
    foreign_identity = replace(
        second.identity, binary_digest=digest("different_binary")
    )
    foreign = Snapshot(foreign_identity, second.function, foreign_identity.snapshot_id)
    assert (
        derive_finite_indirect_return(
            caller, {FIRST: first, SECOND: foreign}, call, targets
        )
        is None
    )
    unknown = StorageLocation("microregister", "microregister", 2048, 64)
    partial_caller = indirect_snapshot(unknown)
    partial_call = partial_caller.function.blocks[3].instructions[0].operands[0].children[2].call
    partial_targets = resolve_finite_indirect_targets(
        build_ssa(partial_caller, storage_model="memory"), 3, 0
    )
    assert partial_call is not None and partial_targets is not None
    assert not partial_targets.complete
    assert (
        derive_finite_indirect_return(
            partial_caller, {FIRST: first}, partial_call, partial_targets
        )
        is None
    )
