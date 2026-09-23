"""Independent implicit-flow fixtures; no engine-output golden oracle."""

from dataclasses import replace
import json
from pathlib import Path
from typing import Literal

import pytest

from ida_pro_mcp.flow_core import ContractError, canonical_json, digest
from ida_pro_mcp.flow_core.analysis import Seed, analyze
from ida_pro_mcp.flow_core.contracts import Block, FunctionInput, Instruction, Operand
from ida_pro_mcp.flow_core.implicit_analysis import (
    ImplicitPolicy,
    ImplicitResult,
    analyze_implicit,
)
from ida_pro_mcp.flow_core.implicit_cfg import (
    ImplicitCFG,
    ImplicitCFGPolicy,
    analyze_implicit_cfg,
)
from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
from ida_pro_mcp.flow_core.ssa import SSAProgram, build_ssa
from ida_pro_mcp.flow_core.states import Labels, StorageLocation
from ida_pro_mcp.flow_core.contracts import Snapshot
from test_memory import const as memory_const
from test_memory import load as memory_load
from test_memory import plan as memory_plan
from test_memory import reg as memory_reg
from test_memory import ret as memory_ret
from test_memory import store as memory_store

ROOT = Path(__file__).resolve().parents[2]


def reg(offset: int = 0, bits: int = 8, role: str = "left") -> Operand:
    return Operand(
        "storage",
        bits,
        storage=StorageLocation("scalar", "bank", offset, bits),
        role=role,
    )


def const(value: int, bits: int = 8, role: str = "left") -> Operand:
    return Operand("constant", bits, constant=value, role=role)


def ins(
    index: int,
    opcode: str,
    left: Operand,
    right: Operand | None = None,
    dest: Operand | None = None,
) -> Instruction:
    return Instruction(
        index, opcode, tuple(item for item in (left, right, dest) if item is not None)
    )


def snapshot(blocks: tuple[Block, ...]) -> Snapshot:
    base = Snapshot.from_data(
        json.loads(
            (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
        )["snapshot"]
    )
    blocks = tuple(
        replace(
            block,
            successors=tuple(
                candidate.index
                for candidate in blocks
                if block.index in candidate.predecessors
            ),
        )
        for block in blocks
    )
    function = FunctionInput("implicit-test", 0, blocks)
    identity = replace(
        base.identity, function_id=function.function_id, input_digest=digest(function)
    )
    return Snapshot(identity, function, identity.snapshot_id)


def entry_seed(program: SSAProgram, offset: int, label: str) -> Seed:
    entry = next(
        item for item in program.entry_storage if item.storage.bit_offset == offset
    )
    return Seed(entry.node_id, Labels((label,)))


def definitions(
    program: SSAProgram, block: int, kind: str | None = None
) -> tuple[str, ...]:
    nodes = {node.node_id: node for node in program.graph.nodes}
    return tuple(
        item.node_id
        for item in program.definitions
        if item.block == block and (kind is None or nodes[item.node_id].kind == kind)
    )


def branch(program: SSAProgram, block: int) -> tuple[str, str, tuple[str, ...]]:
    node_id = definitions(program, block, "Branch")[0]
    node = next(node for node in program.graph.nodes if node.node_id == node_id)
    assert len(node.inputs) == 1
    return node_id, node.inputs[0], node.evidence_ids


def result(
    program: SSAProgram,
    seeds: tuple[Seed, ...],
    policy: ImplicitPolicy = ImplicitPolicy(),
    *,
    control: ImplicitCFG | None = None,
) -> ImplicitResult:
    return analyze_implicit(
        program,
        tuple(sorted(seeds, key=lambda seed: seed.node_id)),
        policy,
        control,
    )


def facts(value: ImplicitResult) -> dict[str, Labels]:
    return {fact.node_id: fact.labels for fact in value.facts}


def returned(program: SSAProgram, value: ImplicitResult) -> Labels:
    node_id = next(
        node.node_id for node in program.graph.nodes if node.kind == "Return"
    )
    return facts(value)[node_id]


def test_t01_predicate_controls_clean_assignment_without_explicit_flow():
    program = build_ssa(
        snapshot(
            (
                Block(0, (), (ins(0, "m_jcnd", reg(0)),)),
                Block(
                    1,
                    (0,),
                    (ins(0, "m_mov", const(1), dest=reg(8, role="destination")),),
                ),
                Block(2, (0,), ()),
                Block(3, (1, 2), (ins(0, "m_ret", reg(8)),)),
            )
        )
    )
    value = result(program, (entry_seed(program, 0, "P"),))
    assigned = definitions(program, 1, "Constant")[0]
    assert facts(value)[assigned].explicit == ()
    assert facts(value)[assigned].control == ("P",)
    assert returned(program, value).explicit == ()
    assert returned(program, value).control == ("P",)
    assert any(
        relation.predicate_node_id == branch(program, 0)[1]
        and relation.target_node_id == assigned
        and relation.branch_node_id == branch(program, 0)[0]
        and relation.successor_block == 1
        for relation in value.relations
    )


def test_t02_postdominator_join_ends_injection_for_independent_assignment():
    program = build_ssa(
        snapshot(
            (
                Block(
                    0,
                    (),
                    (
                        ins(0, "m_mov", const(9), dest=reg(24, role="destination")),
                        ins(1, "m_jcnd", reg(0)),
                    ),
                ),
                Block(1, (0,), ()),
                Block(2, (0,), ()),
                Block(
                    3,
                    (1, 2),
                    (
                        ins(0, "m_mov", const(7), dest=reg(8, role="destination")),
                        ins(1, "m_ret", reg(8)),
                    ),
                ),
            )
        )
    )
    value = result(
        program,
        (entry_seed(program, 0, "P"),),
    )
    assert returned(program, value) == Labels()
    assert all(
        relation.target_node_id not in definitions(program, 3)
        for relation in value.relations
    )


def test_t03_nested_predicates_are_ordered_and_attributed_independently():
    program = build_ssa(
        snapshot(
            (
                Block(0, (), (ins(0, "m_jcnd", reg(0)),)),
                Block(1, (0,), (ins(0, "m_jcnd", reg(8)),)),
                Block(
                    2,
                    (1,),
                    (ins(0, "m_mov", const(1), dest=reg(16, role="destination")),),
                ),
                Block(3, (1,), ()),
                Block(
                    4,
                    (2, 3),
                    (ins(0, "m_mov", const(2), dest=reg(24, role="destination")),),
                ),
                Block(5, (0, 4), (ins(0, "m_ret", reg(24)),)),
            )
        )
    )
    value = result(
        program,
        (entry_seed(program, 0, "OUTER"), entry_seed(program, 8, "INNER")),
    )
    inner_assignment = definitions(program, 2, "Constant")[0]
    outer_assignment = definitions(program, 4, "Constant")[0]
    assert facts(value)[inner_assignment].control == ("INNER", "OUTER")
    assert facts(value)[outer_assignment].control == ("OUTER",)
    assert facts(value)[branch(program, 1)[0]].control == ("OUTER",)
    assert tuple(relation.sort_key for relation in value.relations) == tuple(
        sorted(relation.sort_key for relation in value.relations)
    )
    assert {
        (relation.predicate_node_id, relation.branch_node_id, relation.successor_block)
        for relation in value.relations
        if relation.target_node_id == inner_assignment
    } == {
        (branch(program, 1)[1], branch(program, 1)[0], 2),
    }
    assert any(
        relation.predicate_node_id == branch(program, 0)[1]
        and relation.branch_node_id == branch(program, 0)[0]
        and relation.target_node_id == branch(program, 1)[0]
        for relation in value.relations
    )


def test_t04_phi_keeps_control_label_after_region_end():
    program = build_ssa(
        snapshot(
            (
                Block(0, (), (ins(0, "m_jcnd", reg(0)),)),
                Block(
                    1,
                    (0,),
                    (ins(0, "m_mov", const(1), dest=reg(8, role="destination")),),
                ),
                Block(
                    2,
                    (0,),
                    (ins(0, "m_mov", const(2), dest=reg(8, role="destination")),),
                ),
                Block(3, (1, 2), (ins(0, "m_ret", reg(8)),)),
            )
        )
    )
    value = result(
        program,
        (entry_seed(program, 0, "P"),),
    )
    phi = definitions(program, 3, "Phi")[0]
    assert facts(value)[phi].explicit == ()
    assert facts(value)[phi].control == ("P",)
    assert returned(program, value).control == ("P",)


@pytest.mark.parametrize(
    "case,expected_diagnostic",
    (
        ("unknown_terminal", "unknown_exit_coverage"),
        ("closed_loop", "nonreturning_cfg_region"),
        ("cfg_budget", "iteration_budget_exceeded:terminal_reachability"),
    ),
)
def test_t05_actual_partial_certificates_never_publish_clean_no_flow(
    case: str, expected_diagnostic: str
):
    if case == "unknown_terminal":
        program = build_ssa(
            snapshot(
                (
                    Block(0, (), (ins(0, "m_jcnd", reg(0)),)),
                    Block(
                        1,
                        (0,),
                        (
                            ins(
                                0,
                                "m_mov",
                                const(1),
                                dest=reg(8, role="destination"),
                            ),
                        ),
                    ),
                    Block(2, (0,), ()),
                    Block(
                        3,
                        (1, 2),
                        (
                            ins(
                                0,
                                "m_mov",
                                reg(8),
                                dest=reg(16, role="destination"),
                            ),
                        ),
                    ),
                )
            )
        )
        control = analyze_implicit_cfg(program)
    else:
        program = build_ssa(
            snapshot(
                (
                    Block(0, (), (ins(0, "m_jcnd", reg(0)),)),
                    Block(1, (0, 1), (ins(0, "m_jcnd", reg(0)),)),
                    Block(2, (0,), (ins(0, "m_ret", reg(8)),)),
                )
            )
        )
        control = analyze_implicit_cfg(
            program,
            ImplicitCFGPolicy(max_iterations=3)
            if case == "cfg_budget"
            else ImplicitCFGPolicy(),
        )
    value = result(
        program,
        (entry_seed(program, 0, "P"),),
        control=control,
    )
    affected = tuple(
        definition.node_id
        for definition in program.definitions
        if definition.block in control.frontier
    )
    assert control.status == "partial" and control.frontier and control.diagnostics
    assert value.status == "partial" and value.frontier and value.diagnostics
    assert expected_diagnostic in value.diagnostics
    assert affected
    assert all(node_id in value.frontier for node_id in affected)
    assert all(
        facts(value)[node_id].any_control_source
        and facts(value)[node_id].unknown_provenance
        for node_id in affected
    )


def test_t05_empty_structural_frontier_taints_downstream_not_clean():
    empty_frontier = build_ssa(
        snapshot(
            (
                Block(0, (), (ins(0, "m_jcnd", reg(0)),)),
                Block(1, (0,), ()),
                Block(2, (0,), ()),
                Block(
                    3,
                    (1, 2),
                    (
                        ins(0, "m_mov", const(7), dest=reg(8, role="destination")),
                        ins(1, "m_ret", reg(8)),
                    ),
                ),
            )
        )
    )
    complete = analyze_implicit_cfg(empty_frontier)
    partial = replace(
        complete,
        frontier=(1,),
        status="partial",
        diagnostics=("hostile_empty_block_frontier",),
    )
    empty_value = result(empty_frontier, (), control=partial)
    assert returned(empty_frontier, empty_value).any_control_source
    assert returned(empty_frontier, empty_value).unknown_provenance


def test_select_condition_injects_control_but_not_explicit_payload():
    program = build_ssa(
        snapshot(
            (
                Block(
                    0,
                    (),
                    (
                        Instruction(
                            0,
                            "m_select",
                            (
                                reg(0),
                                const(1, role="right"),
                                const(2, role="argument"),
                                reg(8, role="destination"),
                            ),
                        ),
                        ins(1, "m_ret", reg(8)),
                    ),
                ),
            )
        )
    )
    value = result(program, (entry_seed(program, 0, "P"),))
    assert returned(program, value).explicit == ()
    assert returned(program, value).control == ("P",)
    assert any(relation.origin == "select" for relation in value.relations)


def test_control_labels_follow_memory_data_but_not_address_relations():
    program = build_ssa(
        snapshot(
            (
                Block(
                    0,
                    (),
                    (
                        ins(0, "m_mov", reg(0), dest=reg(8, role="destination")),
                        ins(1, "m_ret", reg(8)),
                    ),
                ),
            )
        )
    )
    copy = definitions(program, 0, "Copy")[0]
    source = next(
        edge.source
        for edge in program.graph.edges
        if edge.target == copy and edge.kind == "value_dependency"
    )
    seed = Seed(source, Labels(control=("C",)))

    def with_edge(
        kind: Literal["memory_data_dependency", "address_dependency"],
    ) -> SSAProgram:
        edges = tuple(
            sorted(
                [
                    replace(edge, kind=kind)
                    if edge.source == source and edge.target == copy
                    else edge
                    for edge in program.graph.edges
                ],
                key=lambda edge: edge.edge_id,
            )
        )
        return replace(program, graph=replace(program.graph, edges=edges))

    memory_program = with_edge("memory_data_dependency")
    memory = result(memory_program, (seed,))
    assert facts(memory)[copy].control == ("C",)
    assert facts(memory)[copy].explicit == ()

    address_program = with_edge("address_dependency")
    address = result(address_program, (seed,))
    assert facts(address)[copy].control == ()


def test_verified_memory_data_carries_explicit_labels_without_pointer_bleed():
    base = memory_plan(
        (
            memory_store(0, memory_reg(192, 8)),
            memory_load(1),
            memory_ret(2),
        )
    )
    bundle = build_memory_graph(base.program.graph.snapshot)
    program = bundle.program
    nodes = {node.node_id: node for node in bundle.graph.nodes}
    load_id = next(node.node_id for node in bundle.graph.nodes if node.kind == "Load")
    return_id = next(
        node.node_id for node in bundle.graph.nodes if node.kind == "Return"
    )
    reaching = [
        edge
        for edge in bundle.graph.edges
        if edge.kind == "memory_data_dependency" and edge.target == load_id
    ]
    assert len(reaching) == 1
    assert nodes[reaching[0].source].kind == "Store"
    assert reaching[0].axes.precision == "exact"
    assert reaching[0].memory_rule_id == "byte-reaching-store-v1"

    data_seed = entry_seed(program, 192, "DATA")
    address_seed = entry_seed(program, 0, "ADDRESS")
    store_seed = Seed(reaching[0].source, Labels(("STORED_BYTES",)))
    for evaluate in (
        lambda seeds: {
            fact.node_id: fact.labels for fact in analyze(bundle.graph, seeds).facts
        },
        lambda seeds: facts(result(program, seeds)),
    ):
        data = evaluate((data_seed,))
        assert data[load_id].explicit == ("DATA",)
        assert data[return_id].explicit == ("DATA",)
        assert data[load_id].unknown_provenance

        address = evaluate((address_seed,))
        assert address[load_id].explicit == ()
        assert address[return_id].explicit == ()
        assert address[load_id].unknown_provenance

        directly_seeded_store = evaluate((store_seed,))
        assert directly_seeded_store[load_id].explicit == ("STORED_BYTES",)
        assert directly_seeded_store[return_id].explicit == ("STORED_BYTES",)


def test_memory_labels_require_bound_derivation_and_stop_at_overwrite():
    base = memory_plan(
        (memory_store(0, memory_reg(192, 8)), memory_load(1), memory_ret(2))
    )
    bundle = build_memory_graph(base.program.graph.snapshot)
    memory_edge = next(
        edge
        for edge in bundle.graph.edges
        if edge.kind == "memory_data_dependency"
        and edge.memory_rule_id == "byte-reaching-store-v1"
    )
    unbound = replace(
        memory_edge,
        memory_object_id=None,
        memory_rule_id=None,
        width_bits=None,
        interval=None,
    )
    graph = replace(
        bundle.graph,
        edges=tuple(
            sorted(
                (
                    unbound if edge == memory_edge else edge
                    for edge in bundle.graph.edges
                ),
                key=lambda edge: edge.edge_id,
            )
        ),
    )
    program = replace(bundle.program, graph=graph)
    seed = entry_seed(program, 192, "DATA")
    unverified = result(program, (seed,))
    assert facts(unverified)[memory_edge.target].explicit == ()
    assert facts(unverified)[memory_edge.target].unknown_provenance

    overwritten = memory_plan(
        (
            memory_store(0, memory_reg(192, 8)),
            memory_store(1, memory_const(0)),
            memory_load(2),
            memory_ret(3),
        )
    )
    final = build_memory_graph(overwritten.program.graph.snapshot)
    output = result(final.program, (entry_seed(final.program, 192, "DATA"),))
    assert returned(final.program, output).explicit == ()


def test_roundtrip_cache_separation_budget_and_stale_certificate():
    program = build_ssa(
        snapshot(
            (
                Block(0, (), (ins(0, "m_jcnd", reg(0)),)),
                Block(
                    1,
                    (0,),
                    (ins(0, "m_mov", const(1), dest=reg(8, role="destination")),),
                ),
                Block(2, (0,), ()),
                Block(3, (1, 2), (ins(0, "m_ret", reg(8)),)),
            )
        )
    )
    seed = entry_seed(program, 0, "P")
    control = analyze_implicit_cfg(program)
    value = result(program, (seed,), control=control)
    assert ImplicitResult.from_json(canonical_json(value)) == value
    assert result(program, (seed,), control=control) == value
    assert digest(result(program, (seed,), control=control)) == digest(value)
    changed_source = result(program, (entry_seed(program, 0, "Q"),))
    changed_policy = result(program, (seed,), ImplicitPolicy(1))
    changed_control = result(
        program,
        (seed,),
        control=replace(
            control, policy=ImplicitCFGPolicy(max_iterations=control.iterations + 1)
        ),
    )
    assert (
        len(
            {
                value.cache_key,
                changed_source.cache_key,
                changed_policy.cache_key,
                changed_control.cache_key,
            }
        )
        == 4
    )
    assert changed_policy.status == "partial" and changed_policy.frontier
    assert returned(program, changed_policy).any_control_source

    changed_program = build_ssa(
        snapshot(
            (
                Block(0, (), (ins(0, "m_jcnd", reg(0)),)),
                Block(
                    1,
                    (0,),
                    (ins(0, "m_mov", const(2), dest=reg(8, role="destination")),),
                ),
                Block(2, (0,), ()),
                Block(3, (1, 2), (ins(0, "m_ret", reg(8)),)),
            )
        )
    )
    assert result(
        changed_program, (entry_seed(changed_program, 0, "P"),)
    ).cache_key != (value.cache_key)
    with pytest.raises(ContractError, match="Stale implicit CFG certificate"):
        result(
            changed_program,
            (entry_seed(changed_program, 0, "P"),),
            control=control,
        )


@pytest.mark.parametrize(
    "location,expected",
    (
        ("top_frontier", "frontier block"),
        ("controlled", "controlled block"),
        ("region_frontier", "region frontier block"),
        ("unreachable_frontier", "frontier block"),
    ),
)
def test_forged_control_block_ids_fail_closed_before_frontier_walk(
    location: str, expected: str
):
    program = build_ssa(
        snapshot(
            (
                Block(0, (), (ins(0, "m_jcnd", reg(0)),)),
                Block(1, (0,), ()),
                Block(2, (0,), ()),
                Block(3, (1, 2), (ins(0, "m_ret", reg(8)),)),
                Block(4, (), ()),
            )
        )
    )
    control = analyze_implicit_cfg(program)
    out_of_range = len(program.graph.snapshot.function.blocks)
    if location == "top_frontier":
        forged = replace(
            control,
            status="partial",
            frontier=(out_of_range,),
            diagnostics=("forged",),
        )
    elif location == "unreachable_frontier":
        forged = replace(
            control,
            status="partial",
            frontier=(4,),
            diagnostics=("forged",),
        )
    else:
        first = control.regions[0]
        if location == "controlled":
            first = replace(first, controlled_blocks=(out_of_range,))
        else:
            first = replace(
                first,
                status="partial",
                frontier=(out_of_range,),
                diagnostics=("forged",),
            )
        forged = replace(control, regions=(first,) + control.regions[1:])
    with pytest.raises(ContractError, match=expected):
        result(program, (), control=forged)


def test_checkpoints_do_not_change_certificates_or_labels():
    program = build_ssa(snapshot((Block(0, (), (ins(0, "m_ret", reg(0)),)),)))
    checkpoints = []

    def checkpoint():
        checkpoints.append(None)

    control = analyze_implicit_cfg(program)
    assert analyze_implicit_cfg(program, checkpoint=checkpoint) == control
    assert checkpoints
    checkpoints.clear()
    expected = analyze_implicit(program)
    assert analyze_implicit(program, checkpoint=checkpoint) == expected
    assert analyze_implicit(program, control=control, checkpoint=checkpoint) == expected
    assert checkpoints
