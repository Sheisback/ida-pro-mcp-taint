"""Independent structural post-dominance/control-region expectations."""

from dataclasses import replace
import json
from pathlib import Path

import pytest

from ida_pro_mcp.flow_core import ContractError, canonical_json, digest
from ida_pro_mcp.flow_core.contracts import (
    Block,
    FunctionInput,
    Instruction,
    Operand,
    Snapshot,
    StorageLocation,
)
from ida_pro_mcp.flow_core.implicit_cfg import (
    ImplicitCFG,
    ImplicitCFGPolicy,
    analyze_implicit_cfg,
)
from ida_pro_mcp.flow_core.ssa import build_ssa

ROOT = Path(__file__).resolve().parents[2]


def reg(offset=0, bits=8, role="left"):
    return Operand(
        "storage",
        bits,
        storage=StorageLocation("scalar", "bank", offset, bits),
        role=role,
    )


def ins(index, opcode, *operands):
    return Instruction(index, opcode, operands)


def snapshot(blocks):
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
    function = FunctionInput("implicit-cfg-test", 0, blocks)
    identity = replace(
        base.identity,
        function_id=function.function_id,
        input_digest=digest(function),
    )
    return Snapshot(identity, function, identity.snapshot_id)


def diamond():
    return snapshot(
        (
            Block(0, (), (ins(0, "m_jcnd", reg(16)),)),
            Block(1, (0,), ()),
            Block(2, (0,), ()),
            Block(3, (1, 2), (ins(0, "m_ret"),)),
        )
    )


def by_block(result):
    return {block.block: block for block in result.post_dominators}


def test_diamond_post_dominators_and_exact_successor_regions():
    program = build_ssa(diamond())
    result = analyze_implicit_cfg(program)

    assert result.status == "complete"
    assert result.reachable == (0, 1, 2, 3)
    assert result.terminal_blocks == result.return_exits == (3,)
    assert not result.unknown_exits
    assert by_block(result)[0].post_dominators == (0, 3)
    assert by_block(result)[0].immediate == 3
    assert by_block(result)[3].immediate_virtual_exit

    branch = next(node for node in program.graph.nodes if node.kind == "Branch")
    assert [
        (region.successor, region.controlled_blocks) for region in result.regions
    ] == [
        (1, (1,)),
        (2, (2,)),
    ]
    assert all(region.branch_node_id == branch.node_id for region in result.regions)
    assert all(
        region.predicate_node_id == branch.inputs[0] for region in result.regions
    )
    assert all(region.sites[0].block_index == 0 for region in result.regions)
    assert all(region.status == "complete" for region in result.regions)
    assert ImplicitCFG.from_json(canonical_json(result)) == result


def test_nested_regions_are_outer_first_and_keep_predicate_attribution():
    source = snapshot(
        (
            Block(0, (), (ins(0, "m_jcnd", reg(16)),)),
            Block(1, (0,), (ins(0, "m_jcnd", reg(24)),)),
            Block(2, (1,), ()),
            Block(3, (1,), ()),
            Block(4, (0, 2, 3), (ins(0, "m_ret"),)),
        )
    )
    program = build_ssa(source)
    result = analyze_implicit_cfg(program)

    assert result.status == "complete"
    assert [
        (r.ordinal, r.branch_block, r.successor, r.controlled_blocks)
        for r in result.regions
    ] == [
        (0, 0, 1, (1,)),
        (1, 1, 2, (2,)),
        (2, 1, 3, (3,)),
    ]
    predicates = {
        region.branch_block: region.predicate_node_id for region in result.regions
    }
    assert len(set(predicates.values())) == 2


def test_synthetic_branch_evidence_is_preserved_on_each_region():
    branch = replace(ins(0, "m_jcnd", reg()), synthetic=True)
    source = snapshot(
        (
            Block(0, (), (branch,)),
            Block(1, (0,), ()),
            Block(2, (0,), ()),
            Block(3, (1, 2), (ins(0, "m_ret"),)),
        )
    )
    result = analyze_implicit_cfg(build_ssa(source))

    assert result.status == "complete"
    assert all(region.synthetic for region in result.regions)
    assert all(region.evidence_ids for region in result.regions)


def test_multiple_returns_use_virtual_exit_but_stay_partial():
    source = snapshot(
        (
            Block(0, (), (ins(0, "m_jcnd", reg()),)),
            Block(1, (0,), (ins(0, "m_ret"),)),
            Block(2, (0,), (ins(0, "m_ret"),)),
        )
    )
    result = analyze_implicit_cfg(build_ssa(source))

    assert result.status == "partial"
    assert result.return_exits == (1, 2)
    assert "multiple_terminal_exits" in result.diagnostics
    assert result.frontier == result.reachable
    assert by_block(result)[0].immediate_virtual_exit
    assert {region.successor for region in result.regions} == {1, 2}
    assert all(region.status == "partial" for region in result.regions)


def test_unknown_terminal_and_unresolved_branch_are_unknown_coverage():
    source = snapshot(
        (
            Block(0, (), (ins(0, "m_jcnd", reg()),)),
            Block(1, (0,), (ins(0, "m_ret"),)),
            Block(2, (0,), (ins(0, "m_goto"),)),
        )
    )
    result = analyze_implicit_cfg(build_ssa(source))

    assert result.status == "partial"
    assert result.return_exits == (1,)
    assert result.unknown_exits == (2,)
    assert "unknown_terminal:2" in result.diagnostics
    assert "unresolved_branch_successor:2" in result.diagnostics
    assert set(result.frontier) == {0, 1, 2}
    assert all(region.status == "partial" for region in result.regions)


def test_closed_loop_is_not_virtualized_as_a_clean_exit():
    source = snapshot(
        (
            Block(0, (), (ins(0, "m_jcnd", reg()),)),
            Block(1, (0,), (ins(0, "m_ret"),)),
            Block(2, (0, 2), (ins(0, "m_goto"),)),
        )
    )
    result = analyze_implicit_cfg(build_ssa(source))

    assert result.status == "partial"
    assert result.nonreturning_blocks == (2,)
    assert "nonreturning_cfg_region" in result.diagnostics
    assert set(result.frontier) == {0, 1, 2}
    assert tuple(block.block for block in result.post_dominators) == (1,)
    assert any(
        region.successor == 2 and 2 in region.frontier for region in result.regions
    )


def test_ambiguous_branch_nodes_do_not_invent_a_predicate_binding():
    source = snapshot(
        (
            Block(
                0,
                (),
                (ins(0, "m_jcnd", reg()), ins(1, "m_jcnd", reg(8))),
            ),
            Block(1, (0,), ()),
            Block(2, (0,), ()),
            Block(3, (1, 2), (ins(0, "m_ret"),)),
        )
    )
    result = analyze_implicit_cfg(build_ssa(source))

    assert result.status == "partial"
    assert "ambiguous_branch_node:0" in result.diagnostics
    assert all(region.branch_node_id is None for region in result.regions)
    assert all(region.predicate_node_id is None for region in result.regions)
    assert all(region.frontier == (0,) for region in result.regions)


def test_unreachable_blocks_are_classified_without_entering_certificates():
    source = snapshot(
        (
            Block(0, (), (ins(0, "m_ret"),)),
            Block(1, (), (ins(0, "m_ret"),)),
        )
    )
    result = analyze_implicit_cfg(build_ssa(source))

    assert result.reachable == (0,)
    assert result.unreachable == (1,)
    assert tuple(block.block for block in result.post_dominators) == (0,)
    assert result.status == "partial"
    assert "input_graph_partial" in result.diagnostics


@pytest.mark.parametrize(
    "policy,diagnostic",
    [
        (ImplicitCFGPolicy(max_blocks=1), "block_budget_exceeded"),
        (ImplicitCFGPolicy(max_edges=1), "edge_budget_exceeded"),
        (
            ImplicitCFGPolicy(max_iterations=1),
            "iteration_budget_exceeded:reachability",
        ),
    ],
)
def test_budgets_return_partial_frontier_not_empty_no_flow(policy, diagnostic):
    result = analyze_implicit_cfg(build_ssa(diamond()), policy)

    assert result.status == "partial"
    assert diagnostic in result.diagnostics
    assert result.frontier
    assert not result.regions


def test_contract_rejects_duplicate_control_walk_blocks():
    result = analyze_implicit_cfg(build_ssa(diamond()))
    with pytest.raises(ContractError, match="Duplicate"):
        replace(
            result.regions[0],
            controlled_blocks=(1, 1),
        )
