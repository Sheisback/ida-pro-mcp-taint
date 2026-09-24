"""Local causal candidates never replace global partial or path proof."""

from dataclasses import replace

import pytest

from ida_pro_mcp.flow_core import ContractError, digest
from ida_pro_mcp.flow_core.analysis import seeds_for_entry
from ida_pro_mcp.flow_core.contracts import Block, Instruction, Operand
from ida_pro_mcp.flow_core.derived_calls import derive_direct_return
from ida_pro_mcp.flow_core.explain import ObservationExplanation, explain_observation
from ida_pro_mcp.flow_core.implicit_analysis import analyze_implicit
from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
from ida_pro_mcp.flow_core.states import Labels, StorageLocation
from test_derived_calls import (
    caller_preserving_stack_across_call,
    constant_callee,
)
from test_ssa import snapshot
from test_memory import load, plan, reg, ret, store


def returned(bundle):
    return next(node for node in bundle.graph.nodes if node.kind == "Return")


def seeded_call(*, pure):
    source, info = caller_preserving_stack_across_call()
    derived = derive_direct_return(source, constant_callee(), info, 0, 2)
    assert derived is not None
    bundle = build_memory_graph(source, derived_returns=(derived,) if pure else ())
    seeds = seeds_for_entry(
        bundle.program,
        StorageLocation("microregister", "microregister", 448, 32),
        Labels(("X",)),
    )
    return bundle, analyze_implicit(bundle.program, seeds, memory_model=bundle)


def test_global_partial_does_not_fabricate_local_unknown_cause():
    bundle, analysis = seeded_call(pure=True)
    explanation = explain_observation(
        bundle.program, bundle, analysis, returned(bundle).node_id
    )
    assert isinstance(explanation, ObservationExplanation)
    assert explanation.analysis_status == "partial"
    assert explanation.labels.explicit == ("X",)
    assert explanation.labels.unknown_provenance is False
    assert explanation.causes == () and explanation.visited_nodes == 0
    assert "partial_scalar_input" in explanation.global_diagnostics
    assert not explanation.truncated
    assert ObservationExplanation.from_data(explanation.to_data()) == explanation


def test_unknown_call_memory_has_bound_local_candidate_and_budget():
    bundle, analysis = seeded_call(pure=False)
    target = returned(bundle).node_id
    explanation = explain_observation(bundle.program, bundle, analysis, target)
    assert explanation.labels.unknown_provenance
    assert explanation.analysis_status == "partial"
    assert explanation.causes
    assert any(
        item.reason_code in {"unknown_memory_effect", "call_boundary"}
        for item in explanation.causes
    )
    node_ids = {node.node_id for node in bundle.graph.nodes}
    edge_ids = {edge.edge_id for edge in bundle.graph.edges}
    assert all(
        item.source_node_id in node_ids
        and item.affected_node_id in node_ids
        and (item.edge_id is None or item.edge_id in edge_ids)
        for item in explanation.causes
    )
    bounded = explain_observation(bundle.program, bundle, analysis, target, max_nodes=1)
    assert bounded.truncated and bounded.visited_nodes == 1
    with pytest.raises(ContractError, match="Invalid explanation budget"):
        explain_observation(bundle.program, bundle, analysis, target, max_nodes=True)
    with pytest.raises(ContractError, match="Explanation graph mismatch"):
        explain_observation(
            bundle.program,
            bundle,
            replace(analysis, graph_digest=digest("foreign-graph")),
            target,
        )


def test_cross_object_may_alias_explains_possible_taint_not_definite_flow():
    value = StorageLocation("microregister", "microregister", 0, 32)
    pointer = StorageLocation("microregister", "microregister", 64, 64)
    spill = StorageLocation("stack", "stack", 0, 32)
    result = StorageLocation("microregister", "microregister", 128, 32)
    source = snapshot(
        (
            Block(
                0,
                (),
                (
                    Instruction(
                        0,
                        "m_mov",
                        (
                            Operand("storage", 32, storage=value, role="left"),
                            Operand("storage", 32, storage=spill, role="destination"),
                        ),
                    ),
                    Instruction(
                        1,
                        "m_ldx",
                        (
                            Operand("constant", 16, constant=0, role="left"),
                            Operand("storage", 64, storage=pointer, role="right"),
                            Operand("storage", 32, storage=result, role="destination"),
                        ),
                    ),
                    Instruction(2, "m_ret", (Operand("storage", 32, storage=result),)),
                ),
            ),
        )
    )
    bundle = build_memory_graph(source)
    seeds = seeds_for_entry(bundle.program, value, Labels(("X",)))
    analysis = analyze_implicit(bundle.program, seeds, memory_model=bundle)
    explanation = explain_observation(
        bundle.program, bundle, analysis, returned(bundle).node_id
    )
    assert explanation.labels.explicit == ("X",)
    assert explanation.labels.unknown_provenance
    alias = [
        item
        for item in explanation.causes
        if item.reason_code == "cross_object_may_alias"
    ]
    assert alias
    assert all(
        item.precision == "may_alias"
        and item.scope == "candidate_structural_backward_slice"
        and item.edge_id is not None
        for item in alias
    )


def test_unknown_dereference_explains_possible_clobber_of_pointer_spill():
    data = StorageLocation("microregister", "bank", 128, 32)
    spill = StorageLocation("stack", "stack", 0, 64)
    source = plan(
        (
            Instruction(
                0,
                "m_mov",
                (
                    reg(0, 64),
                    Operand("storage", 64, storage=spill, role="destination"),
                ),
            ),
            store(1, data=reg(128, 32), address=reg(0, 64, "destination")),
            Instruction(
                2,
                "m_mov",
                (Operand("storage", 64, storage=spill), reg(64, 64, "destination")),
            ),
            load(3, out=256, bits=32, address=reg(64, 64, "right")),
            ret(4, offset=256, bits=32),
        )
    ).program.graph.snapshot
    bundle = build_memory_graph(source)
    seeds = seeds_for_entry(bundle.program, data, Labels(("X",)))
    analysis = analyze_implicit(bundle.program, seeds, memory_model=bundle)
    explanation = explain_observation(
        bundle.program, bundle, analysis, returned(bundle).node_id
    )
    possible_clobbers = {
        (dep.source, dep.target)
        for dep in bundle.result.dependencies
        if dep.precision == "may_alias"
    }

    assert explanation.labels.explicit == ("X",)
    assert explanation.labels.unknown_provenance
    assert "partial_pointer_reload" in bundle.result.diagnostics
    assert any(
        cause.reason_code == "cross_object_may_alias"
        and (cause.source_node_id, cause.affected_node_id) in possible_clobbers
        and cause.edge_id is not None
        and cause.evidence_ids
        for cause in explanation.causes
    )
