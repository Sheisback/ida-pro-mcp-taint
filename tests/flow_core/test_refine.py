"""A08: default refinement equals v1, links are exact, solver opt-in only."""

import pytest

from ida_pro_mcp.flow_core.contracts import Block, Operand
from ida_pro_mcp.flow_core.path_conditions import (
    PathSelector,
    path_bindings,
    prove_path,
)
from ida_pro_mcp.flow_core.path_symbolic import (
    FEASIBLE_SYMBOLIC,
    INFEASIBLE_SMT_BOUNDED,
    derive_symbolic_path_query,
    replay_witness,
    conjunction,
)
from ida_pro_mcp.flow_core.proof import validate_proof_result
from ida_pro_mcp.flow_core.refine import (
    RefinementSpec,
    check_refined_memory_artifact,
    check_refined_path_artifact,
    decode_witness,
    refine_memory_proof,
    refine_path_proof,
    refinement_agreement,
)
from ida_pro_mcp.flow_core.serialization import digest
from ida_pro_mcp.flow_core.ssa import build_ssa
from ida_pro_mcp.flow_core.symbolic import Z3Backend
from test_ssa import const, ins, reg, snapshot

needs_z3 = pytest.mark.skipif(
    not Z3Backend().available, reason="z3-solver extra not installed"
)


class ExplodingBackend:
    """Any solver touch fails the no-solver-by-default tests."""

    available = True
    timeout_ms = 5000

    def __getattr__(self, _name):
        raise AssertionError("solver touched with default refinement spec")


def branch_graph(left=None, *, bits=8, opcode="m_jz"):
    left = left if left is not None else const(3, bits=bits)
    return build_ssa(
        snapshot(
            (
                Block(
                    0,
                    (),
                    (
                        ins(
                            0,
                            opcode,
                            left,
                            const(3, bits=bits, role="right"),
                            Operand("block", None, block_index=1, role="destination"),
                        ),
                    ),
                ),
                Block(1, (0,), ()),
                Block(2, (0,), ()),
            )
        )
    ).graph


def vanishing_graph():
    # (x ^ x) == 1 never holds; v1 cannot see through the xor.
    return build_ssa(
        snapshot(
            (
                Block(
                    0,
                    (),
                    (
                        ins(0, "m_xor", reg(bits=32), reg(bits=32, role="right"),
                            reg(64, 32, "destination")),
                        ins(
                            1,
                            "m_jz",
                            reg(64, 32),
                            const(1, bits=32, role="right"),
                            Operand("block", None, block_index=1, role="destination"),
                        ),
                    ),
                ),
                Block(1, (0,), ()),
                Block(2, (0,), ()),
            )
        )
    ).graph


def test_default_refinement_equals_v1_feasible():
    graph = branch_graph()
    selector = PathSelector(path_bindings(graph), (0, 1))
    expected_query, expected = prove_path(graph, selector)
    validate_proof_result(expected_query, expected)
    artifact = refine_path_proof(
        graph, selector, RefinementSpec(), backend=ExplodingBackend()
    )
    check_refined_path_artifact(artifact)
    assert artifact["original"] is None
    assert artifact["baseline"]["status"] == expected.status == "feasible"
    assert artifact["baseline"]["result_digest"] == digest(expected.to_data())
    assert artifact["baseline"]["query_digest"] == expected_query.query_digest
    assert artifact["baseline"]["unresolved"] == list(expected.unresolved)
    assert artifact["refined"] == {
        "attempted": False,
        "status": "unknown",
        "reason": "solver_not_invoked",
    }
    assert artifact["agreement"] == "consistent"
    assert artifact["target_executed"] is False
    assert artifact["no_auto_vulnerability_verdict"] is True


def test_default_refinement_equals_v1_unknown():
    graph = vanishing_graph()
    selector = PathSelector(path_bindings(graph), (0, 1))
    _query, expected = prove_path(graph, selector)
    assert expected.status == "unknown"
    artifact = refine_path_proof(
        graph, selector, RefinementSpec(), backend=ExplodingBackend()
    )
    assert artifact["baseline"]["status"] == "unknown"
    assert artifact["baseline"]["result_digest"] == digest(expected.to_data())
    assert artifact["refined"]["attempted"] is False


def test_original_link_cross_checked():
    graph = branch_graph()
    selector = PathSelector(path_bindings(graph), (0, 1))
    query, result = prove_path(graph, selector)
    original = {
        "artifact_id": "artifact-original",
        "query": query.to_data(),
        "proof": result.to_data(),
    }
    artifact = refine_path_proof(
        graph, selector, RefinementSpec(), original=original
    )
    link = artifact["original"]
    assert link["artifact_id"] == "artifact-original"
    assert link["query_digest"] == query.query_digest
    assert link["result_digest"] == digest(result.to_data())
    assert link["status"] == result.status
    # A tampered original must refuse, not silently rebaseline.
    tampered_proof = dict(result.to_data())
    tampered_proof["assignments_checked"] = tampered_proof["assignments_checked"] + 1
    tampered = {
        "artifact_id": "artifact-original",
        "query": query.to_data(),
        "proof": tampered_proof,
    }
    with pytest.raises(Exception, match="refine_baseline_mismatch"):
        refine_path_proof(graph, selector, RefinementSpec(), original=tampered)


def test_refinement_agreement_matrix():
    assert refinement_agreement("feasible", FEASIBLE_SYMBOLIC) == "consistent"
    assert refinement_agreement("infeasible", INFEASIBLE_SMT_BOUNDED) == "consistent"
    assert refinement_agreement("unknown", "unknown") == "consistent"
    assert refinement_agreement("unknown", FEASIBLE_SYMBOLIC) == "refined"
    assert refinement_agreement("unknown", INFEASIBLE_SMT_BOUNDED) == "refined"
    assert refinement_agreement("feasible", "unknown") == "consistent"
    assert refinement_agreement("feasible", INFEASIBLE_SMT_BOUNDED) == "contradiction"
    assert refinement_agreement("infeasible", FEASIBLE_SYMBOLIC) == "contradiction"


@needs_z3
def test_symbolic_refinement_can_settle_v1_unknown():
    graph = vanishing_graph()
    selector = PathSelector(path_bindings(graph), (0, 1))
    artifact = refine_path_proof(
        graph,
        selector,
        RefinementSpec(symbolic_path=True),
        backend=Z3Backend(),
    )
    check_refined_path_artifact(artifact)
    assert artifact["baseline"]["status"] == "unknown"
    assert artifact["refined"]["attempted"] is True
    assert artifact["refined"]["status"] == INFEASIBLE_SMT_BOUNDED
    assert artifact["refined"]["solver_stamp"]
    assert artifact["agreement"] == "refined"


@needs_z3
def test_refined_witness_hex_round_trip_and_replay():
    graph = branch_graph(reg(bits=64), bits=64)
    selector = PathSelector(path_bindings(graph), (0, 1))
    artifact = refine_path_proof(
        graph,
        selector,
        RefinementSpec(symbolic_path=True),
        backend=Z3Backend(),
    )
    assert artifact["refined"]["status"] == FEASIBLE_SYMBOLIC
    encoded = artifact["refined"]["witness"]
    assert encoded
    assert all(
        item["value_hex"].startswith("0x") for item in encoded
    )
    query, unresolved, _translated = derive_symbolic_path_query(graph, selector)
    assert not unresolved
    assert replay_witness(conjunction(query.predicates), decode_witness(encoded))


def test_symbolic_requested_without_solver_stays_unknown():
    graph = branch_graph()
    selector = PathSelector(path_bindings(graph), (0, 1))
    artifact = refine_path_proof(
        graph,
        selector,
        RefinementSpec(symbolic_path=True),
        backend=None,
    )
    assert artifact["baseline"]["status"] == "feasible"
    assert artifact["refined"]["attempted"] is True
    assert artifact["refined"]["status"] == "unknown"
    assert "solver_unavailable" in artifact["refined"]["unresolved"]
    assert artifact["agreement"] == "consistent"


def _mem_plan(instructions, blocks=None):
    from test_memory_symbolic import plan as make_plan

    return make_plan(instructions, blocks=blocks)


def test_default_memory_refinement_quotes_v1_verbatim():
    from test_memory import obj, ptrseed, run
    from test_memory_symbolic import access_ids, load, reg, store

    memory_plan, graph = _mem_plan((
        store(0, reg(8, 8), reg(0, 64, "destination")),
        load(1, bits=8, address=reg(0, 64, "right")),
    ))
    stores, loads = access_ids(memory_plan, graph)
    first, second = obj(memory_plan, key="A"), obj(memory_plan, key="B")
    facts = run(memory_plan, (first, second),
                (ptrseed(memory_plan, first, register=0),))
    assert facts.dependencies, "v1 fixture must yield candidate objects"
    selector = PathSelector(path_bindings(graph), (0,))
    artifact = refine_memory_proof(
        memory_plan,
        graph,
        facts,
        selector,
        loads[0],
        stores[0],
        RefinementSpec(),
        backend=ExplodingBackend(),
    )
    check_refined_memory_artifact(artifact)
    assert artifact["load_id"] == loads[0]
    assert artifact["store_id"] == stores[0]
    baseline = artifact["baseline"]
    assert baseline["result_digest"] == digest(facts.to_data())
    assert baseline["plan_digest"] == facts.plan_digest == memory_plan.plan_digest
    pair = {loads[0], stores[0]}
    assert baseline["facts"] == [
        item.to_data() for item in facts.facts if item.node_id in pair
    ]
    assert baseline["dependencies"] == [
        item.to_data()
        for item in facts.dependencies
        if item.source in pair or item.target in pair
    ]
    assert artifact["refined"] == {
        "attempted": False,
        "status": "unknown",
        "reason": "solver_not_invoked",
    }


@needs_z3
def test_symbolic_memory_refinement_records_forwarding():
    from test_memory import obj, ptrseed, run
    from test_memory_symbolic import access_ids, load, reg, store

    memory_plan, graph = _mem_plan((
        store(0, reg(8, 8), reg(0, 64, "destination")),
        load(1, bits=8, address=reg(0, 64, "right")),
    ))
    stores, loads = access_ids(memory_plan, graph)
    first, second = obj(memory_plan, key="A"), obj(memory_plan, key="B")
    facts = run(memory_plan, (first, second),
                (ptrseed(memory_plan, first, register=0),))
    selector = PathSelector(path_bindings(graph), (0,))
    artifact = refine_memory_proof(
        memory_plan,
        graph,
        facts,
        selector,
        loads[0],
        stores[0],
        RefinementSpec(symbolic_memory=True),
        backend=Z3Backend(),
    )
    check_refined_memory_artifact(artifact)
    assert artifact["refined"]["attempted"] is True
    assert artifact["refined"]["status"] == "must_forward_value_bounded_v1"
    assert artifact["refined"]["overlap"] == "must_overlap"
    assert artifact["refined"]["value_forward"] is True
    assert artifact["refined"]["solver_stamp"]


def test_memory_refinement_rejects_plan_drift():
    from test_memory import obj, ptrseed, run
    from test_memory_symbolic import access_ids, load, reg, store

    memory_plan, graph = _mem_plan((
        store(0, reg(8, 8), reg(0, 64, "destination")),
        load(1, bits=8, address=reg(0, 64, "right")),
    ))
    stores, loads = access_ids(memory_plan, graph)
    first, second = obj(memory_plan, key="A"), obj(memory_plan, key="B")
    facts = run(memory_plan, (first, second),
                (ptrseed(memory_plan, first, register=0),))
    other_plan, _other_graph = _mem_plan((
        store(0, reg(8, 8), reg(16, 64, "destination")),
        load(1, bits=8, address=reg(16, 64, "right")),
    ))
    selector = PathSelector(path_bindings(graph), (0,))
    with pytest.raises(Exception, match="refine_plan_mismatch"):
        refine_memory_proof(
            other_plan,
            graph,
            facts,
            selector,
            loads[0],
            stores[0],
            RefinementSpec(),
        )


def test_refinement_spec_rejects_bad_budgets():
    with pytest.raises(Exception, match="invalid_refinement_timeout"):
        RefinementSpec(solver_timeout_ms=0)
    with pytest.raises(Exception, match="invalid_refinement_timeout"):
        RefinementSpec(solver_timeout_ms=120001)
    from ida_pro_mcp.flow_core.serialization import ContractError

    with pytest.raises(ContractError):
        RefinementSpec(symbolic_path="yes")
    with pytest.raises(ContractError):
        RefinementSpec.from_data(
            {"symbolic_path": 1, "symbolic_memory": False,
             "solver_timeout_ms": 5000, "schema_version": 1}
        )
