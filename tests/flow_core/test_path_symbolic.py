"""Symbolic wide path proofs: tiers, Phi/Select, A04, hostile, v1 agreement."""

import pytest

from ida_pro_mcp.flow_core import ContractError
from ida_pro_mcp.flow_core.contracts import Block, Operand
from ida_pro_mcp.flow_core.path_conditions import (
    PathSelector,
    path_bindings,
    prove_path,
)
from ida_pro_mcp.flow_core.path_symbolic import (
    FEASIBLE_SYMBOLIC,
    INFEASIBLE_SMT_BOUNDED,
    prove_symbolic_path,
    validate_symbolic_result,
)
from ida_pro_mcp.flow_core.proof import StaleProofEvidenceError
from ida_pro_mcp.flow_core.serialization import digest
from ida_pro_mcp.flow_core.ssa import build_ssa
from ida_pro_mcp.flow_core.symbolic import Z3Answer, Z3Backend
from test_ssa import const, ins, reg, snapshot

needs_z3 = pytest.mark.skipif(
    not Z3Backend().available, reason="z3-solver extra not installed"
)


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


def prove(graph, *blocks, **kwargs):
    return prove_symbolic_path(
        graph, PathSelector(path_bindings(graph), blocks), **kwargs
    )


@needs_z3
def test_wide_input_both_directions_feasible():
    graph = branch_graph(reg(bits=64), bits=64)
    _, taken = prove(graph, 0, 1, backend=Z3Backend())
    _, missed = prove(graph, 0, 2, backend=Z3Backend())
    assert taken.status == FEASIBLE_SYMBOLIC
    assert missed.status == FEASIBLE_SYMBOLIC
    assert taken.witness and missed.witness
    # v1 cannot do this at all.
    _, legacy = prove_path(graph, PathSelector(path_bindings(graph), (0, 1)))
    assert legacy.status == "unknown"


@needs_z3
def test_contradictory_correlated_64bit_guards_bounded_infeasible():
    def branch(opcode, target):
        return ins(
            0,
            opcode,
            reg(bits=64),
            const(3, bits=64, role="right"),
            Operand("block", None, block_index=target, role="destination"),
        )

    graph = build_ssa(
        snapshot(
            (
                Block(0, (), (branch("m_jz", 1),)),
                Block(1, (0,), (branch("m_jnz", 3),)),
                Block(2, (0, 1), ()),
                Block(3, (1,), ()),
            )
        )
    ).graph
    query, proof = prove(graph, 0, 1, 3, backend=Z3Backend())
    assert proof.status == INFEASIBLE_SMT_BOUNDED
    assert proof.status != "infeasible"
    assert proof.solver_stamp.startswith("solver_derived_v1:")
    assert proof.refutation_predicate_ids == tuple(
        item.constraint_id for item in query.predicates
    )
    validate_symbolic_result(query, proof)


@needs_z3
def test_v1_and_symbolic_agree_where_both_defined():
    graph = branch_graph()
    mapping = {"feasible": FEASIBLE_SYMBOLIC, "infeasible": INFEASIBLE_SMT_BOUNDED}
    for target in (1, 2):
        _, legacy = prove_path(graph, PathSelector(path_bindings(graph), (0, target)))
        _, refined = prove(graph, 0, target, backend=Z3Backend())
        assert refined.status == mapping[legacy.status]


@needs_z3
def test_a04_vanishing_influence_is_bounded_infeasible():
    # (x ^ x) == 1 can never hold at 32 bits: influence of x vanishes.
    graph = build_ssa(
        snapshot(
            (
                Block(
                    0,
                    (),
                    (
                        ins(
                            0, "m_xor",
                            reg(bits=32), reg(bits=32, role="right"),
                            dest=reg(32, bits=32, role="destination"),
                        ),
                        ins(
                            1, "m_jz",
                            reg(32, bits=32), const(1, bits=32, role="right"),
                            Operand("block", None, block_index=1, role="destination"),
                        ),
                    ),
                ),
                Block(1, (0,), ()),
                Block(2, (0,), ()),
            )
        )
    ).graph
    query, taken = prove(graph, 0, 1, backend=Z3Backend())
    assert taken.status == INFEASIBLE_SMT_BOUNDED
    assert taken.evidence_ids
    assert query.predicates[0].origin_id in {n.node_id for n in graph.nodes}
    _, missed = prove(graph, 0, 2, backend=Z3Backend())
    assert missed.status == FEASIBLE_SYMBOLIC


@needs_z3
def test_a04_remaining_influence_stays_feasible_with_provenance():
    # (x + 1) == 42 at 32 bits: x genuinely matters, both sides feasible.
    graph = build_ssa(
        snapshot(
            (
                Block(
                    0,
                    (),
                    (
                        ins(
                            0, "m_add",
                            reg(bits=32), const(1, bits=32, role="right"),
                            dest=reg(32, bits=32, role="destination"),
                        ),
                        ins(
                            1, "m_jz",
                            reg(32, bits=32), const(42, bits=32, role="right"),
                            Operand("block", None, block_index=1, role="destination"),
                        ),
                    ),
                ),
                Block(1, (0,), ()),
                Block(2, (0,), ()),
            )
        )
    ).graph
    _, taken = prove(graph, 0, 1, backend=Z3Backend())
    _, missed = prove(graph, 0, 2, backend=Z3Backend())
    assert taken.status == missed.status == FEASIBLE_SYMBOLIC
    assert taken.witness and missed.witness


@needs_z3
def test_a04_results_are_path_scoped_never_promoted():
    graph = branch_graph(reg(bits=32), bits=32)
    query_taken, taken = prove(graph, 0, 1, backend=Z3Backend())
    query_missed, missed = prove(graph, 0, 2, backend=Z3Backend())
    for result in (taken, missed):
        assert result.scope == "path_prefix_only"
        assert "bounded" in result.status or "symbolic" in result.status
    assert taken.path_blocks == (0, 1)
    assert missed.path_blocks == (0, 2)
    assert query_taken.query_digest != query_missed.query_digest


@needs_z3
def test_phi_selected_predecessor_resolves():
    def branch(index, target, left):
        return ins(
            index, "m_jz", left, const(3, role="right"),
            Operand("block", None, block_index=target, role="destination"),
        )

    graph = build_ssa(
        snapshot(
            (
                Block(0, (), (branch(0, 1, reg(16)),)),
                Block(1, (0,), (ins(0, "m_mov", const(3), dest=reg(role="destination")),)),
                Block(2, (0,), (ins(0, "m_mov", const(4), dest=reg(role="destination")),)),
                Block(3, (1, 2), (branch(0, 4, reg()),)),
                Block(4, (3,), ()),
                Block(5, (3,), ()),
            )
        )
    ).graph
    assert any(n.kind == "Phi" for n in graph.nodes)
    _, taken = prove(graph, 0, 1, 3, 4, backend=Z3Backend())
    assert taken.status == FEASIBLE_SYMBOLIC
    _, missed = prove(graph, 0, 1, 3, 5, backend=Z3Backend())
    assert missed.status == INFEASIBLE_SMT_BOUNDED
    # v1 stays unknown on the same Phi dependency.
    _, legacy = prove_path(graph, PathSelector(path_bindings(graph), (0, 1, 3, 4)))
    assert legacy.status == "unknown"


@needs_z3
def test_select_in_prefix_resolves_exactly():
    from ida_pro_mcp.flow_core.contracts import Instruction

    select = Instruction(
        0, "m_select",
        (reg(16), reg(0, role="right"), reg(8, role="argument"),
         reg(24, role="destination")),
    )
    graph = build_ssa(
        snapshot(
            (
                Block(
                    0, (),
                    (
                        select,
                        ins(
                            1, "m_jz", reg(24), const(3, role="right"),
                            Operand("block", None, block_index=1, role="destination"),
                        ),
                    ),
                ),
                Block(1, (0,), ()),
                Block(2, (0,), ()),
            )
        )
    ).graph
    assert any(n.kind == "Select" for n in graph.nodes)
    _, proof = prove(graph, 0, 1, backend=Z3Backend())
    assert proof.status == FEASIBLE_SYMBOLIC
    _, legacy = prove_path(graph, PathSelector(path_bindings(graph), (0, 1)))
    assert legacy.status == "unknown"


class StubBackend:
    backend_version = "stub-backend-v1"

    def __init__(self, answer=None, *, available=True, timeout_ms=5):
        self._answer = answer
        self._available = available
        self._timeout_ms = timeout_ms

    @property
    def available(self):
        return self._available

    @property
    def timeout_ms(self):
        return self._timeout_ms

    def check_nonzero(self, expression):
        return self._answer


def test_missing_backend_cancel_and_budget_are_unknown():
    graph = branch_graph(reg(), bits=8)
    _, proof = prove(graph, 0, 1, backend=None)
    assert proof.status == "unknown"
    assert "solver_unavailable" in proof.unresolved
    _, proof = prove(graph, 0, 1, backend=StubBackend(), cancelled=lambda: True)
    assert proof.status == "unknown"
    assert "cancelled" in proof.unresolved
    stub = StubBackend(timeout_ms=99999)
    _, proof = prove(graph, 0, 1, backend=stub, timeout_ms=5)
    assert proof.status == "unknown"
    assert "solver_timeout_exceeds_job_budget" in proof.unresolved


def test_solver_unknown_passthrough_never_definite():
    graph = branch_graph(reg(), bits=8)
    stub = StubBackend(Z3Answer("unknown", reason="solver_unknown"))
    _, proof = prove(graph, 0, 1, backend=stub)
    assert proof.status == "unknown"
    assert "solver_unknown" in proof.unresolved


def test_unsupported_effect_blocks_definite():
    graph = build_ssa(
        snapshot(
            (
                Block(0, (), (ins(0, "m_call", const(0)),
                              ins(
                                  1, "m_jz", const(3), const(3, role="right"),
                                  Operand("block", None, block_index=1,
                                          role="destination"),
                              ))),
                Block(1, (0,), ()),
                Block(2, (0,), ()),
            )
        )
    ).graph
    _, proof = prove(graph, 0, 1, backend=StubBackend())
    assert proof.status == "unknown"
    assert "unsupported_path_effect" in proof.unresolved


@needs_z3
def test_timeout_value_reaches_solver_stamp():
    graph = branch_graph(reg(), bits=8)
    _, proof = prove(graph, 0, 1, backend=Z3Backend(timeout_ms=7), timeout_ms=9)
    assert proof.status == FEASIBLE_SYMBOLIC
    assert "timeout_ms=7" in proof.solver_stamp
    assert proof.solver_timeout_ms == 9


@needs_z3
def test_validate_rejects_stale_and_forged_results():
    from dataclasses import replace

    graph = branch_graph(reg(), bits=8)
    query, proof = prove(graph, 0, 1, backend=Z3Backend())
    assert proof.status == FEASIBLE_SYMBOLIC
    validate_symbolic_result(query, proof)
    with pytest.raises(StaleProofEvidenceError):
        validate_symbolic_result(
            query, replace(proof, query_digest=digest("foreign")))
    with pytest.raises(StaleProofEvidenceError):
        validate_symbolic_result(query, replace(proof, assumptions=()))
    with pytest.raises(StaleProofEvidenceError):
        validate_symbolic_result(
            query, replace(proof, path_blocks=(0, 2)))
    forged_witness = tuple(
        replace(item, value=(item.value + 1) & 0xFF) for item in proof.witness)
    with pytest.raises(ContractError):
        validate_symbolic_result(query, replace(proof, witness=forged_witness))
    with pytest.raises(ContractError):
        validate_symbolic_result(query, replace(proof, evidence_ids=()))
    const_graph = branch_graph()
    const_query, refuted = prove(const_graph, 0, 2, backend=Z3Backend())
    assert refuted.status == INFEASIBLE_SMT_BOUNDED
    validate_symbolic_result(const_query, refuted)
    with pytest.raises(StaleProofEvidenceError):
        validate_symbolic_result(query, refuted)
    with pytest.raises(ContractError):
        validate_symbolic_result(
            const_query, replace(refuted, refutation_predicate_ids=()))
