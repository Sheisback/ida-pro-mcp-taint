"""Z3 backend: stamped answers, witness replay, A01, hostile paths."""

import builtins
from types import SimpleNamespace as NS

import pytest

from ida_pro_mcp.flow_core.symbolic import (
    SymExpr,
    SymbolicMissingDependency,
    Z3Answer,
    Z3Backend,
    replay_witness,
    translate_node,
)

needs_z3 = pytest.mark.skipif(
    not Z3Backend().available, reason="z3-solver extra not installed"
)


def const(value, width):
    return SymExpr("const", width, value=value)


def var(name, width):
    return SymExpr("var", width, name=name)


def op(name, width, *children):
    return SymExpr("op", width, op=name, children=children)


@needs_z3
def test_sat_witness_replays_through_oracle():
    # (x + 1 == 42) with x free: SAT, witness must replay nonzero.
    expr = op("eq", 1, op("add", 32, var("x", 32), const(1, 32)), const(42, 32))
    answer = Z3Backend().check_nonzero(expr)
    assert answer.status == "sat"
    assert answer.stamp.startswith("solver_derived_v1:")
    assert replay_witness(expr, answer.model)


@needs_z3
def test_unsat_is_stamped_and_bounded():
    expr = op("eq", 1, op("xor", 8, var("x", 8), var("x", 8)), const(1, 8))
    answer = Z3Backend().check_nonzero(expr)
    assert answer.status == "unsat"
    assert answer.stamp.startswith("solver_derived_v1:")
    assert "timeout_ms=" in answer.stamp


@needs_z3
def test_unknown_expr_is_unknown_not_unsat():
    expr = op(
        "eq", 1,
        SymExpr("unknown", 8, reason="probe"),
        const(0, 8),
    )
    answer = Z3Backend().check_nonzero(expr)
    assert answer.status == "unknown"
    assert answer.reason


@needs_z3
def test_a01_same_microcode_meaning_same_smt():
    # Identical op structure from different origins (evidence/blocks differ,
    # node ids shared): the translator ignores origin, SMT must be identical.
    def program():
        return {
            "x": NS(kind="InputValue", width_bits=32, operation=None,
                    inputs=(), constant=None),
            "k": NS(kind="Constant", width_bits=32, operation=None,
                    inputs=(), constant=7),
            "a": NS(kind="Binary", width_bits=32, operation="add",
                    inputs=("x", "k"), constant=None),
            "c": NS(kind="Compare", width_bits=1, operation="ugt",
                    inputs=("a", "k"), constant=None),
        }

    left = translate_node(program(), "c").roots[0]
    right = translate_node(program(), "c").roots[0]
    backend = Z3Backend()
    assert backend.smt2(left) == backend.smt2(right)


def test_missing_dependency_is_explicit():
    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name == "z3":
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)

    import unittest.mock as mock

    with mock.patch.object(builtins, "__import__", side_effect=blocked):
        assert not Z3Backend().available
        with pytest.raises(SymbolicMissingDependency):
            Z3Backend().check_nonzero(const(1, 1))


def test_replay_rejects_unknown_and_bad_models():
    from ida_pro_mcp.flow_core.symbolic import SymBinding

    expr = op("eq", 1, var("x", 8), const(3, 8))
    assert not replay_witness(expr, ())
    assert not replay_witness(expr, (SymBinding("x", 8, 4),))
    assert replay_witness(expr, (SymBinding("x", 8, 3),))
    unk = SymExpr("unknown", 8, reason="probe")
    assert not replay_witness(unk, ())


def test_definite_answers_require_stamp():
    from ida_pro_mcp.flow_core.symbolic import SymBinding

    with pytest.raises(Exception):
        Z3Answer("sat", model=(SymBinding("x", 8, 1),), stamp="")
    with pytest.raises(Exception):
        Z3Answer("unsat", stamp="")
    assert Z3Answer("unknown").status == "unknown"


@needs_z3
def test_unreadable_sat_model_is_unknown_not_job_failure():
    import unittest.mock as mock

    from ida_pro_mcp.flow_core.symbolic import MalformedSolverResponse

    expr = op("eq", 1, op("add", 32, var("x", 32), const(1, 32)), const(42, 32))
    backend = Z3Backend()
    with mock.patch.object(
        Z3Backend,
        "read_model",
        side_effect=MalformedSolverResponse("unreadable model: probe"),
    ):
        answer = backend.check_nonzero(expr)
    assert answer.status == "unknown"
    assert answer.reason is not None and "solver_error" in answer.reason
    assert answer.model == ()
