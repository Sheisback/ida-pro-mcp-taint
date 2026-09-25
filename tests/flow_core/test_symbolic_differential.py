"""Narrow differential: oracle vs reference evaluator on ≤8-bit overlap (F1)."""

import random

import pytest

from ida_pro_mcp.flow_core.constraints import (
    ConstraintAssignment,
    ConstraintExpression,
    UnsupportedConstraintError,
    evaluate_expression,
)
from ida_pro_mcp.flow_core.serialization import canonical_json
from ida_pro_mcp.flow_core.symbolic import (
    SymExpr,
    UnsupportedSymbolicError,
    evaluate_sym,
)

_ALIASES = {"bit_and": "and", "bit_or": "or", "bit_xor": "xor", "bit_not": "not"}


def to_sym(expression: ConstraintExpression) -> SymExpr:
    if expression.kind == "constant":
        assert expression.value is not None
        return SymExpr("const", expression.width_bits, value=expression.value)
    if expression.kind == "variable":
        assert expression.variable is not None
        return SymExpr("var", expression.width_bits, name=expression.variable)
    assert expression.operator is not None
    op = _ALIASES.get(expression.operator, expression.operator)
    return SymExpr(
        "op", expression.width_bits, op=op,
        children=tuple(to_sym(item) for item in expression.operands),
    )


def _expr(rng, depth, width):
    if depth <= 0 or rng.random() < 0.35:
        if rng.random() < 0.5:
            return ConstraintExpression("variable", width, variable=rng.choice("xy"))
        return ConstraintExpression("constant", width, value=rng.randrange(1 << width))
    unary = rng.random() < 0.25
    if unary:
        op = rng.choice(["bit_not", "neg"])
        return ConstraintExpression(
            "unary", width, operator=op, operands=(_expr(rng, depth - 1, width),))
    op = rng.choice(["add", "sub", "mul", "bit_and", "bit_or", "bit_xor",
                     "shl", "lshr", "ashr"])
    left = _expr(rng, depth - 1, width)
    if op in {"shl", "lshr", "ashr"}:
        # Keep counts in the reference profile so both sides are defined.
        right = ConstraintExpression("constant", width, value=rng.randrange(width))
    else:
        right = _expr(rng, depth - 1, width)
    operands = (left, right)
    if op in {"add", "mul", "bit_and", "bit_or", "bit_xor"}:
        operands = tuple(sorted(operands, key=canonical_json))
    return ConstraintExpression(
        "binary", width, operator=op, operands=operands)


@pytest.mark.parametrize("width", [1, 4, 8])
def test_oracle_matches_reference_on_overlap(width):
    rng = random.Random(0x5EED + width)
    for _ in range(150):
        expression = _expr(rng, 3, width)
        env = {"x": rng.randrange(1 << width), "y": rng.randrange(1 << width)}
        assignments = tuple(
            ConstraintAssignment(name, width, env[name]) for name in ("x", "y"))
        expected = evaluate_expression(expression, assignments)
        assert evaluate_sym(to_sym(expression), env) == expected


def test_overshift_raises_on_both_sides():
    expression = ConstraintExpression(
        "binary", 8, operator="shl",
        operands=(
            ConstraintExpression("constant", 8, value=1),
            ConstraintExpression("constant", 8, value=8),
        ),
    )
    with pytest.raises(UnsupportedConstraintError):
        evaluate_expression(expression, ())
    with pytest.raises(UnsupportedSymbolicError):
        evaluate_sym(to_sym(expression), {})
