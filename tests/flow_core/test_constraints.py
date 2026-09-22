"""Independent fixed-width contract/evaluator tests for the bounded proof core."""

from dataclasses import replace
import itertools

import pytest

from ida_pro_mcp.flow_core import ContractError, canonical_json, digest, stable_id
from ida_pro_mcp.flow_core.constraints import (
    ConstraintAssignment,
    ConstraintBindings,
    ConstraintBudgetError,
    ConstraintExpression,
    ConstraintQuery,
    ConstraintVariable,
    DeclaredCoverage,
    PathConstraint,
    ProofAssumption,
    ProofBounds,
    ProofBudget,
    UnsupportedConstraintError,
    evaluate_constraint_query,
    evaluate_expression,
    exhaustive_evaluation_size,
    finite_domain_size,
    query_evaluation_cost,
    variable_domain_digest,
)


def const(width: int, value: int) -> ConstraintExpression:
    return ConstraintExpression("constant", width, value=value)


def var(width: int, name: str) -> ConstraintExpression:
    return ConstraintExpression("variable", width, variable=name)


def binary(
    width: int, operator: str, left: ConstraintExpression, right: ConstraintExpression
) -> ConstraintExpression:
    operands = (left, right)
    if operator in {"add", "mul", "bit_and", "bit_or", "bit_xor"}:
        operands = tuple(sorted(operands, key=canonical_json))
    return ConstraintExpression("binary", width, operator=operator, operands=operands)


def comparison(
    constraint_id: str,
    left: ConstraintExpression,
    predicate: str,
    right: ConstraintExpression,
    *,
    expected: bool = True,
) -> PathConstraint:
    return PathConstraint(
        constraint_id,
        left,
        predicate,  # type: ignore[arg-type]
        right,
        "signed" if predicate.startswith("s") else None,
        expected,
        "rule:test",
        "origin:test",
        (stable_id("evidence", constraint_id),),
    )


def sample_query(
    *,
    variables: tuple[ConstraintVariable, ...] | None = None,
    constraints: tuple[PathConstraint, ...] | None = None,
    budget: ProofBudget | None = None,
) -> ConstraintQuery:
    if variables is None:
        variables = (
            ConstraintVariable("x", 4, tuple(range(16))),
            ConstraintVariable("y", 4, tuple(range(16))),
        )
    if constraints is None:
        constraints = (
            comparison(
                "c:add",
                binary(4, "add", var(4, "x"), var(4, "y")),
                "eq",
                const(4, 0),
            ),
            comparison("c:signed", var(4, "x"), "slt", var(4, "y")),
        )
    operators = set()

    def collect(expression: ConstraintExpression) -> None:
        if expression.operator is not None:
            operators.add(expression.operator)
        for operand in expression.operands:
            collect(operand)

    for constraint in constraints:
        operators.add(constraint.predicate)
        collect(constraint.left)
        collect(constraint.right)
    d = digest("binding")
    return ConstraintQuery(
        ConstraintBindings(stable_id("snapshot", "s"), d, d, d, (digest("summary"),)),
        variables,
        constraints,
        (ProofAssumption("analysis", "maturity", "MMAT_GLBOPT3"),),
        ProofBounds(3, 2),
        budget or ProofBudget(256, 10_000, 1_000, 32),
        DeclaredCoverage(
            "fixed_width_bitvectors",
            tuple(item.name for item in variables),
            variable_domain_digest(variables),
            tuple(item.constraint_id for item in constraints),
            tuple(sorted(operators)),
        ),
    )


def test_query_roundtrip_digests_and_freshness_bindings_are_stable():
    query = sample_query()
    restored = ConstraintQuery.from_json(canonical_json(query))
    assert restored == query
    assert restored.budget.timeout_ms == 1_000
    assert restored.query_digest == query.query_digest
    assert restored.cache_key == query.cache_key
    assert replace(query, bounds=ProofBounds(4, 2)).query_digest != query.query_digest
    changed = replace(
        query,
        bindings=replace(query.bindings, profile_digest=digest("other-profile")),
    )
    assert changed.query_digest != query.query_digest
    assert changed.cache_key != query.cache_key


@pytest.mark.parametrize(
    "build",
    [
        lambda: ConstraintVariable("x", 0, (0,)),
        lambda: ConstraintVariable("x", 65, (0,)),
        lambda: ConstraintVariable("x", 2, (0, 0)),
        lambda: ConstraintVariable("x", 2, (1, 0)),
        lambda: ConstraintVariable("x", 2, (4,)),
        lambda: ConstraintExpression("constant", 2, value=4),
        lambda: ConstraintExpression("constant", 2, value=1, variable="x"),
        lambda: ConstraintExpression("variable", 2, variable=""),
        lambda: ConstraintExpression("unary", 2, operator="neg", operands=()),
        lambda: ConstraintExpression(
            "binary", 2, operator="sub", operands=(const(2, 0),)
        ),
        lambda: ConstraintExpression(
            "unary", 2, operator="add", operands=(const(2, 0),)
        ),
        lambda: ConstraintAssignment("x", 2, 4),
        lambda: ProofBounds(-1, 0),
        lambda: ProofBudget(0, 1, 1),
        lambda: ProofBudget(1, 1, 0),
    ],
)
def test_hostile_scalar_contracts_are_rejected(build):
    with pytest.raises(ContractError):
        build()


def test_noncanonical_expression_constraint_and_query_sets_are_rejected():
    left, right = var(4, "x"), var(4, "y")
    ordered = tuple(sorted((left, right), key=canonical_json))
    with pytest.raises(ContractError, match="Commutative"):
        ConstraintExpression("binary", 4, operator="add", operands=ordered[::-1])
    with pytest.raises(ContractError, match="Signedness"):
        replace(comparison("c", left, "slt", right), signedness=None)
    with pytest.raises(ContractError, match="Signedness"):
        replace(comparison("c", left, "ult", right), signedness="signed")
    with pytest.raises(ContractError, match="evidence"):
        replace(comparison("c", left, "eq", right), evidence_ids=("bad",))

    query = sample_query()
    with pytest.raises(ContractError, match="sorted"):
        replace(query, variables=query.variables[::-1])
    with pytest.raises(ContractError, match="sorted"):
        replace(query, constraints=query.constraints[::-1])
    with pytest.raises(ContractError, match="Coverage operator"):
        replace(query, coverage=replace(query.coverage, operators=("eq",)))
    with pytest.raises(ContractError, match="Coverage variable domain"):
        replace(
            query,
            coverage=replace(query.coverage, variable_domain_digest=digest("wrong")),
        )
    with pytest.raises(ContractError, match="undeclared"):
        replace(
            query,
            constraints=(comparison("c:z", var(4, "z"), "eq", const(4, 0)),),
            coverage=replace(
                query.coverage,
                constraint_ids=("c:z",),
                operators=("eq",),
            ),
        )


def test_expression_depth_is_rejected_at_schema_boundary_before_recursion_overflow():
    query = sample_query()
    expression = var(4, "x")
    for _ in range(128):
        expression = ConstraintExpression(
            "unary", 4, operator="neg", operands=(expression,)
        )
    constraint = comparison("c:deep", expression, "eq", const(4, 0))
    with pytest.raises(ContractError, match="schema depth"):
        replace(
            query,
            constraints=(constraint,),
            coverage=replace(
                query.coverage,
                constraint_ids=(constraint.constraint_id,),
                operators=("eq", "neg"),
            ),
        )


def test_hostile_deserialization_rejects_extensions_and_duplicates():
    query = sample_query()
    data = query.to_data()
    data["extra"] = True
    with pytest.raises(ContractError, match="Wrong fields"):
        ConstraintQuery.from_data(data)
    raw = canonical_json(query).replace(
        '"schema_version":1', '"schema_version":1,"schema_version":1'
    )
    with pytest.raises(ContractError, match="Duplicate JSON key"):
        ConstraintQuery.from_json(raw)
    data = query.to_data()
    data["bindings"]["summary_digests"] *= 2
    with pytest.raises(ContractError, match="sorted unique"):
        ConstraintQuery.from_data(data)


def test_assignment_domain_accounting_fails_closed_without_narrowing():
    query = sample_query(budget=ProofBudget(256, 100, 1_000, 32))
    assert finite_domain_size(query) == 256
    too_small = replace(query, budget=ProofBudget(255, 100, 1_000, 32))
    with pytest.raises(ConstraintBudgetError, match="Assignment domain"):
        finite_domain_size(too_small)
    assert tuple(len(variable.domain) for variable in too_small.variables) == (16, 16)

    exact_work = replace(query, budget=ProofBudget(256, 2048, 1_000, 32))
    assert query_evaluation_cost(exact_work) == 8
    assert exhaustive_evaluation_size(exact_work) == 2048
    with pytest.raises(ConstraintBudgetError, match="Exhaustive evaluation"):
        exhaustive_evaluation_size(
            replace(exact_work, budget=ProofBudget(256, 2047, 1_000, 32))
        )


def test_constant_only_query_has_one_empty_assignment():
    constraint = comparison("c:false", const(4, 1), "eq", const(4, 0))
    query = sample_query(
        variables=(),
        constraints=(constraint,),
        budget=ProofBudget(1, 3, 1_000, 4),
    )
    assert finite_domain_size(query) == 1
    assert query_evaluation_cost(query) == 3
    assert exhaustive_evaluation_size(query) == 3
    evaluation = evaluate_constraint_query(query, ())
    assert len(evaluation) == 1 and not evaluation[0].satisfied


def test_assignments_must_be_complete_canonical_width_correct_and_in_domain():
    query = sample_query()
    valid = (ConstraintAssignment("x", 4, 0), ConstraintAssignment("y", 4, 0))
    evaluations = evaluate_constraint_query(query, valid)
    assert evaluations[0].satisfied
    assert not evaluations[1].satisfied
    bad_cases = (
        valid[::-1],
        valid[:1],
        valid + (ConstraintAssignment("z", 4, 0),),
        (ConstraintAssignment("x", 3, 0), valid[1]),
    )
    for assignments in bad_cases:
        with pytest.raises(ContractError):
            evaluate_constraint_query(query, assignments)
    restricted = sample_query(
        variables=(ConstraintVariable("x", 4, (0,)), ConstraintVariable("y", 4, (0,)))
    )
    with pytest.raises(ContractError, match="declared domain"):
        evaluate_constraint_query(
            restricted,
            (ConstraintAssignment("x", 4, 1), ConstraintAssignment("y", 4, 0)),
        )


def _signed(value: int, width: int) -> int:
    return value - (1 << width) if value & (1 << (width - 1)) else value


@pytest.mark.parametrize("width", (2, 3, 4))
def test_p06_modular_arithmetic_matches_independent_small_width_oracle(width):
    mask = (1 << width) - 1
    for left, right in itertools.product(range(mask + 1), repeat=2):
        assignments = (
            ConstraintAssignment("x", width, left),
            ConstraintAssignment("y", width, right),
        )
        x, y = var(width, "x"), var(width, "y")
        expected = {
            "add": (left + right) & mask,
            "sub": (left - right) & mask,
            "mul": (left * right) & mask,
            "bit_and": left & right,
            "bit_or": left | right,
            "bit_xor": left ^ right,
        }
        for operator, oracle in expected.items():
            assert (
                evaluate_expression(binary(width, operator, x, y), assignments)
                == oracle
            )
        assert (
            evaluate_expression(
                ConstraintExpression("unary", width, operator="neg", operands=(x,)),
                assignments,
            )
            == (-left) & mask
        )
        assert (
            evaluate_expression(
                ConstraintExpression("unary", width, operator="bit_not", operands=(x,)),
                assignments,
            )
            == (~left) & mask
        )


@pytest.mark.parametrize("width", (2, 3, 4))
def test_p06_signed_and_unsigned_comparisons_use_distinct_oracles(width):
    domain = tuple(range(1 << width))
    predicates = ("eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge")
    constraints = tuple(
        sorted(
            (
                comparison(
                    f"c:{predicate}", var(width, "x"), predicate, var(width, "y")
                )
                for predicate in predicates
            ),
            key=lambda item: item.constraint_id,
        )
    )
    query = sample_query(
        variables=(
            ConstraintVariable("x", width, domain),
            ConstraintVariable("y", width, domain),
        ),
        constraints=constraints,
        budget=ProofBudget(len(domain) ** 2, 100, 1_000, 32),
    )
    for left, right in itertools.product(domain, repeat=2):
        observed = {
            item.predicate: item.actual
            for item in evaluate_constraint_query(
                query,
                (
                    ConstraintAssignment("x", width, left),
                    ConstraintAssignment("y", width, right),
                ),
            )
        }
        signed_left, signed_right = _signed(left, width), _signed(right, width)
        assert observed == {
            "eq": left == right,
            "ne": left != right,
            "ult": left < right,
            "ule": left <= right,
            "ugt": left > right,
            "uge": left >= right,
            "slt": signed_left < signed_right,
            "sle": signed_left <= signed_right,
            "sgt": signed_left > signed_right,
            "sge": signed_left >= signed_right,
        }


def test_shift_and_unknown_operations_fail_as_unsupported_not_guessed():
    assignment = (ConstraintAssignment("x", 4, 8),)
    assert (
        evaluate_expression(binary(4, "lshr", var(4, "x"), const(4, 1)), assignment)
        == 4
    )
    assert (
        evaluate_expression(binary(4, "ashr", var(4, "x"), const(4, 1)), assignment)
        == 12
    )
    with pytest.raises(UnsupportedConstraintError, match="Shift count"):
        evaluate_expression(binary(4, "shl", var(4, "x"), const(4, 4)), assignment)
    with pytest.raises(UnsupportedConstraintError, match="Unsupported binary"):
        evaluate_expression(binary(4, "rotate", var(4, "x"), const(4, 1)), assignment)


def test_evaluation_and_depth_budgets_are_cooperative():
    expression = binary(4, "sub", var(4, "x"), const(4, 1))
    with pytest.raises(ConstraintBudgetError, match="Evaluation"):
        evaluate_expression(
            expression, (ConstraintAssignment("x", 4, 2),), max_evaluations=2
        )
    with pytest.raises(ConstraintBudgetError, match="depth"):
        evaluate_expression(
            expression,
            (ConstraintAssignment("x", 4, 2),),
            max_expression_depth=1,
        )
