"""Canonical, IDA-independent fixed-width path-constraint contracts.

This module deliberately stops at pure model validation and evaluation.  Solver
answers, witness policy, and public proof-status classification live at the
proof-engine boundary.
"""

from dataclasses import dataclass
from typing import Literal

from .serialization import ContractError, Model, canonical_json, digest
from .states import canonical_set, check_digest, check_id, nonempty, require

MAX_WIDTH_BITS = 64
MAX_EXPRESSION_DEPTH = 128

ExpressionKind = Literal["constant", "variable", "unary", "binary"]
Predicate = Literal["eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge"]
Signedness = Literal["signed"] | None
AssumptionKind = Literal["analysis", "branch", "summary", "environment", "bound"]

_UNARY_OPERATORS = frozenset({"bit_not", "neg"})
_BINARY_OPERATORS = frozenset(
    {
        "add",
        "sub",
        "mul",
        "bit_and",
        "bit_or",
        "bit_xor",
        "shl",
        "lshr",
        "ashr",
    }
)
_COMMUTATIVE_OPERATORS = frozenset({"add", "mul", "bit_and", "bit_or", "bit_xor"})
_SIGNED_PREDICATES = frozenset({"slt", "sle", "sgt", "sge"})


class UnsupportedConstraintError(ContractError):
    """The canonical query uses an operation outside the reference profile."""


class ConstraintBudgetError(ContractError):
    """The declared finite-domain or evaluation budget was exhausted."""


def _width(value: int) -> None:
    require(0 < value <= MAX_WIDTH_BITS, "Unsupported bit-vector width")


def _bit_value(value: int, width_bits: int, label: str) -> None:
    require(0 <= value < (1 << width_bits), f"{label} outside width")


def _canonical_strings(values: tuple[str, ...], label: str) -> None:
    canonical_set(values)
    for value in values:
        nonempty(value)


@dataclass(frozen=True)
class ConstraintVariable(Model):
    name: str
    width_bits: int
    domain: tuple[int, ...]

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.name)
        _width(self.width_bits)
        require(bool(self.domain), "Variable domain must be nonempty")
        require(
            self.domain == tuple(sorted(set(self.domain))),
            "Variable domain must be sorted and unique",
        )
        for value in self.domain:
            _bit_value(value, self.width_bits, "Domain value")


@dataclass(frozen=True)
class ConstraintExpression(Model):
    kind: ExpressionKind
    width_bits: int
    operator: str | None = None
    value: int | None = None
    variable: str | None = None
    operands: tuple["ConstraintExpression", ...] = ()

    def __post_init__(self):
        super().__post_init__()
        _width(self.width_bits)
        if self.kind == "constant":
            require(self.value is not None, "Constant expression requires a value")
            assert self.value is not None
            require(
                self.operator is None and self.variable is None and not self.operands,
                "Constant expression has unexpected payload",
            )
            _bit_value(self.value, self.width_bits, "Constant")
            return
        if self.kind == "variable":
            require(self.variable is not None, "Variable expression requires a name")
            assert self.variable is not None
            nonempty(self.variable)
            require(
                self.operator is None and self.value is None and not self.operands,
                "Variable expression has unexpected payload",
            )
            return
        require(self.operator is not None, "Operator expression requires an operator")
        assert self.operator is not None
        nonempty(self.operator)
        require(
            self.value is None and self.variable is None,
            "Operator expression has scalar payload",
        )
        arity = 1 if self.kind == "unary" else 2
        require(len(self.operands) == arity, f"{self.kind.title()} expression arity")
        if self.operator in _UNARY_OPERATORS | _BINARY_OPERATORS:
            expected_kind = "unary" if self.operator in _UNARY_OPERATORS else "binary"
            require(self.kind == expected_kind, "Operator kind mismatch")
        require(
            all(item.width_bits == self.width_bits for item in self.operands),
            "Expression operand width mismatch",
        )
        if self.operator in _COMMUTATIVE_OPERATORS:
            encoded = tuple(canonical_json(item) for item in self.operands)
            require(
                encoded == tuple(sorted(encoded)), "Commutative operands not canonical"
            )


@dataclass(frozen=True)
class PathConstraint(Model):
    constraint_id: str
    left: ConstraintExpression
    predicate: Predicate
    right: ConstraintExpression
    signedness: Signedness
    expected: bool
    rule_id: str
    origin_id: str
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.constraint_id)
        require(
            self.left.width_bits == self.right.width_bits, "Comparison width mismatch"
        )
        require(
            (self.predicate in _SIGNED_PREDICATES) == (self.signedness == "signed"),
            "Signedness is allowed and required only for signed predicates",
        )
        nonempty(self.rule_id)
        nonempty(self.origin_id)
        canonical_set(self.evidence_ids)
        for evidence_id in self.evidence_ids:
            check_id(evidence_id, "evidence")


@dataclass(frozen=True)
class ConstraintAssignment(Model):
    name: str
    width_bits: int
    value: int

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.name)
        _width(self.width_bits)
        _bit_value(self.value, self.width_bits, "Assignment")


@dataclass(frozen=True)
class ProofAssumption(Model):
    kind: AssumptionKind
    key: str
    value: str
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.key)
        nonempty(self.value)
        canonical_set(self.evidence_ids)
        for evidence_id in self.evidence_ids:
            check_id(evidence_id, "evidence")


@dataclass(frozen=True)
class ProofBounds(Model):
    loop_bound: int
    call_bound: int

    def __post_init__(self):
        super().__post_init__()
        require(self.loop_bound >= 0, "Negative loop bound")
        require(self.call_bound >= 0, "Negative call bound")


@dataclass(frozen=True)
class ProofBudget(Model):
    """Total reference-engine budgets; timeout unit is frozen to milliseconds."""

    max_assignments: int
    max_evaluations: int
    timeout_ms: int
    max_expression_depth: int = 32

    def __post_init__(self):
        super().__post_init__()
        require(self.max_assignments > 0, "Assignment budget must be positive")
        require(self.max_evaluations > 0, "Evaluation budget must be positive")
        require(self.timeout_ms > 0, "Timeout must be positive milliseconds")
        require(
            0 < self.max_expression_depth <= MAX_EXPRESSION_DEPTH,
            "Invalid expression-depth budget",
        )


@dataclass(frozen=True)
class DeclaredCoverage(Model):
    theory: Literal["fixed_width_bitvectors"]
    variable_names: tuple[str, ...]
    variable_domain_digest: str
    constraint_ids: tuple[str, ...]
    operators: tuple[str, ...]
    domains_are_exact: Literal[True] = True
    bounded_only: Literal[True] = True

    def __post_init__(self):
        super().__post_init__()
        _canonical_strings(self.variable_names, "coverage variables")
        check_digest(self.variable_domain_digest)
        _canonical_strings(self.constraint_ids, "coverage constraints")
        _canonical_strings(self.operators, "coverage operators")


@dataclass(frozen=True)
class ConstraintBindings(Model):
    snapshot_id: str
    graph_digest: str
    profile_digest: str
    ruleset_digest: str
    summary_digests: tuple[str, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        check_id(self.snapshot_id, "snapshot")
        for value in (
            self.graph_digest,
            self.profile_digest,
            self.ruleset_digest,
            *self.summary_digests,
        ):
            check_digest(value)
        canonical_set(self.summary_digests)


def variable_domain_digest(variables: tuple[ConstraintVariable, ...]) -> str:
    """Digest the exact declared variable domains in canonical variable order."""
    return digest([item.to_data() for item in variables])


def _walk_expression(
    expression: ConstraintExpression,
    *,
    depth: int = 1,
) -> tuple[tuple[str, int], ...]:
    require(depth <= MAX_EXPRESSION_DEPTH, "Expression tree exceeds schema depth")
    variables = (
        ((expression.variable, expression.width_bits),)
        if expression.variable is not None
        else ()
    )
    for operand in expression.operands:
        variables += _walk_expression(operand, depth=depth + 1)
    return variables


def _expression_depth(expression: ConstraintExpression) -> int:
    if not expression.operands:
        return 1
    return 1 + max(_expression_depth(item) for item in expression.operands)


def _expression_operators(expression: ConstraintExpression) -> tuple[str, ...]:
    values = () if expression.operator is None else (expression.operator,)
    for operand in expression.operands:
        values += _expression_operators(operand)
    return values


@dataclass(frozen=True)
class ConstraintQuery(Model):
    bindings: ConstraintBindings
    variables: tuple[ConstraintVariable, ...]
    constraints: tuple[PathConstraint, ...]
    assumptions: tuple[ProofAssumption, ...]
    bounds: ProofBounds
    budget: ProofBudget
    coverage: DeclaredCoverage
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        require(bool(self.constraints), "Constraint query requires constraints")
        variable_names = tuple(item.name for item in self.variables)
        constraint_ids = tuple(item.constraint_id for item in self.constraints)
        canonical_set(variable_names)
        canonical_set(constraint_ids)
        assumption_keys = tuple(
            (item.kind, item.key, item.value, item.evidence_ids)
            for item in self.assumptions
        )
        require(
            assumption_keys == tuple(sorted(set(assumption_keys))),
            "Assumptions must be sorted and unique",
        )
        declared = {item.name: item.width_bits for item in self.variables}
        operators: set[str] = set()
        for constraint in self.constraints:
            operators.add(constraint.predicate)
            for expression in (constraint.left, constraint.right):
                require(
                    _expression_depth(expression) <= MAX_EXPRESSION_DEPTH,
                    "Expression tree exceeds schema depth",
                )
                for name, width_bits in _walk_expression(expression):
                    require(
                        name in declared, "Expression references undeclared variable"
                    )
                    require(
                        declared[name] == width_bits,
                        "Variable expression width mismatch",
                    )
                operators.update(_expression_operators(expression))
        require(
            self.coverage.variable_names == variable_names,
            "Coverage variable set mismatch",
        )
        require(
            self.coverage.variable_domain_digest
            == variable_domain_digest(self.variables),
            "Coverage variable domain mismatch",
        )
        require(
            self.coverage.constraint_ids == constraint_ids,
            "Coverage constraint set mismatch",
        )
        require(
            self.coverage.operators == tuple(sorted(operators)),
            "Coverage operator set mismatch",
        )

    @property
    def query_digest(self) -> str:
        return digest(self)

    @property
    def cache_key(self) -> str:
        return digest(
            {
                "domain": "bounded-path-proof-cache-v1",
                "bindings": self.bindings.to_data(),
                "query_digest": self.query_digest,
            }
        )


@dataclass(frozen=True)
class ConstraintEvaluation(Model):
    constraint_id: str
    width_bits: int
    predicate: Predicate
    left_value: int
    right_value: int
    actual: bool
    expected: bool
    satisfied: bool

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.constraint_id)
        _width(self.width_bits)
        _bit_value(self.left_value, self.width_bits, "Evaluated left value")
        _bit_value(self.right_value, self.width_bits, "Evaluated right value")
        require(
            self.satisfied == (self.actual == self.expected),
            "Invalid constraint evaluation",
        )


def finite_domain_size(query: ConstraintQuery) -> int:
    """Return the declared Cartesian size or fail at the assignment policy limit."""
    size = 1
    for variable in query.variables:
        if size > query.budget.max_assignments // len(variable.domain):
            raise ConstraintBudgetError("Assignment domain exceeds declared budget")
        size *= len(variable.domain)
    return size


def _expression_size(expression: ConstraintExpression) -> int:
    return 1 + sum(_expression_size(item) for item in expression.operands)


def query_evaluation_cost(query: ConstraintQuery) -> int:
    """Return node visits plus predicate checks for one complete assignment."""
    return sum(
        _expression_size(constraint.left) + _expression_size(constraint.right) + 1
        for constraint in query.constraints
    )


def exhaustive_evaluation_size(query: ConstraintQuery) -> int:
    """Return reference-enumeration work or fail at the evaluation policy limit."""
    assignments = finite_domain_size(query)
    per_assignment = query_evaluation_cost(query)
    if assignments > query.budget.max_evaluations // per_assignment:
        raise ConstraintBudgetError("Exhaustive evaluation exceeds declared budget")
    return assignments * per_assignment


class _EvaluationCounter:
    def __init__(self, limit: int):
        self.limit = limit
        self.count = 0

    def step(self, depth: int, depth_limit: int) -> None:
        if depth > depth_limit:
            raise ConstraintBudgetError("Expression-depth budget exhausted")
        self.consume()

    def consume(self) -> None:
        self.count += 1
        if self.count > self.limit:
            raise ConstraintBudgetError("Evaluation budget exhausted")


def _assignment_map(
    assignments: tuple[ConstraintAssignment, ...],
) -> dict[str, ConstraintAssignment]:
    names = tuple(item.name for item in assignments)
    canonical_set(names)
    return {item.name: item for item in assignments}


def _signed(value: int, width_bits: int) -> int:
    sign_bit = 1 << (width_bits - 1)
    return value - (1 << width_bits) if value & sign_bit else value


def _evaluate_expression(
    expression: ConstraintExpression,
    assignments: dict[str, ConstraintAssignment],
    counter: _EvaluationCounter,
    depth_limit: int,
    depth: int = 1,
) -> int:
    counter.step(depth, depth_limit)
    if expression.kind == "constant":
        assert expression.value is not None
        return expression.value
    if expression.kind == "variable":
        assert expression.variable is not None
        assignment = assignments.get(expression.variable)
        require(assignment is not None, "Missing variable assignment")
        assert assignment is not None
        require(
            assignment.width_bits == expression.width_bits,
            "Assignment width mismatch",
        )
        return assignment.value

    values = tuple(
        _evaluate_expression(item, assignments, counter, depth_limit, depth + 1)
        for item in expression.operands
    )
    operator = expression.operator
    mask = (1 << expression.width_bits) - 1
    if expression.kind == "unary":
        if operator == "bit_not":
            return (~values[0]) & mask
        if operator == "neg":
            return (-values[0]) & mask
        raise UnsupportedConstraintError(f"Unsupported unary operator: {operator}")

    left, right = values
    if operator == "add":
        return (left + right) & mask
    if operator == "sub":
        return (left - right) & mask
    if operator == "mul":
        return (left * right) & mask
    if operator == "bit_and":
        return left & right
    if operator == "bit_or":
        return left | right
    if operator == "bit_xor":
        return left ^ right
    if operator in {"shl", "lshr", "ashr"}:
        if right >= expression.width_bits:
            raise UnsupportedConstraintError("Shift count outside reference profile")
        if operator == "shl":
            return (left << right) & mask
        if operator == "lshr":
            return left >> right
        return (_signed(left, expression.width_bits) >> right) & mask
    raise UnsupportedConstraintError(f"Unsupported binary operator: {operator}")


def evaluate_expression(
    expression: ConstraintExpression,
    assignments: tuple[ConstraintAssignment, ...],
    *,
    max_evaluations: int = 10_000,
    max_expression_depth: int = 32,
) -> int:
    """Evaluate one expression under explicit, width-carrying assignments."""
    require(max_evaluations > 0, "Evaluation budget must be positive")
    require(
        0 < max_expression_depth <= MAX_EXPRESSION_DEPTH,
        "Invalid expression-depth budget",
    )
    return _evaluate_expression(
        expression,
        _assignment_map(assignments),
        _EvaluationCounter(max_evaluations),
        max_expression_depth,
    )


def _compare(predicate: Predicate, left: int, right: int, width_bits: int) -> bool:
    if predicate == "eq":
        return left == right
    if predicate == "ne":
        return left != right
    if predicate == "ult":
        return left < right
    if predicate == "ule":
        return left <= right
    if predicate == "ugt":
        return left > right
    if predicate == "uge":
        return left >= right
    signed_left, signed_right = _signed(left, width_bits), _signed(right, width_bits)
    if predicate == "slt":
        return signed_left < signed_right
    if predicate == "sle":
        return signed_left <= signed_right
    if predicate == "sgt":
        return signed_left > signed_right
    return signed_left >= signed_right


def evaluate_constraint_query(
    query: ConstraintQuery,
    assignments: tuple[ConstraintAssignment, ...],
) -> tuple[ConstraintEvaluation, ...]:
    """Replay one assignment; engines use query_evaluation_cost across candidates."""
    finite_domain_size(query)
    assignment_map = _assignment_map(assignments)
    expected_names = tuple(item.name for item in query.variables)
    require(
        tuple(assignment_map) == expected_names, "Assignment set does not match query"
    )
    for variable in query.variables:
        assignment = assignment_map[variable.name]
        require(
            assignment.width_bits == variable.width_bits, "Assignment width mismatch"
        )
        require(
            assignment.value in variable.domain, "Assignment outside declared domain"
        )

    counter = _EvaluationCounter(query.budget.max_evaluations)
    evaluations = []
    for constraint in query.constraints:
        left = _evaluate_expression(
            constraint.left,
            assignment_map,
            counter,
            query.budget.max_expression_depth,
        )
        right = _evaluate_expression(
            constraint.right,
            assignment_map,
            counter,
            query.budget.max_expression_depth,
        )
        counter.consume()
        actual = _compare(
            constraint.predicate,
            left,
            right,
            constraint.left.width_bits,
        )
        evaluations.append(
            ConstraintEvaluation(
                constraint.constraint_id,
                constraint.left.width_bits,
                constraint.predicate,
                left,
                right,
                actual,
                constraint.expected,
                actual == constraint.expected,
            )
        )
    return tuple(evaluations)


__all__ = [
    "ConstraintAssignment",
    "ConstraintBindings",
    "ConstraintBudgetError",
    "ConstraintEvaluation",
    "ConstraintExpression",
    "ConstraintQuery",
    "ConstraintVariable",
    "DeclaredCoverage",
    "PathConstraint",
    "ProofAssumption",
    "ProofBounds",
    "ProofBudget",
    "UnsupportedConstraintError",
    "evaluate_constraint_query",
    "evaluate_expression",
    "exhaustive_evaluation_size",
    "finite_domain_size",
    "query_evaluation_cost",
    "variable_domain_digest",
]
