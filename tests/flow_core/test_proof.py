"""P01-P08 policy tests for the pure bounded proof-engine boundary."""

from dataclasses import replace

import pytest

from ida_pro_mcp.flow_core.constraints import (
    ConstraintAssignment,
    ConstraintBindings,
    ConstraintExpression,
    ConstraintQuery,
    ConstraintVariable,
    DeclaredCoverage,
    PathConstraint,
    Predicate,
    ProofBounds,
    ProofBudget,
    variable_domain_digest,
)
from ida_pro_mcp.flow_core.proof import (
    EngineDisposition,
    EngineAnswer,
    ModelKind,
    ProofResult,
    ReferenceProofEngine,
    StaleProofEvidenceError,
    classify_proof,
    validate_proof_result,
)
from ida_pro_mcp.flow_core.serialization import ContractError, canonical_json


def _digest(seed: str) -> str:
    return "sha256-v1:" + seed * 64


def _identity(kind: str, seed: str) -> str:
    return f"{kind}-v1:" + seed * 64


def _variable(name: str = "x", width_bits: int = 2) -> ConstraintExpression:
    return ConstraintExpression("variable", width_bits, variable=name)


def _constant(value: int, width_bits: int = 2) -> ConstraintExpression:
    return ConstraintExpression("constant", width_bits, value=value)


def _constraint(
    constraint_id: str,
    predicate: Predicate,
    right: int,
    *,
    left: ConstraintExpression | None = None,
    expected: bool = True,
) -> PathConstraint:
    return PathConstraint(
        constraint_id=constraint_id,
        left=left or _variable(),
        predicate=predicate,
        right=_constant(right),
        signedness="signed" if predicate.startswith("s") else None,
        expected=expected,
        rule_id="rule:explicit-branch-v1",
        origin_id="origin:fixture",
        evidence_ids=(_identity("evidence", "a"),),
    )


def _operators(constraints: tuple[PathConstraint, ...]) -> tuple[str, ...]:
    values = {constraint.predicate for constraint in constraints}

    def visit(expression: ConstraintExpression) -> None:
        if expression.operator is not None:
            values.add(expression.operator)
        for operand in expression.operands:
            visit(operand)

    for constraint in constraints:
        visit(constraint.left)
        visit(constraint.right)
    return tuple(sorted(values))


def _query(
    constraints: tuple[PathConstraint, ...],
    *,
    domain: tuple[int, ...] = (0, 1, 2, 3),
    loop_bound: int = 1,
    call_bound: int = 1,
    max_assignments: int = 16,
    max_evaluations: int = 128,
    timeout_ms: int = 1000,
) -> ConstraintQuery:
    variables = (ConstraintVariable("x", 2, domain),)
    return ConstraintQuery(
        bindings=ConstraintBindings(
            snapshot_id=_identity("snapshot", "1"),
            graph_digest=_digest("2"),
            profile_digest=_digest("3"),
            ruleset_digest=_digest("4"),
            summary_digests=(_digest("5"),),
        ),
        variables=variables,
        constraints=constraints,
        assumptions=(),
        bounds=ProofBounds(loop_bound, call_bound),
        budget=ProofBudget(
            max_assignments=max_assignments,
            max_evaluations=max_evaluations,
            max_expression_depth=16,
            timeout_ms=timeout_ms,
        ),
        coverage=DeclaredCoverage(
            theory="fixed_width_bitvectors",
            variable_names=("x",),
            variable_domain_digest=variable_domain_digest(variables),
            constraint_ids=tuple(item.constraint_id for item in constraints),
            operators=_operators(constraints),
        ),
    )


class _FakeEngine:
    def __init__(self, answer, version: str = "fake-proof-v1"):
        self.engine_version = version
        self.answer = answer
        self.called = False

    def solve(self, query):
        self.called = True
        return self.answer


def _fake_answer(
    query: ConstraintQuery,
    *,
    model_kind: ModelKind,
    disposition: EngineDisposition,
    assignments: tuple[ConstraintAssignment, ...] = (),
) -> EngineAnswer:
    return EngineAnswer(
        bindings=query.bindings,
        query_digest=query.query_digest,
        engine_version="fake-proof-v1",
        model_kind=model_kind,
        disposition=disposition,
        assumptions=query.assumptions,
        bounds=query.bounds,
        budget=query.budget,
        coverage=query.coverage,
        assignments=assignments,
        evidence_ids=(_identity("evidence", "a"),),
        assignment_count=1 if disposition == "sat" else 0,
    )


def test_p01_contradictory_integer_guards_are_infeasible_only_within_bounds():
    query = _query(
        (
            _constraint("c01-lt", "ult", 1),
            _constraint("c02-ge", "uge", 1),
        ),
        loop_bound=2,
        call_bound=3,
    )

    result = classify_proof(query, ReferenceProofEngine())

    assert result.status == "infeasible"
    assert result.scope == "within_bounds"
    assert result.bounds == ProofBounds(2, 3)
    assert result.refutation_constraint_ids == ("c01-lt", "c02-ge")


def test_p02_exact_sat_is_feasible_only_after_independent_witness_replay():
    query = _query((_constraint("c01-eq", "eq", 2),))

    result = classify_proof(query, ReferenceProofEngine())

    assert result.status == "feasible"
    assert result.model_kind == "exact"
    assert result.witness is not None
    assert result.witness.valid is True
    assert result.witness.assignments == (ConstraintAssignment("x", 2, 2),)
    assert all(item.satisfied for item in result.witness.evaluations)


def test_definite_result_requires_evidence_for_every_constraint():
    query = _query(
        (
            _constraint("c01-evidenced", "eq", 1),
            replace(_constraint("c02-gap", "ule", 3), evidence_ids=()),
        )
    )

    result = classify_proof(query, ReferenceProofEngine())

    assert result.status == "unknown"
    assert "missing_constraint_evidence" in result.unresolved

    forged = replace(result, status="feasible")
    with pytest.raises(ContractError, match="missing constraint evidence"):
        validate_proof_result(query, forged)


def test_p03_unsupported_timeout_and_assignment_budget_are_unknown():
    unsupported_expression = ConstraintExpression(
        "binary",
        2,
        operator="divide",
        operands=(_constant(1), _variable()),
    )
    unsupported = _query(
        (_constraint("c01-unsupported", "eq", 0, left=unsupported_expression),)
    )
    unsupported_result = classify_proof(unsupported, ReferenceProofEngine())
    assert unsupported_result.status == "unknown"
    assert unsupported_result.unresolved == (
        "incomplete_model",
        "unsupported_constraint",
    )

    timeout_query = _query((_constraint("c01-timeout", "eq", 3),), timeout_ms=1)
    clock = iter((0.0, 1.0)).__next__
    timeout_result = classify_proof(
        timeout_query, ReferenceProofEngine(monotonic=clock)
    )
    assert timeout_result.status == "unknown"
    assert "timeout" in timeout_result.unresolved

    budget_query = _query(
        (_constraint("c01-budget", "eq", 3),),
        max_assignments=2,
    )
    budget_result = classify_proof(budget_query, ReferenceProofEngine())
    assert budget_result.status == "unknown"
    assert "incomplete_model" in budget_result.unresolved

    evaluation_budget_query = _query(
        (_constraint("c01-evaluation-budget", "eq", 3),),
        max_evaluations=3,
    )
    evaluation_budget_result = classify_proof(
        evaluation_budget_query, ReferenceProofEngine()
    )
    assert evaluation_budget_result.status == "unknown"
    assert "evaluation_budget_exceeded" in evaluation_budget_result.unresolved


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("snapshot_id", _identity("snapshot", "9")),
        ("graph_digest", _digest("8")),
        ("profile_digest", _digest("7")),
        ("ruleset_digest", _digest("6")),
        ("summary_digests", (_digest("0"),)),
    ),
)
def test_p04_stale_snapshot_graph_profile_summary_or_ruleset_is_rejected(
    field: str, value: object
):
    query = _query((_constraint("c01-stale", "eq", 1),))
    answer = _fake_answer(
        query,
        model_kind="exact",
        disposition="sat",
        assignments=(ConstraintAssignment("x", 2, 1),),
    )
    stale_bindings = replace(query.bindings, **{field: value})
    engine = _FakeEngine(replace(answer, bindings=stale_bindings))

    with pytest.raises(StaleProofEvidenceError, match="bindings"):
        classify_proof(query, engine, approved_engines=(engine.engine_version,))


def test_p04_stale_query_digest_is_rejected_before_classification():
    query = _query((_constraint("c01-stale-query", "eq", 1),))
    answer = _fake_answer(
        query,
        model_kind="exact",
        disposition="sat",
        assignments=(ConstraintAssignment("x", 2, 1),),
    )
    engine = _FakeEngine(replace(answer, query_digest=_digest("9")))

    with pytest.raises(StaleProofEvidenceError, match="query digest"):
        classify_proof(query, engine, approved_engines=(engine.engine_version,))


def test_p05_overapproximate_sat_is_unknown_with_abstract_sat():
    query = _query((_constraint("c01-abstract", "eq", 1),))
    answer = _fake_answer(
        query,
        model_kind="sound_overapprox",
        disposition="sat",
        assignments=(ConstraintAssignment("x", 2, 1),),
    )
    engine = _FakeEngine(answer)

    result = classify_proof(query, engine, approved_engines=(engine.engine_version,))

    assert result.status == "unknown"
    assert result.abstract_sat is True
    assert result.witness is None
    assert "correlation_lost" in result.unresolved


def test_p05_overapproximate_unsat_is_not_approved_for_definite_classification():
    query = _query((_constraint("c01-abstract-unsat", "eq", 1),))
    answer = EngineAnswer(
        bindings=query.bindings,
        query_digest=query.query_digest,
        engine_version="fake-proof-v1",
        model_kind="sound_overapprox",
        disposition="unsat",
        assumptions=query.assumptions,
        bounds=query.bounds,
        budget=query.budget,
        coverage=query.coverage,
        complete_domain=True,
        refutation_constraint_ids=("c01-abstract-unsat",),
        evidence_ids=(_identity("evidence", "a"),),
        assignment_count=4,
    )
    engine = _FakeEngine(answer)

    result = classify_proof(query, engine, approved_engines=(engine.engine_version,))

    assert result.status == "unknown"
    assert "unvalidated_refutation" in result.unresolved


@pytest.mark.parametrize(
    ("left", "predicate", "right", "expected_witness"),
    (
        (
            ConstraintExpression(
                "binary",
                2,
                operator="add",
                operands=(_constant(1), _variable()),
            ),
            "eq",
            0,
            3,
        ),
        (_variable(), "slt", 0, 2),
        (_variable(), "ult", 1, 0),
    ),
)
def test_p06_modular_and_signed_unsigned_results_match_independent_oracle(
    left: ConstraintExpression,
    predicate: Predicate,
    right: int,
    expected_witness: int,
):
    query = _query((_constraint("c01-oracle", predicate, right, left=left),))

    result = classify_proof(query, ReferenceProofEngine())

    assert result.status == "feasible"
    assert result.witness is not None
    assert result.witness.assignments[0].value == expected_witness


def test_p07_bounded_unsat_preserves_loop_and_call_bounds_without_generalizing():
    query = _query(
        (_constraint("c01-in-bound", "eq", 3),),
        domain=(0, 1, 2),
        loop_bound=1,
        call_bound=0,
    )

    result = classify_proof(query, ReferenceProofEngine())

    assert result.status == "infeasible"
    assert result.scope == "within_bounds"
    assert result.bounds.loop_bound == 1
    assert result.bounds.call_bound == 0
    assert result.coverage.bounded_only is True


def test_p08_unapproved_incomplete_malformed_or_invalid_witness_is_never_definite():
    query = _query((_constraint("c01-p08", "eq", 1),))
    valid_answer = _fake_answer(
        query,
        model_kind="exact",
        disposition="sat",
        assignments=(ConstraintAssignment("x", 2, 1),),
    )

    unapproved = _FakeEngine(valid_answer)
    result = classify_proof(query, unapproved)
    assert result.status == "unknown"
    assert unapproved.called is False

    incomplete = _FakeEngine(
        _fake_answer(query, model_kind="incomplete", disposition="unknown")
    )
    result = classify_proof(
        query, incomplete, approved_engines=(incomplete.engine_version,)
    )
    assert result.status == "unknown"

    malformed = _FakeEngine({"not": "an EngineAnswer"})
    result = classify_proof(
        query, malformed, approved_engines=(malformed.engine_version,)
    )
    assert result.status == "unknown"

    missing_assignment = _FakeEngine(
        _fake_answer(query, model_kind="exact", disposition="sat")
    )
    result = classify_proof(
        query,
        missing_assignment,
        approved_engines=(missing_assignment.engine_version,),
    )
    assert result.status == "unknown"
    assert result.witness is not None and result.witness.valid is False


def test_p08_false_unsat_from_version_spoofing_engine_is_unknown():
    query = _query((_constraint("c01-false-unsat", "eq", 1),))
    answer = EngineAnswer(
        bindings=query.bindings,
        query_digest=query.query_digest,
        engine_version=ReferenceProofEngine.engine_version,
        model_kind="exact",
        disposition="unsat",
        assumptions=query.assumptions,
        bounds=query.bounds,
        budget=query.budget,
        coverage=query.coverage,
        complete_domain=True,
        refutation_constraint_ids=("c01-false-unsat",),
        evidence_ids=(_identity("evidence", "a"),),
        assignment_count=4,
    )
    spoof = _FakeEngine(answer, version=ReferenceProofEngine.engine_version)

    result = classify_proof(query, spoof)

    assert result.status == "unknown"
    assert "unvalidated_refutation" in result.unresolved

    invalid_witness = _FakeEngine(
        _fake_answer(
            query,
            model_kind="exact",
            disposition="sat",
            assignments=(ConstraintAssignment("x", 2, 0),),
        )
    )
    result = classify_proof(
        query, invalid_witness, approved_engines=(invalid_witness.engine_version,)
    )
    assert result.status == "unknown"
    assert result.witness is not None and result.witness.valid is False


def test_proof_result_round_trip_and_digests_are_deterministic():
    query = _query((_constraint("c01-roundtrip", "eq", 1),))
    result = classify_proof(query, ReferenceProofEngine())

    restored = type(result).from_json(canonical_json(result))

    assert restored == result
    assert restored.result_digest == result.result_digest
    assert restored.cache_key == result.cache_key

    stale = replace(restored, budget=replace(restored.budget, timeout_ms=999))
    with pytest.raises(StaleProofEvidenceError, match="budget"):
        validate_proof_result(query, stale)


def test_hostile_proof_result_deserialization_rejects_extensions_and_false_status():
    query = _query((_constraint("c01-hostile-result", "eq", 1),))
    result = classify_proof(query, ReferenceProofEngine())
    data = result.to_data()

    with pytest.raises(ContractError, match="Wrong fields"):
        ProofResult.from_data({**data, "extension": True})

    data["status"] = "infeasible"
    with pytest.raises(ContractError, match="Infeasible"):
        ProofResult.from_data(data)

    assert result.witness is not None
    tampered_witness = replace(
        result.witness,
        assignments=(ConstraintAssignment("x", 2, 0),),
    )
    tampered_result = replace(result, witness=tampered_witness)
    with pytest.raises(ContractError, match="witness replay"):
        validate_proof_result(query, tampered_result)
