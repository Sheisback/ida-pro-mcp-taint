"""Pure bounded path-proof policy and a finite reference engine.

The engine answer is deliberately distinct from the public proof result.  An
engine may report an abstract SAT candidate or an exhaustive bounded UNSAT
certificate, but policy classification happens here only after freshness,
approval, coverage, and witness checks have succeeded.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from itertools import product
import time
from typing import Literal, Protocol

from .constraints import (
    ConstraintAssignment,
    ConstraintBindings,
    ConstraintBudgetError,
    ConstraintEvaluation,
    ConstraintQuery,
    DeclaredCoverage,
    ProofAssumption,
    ProofBounds,
    ProofBudget,
    UnsupportedConstraintError,
    evaluate_constraint_query,
    exhaustive_evaluation_size,
    finite_domain_size,
)
from .serialization import ContractError, Model, digest
from .states import canonical_set, check_digest, check_id, nonempty, require

ModelKind = Literal["exact", "sound_overapprox", "incomplete"]
EngineDisposition = Literal["sat", "unsat", "unknown"]
ProofStatus = Literal["feasible", "infeasible", "unknown"]
BitvectorSemantics = Literal["fixed_width_modular_twos_complement_v1"]
BITVECTOR_SEMANTICS: BitvectorSemantics = "fixed_width_modular_twos_complement_v1"
REFERENCE_ENGINE_VERSION = "finite-reference-v1"


class StaleProofEvidenceError(ContractError):
    """An engine answer is bound to different immutable proof inputs."""


@dataclass(frozen=True)
class EngineAnswer(Model):
    """Raw, untrusted answer returned by a proof engine."""

    bindings: ConstraintBindings
    query_digest: str
    engine_version: str
    model_kind: ModelKind
    disposition: EngineDisposition
    assumptions: tuple[ProofAssumption, ...]
    bounds: ProofBounds
    budget: ProofBudget
    coverage: DeclaredCoverage
    bitvector_semantics: BitvectorSemantics = BITVECTOR_SEMANTICS
    assignments: tuple[ConstraintAssignment, ...] = ()
    evaluations: tuple[ConstraintEvaluation, ...] = ()
    complete_domain: bool = False
    refutation_constraint_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()
    assignment_count: int = 0
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        check_digest(self.query_digest)
        nonempty(self.engine_version)
        require(self.assignment_count >= 0, "Negative assignment count")
        canonical_set(tuple(item.name for item in self.assignments))
        canonical_set(self.refutation_constraint_ids)
        canonical_set(self.evidence_ids)
        for evidence_id in self.evidence_ids:
            check_id(evidence_id, "evidence")
        canonical_set(self.diagnostics)
        canonical_set(self.unresolved)
        require(
            self.disposition == "sat" or not self.assignments,
            "Only SAT answers carry assignments",
        )
        require(
            self.disposition != "sat" or self.assignment_count > 0,
            "SAT answer must report checked assignments",
        )
        require(
            self.disposition == "sat" or not self.evaluations,
            "Only SAT answers carry evaluations",
        )
        require(
            self.disposition == "unsat" or not self.refutation_constraint_ids,
            "Only UNSAT answers carry refutation constraints",
        )
        require(
            not self.complete_domain or self.disposition == "unsat",
            "Only UNSAT answers may certify a complete domain",
        )
        require(
            self.model_kind != "incomplete" or self.disposition == "unknown",
            "Incomplete models cannot report definite raw dispositions",
        )

    @property
    def answer_digest(self) -> str:
        return digest(self)


@dataclass(frozen=True)
class WitnessValidation(Model):
    valid: bool
    assignments: tuple[ConstraintAssignment, ...]
    evaluations: tuple[ConstraintEvaluation, ...]
    diagnostics: tuple[str, ...] = ()
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        canonical_set(tuple(item.name for item in self.assignments))
        canonical_set(self.diagnostics)
        require(
            self.valid == (not self.diagnostics),
            "Witness validity and diagnostics disagree",
        )


@dataclass(frozen=True)
class ProofResult(Model):
    """Policy-classified, bounded proof evidence."""

    bindings: ConstraintBindings
    query_digest: str
    engine_version: str
    model_kind: ModelKind
    raw_disposition: EngineDisposition
    status: ProofStatus
    abstract_sat: bool
    scope: Literal["within_bounds"]
    assumptions: tuple[ProofAssumption, ...]
    bounds: ProofBounds
    budget: ProofBudget
    coverage: DeclaredCoverage
    bitvector_semantics: BitvectorSemantics
    engine_answer_digest: str
    assignments_checked: int
    complete_domain: bool
    witness: WitnessValidation | None = None
    refutation_constraint_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        check_digest(self.query_digest)
        check_digest(self.engine_answer_digest)
        nonempty(self.engine_version)
        require(self.assignments_checked >= 0, "Negative checked-assignment count")
        canonical_set(self.refutation_constraint_ids)
        canonical_set(self.evidence_ids)
        for evidence_id in self.evidence_ids:
            check_id(evidence_id, "evidence")
        canonical_set(self.diagnostics)
        canonical_set(self.unresolved)
        require(
            self.status != "feasible"
            or (
                self.model_kind == "exact"
                and self.raw_disposition == "sat"
                and self.witness is not None
                and self.witness.valid
                and bool(self.evidence_ids)
            ),
            "Feasible requires a validated exact witness",
        )
        require(
            self.status != "infeasible"
            or (
                self.model_kind in ("exact", "sound_overapprox")
                and self.raw_disposition == "unsat"
                and bool(self.refutation_constraint_ids)
                and bool(self.evidence_ids)
                and self.complete_domain
            ),
            "Infeasible requires bounded UNSAT refutation evidence",
        )
        require(
            self.abstract_sat
            == (
                self.model_kind == "sound_overapprox" and self.raw_disposition == "sat"
            ),
            "abstract_sat is reserved for over-approximate SAT",
        )

    @property
    def result_digest(self) -> str:
        return digest(self)

    @property
    def cache_key(self) -> str:
        return digest(
            {
                "query_digest": self.query_digest,
                "engine_version": self.engine_version,
                "model_kind": self.model_kind,
                "answer_digest": self.engine_answer_digest,
            }
        )


class ProofEngine(Protocol):
    """Injectable proof engine.  Implementations return policy-neutral answers."""

    engine_version: str

    def solve(self, query: ConstraintQuery) -> EngineAnswer: ...


def _unknown_answer(
    query: ConstraintQuery,
    engine_version: str,
    reason: str,
    *,
    assignment_count: int = 0,
) -> EngineAnswer:
    return EngineAnswer(
        bindings=query.bindings,
        query_digest=query.query_digest,
        engine_version=engine_version,
        model_kind="incomplete",
        disposition="unknown",
        assumptions=query.assumptions,
        bounds=query.bounds,
        budget=query.budget,
        coverage=query.coverage,
        diagnostics=(reason,),
        unresolved=(reason,),
        assignment_count=assignment_count,
    )


class ReferenceProofEngine:
    """Exhaustive stdlib engine for explicitly declared finite domains only."""

    engine_version = REFERENCE_ENGINE_VERSION

    def __init__(
        self,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        cancelled: Callable[[], bool] = lambda: False,
    ):
        self._monotonic = monotonic
        self._cancelled = cancelled

    def solve(self, query: ConstraintQuery) -> EngineAnswer:
        started = self._monotonic()
        deadline = started + query.budget.timeout_ms / 1000
        try:
            finite_domain_size(query)
        except ConstraintBudgetError:
            return _unknown_answer(
                query,
                self.engine_version,
                "assignment_budget_exceeded",
            )
        try:
            exhaustive_evaluation_size(query)
        except ConstraintBudgetError:
            return _unknown_answer(
                query,
                self.engine_version,
                "evaluation_budget_exceeded",
            )

        assignment_count = 0
        domains = tuple(variable.domain for variable in query.variables)
        for values in product(*domains):
            if self._cancelled():
                return _unknown_answer(
                    query,
                    self.engine_version,
                    "cancelled",
                    assignment_count=assignment_count,
                )
            if self._monotonic() >= deadline:
                return _unknown_answer(
                    query,
                    self.engine_version,
                    "timeout",
                    assignment_count=assignment_count,
                )
            assignments = tuple(
                ConstraintAssignment(variable.name, variable.width_bits, value)
                for variable, value in zip(query.variables, values, strict=True)
            )
            try:
                evaluations = evaluate_constraint_query(query, assignments)
            except ConstraintBudgetError:
                return _unknown_answer(
                    query,
                    self.engine_version,
                    "evaluation_budget_exceeded",
                    assignment_count=assignment_count,
                )
            except UnsupportedConstraintError:
                return _unknown_answer(
                    query,
                    self.engine_version,
                    "unsupported_constraint",
                    assignment_count=assignment_count,
                )
            assignment_count += 1
            if self._cancelled():
                return _unknown_answer(
                    query,
                    self.engine_version,
                    "cancelled",
                    assignment_count=assignment_count,
                )
            if self._monotonic() >= deadline:
                return _unknown_answer(
                    query,
                    self.engine_version,
                    "timeout",
                    assignment_count=assignment_count,
                )
            if all(evaluation.satisfied for evaluation in evaluations):
                return EngineAnswer(
                    bindings=query.bindings,
                    query_digest=query.query_digest,
                    engine_version=self.engine_version,
                    model_kind="exact",
                    disposition="sat",
                    assumptions=query.assumptions,
                    bounds=query.bounds,
                    budget=query.budget,
                    coverage=query.coverage,
                    assignments=assignments,
                    evaluations=evaluations,
                    evidence_ids=tuple(
                        sorted(
                            {
                                evidence_id
                                for constraint in query.constraints
                                for evidence_id in constraint.evidence_ids
                            }
                        )
                    ),
                    assignment_count=assignment_count,
                )

        return EngineAnswer(
            bindings=query.bindings,
            query_digest=query.query_digest,
            engine_version=self.engine_version,
            model_kind="exact",
            disposition="unsat",
            assumptions=query.assumptions,
            bounds=query.bounds,
            budget=query.budget,
            coverage=query.coverage,
            complete_domain=True,
            refutation_constraint_ids=tuple(
                constraint.constraint_id for constraint in query.constraints
            ),
            evidence_ids=tuple(
                sorted(
                    {
                        evidence_id
                        for constraint in query.constraints
                        for evidence_id in constraint.evidence_ids
                    }
                )
            ),
            assignment_count=assignment_count,
        )


def validate_witness(
    query: ConstraintQuery, assignments: tuple[ConstraintAssignment, ...]
) -> WitnessValidation:
    """Replay an engine candidate independently through the canonical evaluator."""

    expected = tuple(variable.name for variable in query.variables)
    observed = tuple(assignment.name for assignment in assignments)
    if observed != expected:
        return WitnessValidation(
            False,
            assignments,
            (),
            ("witness_variable_set_mismatch",),
        )
    for variable, assignment in zip(query.variables, assignments, strict=True):
        if assignment.width_bits != variable.width_bits:
            return WitnessValidation(
                False,
                assignments,
                (),
                ("witness_width_mismatch",),
            )
        if assignment.value not in variable.domain:
            return WitnessValidation(
                False,
                assignments,
                (),
                ("witness_value_outside_declared_domain",),
            )
    try:
        evaluations = evaluate_constraint_query(query, assignments)
    except (ConstraintBudgetError, UnsupportedConstraintError):
        return WitnessValidation(
            False,
            assignments,
            (),
            ("witness_replay_incomplete",),
        )
    if not all(evaluation.satisfied for evaluation in evaluations):
        return WitnessValidation(
            False,
            assignments,
            evaluations,
            ("witness_constraint_failed",),
        )
    return WitnessValidation(True, assignments, evaluations)


def _check_fresh(query: ConstraintQuery, answer: EngineAnswer) -> None:
    if answer.query_digest != query.query_digest:
        raise StaleProofEvidenceError("Stale proof query digest")
    if answer.bindings != query.bindings:
        raise StaleProofEvidenceError("Stale proof bindings")
    if answer.assumptions != query.assumptions:
        raise StaleProofEvidenceError("Stale proof assumptions")
    if answer.bounds != query.bounds:
        raise StaleProofEvidenceError("Stale proof bounds")
    if answer.budget != query.budget:
        raise StaleProofEvidenceError("Stale proof budget")
    if answer.coverage != query.coverage:
        raise StaleProofEvidenceError("Stale proof coverage")
    if answer.bitvector_semantics != BITVECTOR_SEMANTICS:
        raise StaleProofEvidenceError("Stale bit-vector semantics")


def validate_proof_result(query: ConstraintQuery, result: ProofResult) -> None:
    """Reject a serialized result that is stale for the current query."""

    if result.query_digest != query.query_digest:
        raise StaleProofEvidenceError("Stale proof-result query digest")
    if result.bindings != query.bindings:
        raise StaleProofEvidenceError("Stale proof-result bindings")
    if result.assumptions != query.assumptions:
        raise StaleProofEvidenceError("Stale proof-result assumptions")
    if result.bounds != query.bounds:
        raise StaleProofEvidenceError("Stale proof-result bounds")
    if result.budget != query.budget:
        raise StaleProofEvidenceError("Stale proof-result budget")
    if result.coverage != query.coverage:
        raise StaleProofEvidenceError("Stale proof-result coverage")
    if result.bitvector_semantics != BITVECTOR_SEMANTICS:
        raise StaleProofEvidenceError("Stale proof-result bit-vector semantics")
    if result.status in ("feasible", "infeasible"):
        if not all(constraint.evidence_ids for constraint in query.constraints):
            raise ContractError("Definite proof result has missing constraint evidence")
        if result.evidence_ids != _expected_evidence(query):
            raise ContractError(
                "Definite proof result has mismatched constraint evidence"
            )
    if result.status == "feasible":
        assert result.witness is not None
        replay = validate_witness(query, result.witness.assignments)
        if not replay.valid or replay != result.witness:
            raise ContractError("Feasible proof result has an invalid witness replay")
    if result.status == "infeasible":
        try:
            domain_size = finite_domain_size(query)
        except ConstraintBudgetError as exc:
            raise ContractError("Infeasible proof exceeds assignment budget") from exc
        expected_constraints = tuple(
            constraint.constraint_id for constraint in query.constraints
        )
        if not (
            result.engine_version == REFERENCE_ENGINE_VERSION
            and result.model_kind == "exact"
            and result.assignments_checked == domain_size
            and result.complete_domain
            and result.refutation_constraint_ids == expected_constraints
            and not result.diagnostics
            and not result.unresolved
        ):
            raise ContractError(
                "Infeasible proof result lacks exhaustive certification"
            )


def _expected_evidence(query: ConstraintQuery) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                evidence_id
                for constraint in query.constraints
                for evidence_id in constraint.evidence_ids
            }
        )
    )


def classify_proof(
    query: ConstraintQuery,
    engine: ProofEngine,
    *,
    approved_engines: tuple[str, ...] = (ReferenceProofEngine.engine_version,),
) -> ProofResult:
    """Run an approved engine and apply the soundness-first public policy."""

    canonical_set(approved_engines)
    if engine.engine_version not in approved_engines:
        answer = _unknown_answer(query, engine.engine_version, "unapproved_engine")
    else:
        try:
            candidate = engine.solve(query)
        except (ContractError, TypeError, ValueError):
            candidate = _unknown_answer(
                query, engine.engine_version, "malformed_engine_answer"
            )
        if type(candidate) is not EngineAnswer:
            answer = _unknown_answer(
                query, engine.engine_version, "malformed_engine_answer"
            )
        else:
            answer = candidate
            require(
                answer.engine_version == engine.engine_version,
                "Engine version changed inside answer",
            )
            _check_fresh(query, answer)

    witness: WitnessValidation | None = None
    status: ProofStatus = "unknown"
    diagnostics = set(answer.diagnostics)
    unresolved = set(answer.unresolved)
    refutation_ids: tuple[str, ...] = ()
    constraints_evidenced = all(
        constraint.evidence_ids for constraint in query.constraints
    )
    answer_evidence_bound = answer.evidence_ids == _expected_evidence(query)
    evidence_complete = constraints_evidenced and answer_evidence_bound

    if answer.model_kind == "exact" and answer.disposition == "sat":
        witness = validate_witness(query, answer.assignments)
        if witness.valid and evidence_complete:
            status = "feasible"
        else:
            diagnostics.update(witness.diagnostics)
            if not witness.valid:
                unresolved.add("invalid_witness")
            elif not constraints_evidenced:
                unresolved.add("missing_constraint_evidence")
            else:
                unresolved.add("mismatched_constraint_evidence")
    elif answer.model_kind == "sound_overapprox" and answer.disposition == "sat":
        diagnostics.add("abstract_sat_not_concrete_witness")
        unresolved.add("correlation_lost")
    elif (
        answer.model_kind in ("exact", "sound_overapprox")
        and answer.disposition == "unsat"
    ):
        expected_constraints = tuple(
            constraint.constraint_id for constraint in query.constraints
        )
        try:
            domain_size = finite_domain_size(query)
        except ConstraintBudgetError:
            domain_size = -1
        trusted_exhaustive_reference = (
            type(engine) is ReferenceProofEngine
            and answer.model_kind == "exact"
            and answer.assignment_count == domain_size
            and not answer.diagnostics
            and not answer.unresolved
            and evidence_complete
        )
        if (
            trusted_exhaustive_reference
            and answer.complete_domain
            and answer.refutation_constraint_ids == expected_constraints
        ):
            status = "infeasible"
            refutation_ids = answer.refutation_constraint_ids
        else:
            diagnostics.add("incomplete_unsat_certificate")
            unresolved.add("unvalidated_refutation")
    elif answer.model_kind == "incomplete":
        unresolved.add("incomplete_model")
    else:
        unresolved.add("engine_unknown")

    result = ProofResult(
        bindings=query.bindings,
        query_digest=query.query_digest,
        engine_version=answer.engine_version,
        model_kind=answer.model_kind,
        raw_disposition=answer.disposition,
        status=status,
        abstract_sat=(
            answer.model_kind == "sound_overapprox" and answer.disposition == "sat"
        ),
        scope="within_bounds",
        assumptions=answer.assumptions,
        bounds=answer.bounds,
        budget=answer.budget,
        coverage=answer.coverage,
        bitvector_semantics=answer.bitvector_semantics,
        engine_answer_digest=answer.answer_digest,
        assignments_checked=answer.assignment_count,
        complete_domain=answer.complete_domain,
        witness=witness,
        refutation_constraint_ids=refutation_ids,
        evidence_ids=answer.evidence_ids,
        diagnostics=tuple(sorted(diagnostics)),
        unresolved=tuple(sorted(unresolved)),
    )
    validate_proof_result(query, result)
    return result


__all__ = [
    "BITVECTOR_SEMANTICS",
    "REFERENCE_ENGINE_VERSION",
    "EngineAnswer",
    "ProofEngine",
    "ProofResult",
    "ReferenceProofEngine",
    "StaleProofEvidenceError",
    "WitnessValidation",
    "classify_proof",
    "validate_proof_result",
    "validate_witness",
]
