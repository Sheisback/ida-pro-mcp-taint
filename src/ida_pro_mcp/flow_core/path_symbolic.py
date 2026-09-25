"""Symbolic (wide, solver-backed) CFG-prefix path queries. Schema v2.

v1 (``path_conditions``) is frozen: explicit finite domains, ≤8-bit inputs,
Select/Phi rejected. This module derives full-width symbolic queries over the
shared SSA op table, projects Phi deterministically on the fixed path, and
classifies solver answers into versioned tiers that never reuse ``infeasible``.
"""

import json
from dataclasses import dataclass, replace
from typing import Literal

from .constraints import (
    ConstraintBindings,
    Predicate,
    ProofAssumption,
    ProofBounds,
    ProofBudget,
)
from .path_conditions import PathSelector, path_bindings
from .proof import StaleProofEvidenceError
from .serialization import ContractError, Model, canonical_json, digest
from .states import canonical_set, check_digest, check_id, nonempty, require
from .symbolic import (
    OP_TABLE_VERSION,
    SYMBOLIC_IR_VERSION,
    SymBinding,
    SymExpr,
    SymbolicBudgetError,
    Z3Backend,
    replay_witness,
    translate_node,
)

SYMBOLIC_QUERY_VERSION = 2
SYMBOLIC_THEORY = "fixed_width_bitvectors_symbolic_v1"
SYMBOLIC_RULE = "program-path-symbolic-v1"
FEASIBLE_SYMBOLIC = "feasible_symbolic_v1"
INFEASIBLE_SMT_BOUNDED = "infeasible_smt_bounded_v1"

SymbolicStatus = Literal[
    "feasible_symbolic_v1", "infeasible_smt_bounded_v1", "unknown"
]
SymbolicModelKind = Literal["exact", "sound_overapprox", "incomplete"]
SymbolicDisposition = Literal["sat", "unsat", "unknown"]


@dataclass(frozen=True)
class SymVariable(Model):
    name: str
    width_bits: int

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.name)
        require(1 <= self.width_bits <= 64, "Symbolic variable needs 1..64 bits")


@dataclass(frozen=True)
class SymPredicate(Model):
    constraint_id: str
    left: SymExpr
    predicate: Predicate
    right: SymExpr
    expected: bool
    rule_id: str
    origin_id: str
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.constraint_id)
        require(
            self.left.width_bits == self.right.width_bits,
            "Symbolic comparison width mismatch",
        )
        nonempty(self.rule_id)
        check_id(self.origin_id, "node")
        canonical_set(self.evidence_ids)
        for evidence_id in self.evidence_ids:
            check_id(evidence_id, "evidence")


@dataclass(frozen=True)
class SymbolicCoverage(Model):
    theory: Literal["fixed_width_bitvectors_symbolic_v1", "flat_array_bitvectors_symbolic_v1"]
    variable_names: tuple[str, ...]
    variable_digest: str
    constraint_ids: tuple[str, ...]
    operators: tuple[str, ...]
    domains_are_exact: Literal[False] = False
    bounded_only: Literal[True] = True

    def __post_init__(self):
        super().__post_init__()
        canonical_set(self.variable_names)
        for value in self.variable_names:
            nonempty(value)
        check_digest(self.variable_digest)
        canonical_set(self.constraint_ids)
        canonical_set(self.operators)


def symbolic_variable_digest(variables: tuple[SymVariable, ...]) -> str:
    return digest([item.to_data() for item in variables])


@dataclass(frozen=True)
class SymbolicPathQuery(Model):
    bindings: ConstraintBindings
    variables: tuple[SymVariable, ...]
    predicates: tuple[SymPredicate, ...]
    assumptions: tuple[ProofAssumption, ...]
    bounds: ProofBounds
    budget: ProofBudget
    coverage: SymbolicCoverage
    schema_version: Literal[2] = 2

    def __post_init__(self):
        super().__post_init__()
        require(self.schema_version == 2, "invalid_symbolic_query_version")
        canonical_set(tuple(item.name for item in self.variables))
        canonical_set(tuple(item.constraint_id for item in self.predicates))
        require(
            self.coverage.variable_names == tuple(item.name for item in self.variables),
            "Symbolic coverage/variable mismatch",
        )
        require(
            self.coverage.constraint_ids
            == tuple(item.constraint_id for item in self.predicates),
            "Symbolic coverage/predicate mismatch",
        )
        require(
            self.coverage.variable_digest == symbolic_variable_digest(self.variables),
            "Symbolic coverage digest mismatch",
        )

    @property
    def query_digest(self) -> str:
        return digest(self)


@dataclass(frozen=True)
class SymbolicProofResult(Model):
    query_digest: str
    engine_version: str
    model_kind: SymbolicModelKind
    raw_disposition: SymbolicDisposition
    status: SymbolicStatus
    scope: Literal["path_prefix_only"]
    assumptions: tuple[ProofAssumption, ...]
    bounds: ProofBounds
    budget: ProofBudget
    coverage: SymbolicCoverage
    path_blocks: tuple[int, ...]
    translated_roots: int
    solver_timeout_ms: int
    solver_stamp: str = ""
    solver_version: str = ""
    witness: tuple[SymBinding, ...] = ()
    refutation_predicate_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        check_digest(self.query_digest)
        nonempty(self.engine_version)
        require(bool(self.path_blocks), "Symbolic result needs its path")
        require(self.translated_roots >= 0, "Negative translation count")
        require(self.solver_timeout_ms > 0, "Solver timeout must be positive")
        canonical_set(tuple(item.name for item in self.witness))
        canonical_set(self.refutation_predicate_ids)
        canonical_set(self.evidence_ids)
        for evidence_id in self.evidence_ids:
            check_id(evidence_id, "evidence")
        canonical_set(self.diagnostics)
        canonical_set(self.unresolved)
        if self.status in (FEASIBLE_SYMBOLIC, INFEASIBLE_SMT_BOUNDED):
            require(self.solver_stamp != "", "Definite symbolic result needs a stamp")
            require(not self.unresolved, "Definite symbolic result must resolve")
            require(not self.diagnostics, "Definite symbolic result must be clean")


def project_value_phi(nodes: dict, path: tuple[int, ...]) -> dict:
    """Replace fixed-path Phi nodes with Copy nodes.

    Only translated nodes matter: unresolvable Phi nodes stay in place and the
    translator marks them unsupported if (and only if) a predicate needs them.
    """
    projected = dict(nodes)
    position = {block: index for index, block in enumerate(path)}
    for identifier, node in nodes.items():
        if node.kind != "Phi":
            continue
        block = node.phi_block
        index = position.get(block, -1) if block is not None else -1
        if index <= 0:
            continue
        matches = [item for item in node.phi_inputs if item.predecessor == path[index - 1]]
        if len(matches) != 1:
            continue
        projected[identifier] = replace(
            node, kind="Copy", inputs=(matches[0].node_id,), phi_inputs=(),
            phi_block=None, operation=None,
        )
    return projected


def _translator_unknown_to_unresolved(reason: str) -> str:
    if reason.startswith("unsupported_Phi"):
        return "unreachable_phi_predecessor" + reason[len("unsupported_Phi"):]
    return reason


_PATH_EFFECTS_REJECTED = frozenset(
    {
        "Call",
        "Load",
        "Store",
        "UnknownValue",
        "Allocation",
        "Free",
        "Return",
        "OpaqueEffect",
        "MemoryPhi",
    }
)

_BRANCH_PREDICATES: dict[str, Predicate] = {
    "m_jz": "eq",
    "m_jnz": "ne",
    "m_ja": "ugt",
    "m_jae": "uge",
    "m_jb": "ult",
    "m_jbe": "ule",
    "m_jg": "sgt",
    "m_jge": "sge",
    "m_jl": "slt",
    "m_jle": "sle",
}


def _collect_vars(expression: SymExpr, into: dict[str, int]) -> None:
    if expression.kind == "var":
        assert expression.name is not None
        into.setdefault(expression.name, expression.width_bits)
    for child in expression.children:
        _collect_vars(child, into)


def _collect_ops(expression: SymExpr, into: set[str]) -> None:
    if expression.op is not None:
        into.add(expression.op)
    for child in expression.children:
        _collect_ops(child, into)


def symbolic_predicate_summary(predicates):
    """Sorted free variables and operators over rewritten predicates."""
    variables: dict[str, int] = {}
    operators: set[str] = set()
    for item in predicates:
        _collect_vars(item.left, variables)
        _collect_vars(item.right, variables)
        _collect_ops(item.left, operators)
        _collect_ops(item.right, operators)
        operators.add(item.predicate)
    ordered = tuple(SymVariable(name, variables[name]) for name in sorted(variables))
    return ordered, tuple(sorted(operators))


def derive_symbolic_path_query(
    graph,
    selector: PathSelector,
    *,
    allow_memory_effects=False,
    callee_prefix=False,
    inlined_calls=frozenset(),
    overrides=None,
):
    """Derive a schema-v2 symbolic query. v1 derivation is untouched.

    ``allow_memory_effects`` keeps Load/Store/MemoryPhi steps in the prefix so
    the memory layer can encode them; memory-dependent branch conditions still
    resolve to unknown through the translator.

    ``callee_prefix`` derives a callee path for inline expansion: nested Call
    steps become havoc (their result values stay unmodeled) and Return
    terminators are permitted. ``inlined_calls`` exempts specific caller Call
    node IDs whose effect is replaced by a callee fragment, together with
    the havoc unknowns pushed at exactly those call sites (sibling atoms
    stay unknown-if-used through the translator). ``overrides`` replaces
    projected nodes before branch translation so inlined results resolve.
    """
    require(selector.bindings == path_bindings(graph), "path_query_artifact_mismatch")
    function = graph.snapshot.function
    path = selector.blocks
    require(path[0] == function.entry_block, "path_must_start_at_entry")
    require(all(i < len(function.blocks) for i in path), "path_foreign_block")
    require(
        all(b in function.blocks[a].successors for a, b in zip(path, path[1:])),
        "path_foreign_transition",
    )
    unresolved = set()
    if any(item.severity != "information" for item in function.diagnostics):
        unresolved.add("function_diagnostics_unresolved")
    if len(set(path)) != len(path):
        unresolved.add("loop_unrolling_unsupported")
    raw_nodes = {n.node_id: n for n in graph.nodes}
    nodes = project_value_phi(raw_nodes, path)
    if overrides:
        merged = dict(nodes)
        merged.update(overrides)
        nodes = merged
    evidence = {e.evidence_id: e for e in graph.evidence}

    def sites(node):
        return tuple(site for eid in node.evidence_ids for site in evidence[eid].sites)

    inlined_sites = set()
    for candidate in graph.nodes:
        if candidate.kind == "Call" and candidate.node_id in inlined_calls:
            for site in sites(candidate):
                inlined_sites.add((site.block_index, site.instruction_index))

    def inlined_havoc(node):
        if node.kind != "UnknownValue":
            return False
        if node.operation != "unmodeled_memory_or_call_effect":
            return False
        positions = [
            (site.block_index, site.instruction_index) for site in sites(node)
        ]
        return bool(positions) and all(
            position in inlined_sites for position in positions
        )

    predicates: list[SymPredicate] = []
    translated = 0

    def translate(identifier: str) -> SymExpr:
        nonlocal translated
        try:
            result = translate_node(nodes, identifier)
        except SymbolicBudgetError as exc:
            raise ValueError(str(exc)) from exc
        translated += 1
        for reason in result.unknowns:
            unresolved.add(_translator_unknown_to_unresolved(reason))
        return result.roots[0]

    for ordinal, (block_index, successor) in enumerate(zip(path, path[1:])):
        block = function.blocks[block_index]
        local = [
            n
            for n in graph.nodes
            if any(site.block_index == block_index for site in sites(n))
        ]
        exempt = set()
        if allow_memory_effects:
            exempt |= {"Load", "Store", "MemoryPhi"}
        if callee_prefix:
            exempt |= {"Call", "Return"}
        rejected = _PATH_EFFECTS_REJECTED - exempt
        if any(
            n.kind in rejected
            and not (n.kind == "Call" and n.node_id in inlined_calls)
            and not inlined_havoc(n)
            for n in local
        ):
            unresolved.add("unsupported_path_effect")
        branches = [n for n in local if n.kind == "Branch"]
        if not branches and len(block.successors) == 1:
            continue
        if len(branches) != 1 or not block.instructions:
            unresolved.add("unsupported_branch_correspondence")
            continue
        branch = branches[0]
        instruction = block.instructions[-1]
        targets = [o.block_index for o in instruction.operands if o.kind == "block"]
        if (
            not any(
                site.block_index == block_index
                and site.instruction_index == instruction.index
                for site in sites(branch)
            )
            or len(targets) != 1
            or targets[0] not in block.successors
        ):
            unresolved.add("unsupported_branch_target")
            continue
        if not branch.inputs:
            if instruction.opcode != "m_goto" or len(block.successors) != 1:
                unresolved.add("unsupported_unconditional_branch")
            continue
        if len(block.successors) != 2 or instruction.opcode not in _BRANCH_PREDICATES:
            unresolved.add("unsupported_branch_semantics")
            continue
        try:
            comparison = nodes[branch.inputs[0]]
            predicate = _BRANCH_PREDICATES[instruction.opcode]
            if comparison.kind != "Compare" or comparison.operation != predicate:
                raise ValueError("unsupported_predicate_correspondence")
            left = translate(comparison.inputs[0])
            right = translate(comparison.inputs[1])
            if left.width_bits != right.width_bits:
                raise ValueError("comparison_width")
            predicates.append(
                SymPredicate(
                    f"path-{ordinal:03d}",
                    left,
                    predicate,
                    right,
                    successor == targets[0],
                    SYMBOLIC_RULE,
                    branch.node_id,
                    tuple(sorted(set(branch.evidence_ids + comparison.evidence_ids))),
                )
            )
        except (ValueError, KeyError) as exc:
            unresolved.add(str(exc))
    if not predicates:
        unresolved.add("no_modeled_branch")
    variables: dict[str, int] = {}
    for item in predicates:
        _collect_vars(item.left, variables)
        _collect_vars(item.right, variables)
    ordered = tuple(SymVariable(name, variables[name]) for name in sorted(variables))
    operators: set[str] = set()
    for item in predicates:
        _collect_ops(item.left, operators)
        _collect_ops(item.right, operators)
        operators.add(item.predicate)
    query = SymbolicPathQuery(
        selector.bindings,
        ordered,
        tuple(sorted(predicates, key=lambda item: item.constraint_id)),
        (
            ProofAssumption("analysis", "cfg_prefix", canonical_json(list(path))),
            ProofAssumption("analysis", "scope", "reaches_last_block_before_execution"),
            ProofAssumption("analysis", "symbolic_ir_version", SYMBOLIC_IR_VERSION),
            ProofAssumption("analysis", "op_table_version", OP_TABLE_VERSION),
        ),
        ProofBounds(0, 0),
        ProofBudget(65536, 1000000, 1000),
        SymbolicCoverage(
            SYMBOLIC_THEORY,
            tuple(item.name for item in ordered),
            symbolic_variable_digest(ordered),
            tuple(item.constraint_id for item in predicates),
            tuple(sorted(operators)),
        ),
    )
    return query, tuple(sorted(unresolved)), translated


def conjunction(predicates: tuple[SymPredicate, ...]) -> SymExpr:
    """Single 1-bit expression: every predicate matches its expectation."""
    terms = []
    for item in predicates:
        gate = SymExpr(
            "op", 1, op=item.predicate,
            children=(item.left, item.right),
        )
        if not item.expected:
            gate = SymExpr("op", 1, op="logical_not", children=(gate,))
        terms.append(gate)
    if not terms:
        return SymExpr("const", 1, value=1)
    result = terms[0]
    for term in terms[1:]:
        result = SymExpr("op", 1, op="and", children=(result, term))
    return result


def prove_symbolic_path(
    graph,
    selector: PathSelector,
    *,
    backend: Z3Backend | None = None,
    timeout_ms: int = 5000,
    cancelled=lambda: False,
    inlines=(),
):
    """Prove a path prefix with the symbolic backend. Never touches v1.

    ``inlines`` splices bounded callee fragments at listed call sites; a
    refused fragment degrades the whole proof to unknown, never to unsound.
    """
    require(type(timeout_ms) is int and timeout_ms > 0, "Invalid solver timeout")
    inlines = tuple(inlines)
    inlined_calls = frozenset(request.call_id for request in inlines)
    engine_version = Z3Backend.backend_version
    # Local import: the inline layer builds on this module, so a
    # top-level import would cycle. Fragments stay out of v1.
    from .call_symbolic import build_inline_fragments, merge_inline_query
    fragments: tuple = ()
    refused: set[str] = set()
    translated = 0
    if inlines:
        nodes = project_value_phi(
            {node.node_id: node for node in graph.nodes}, selector.blocks
        )
        fragments, refused, extra_translated = build_inline_fragments(
            inlines, nodes
        )
        translated += extra_translated
        if refused:
            fragments = ()
    overrides = None
    if fragments:
        overrides = {}
        for fragment in fragments:
            overrides.update(fragment.overlay)
    query, unresolved, derive_translated = derive_symbolic_path_query(
        graph, selector, inlined_calls=inlined_calls, overrides=overrides
    )
    translated += derive_translated
    unresolved = set(unresolved) | refused
    if len(inlined_calls) != len(inlines):
        unresolved.add("inline_duplicate_call")
    if fragments and not refused:
        query = merge_inline_query(query, fragments)

    def unknown_result(reason: str, extra=()):
        return query, SymbolicProofResult(
            query_digest=query.query_digest,
            engine_version=engine_version,
            model_kind="incomplete",
            raw_disposition="unknown",
            status="unknown",
            scope="path_prefix_only",
            assumptions=query.assumptions,
            bounds=query.bounds,
            budget=query.budget,
            coverage=query.coverage,
            path_blocks=selector.blocks,
            translated_roots=translated,
            solver_timeout_ms=timeout_ms,
            diagnostics=(reason,),
            unresolved=tuple(sorted(set(unresolved) | {reason} | set(extra))),
        )

    if unresolved:
        return unknown_result("derivation_unresolved")
    if cancelled():
        return unknown_result("cancelled")
    if backend is None or not backend.available:
        return unknown_result("solver_unavailable")
    if backend.timeout_ms > timeout_ms:
        return unknown_result("solver_timeout_exceeds_job_budget")
    term = conjunction(query.predicates)
    answer = backend.check_nonzero(term)
    if answer.status == "sat":
        # Empty models are legitimate for closed terms; replay decides.
        if replay_witness(term, answer.model):
            return query, SymbolicProofResult(
                query_digest=query.query_digest,
                engine_version=engine_version,
                model_kind="exact",
                raw_disposition="sat",
                status=FEASIBLE_SYMBOLIC,
                scope="path_prefix_only",
                assumptions=query.assumptions,
                bounds=query.bounds,
                budget=query.budget,
                coverage=query.coverage,
                path_blocks=selector.blocks,
                translated_roots=translated,
                solver_timeout_ms=timeout_ms,
                solver_stamp=answer.stamp,
                solver_version=answer.solver_version,
                witness=answer.model,
                evidence_ids=tuple(
                    sorted({eid for item in query.predicates for eid in item.evidence_ids})
                ),
            )
        return unknown_result("witness_replay_failed")
    if answer.status == "unsat":
        return query, SymbolicProofResult(
            query_digest=query.query_digest,
            engine_version=engine_version,
            model_kind="exact",
            raw_disposition="unsat",
            status=INFEASIBLE_SMT_BOUNDED,
            scope="path_prefix_only",
            assumptions=query.assumptions,
            bounds=query.bounds,
            budget=query.budget,
            coverage=query.coverage,
            path_blocks=selector.blocks,
            translated_roots=translated,
            solver_timeout_ms=timeout_ms,
            solver_stamp=answer.stamp,
            solver_version=answer.solver_version,
            refutation_predicate_ids=tuple(item.constraint_id for item in query.predicates),
            evidence_ids=tuple(
                sorted({eid for item in query.predicates for eid in item.evidence_ids})
            ),
        )
    return unknown_result(answer.reason or "solver_unknown")


def validate_symbolic_result(query: SymbolicPathQuery, result: SymbolicProofResult) -> None:
    """Reject stale/forged symbolic results. Mirrors v1 staleness discipline."""
    if result.query_digest != query.query_digest:
        raise StaleProofEvidenceError("Stale symbolic query digest")
    if result.assumptions != query.assumptions:
        raise StaleProofEvidenceError("Stale symbolic assumptions")
    if result.bounds != query.bounds:
        raise StaleProofEvidenceError("Stale symbolic bounds")
    if result.budget != query.budget:
        raise StaleProofEvidenceError("Stale symbolic budget")
    if result.coverage != query.coverage:
        raise StaleProofEvidenceError("Stale symbolic coverage")
    if result.path_blocks != tuple(
        json.loads(next(a.value for a in query.assumptions if a.key == "cfg_prefix"))
    ):
        raise StaleProofEvidenceError("Stale symbolic path")
    if result.status in (FEASIBLE_SYMBOLIC, INFEASIBLE_SMT_BOUNDED):
        expected = tuple(
            sorted({eid for item in query.predicates for eid in item.evidence_ids})
        )
        if result.evidence_ids != expected:
            raise ContractError("Definite symbolic result has mismatched evidence")
        if not result.solver_stamp or not result.solver_version:
            raise ContractError("Definite symbolic result lacks a solver stamp")
    if result.status == FEASIBLE_SYMBOLIC:
        # Empty models are legitimate for closed terms; replay decides.
        if not replay_witness(conjunction(query.predicates), result.witness):
            raise ContractError("Feasible symbolic result has an invalid witness")
    if result.status == INFEASIBLE_SMT_BOUNDED:
        expected_ids = tuple(item.constraint_id for item in query.predicates)
        if result.refutation_predicate_ids != expected_ids:
            raise ContractError("Bounded refutation must cover every predicate")
        if result.model_kind != "exact":
            raise ContractError("Bounded refutation needs exact model kind")
