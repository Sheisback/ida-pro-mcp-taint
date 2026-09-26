"""Seeded implicit-flow propagation over structural control regions.

Explicit scalar provenance remains owned by :mod:`analysis`.  This module adds a
separate control-label fixed point: predicates inject control labels only into
definitions structurally attributed to them, while already-carried control
labels continue through value, phi, select-payload, and memory-data relations.
"""

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace, field
from typing import TYPE_CHECKING, Literal

from .analysis import AnalysisResult, BitSeed, Fact, Seed, analyze
from .contracts import ValueSource
from .memory import LabelBitRange
from .serialization import Model, digest
from .ssa import SSAProgram
from .states import Labels, canonical_set, check_digest, check_id, require, unique

if TYPE_CHECKING:
    from .implicit_cfg import ImplicitCFG
    from .memory_graph import MemoryGraphAnalysis


@dataclass(frozen=True)
class ImplicitPolicy(Model):
    max_evaluations: int = 100000
    schema_version: Literal[1] = 1
    mode: Literal["implicit_control"] = "implicit_control"
    ruleset: Literal["implicit-transfer-v7"] = "implicit-transfer-v7"

    def __post_init__(self):
        super().__post_init__()
        require(self.max_evaluations > 0, "Invalid implicit evaluation budget")


@dataclass(frozen=True)
class ImplicitFact(Model):
    node_id: str
    labels: Labels
    explicit_bit_ranges: tuple[LabelBitRange, ...] = field(
        default=(), metadata={"omit_if_default": True}
    )

    def __post_init__(self):
        super().__post_init__()
        check_id(self.node_id, "node")
        canonical_set(
            tuple((span.label, span.bit_offset) for span in self.explicit_bit_ranges)
        )
        require(
            all(
                span.label in self.labels.explicit for span in self.explicit_bit_ranges
            ),
            "Bit-label range without explicit label",
        )


@dataclass(frozen=True)
class ControlDependency(Model):
    predicate_node_id: str
    target_node_id: str
    origin: Literal["cfg_branch", "loop_feedback", "select", "indirect_target"]
    branch_node_id: str | None
    successor_block: int | None
    evidence_ids: tuple[str, ...]
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        check_id(self.predicate_node_id, "node")
        check_id(self.target_node_id, "node")
        require(
            (self.predicate_node_id == self.target_node_id)
            == (self.origin == "loop_feedback"),
            "Only a loop-feedback relation may be self-dependent",
        )
        require(bool(self.evidence_ids), "Control dependency requires evidence")
        canonical_set(self.evidence_ids)
        for evidence_id in self.evidence_ids:
            check_id(evidence_id, "evidence")
        if self.origin in {"cfg_branch", "loop_feedback"}:
            require(
                self.branch_node_id is not None and self.successor_block is not None,
                "CFG control dependency requires branch/successor attribution",
            )
        else:
            require(
                self.branch_node_id is None and self.successor_block is None,
                "Value-selection control dependency has no CFG branch attribution",
            )
        if self.branch_node_id is not None:
            check_id(self.branch_node_id, "node")
        if self.successor_block is not None:
            require(self.successor_block >= 0, "Negative control successor")

    @property
    def sort_key(self) -> tuple[str, str, str, str, int, tuple[str, ...]]:
        return (
            self.target_node_id,
            self.predicate_node_id,
            self.origin,
            self.branch_node_id or "",
            -1 if self.successor_block is None else self.successor_block,
            self.evidence_ids,
        )


@dataclass(frozen=True)
class ImplicitResult(Model):
    graph_digest: str
    source_digest: str
    policy_digest: str
    control_digest: str
    explicit_result_digest: str
    facts: tuple[ImplicitFact, ...]
    relations: tuple[ControlDependency, ...]
    status: Literal["complete_in_scope", "partial"]
    frontier: tuple[str, ...]
    diagnostics: tuple[str, ...]
    evaluations: int
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        for value in (
            self.graph_digest,
            self.source_digest,
            self.policy_digest,
            self.control_digest,
            self.explicit_result_digest,
        ):
            check_digest(value)
        node_ids = tuple(fact.node_id for fact in self.facts)
        canonical_set(node_ids)
        require(
            tuple(relation.sort_key for relation in self.relations)
            == tuple(sorted(set(relation.sort_key for relation in self.relations))),
            "Control dependencies must be sorted and unique",
        )
        require(
            all(
                relation.predicate_node_id in node_ids
                and relation.target_node_id in node_ids
                and (
                    relation.branch_node_id is None
                    or relation.branch_node_id in node_ids
                )
                for relation in self.relations
            ),
            "Control dependency references an unknown node",
        )
        canonical_set(self.frontier)
        canonical_set(self.diagnostics)
        require(set(self.frontier) <= set(node_ids), "Unknown implicit frontier node")
        require(self.evaluations >= 0, "Negative implicit evaluations")
        require(
            self.status != "complete_in_scope"
            or (not self.frontier and not self.diagnostics),
            "Complete implicit result has partial evidence",
        )

    @property
    def cache_key(self) -> str:
        return digest(
            {
                "graph": self.graph_digest,
                "source": self.source_digest,
                "policy": self.policy_digest,
                "control": self.control_digest,
            }
        )


@dataclass(frozen=True)
class _Region:
    """Private normalized view of a Task-1 control-region certificate."""

    predicate_node_id: str
    branch_node_id: str
    successor_block: int
    target_blocks: tuple[int, ...]
    evidence_ids: tuple[str, ...]


def _explicit_seed(seed: Seed | BitSeed) -> Seed | BitSeed:
    labels = seed.labels
    return replace(
        seed,
        labels=Labels(
            explicit=labels.explicit,
            unknown_provenance=labels.unknown_provenance,
            any_explicit_source=labels.any_explicit_source,
        ),
    )


def _control_part(labels: Labels) -> Labels:
    return Labels(
        control=labels.control,
        unknown_provenance=labels.unknown_provenance,
        any_control_source=labels.any_control_source,
    )


def _predicate_control(labels: Labels) -> Labels:
    return Labels(
        control=tuple(sorted(set(labels.explicit) | set(labels.control))),
        unknown_provenance=labels.unknown_provenance,
        any_control_source=(
            labels.any_explicit_source
            or labels.any_control_source
            or labels.unknown_provenance
        ),
    )


def _known_target_control(labels: Labels, *, seeded_unknown: bool) -> Labels:
    """Use a complete finite target proof, not pointer-domain uncertainty."""
    unknown_source = (
        labels.any_explicit_source or labels.any_control_source or seeded_unknown
    )
    return Labels(
        control=tuple(sorted(set(labels.explicit) | set(labels.control))),
        unknown_provenance=unknown_source,
        any_control_source=unknown_source,
    )


def _dataflow(
    program: SSAProgram,
    checkpoint: Callable[[], None] | None = None,
) -> tuple[dict[str, tuple[str, ...]], dict[str, set[str]]]:
    if checkpoint is not None:
        checkpoint()
    nodes = {node.node_id for node in program.graph.nodes}
    dependencies: dict[str, set[str]] = {node_id: set() for node_id in nodes}
    consumers: dict[str, set[str]] = {node_id: set() for node_id in nodes}
    for edge in program.graph.edges:
        if checkpoint is not None:
            checkpoint()
        if edge.kind not in {
            "value_dependency",
            "phi_input",
            "memory_data_dependency",
        }:
            continue
        dependencies[edge.target].add(edge.source)
        consumers[edge.source].add(edge.target)
    return (
        {node_id: tuple(sorted(sources)) for node_id, sources in dependencies.items()},
        consumers,
    )


def _descendants(
    starts: Iterable[str],
    consumers: Mapping[str, set[str]],
    checkpoint: Callable[[], None] | None = None,
) -> set[str]:
    if checkpoint is not None:
        checkpoint()
    reached = set(starts)
    pending = list(reached)
    while pending:
        if checkpoint is not None:
            checkpoint()
        for consumer in consumers[pending.pop()]:
            if checkpoint is not None:
                checkpoint()
            if consumer not in reached:
                reached.add(consumer)
                pending.append(consumer)
    return reached


def _analyze_regions(
    program: SSAProgram,
    regions: tuple[_Region, ...],
    control_digest: str,
    seeds: tuple[Seed | BitSeed, ...],
    policy: ImplicitPolicy,
    *,
    partial_nodes: tuple[str, ...] = (),
    control_diagnostics: tuple[str, ...] = (),
    memory_model: "MemoryGraphAnalysis | None" = None,
    checkpoint: Callable[[], None] | None = None,
) -> ImplicitResult:
    """Run the label fixed point over a normalized Task-1 certificate view."""

    if checkpoint is not None:
        checkpoint()
    check_digest(control_digest)
    canonical_set(
        tuple(
            (
                seed.node_id,
                1 if isinstance(seed, BitSeed) else 0,
                seed.bit_offset if isinstance(seed, BitSeed) else 0,
                seed.width_bits if isinstance(seed, BitSeed) else 0,
            )
            for seed in seeds
        )
    )
    graph = program.graph
    node_ids = {node.node_id for node in graph.nodes}
    evidence_ids = {evidence.evidence_id for evidence in graph.evidence}
    definitions = {definition.node_id: definition for definition in program.definitions}
    for seed in seeds:
        if checkpoint is not None:
            checkpoint()
        graph.validate_source(ValueSource(graph.snapshot.snapshot_id, seed.node_id))
        if isinstance(seed, BitSeed):
            source = next(node for node in graph.nodes if node.node_id == seed.node_id)
            require(
                source.kind == "InputValue"
                and source.width_bits is not None
                and seed.bit_offset + seed.width_bits <= source.width_bits,
                "Bit-range source must fit an InputValue",
            )
    for region in regions:
        if checkpoint is not None:
            checkpoint()
        require(
            region.predicate_node_id in node_ids and region.branch_node_id in node_ids,
            "Control region references an unknown predicate/branch node",
        )
        require(region.successor_block >= 0, "Negative control successor")
        unique(region.target_blocks)
        require(
            all(block >= 0 for block in region.target_blocks),
            "Negative controlled block",
        )
        canonical_set(region.evidence_ids)
        require(
            set(region.evidence_ids) <= evidence_ids,
            "Control region references unknown evidence",
        )
    require(set(partial_nodes) <= node_ids, "Unknown control frontier node")
    canonical_set(partial_nodes)
    canonical_set(control_diagnostics)

    explicit_seeds = tuple(_explicit_seed(seed) for seed in seeds)
    value_seeds = tuple(seed for seed in explicit_seeds if isinstance(seed, Seed))
    bit_seeds = tuple(seed for seed in explicit_seeds if isinstance(seed, BitSeed))
    supported_memory_seed_kinds = {
        "Constant",
        "InputValue",
        "Copy",
        "Unary",
        "Binary",
        "Compare",
        "Select",
        "Phi",
        "Load",
        "UnknownValue",
        "Call",
        "Return",
        "InputMemory",
    }
    use_memory = memory_model is not None and all(
        next(n for n in graph.nodes if n.node_id == seed.node_id).kind
        in supported_memory_seed_kinds
        for seed in explicit_seeds
    )
    require(not bit_seeds or use_memory, "Bit-range source requires memory replay")
    explicit_ranges: dict[str, tuple[LabelBitRange, ...]] = {}
    if use_memory:
        from .memory_graph import analyze_seeded_memory

        assert memory_model is not None
        require(memory_model.graph == graph, "Seeded memory graph mismatch")
        if checkpoint is not None:
            checkpoint()
        memory_result = analyze_seeded_memory(
            memory_model,
            value_seeds,
            bit_seeds=bit_seeds,
            checkpoint=checkpoint,
        )
        if checkpoint is not None:
            checkpoint()
        explicit = AnalysisResult(
            graph.graph_digest,
            memory_result.source_digest,
            memory_result.policy_digest,
            tuple(
                Fact(fact.node_id, fact.value, fact.labels)
                for fact in memory_result.facts
            ),
            memory_result.status,
            memory_result.frontier,
            memory_result.diagnostics,
            memory_result.iterations,
        )
        explicit_ranges = {
            fact.node_id: fact.explicit_bit_ranges for fact in memory_result.facts
        }
    else:
        explicit = analyze(graph, value_seeds, checkpoint=checkpoint)
    explicit_facts = {fact.node_id: fact for fact in explicit.facts}
    seed_controls: dict[str, Labels] = {}
    for seed in seeds:
        seed_controls[seed.node_id] = seed_controls.get(seed.node_id, Labels()).join(
            _control_part(seed.labels)
        )
    labels = {
        node_id: fact.labels.join(seed_controls.get(node_id, Labels()))
        for node_id, fact in explicit_facts.items()
    }
    for node_id in node_ids - labels.keys():
        if checkpoint is not None:
            checkpoint()
        labels[node_id] = seed_controls.get(node_id, Labels())

    dependencies, consumers = _dataflow(program, checkpoint)
    unknown_seed_targets = _descendants(
        (
            seed.node_id
            for seed in seeds
            if seed.labels.unknown_provenance
            or seed.labels.any_explicit_source
            or seed.labels.any_control_source
        ),
        consumers,
        checkpoint,
    )
    injections: dict[str, set[tuple[str, str | None]]] = {
        node_id: set() for node_id in node_ids
    }
    known_target_injections: dict[str, set[str]] = {
        node_id: set() for node_id in node_ids
    }
    relations: list[ControlDependency] = []
    predicate_targets: dict[str, set[str]] = {node_id: set() for node_id in node_ids}
    for region in regions:
        if checkpoint is not None:
            checkpoint()
        targets = tuple(
            sorted(
                node_id
                for node_id, definition in definitions.items()
                if definition.block in region.target_blocks
            )
        )
        for target in targets:
            if checkpoint is not None:
                checkpoint()
            injections[target].add((region.predicate_node_id, region.branch_node_id))
            predicate_targets[region.predicate_node_id].add(target)
            predicate_targets[region.branch_node_id].add(target)
            relations.append(
                ControlDependency(
                    region.predicate_node_id,
                    target,
                    "loop_feedback"
                    if target == region.predicate_node_id
                    else "cfg_branch",
                    region.branch_node_id,
                    region.successor_block,
                    region.evidence_ids,
                )
            )

    for edge in graph.edges:
        if checkpoint is not None:
            checkpoint()
        if edge.kind != "control_dependency":
            continue
        target = next(node for node in graph.nodes if node.node_id == edge.target)
        if target.kind == "Select":
            origin = "select"
        elif (
            target.kind == "CallResult"
            and target.operation == "derived_static_finite_indirect_return"
        ):
            origin = "indirect_target"
        else:
            continue
        if origin == "indirect_target":
            known_target_injections[edge.target].add(edge.source)
        else:
            injections[edge.target].add((edge.source, None))
        predicate_targets[edge.source].add(edge.target)
        relations.append(
            ControlDependency(
                edge.source,
                edge.target,
                origin,
                None,
                None,
                edge.evidence_ids,
            )
        )

    pending = set(node_ids)
    evaluations = 0
    while pending and evaluations < policy.max_evaluations:
        if checkpoint is not None:
            checkpoint()
        node_id = min(pending)
        pending.remove(node_id)
        evaluations += 1
        addition = Labels()
        for source in dependencies[node_id]:
            if checkpoint is not None:
                checkpoint()
            addition = addition.join(_control_part(labels[source]))
        for predicate, branch_node in sorted(
            injections[node_id], key=lambda item: (item[0], item[1] or "")
        ):
            if checkpoint is not None:
                checkpoint()
            addition = addition.join(_predicate_control(labels[predicate]))
            if branch_node is not None:
                addition = addition.join(_control_part(labels[branch_node]))
        for target in sorted(known_target_injections[node_id]):
            if checkpoint is not None:
                checkpoint()
            addition = addition.join(
                _known_target_control(
                    labels[target], seeded_unknown=target in unknown_seed_targets
                )
            )
        updated = labels[node_id].join(addition)
        if updated != labels[node_id]:
            labels[node_id] = updated
            pending.update(consumers[node_id])
            pending.update(predicate_targets[node_id])

    # Preserve the seeded scalar/byte-memory cause codes for *every* source
    # kind. The aggregate partial_explicit_analysis is not a causal reason.
    diagnostics = set(control_diagnostics) | set(explicit.diagnostics)
    if memory_model is not None and not use_memory:
        diagnostics.add("seeded_memory_source_unavailable")
    if explicit.status == "partial":
        diagnostics.add("partial_explicit_analysis")
    frontier = _descendants(partial_nodes, consumers, checkpoint)
    if pending:
        diagnostics.add("implicit_evaluation_budget")
        frontier.update(_descendants(pending, consumers, checkpoint))
    for node_id in frontier:
        if checkpoint is not None:
            checkpoint()
        labels[node_id] = labels[node_id].join(
            Labels(unknown_provenance=True, any_control_source=True)
        )

    ordered_relations = tuple(sorted(set(relations), key=lambda item: item.sort_key))
    return ImplicitResult(
        graph.graph_digest,
        digest([seed.to_data() for seed in seeds]),
        digest(policy),
        control_digest,
        digest(explicit),
        tuple(
            ImplicitFact(
                node_id,
                labels[node_id],
                explicit_ranges.get(node_id, ()),
            )
            for node_id in sorted(node_ids)
        ),
        ordered_relations,
        "partial" if diagnostics or frontier else "complete_in_scope",
        tuple(sorted(frontier)),
        tuple(sorted(diagnostics)),
        evaluations,
    )


def analyze_implicit(
    program: SSAProgram,
    seeds: tuple[Seed | BitSeed, ...] = (),
    policy: ImplicitPolicy = ImplicitPolicy(),
    control: "ImplicitCFG | None" = None,
    *,
    memory_model: "MemoryGraphAnalysis | None" = None,
    checkpoint: Callable[[], None] | None = None,
) -> ImplicitResult:
    """Apply implicit labels using Task 1's structural certificate.

    Passing a certificate supports deterministic cache/replay workflows. A
    supplied stale certificate is rejected instead of being silently recomputed.
    The optional checkpoint runs throughout structural and label computation;
    cancellation/deadline exceptions propagate rather than returning partial facts.
    """

    if checkpoint is not None:
        checkpoint()
    if memory_model is not None:
        require(memory_model.graph == program.graph, "Seeded memory graph mismatch")
    from .implicit_cfg import ImplicitCFG, analyze_implicit_cfg

    if control is None:
        control = analyze_implicit_cfg(program, checkpoint=checkpoint)
    require(type(control) is ImplicitCFG, "Invalid implicit CFG certificate")
    require(
        control.program_digest == digest(program),
        "Stale implicit CFG certificate",
    )
    block_count = len(program.graph.snapshot.function.blocks)
    real_blocks = set(range(block_count))
    reachable = set(control.reachable)
    require(reachable <= real_blocks, "Invalid implicit CFG reachable block")
    require(
        set(control.frontier) <= reachable,
        "Invalid implicit CFG frontier block",
    )
    for region in control.regions:
        if checkpoint is not None:
            checkpoint()
        require(
            set(region.controlled_blocks) <= reachable,
            "Invalid implicit CFG controlled block",
        )
        require(
            set(region.frontier) <= reachable,
            "Invalid implicit CFG region frontier block",
        )

    regions = tuple(
        _Region(
            region.predicate_node_id,
            region.branch_node_id,
            region.successor,
            region.controlled_blocks,
            region.evidence_ids,
        )
        for region in control.regions
        if region.predicate_node_id is not None
        and region.branch_node_id is not None
        and region.controlled_blocks
    )
    frontier_blocks = set(control.frontier)
    diagnostics = set(control.diagnostics)
    for region in control.regions:
        if checkpoint is not None:
            checkpoint()
        frontier_blocks.update(region.frontier)
        diagnostics.update(region.diagnostics)
        if region.status == "partial":
            diagnostics.add("partial_control_region")
            if not region.frontier:
                frontier_blocks.update(region.controlled_blocks)
    if control.status == "partial":
        diagnostics.add("partial_control_certificate")
        if not frontier_blocks:
            frontier_blocks.update(control.reachable)
    pending_blocks = list(frontier_blocks)
    while pending_blocks:
        if checkpoint is not None:
            checkpoint()
        block = pending_blocks.pop()
        for successor in program.graph.snapshot.function.blocks[block].successors:
            if checkpoint is not None:
                checkpoint()
            if successor not in frontier_blocks:
                frontier_blocks.add(successor)
                pending_blocks.append(successor)
    partial_nodes = tuple(
        definition.node_id
        for definition in program.definitions
        if definition.block in frontier_blocks
    )
    return _analyze_regions(
        program,
        regions,
        digest(control),
        seeds,
        policy,
        partial_nodes=tuple(sorted(partial_nodes)),
        control_diagnostics=tuple(sorted(diagnostics)),
        memory_model=memory_model,
        checkpoint=checkpoint,
    )


__all__ = [
    "ControlDependency",
    "ImplicitFact",
    "ImplicitPolicy",
    "ImplicitResult",
    "analyze_implicit",
]
