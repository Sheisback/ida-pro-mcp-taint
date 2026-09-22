"""Seeded implicit-flow propagation over structural control regions.

Explicit scalar provenance remains owned by :mod:`analysis`.  This module adds a
separate control-label fixed point: predicates inject control labels only into
definitions structurally attributed to them, while already-carried control
labels continue through value, phi, select-payload, and memory-data relations.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from .analysis import Seed, analyze
from .contracts import ValueSource
from .serialization import Model, digest
from .ssa import SSAProgram
from .states import Labels, canonical_set, check_digest, check_id, require, unique

if TYPE_CHECKING:
    from .implicit_cfg import ImplicitCFG


@dataclass(frozen=True)
class ImplicitPolicy(Model):
    max_evaluations: int = 100000
    schema_version: Literal[1] = 1
    mode: Literal["implicit_control"] = "implicit_control"
    ruleset: Literal["implicit-transfer-v1"] = "implicit-transfer-v1"

    def __post_init__(self):
        super().__post_init__()
        require(self.max_evaluations > 0, "Invalid implicit evaluation budget")


@dataclass(frozen=True)
class ImplicitFact(Model):
    node_id: str
    labels: Labels

    def __post_init__(self):
        super().__post_init__()
        check_id(self.node_id, "node")


@dataclass(frozen=True)
class ControlDependency(Model):
    predicate_node_id: str
    target_node_id: str
    origin: Literal["cfg_branch", "select"]
    branch_node_id: str | None
    successor_block: int | None
    evidence_ids: tuple[str, ...]
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        check_id(self.predicate_node_id, "node")
        check_id(self.target_node_id, "node")
        require(
            self.predicate_node_id != self.target_node_id,
            "Control predicate cannot depend on itself",
        )
        require(bool(self.evidence_ids), "Control dependency requires evidence")
        canonical_set(self.evidence_ids)
        for evidence_id in self.evidence_ids:
            check_id(evidence_id, "evidence")
        if self.origin == "cfg_branch":
            require(
                self.branch_node_id is not None and self.successor_block is not None,
                "CFG control dependency requires branch/successor attribution",
            )
        else:
            require(
                self.branch_node_id is None and self.successor_block is None,
                "Select control dependency has no CFG branch attribution",
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


def _explicit_seed(seed: Seed) -> Seed:
    labels = seed.labels
    return Seed(
        seed.node_id,
        Labels(
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


def _dataflow(
    program: SSAProgram,
) -> tuple[dict[str, tuple[str, ...]], dict[str, set[str]]]:
    nodes = {node.node_id for node in program.graph.nodes}
    dependencies: dict[str, set[str]] = {node_id: set() for node_id in nodes}
    consumers: dict[str, set[str]] = {node_id: set() for node_id in nodes}
    for edge in program.graph.edges:
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


def _descendants(starts: Iterable[str], consumers: Mapping[str, set[str]]) -> set[str]:
    reached = set(starts)
    pending = list(reached)
    while pending:
        for consumer in consumers[pending.pop()]:
            if consumer not in reached:
                reached.add(consumer)
                pending.append(consumer)
    return reached


def _analyze_regions(
    program: SSAProgram,
    regions: tuple[_Region, ...],
    control_digest: str,
    seeds: tuple[Seed, ...],
    policy: ImplicitPolicy,
    *,
    partial_nodes: tuple[str, ...] = (),
    control_diagnostics: tuple[str, ...] = (),
) -> ImplicitResult:
    """Run the label fixed point over a normalized Task-1 certificate view."""

    check_digest(control_digest)
    canonical_set(tuple(seed.node_id for seed in seeds))
    graph = program.graph
    node_ids = {node.node_id for node in graph.nodes}
    evidence_ids = {evidence.evidence_id for evidence in graph.evidence}
    definitions = {definition.node_id: definition for definition in program.definitions}
    for seed in seeds:
        graph.validate_source(ValueSource(graph.snapshot.snapshot_id, seed.node_id))
    for region in regions:
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
    explicit = analyze(graph, explicit_seeds)
    explicit_facts = {fact.node_id: fact for fact in explicit.facts}
    seed_controls = {seed.node_id: _control_part(seed.labels) for seed in seeds}
    labels = {
        node_id: fact.labels.join(seed_controls.get(node_id, Labels()))
        for node_id, fact in explicit_facts.items()
    }
    for node_id in node_ids - labels.keys():
        labels[node_id] = seed_controls.get(node_id, Labels())

    dependencies, consumers = _dataflow(program)
    injections: dict[str, set[tuple[str, str | None]]] = {
        node_id: set() for node_id in node_ids
    }
    relations: list[ControlDependency] = []
    predicate_targets: dict[str, set[str]] = {node_id: set() for node_id in node_ids}
    for region in regions:
        targets = tuple(
            sorted(
                node_id
                for node_id, definition in definitions.items()
                if definition.block in region.target_blocks
            )
        )
        for target in targets:
            injections[target].add((region.predicate_node_id, region.branch_node_id))
            predicate_targets[region.predicate_node_id].add(target)
            predicate_targets[region.branch_node_id].add(target)
            relations.append(
                ControlDependency(
                    region.predicate_node_id,
                    target,
                    "cfg_branch",
                    region.branch_node_id,
                    region.successor_block,
                    region.evidence_ids,
                )
            )

    for edge in graph.edges:
        if edge.kind != "control_dependency":
            continue
        target = next(node for node in graph.nodes if node.node_id == edge.target)
        if target.kind != "Select":
            continue
        injections[edge.target].add((edge.source, None))
        predicate_targets[edge.source].add(edge.target)
        relations.append(
            ControlDependency(
                edge.source,
                edge.target,
                "select",
                None,
                None,
                edge.evidence_ids,
            )
        )

    pending = set(node_ids)
    evaluations = 0
    while pending and evaluations < policy.max_evaluations:
        node_id = min(pending)
        pending.remove(node_id)
        evaluations += 1
        addition = Labels()
        for source in dependencies[node_id]:
            addition = addition.join(_control_part(labels[source]))
        for predicate, branch_node in sorted(
            injections[node_id], key=lambda item: (item[0], item[1] or "")
        ):
            addition = addition.join(_predicate_control(labels[predicate]))
            if branch_node is not None:
                addition = addition.join(_control_part(labels[branch_node]))
        updated = labels[node_id].join(addition)
        if updated != labels[node_id]:
            labels[node_id] = updated
            pending.update(consumers[node_id])
            pending.update(predicate_targets[node_id])

    diagnostics = set(control_diagnostics)
    if explicit.status == "partial":
        diagnostics.add("partial_explicit_analysis")
    frontier = _descendants(partial_nodes, consumers)
    if pending:
        diagnostics.add("implicit_evaluation_budget")
        frontier.update(_descendants(pending, consumers))
    for node_id in frontier:
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
        tuple(ImplicitFact(node_id, labels[node_id]) for node_id in sorted(node_ids)),
        ordered_relations,
        "partial" if diagnostics or frontier else "complete_in_scope",
        tuple(sorted(frontier)),
        tuple(sorted(diagnostics)),
        evaluations,
    )


def analyze_implicit(
    program: SSAProgram,
    seeds: tuple[Seed, ...] = (),
    policy: ImplicitPolicy = ImplicitPolicy(),
    control: "ImplicitCFG | None" = None,
) -> ImplicitResult:
    """Apply implicit labels using Task 1's structural certificate.

    Passing a certificate supports deterministic cache/replay workflows. A
    supplied stale certificate is rejected instead of being silently recomputed.
    """

    from .implicit_cfg import ImplicitCFG, analyze_implicit_cfg

    if control is None:
        control = analyze_implicit_cfg(program)
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
        block = pending_blocks.pop()
        for successor in program.graph.snapshot.function.blocks[block].successors:
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
    )


__all__ = [
    "ControlDependency",
    "ImplicitFact",
    "ImplicitPolicy",
    "ImplicitResult",
    "analyze_implicit",
]
