"""Bounded, read-only causal candidates for one seeded taint observation.

This is a structural backward slice, not path feasibility or a vulnerability
verdict. Function-wide partial diagnostics remain separate from local causes.
"""

from collections import deque
from dataclasses import dataclass
from typing import Literal

from .implicit_analysis import ImplicitResult
from .memory_graph import (
    MemoryGraphAnalysis,
    memory_access_reasons,
    memory_dependency_cause,
)
from .serialization import Model, digest
from .ssa import SSAProgram
from .states import (
    ByteRange,
    Labels,
    canonical_set,
    check_digest,
    check_id,
    nonempty,
    require,
)


@dataclass(frozen=True)
class ObservationCause(Model):
    reason_code: str
    source_node_id: str
    affected_node_id: str
    edge_id: str | None
    evidence_ids: tuple[str, ...]
    scope: Literal["direct_node", "candidate_structural_backward_slice"]
    precision: str | None = None
    memory_object_id: str | None = None
    interval: ByteRange | None = None
    source_candidate_object_ids: tuple[str, ...] = ()
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.reason_code)
        check_id(self.source_node_id, "node")
        check_id(self.affected_node_id, "node")
        if self.edge_id is not None:
            check_id(self.edge_id, "edge")
        canonical_set(self.evidence_ids)
        for evidence_id in self.evidence_ids:
            check_id(evidence_id, "evidence")
        if self.memory_object_id is not None:
            check_id(self.memory_object_id, "object")
        canonical_set(self.source_candidate_object_ids)
        for object_id in self.source_candidate_object_ids:
            check_id(object_id, "object")

    @property
    def sort_key(self):
        return (
            self.reason_code,
            self.source_node_id,
            self.affected_node_id,
            self.edge_id or "",
            self.memory_object_id or "",
            -1 if self.interval is None else self.interval.start,
            -1 if self.interval is None else self.interval.end,
        )


@dataclass(frozen=True)
class ObservationExplanation(Model):
    graph_digest: str
    analysis_digest: str
    observation_node_id: str
    labels: Labels
    analysis_status: Literal["complete_in_scope", "partial"]
    global_diagnostics: tuple[str, ...]
    causes: tuple[ObservationCause, ...]
    visited_nodes: int
    truncated: bool
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        check_digest(self.graph_digest)
        check_digest(self.analysis_digest)
        check_id(self.observation_node_id, "node")
        canonical_set(self.global_diagnostics)
        require(
            tuple(item.sort_key for item in self.causes)
            == tuple(sorted(set(item.sort_key for item in self.causes))),
            "Explanation causes must be sorted and unique",
        )
        require(self.visited_nodes >= 0, "Negative explanation traversal")


def explain_observation(
    program: SSAProgram,
    memory: MemoryGraphAnalysis,
    analysis: ImplicitResult,
    observation_node_id: str,
    *,
    max_nodes: int = 2048,
    max_causes: int = 256,
) -> ObservationExplanation:
    """Explain candidate local boundaries without conflating global partiality.

    A candidate relation only says it lies on a structural backward slice. It
    does not prove path feasibility or that every possible execution uses it.
    """
    require(
        type(max_nodes) is int
        and type(max_causes) is int
        and 0 < max_nodes <= 10000
        and 0 < max_causes <= 1000,
        "Invalid explanation budget",
    )
    graph = program.graph
    require(memory.graph == graph, "Explanation memory graph mismatch")
    require(analysis.graph_digest == graph.graph_digest, "Explanation graph mismatch")
    nodes = {item.node_id: item for item in graph.nodes}
    facts = {item.node_id: item for item in analysis.facts}
    require(set(facts) == set(nodes), "Explanation fact coverage mismatch")
    require(observation_node_id in nodes, "Unknown observation node")
    observed = facts[observation_node_id].labels
    causes: dict[tuple, ObservationCause] = {}
    visited: set[str] = set()
    truncated = False

    if (
        observed.unknown_provenance
        or observed.any_explicit_source
        or observed.any_control_source
    ):
        incoming = {node_id: [] for node_id in nodes}
        for edge in graph.edges:
            if edge.kind in {
                "value_dependency",
                "phi_input",
                "memory_data_dependency",
                "control_dependency",
                "address_dependency",
            }:
                incoming[edge.target].append(edge)
        accesses = {item.node_id: item for item in memory.result.accesses}
        memory_facts = {item.node_id: item for item in memory.result.facts}
        dependencies = {
            (
                item.source,
                item.target,
                item.object_id,
                item.interval,
                item.rule_id,
            ): item
            for item in memory.result.dependencies
        }

        def add(cause):
            nonlocal truncated
            if cause.sort_key in causes:
                return
            if len(causes) >= max_causes:
                truncated = True
                return
            causes[cause.sort_key] = cause

        pending = deque((observation_node_id,))
        while pending and not truncated:
            if len(visited) >= max_nodes:
                truncated = True
                break
            node_id = pending.popleft()
            if node_id in visited:
                continue
            visited.add(node_id)
            node = nodes[node_id]
            if node_id in analysis.frontier:
                add(
                    ObservationCause(
                        "analysis_frontier",
                        node_id,
                        node_id,
                        None,
                        node.evidence_ids,
                        "direct_node",
                    )
                )
            if (
                node.kind in {"UnknownValue", "Call", "OpaqueEffect", "InputMemory"}
                and node.operation != "nop"
            ):
                add(
                    ObservationCause(
                        node.operation or node.kind.lower() + "_boundary",
                        node_id,
                        node_id,
                        None,
                        node.evidence_ids,
                        "direct_node",
                    )
                )
            access = accesses.get(node_id)
            if node.kind == "Load" and access is not None:
                for reason in memory_access_reasons(access, memory_facts):
                    add(
                        ObservationCause(
                            reason,
                            node_id,
                            node_id,
                            None,
                            access.evidence_ids,
                            "direct_node",
                            access.precision,
                        )
                    )
                if (
                    not access.unresolved
                    and memory_facts[node_id].labels.unknown_provenance
                    and not any(
                        edge.memory_object_id is not None
                        for edge in incoming[node_id]
                        if edge.kind == "memory_data_dependency"
                    )
                ):
                    add(
                        ObservationCause(
                            "possible_uninitialized_memory",
                            node_id,
                            node_id,
                            None,
                            access.evidence_ids,
                            "direct_node",
                            access.precision,
                        )
                    )
            for edge in incoming[node_id]:
                if edge.kind == "address_dependency" and not (
                    observed.unknown_provenance
                    and node.kind == "Load"
                    and access is not None
                    and access.unresolved
                ):
                    continue
                if (
                    edge.memory_object_id is not None
                    and edge.memory_rule_id is not None
                ):
                    dependency = dependencies.get(
                        (
                            edge.source,
                            edge.target,
                            edge.memory_object_id,
                            edge.interval,
                            edge.memory_rule_id,
                        )
                    )
                    require(dependency is not None, "Explanation memory edge mismatch")
                    assert dependency is not None
                    reason, source_objects = memory_dependency_cause(
                        dependency, accesses
                    )
                    if reason is not None:
                        add(
                            ObservationCause(
                                reason,
                                edge.source,
                                edge.target,
                                edge.edge_id,
                                edge.evidence_ids,
                                "candidate_structural_backward_slice",
                                edge.axes.precision,
                                edge.memory_object_id,
                                edge.interval,
                                source_objects,
                            )
                        )
                if edge.source not in visited:
                    pending.append(edge.source)

    return ObservationExplanation(
        graph.graph_digest,
        digest(analysis),
        observation_node_id,
        observed,
        analysis.status,
        analysis.diagnostics,
        tuple(causes[key] for key in sorted(causes)),
        len(visited),
        truncated,
    )
