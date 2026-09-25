"""Explicit, bounded pointee sources; address provenance is not content taint."""

from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Literal

from .analysis import Seed
from .contracts import Edge, Evidence, MemoryObject, MemoryVersion, Node, NodeKey
from .memory_graph import MemoryGraphAnalysis, build_memory_graph_from_program
from .serialization import Model, digest
from .ssa import Definition, PointeeBinding
from .states import (
    ByteRange,
    Labels,
    MemoryReference,
    PointerCandidate,
    PointerValue,
    check_id,
    require,
)


@dataclass(frozen=True)
class PointeeSeed(Model):
    pointer_node_id: str
    interval: ByteRange
    labels: Labels
    binding_mode: Literal["analyst_assumed_exact", "require_program_derived_exact"]
    kind: Literal["pointee_range"] = "pointee_range"
    point: Literal["after_pointer_definition"] = "after_pointer_definition"
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        check_id(self.pointer_node_id, "node")
        require(
            0 < self.interval.end - self.interval.start <= 512,
            "Pointee source byte budget exceeded",
        )
        require(self.interval.end <= 2**31 - 1, "Pointee offset budget exceeded")
        require(
            0 < len(self.labels.explicit) <= 16
            and self.labels == Labels(self.labels.explicit),
            "Pointee sources require bounded explicit-only labels",
        )


def _in_cycle(function, block, checkpoint):
    successors = {b.index: b.successors for b in function.blocks}
    pending = list(successors[block])
    seen = set()
    while pending:
        if checkpoint is not None:
            checkpoint()
        current = pending.pop()
        if current == block:
            return True
        if current not in seen:
            seen.add(current)
            pending.extend(successors[current])
    return False


def bind_pointee_sources(
    base: MemoryGraphAnalysis,
    sources: tuple[PointeeSeed, ...],
    *,
    checkpoint: Callable[[], None] | None = None,
) -> tuple[MemoryGraphAnalysis, tuple[Seed, ...]]:
    """Bind source bytes immediately after a noncyclic pointer definition.

    Analyst bindings assert valid nonnull storage, never disjointness. Labels
    remain separate from graph identity; program-derived bindings add no pointer
    assumptions. A source is not an assertion about earlier memory versions.
    """
    require(len(sources) <= 16, "Pointee source count budget exceeded")
    require(
        len({label for source in sources for label in source.labels.explicit}) <= 16,
        "Pointee label count budget exceeded",
    )
    if not sources:
        return base, ()
    program = base.plan.program
    require(
        not program.pointee_bindings, "Pointee sources must bind an unseeded program"
    )
    graph = program.graph
    nodes = {n.node_id: n for n in graph.nodes}
    definitions = {d.node_id: d for d in program.definitions}
    facts = {f.node_id: f for f in base.result.facts}
    objects = {o.object_id: o for o in graph.objects}
    result_objects = {o.object_id: o for o in base.result.objects}
    versions = {v.version_id: v for v in graph.versions}
    evidence = {e.evidence_id: e for e in graph.evidence}
    edges = {e.edge_id: e for e in graph.edges}
    entries = {e.node_id for e in program.entry_storage}
    environment = graph.snapshot.identity.environment
    bitness = environment.bitness
    sid = graph.snapshot.snapshot_id
    intervals = {}
    modes = {}
    bindings = []
    seeds = []
    inserted = {}
    for source in sorted(sources, key=lambda s: (s.pointer_node_id, s.interval.start)):
        if checkpoint is not None:
            checkpoint()
        root = source.pointer_node_id
        require(root in nodes, "Pointee pointer is not in this snapshot")
        node = nodes[root]
        definition = definitions[root]
        require(
            node.width_bits == bitness
            and (
                (node.kind == "InputValue" and root in entries) or node.kind == "Load"
            ),
            "Pointee source requires an exact entry pointer or full-width Load",
        )
        require(
            not _in_cycle(graph.snapshot.function, definition.block, checkpoint),
            "Pointee sources cannot reseed in a cycle",
        )
        require(
            root not in modes or modes[root] == source.binding_mode,
            "Conflicting pointee binding modes",
        )
        modes[root] = source.binding_mode
        previous = intervals.setdefault(root, [])
        require(
            all(
                source.interval.end <= r.start or source.interval.start >= r.end
                for r in previous
            ),
            "Overlapping pointee source ranges",
        )
        previous.append(source.interval)
        fact = facts[root]
        pointer = fact.pointer
        require(
            not (fact.value is not None and fact.value.value == 0),
            "Null pointee source",
        )
        exact = (
            pointer is not None
            and not pointer.any_compatible_location
            and not pointer.may_be_null
            and len(pointer.candidates) == 1
            and pointer.candidates[0].offset is not None
        )
        assumptions = (
            "analyst designates these bytes as explicit taint at the source point",
        )
        if exact:
            candidate = pointer.candidates[0]
            obj = result_objects[candidate.object_id]
            require(obj.singleton, "Pointee source requires singleton storage")
        else:
            require(
                source.binding_mode == "analyst_assumed_exact",
                "Program-derived exact pointee binding unavailable",
            )
            require(
                not (
                    pointer is not None
                    and not pointer.any_compatible_location
                    and not pointer.candidates
                ),
                "Null pointee source",
            )
            assumptions += (
                "analyst asserts this pointer identifies valid nonnull singleton storage; no disjointness is asserted",
            )
            obj = MemoryObject(
                sid,
                "pointee:" + root,
                environment.address_space,
                None,
                "argument",
                True,
                assumptions[-1],
                False,
            )
            candidate = PointerCandidate(obj.object_id, 0)
            pointer = PointerValue(environment.address_space, bitness, (candidate,))
        require(
            candidate.offset is not None
            and candidate.offset + source.interval.start >= 0,
            "Pointee range precedes object",
        )
        interval = ByteRange(
            candidate.offset + source.interval.start,
            candidate.offset + source.interval.end,
        )
        require(
            interval.end <= 2**31 - 1
            and (obj.size_bytes is None or interval.end <= obj.size_bytes),
            "Pointee range exceeds object bounds",
        )
        objects[obj.object_id] = obj
        discriminator = digest([root, source.interval.to_data(), source.binding_mode])
        key = NodeKey(
            sid,
            graph.snapshot.function.function_id,
            synthetic="pointee-source:" + discriminator,
        )
        version = MemoryVersion(sid, "pointee-source:" + discriminator, key.node_id)
        versions[version.version_id] = version
        item = Evidence(
            sid,
            "analyst-pointee-range-v1"
            if source.binding_mode == "analyst_assumed_exact"
            else "derived-pointee-range-v1",
            synthetic=True,
            origins=(root,),
            assumptions=tuple(sorted(assumptions)),
            memory_object_id=obj.object_id,
        )
        evidence[item.evidence_id] = item
        content = Node(
            key,
            "InputMemory",
            8 * (interval.end - interval.start),
            (item.evidence_id,),
            operation="pointee_source",
            memory=MemoryReference(
                obj.object_id,
                version.version_id,
                obj.address_space,
                interval,
                environment.data_endian,
            ),
        )
        nodes[content.node_id] = content
        inserted.setdefault(root, []).append(content.node_id)
        binding = PointeeBinding(root, content.node_id, pointer, source.binding_mode)
        bindings.append(binding)
        seeds.append(Seed(content.node_id, source.labels))
        edge = Edge(
            root, content.node_id, "address_dependency", (item.evidence_id,), graph.axes
        )
        edges[edge.edge_id] = edge
    # Preserve entry (-2) and phi (-1), while putting every source immediately
    # after its root and before later instruction definitions in the block.
    for block in graph.snapshot.function.blocks:
        if checkpoint is not None:
            checkpoint()
        ordered = sorted(
            (d for d in program.definitions if d.block == block.index),
            key=lambda d: (d.order, d.node_id),
        )
        order = 0
        for definition in ordered:
            if definition.order >= 0:
                definitions[definition.node_id] = replace(definition, order=order)
                order += 1
            for source_id in inserted.get(definition.node_id, ()):
                definitions[source_id] = Definition(source_id, block.index, order)
                order += 1
    graph = replace(
        graph,
        nodes=tuple(nodes[k] for k in sorted(nodes)),
        edges=tuple(edges[k] for k in sorted(edges)),
        evidence=tuple(evidence[k] for k in sorted(evidence)),
        objects=tuple(objects[k] for k in sorted(objects)),
        versions=tuple(versions[k] for k in sorted(versions)),
    )
    program = replace(
        program,
        graph=graph,
        definitions=tuple(definitions[n.node_id] for n in graph.nodes),
        pointee_bindings=tuple(sorted(bindings, key=lambda b: b.source_node_id)),
    )
    return build_memory_graph_from_program(program, checkpoint=checkpoint), tuple(
        sorted(seeds, key=lambda s: s.node_id)
    )
