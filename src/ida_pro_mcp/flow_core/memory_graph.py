"""Conservative frontend bridge from extracted SSA memory effects to query edges."""

from dataclasses import dataclass, replace

from .contracts import (
    Edge,
    Evidence,
    Graph,
    MemoryObject,
    MemoryReference,
    ResultAxes,
    Snapshot,
)
from .memory import (
    MemoryPlan,
    MemoryPolicy,
    MemoryResult,
    PointerSeed,
    build_memory_plan,
)
from .memory_analysis import analyze_memory
from .serialization import Model, digest
from .ssa import SSAProgram, build_ssa
from .states import PointerCandidate, PointerValue, require


FLAT_USERSPACE_ASSUMPTION = (
    "experimental Mach-O flat user-space address model; no TLS or MMIO semantics"
)


@dataclass(frozen=True)
class MemoryGraphAnalysis(Model):
    program: SSAProgram
    plan: MemoryPlan
    result: MemoryResult
    graph: Graph

    def __post_init__(self):
        super().__post_init__()
        self.result.validate_plan(self.plan)
        require(self.program.graph == self.graph, "Public SSA graph mismatch")
        require(
            self.plan.program.graph.snapshot == self.graph.snapshot,
            "Memory graph snapshot mismatch",
        )


def _signed(value, width):
    return value - (1 << width) if value >= (1 << (width - 1)) else value


def _signature_data(value):
    return (
        [_signature_data(item) for item in value] if isinstance(value, tuple) else value
    )


def _address_signature(nodes, identifier, active=frozenset()):
    """Return (base identity, byte offset, object kind) without ABI numbering."""
    if identifier in active:
        return ("cycle", identifier), 0, "unknown"
    node = nodes[identifier]
    active = active | {identifier}
    if node.operation == "stack_address" and node.constant is not None:
        return ("stack-frame",), node.constant, "stack"
    if node.operation == "global_address" and node.constant is not None:
        return ("global", node.constant), 0, "global"
    if node.kind == "InputValue":
        return ("entry", identifier), 0, "argument"
    if node.kind == "Copy" and len(node.inputs) == 1:
        return _address_signature(nodes, node.inputs[0], active)
    if (
        node.kind == "Unary"
        and len(node.inputs) == 1
        and node.width_bits == nodes[node.inputs[0]].width_bits
        and node.operation in {"trunc", "zext", "sext", "extract:0"}
    ):
        return _address_signature(nodes, node.inputs[0], active)
    if node.operation == "concat_low" and node.inputs:
        children = tuple(
            _address_signature(nodes, child, active) for child in node.inputs
        )
        kind = (
            "argument"
            if all(child[2] == "argument" for child in children)
            else "unknown"
        )
        return ("entry-expression", children), 0, kind
    if node.kind == "Binary" and node.operation in {"add", "sub"}:
        left, right = (nodes[value] for value in node.inputs)
        if right.kind == "Constant" and right.constant is not None:
            base, offset, kind = _address_signature(nodes, node.inputs[0], active)
            delta = _signed(right.constant, right.width_bits)
            return base, offset + (delta if node.operation == "add" else -delta), kind
        if (
            node.operation == "add"
            and left.kind == "Constant"
            and left.constant is not None
        ):
            base, offset, kind = _address_signature(nodes, node.inputs[1], active)
            return base, offset + _signed(left.constant, left.width_bits), kind
    if node.kind == "Constant" and node.constant is not None:
        return ("literal-address", node.constant), 0, "unknown"
    return ("expression", identifier), 0, "unknown"


def _objects_and_pointers(plan):
    graph = plan.program.graph
    nodes = {node.node_id: node for node in graph.nodes}
    accesses = [
        node
        for node in graph.nodes
        if node.kind in {"Load", "Store"} and node.memory_operands is not None
    ]
    specs = []
    extents = {}
    for node in accesses:
        address = nodes[node.memory_operands.address]
        base, offset, kind = _address_signature(nodes, address.node_id)
        key = f"auto-{kind}:" + digest(_signature_data(base))
        specs.append((address, key, offset, kind))
        if kind in {"stack", "global"} and offset >= 0:
            extents[key] = max(extents.get(key, 0), offset + node.width_bits // 8)
    objects = {}
    for _, key, _, kind in specs:
        if key in objects:
            continue
        singleton = kind in {"stack", "global", "argument"}
        objects[key] = MemoryObject(
            graph.snapshot.snapshot_id,
            key,
            graph.snapshot.identity.environment.address_space,
            extents.get(key),
            kind,
            singleton,
            (
                "one current frame/global or canonical entry-pointee abstraction per function invocation"
                if singleton
                else None
            ),
            kind == "stack",
            "current stack frame is distinct from non-stack objects"
            if kind == "stack"
            else None,
        )
    by_node = {}
    for address, key, offset, kind in specs:
        if kind not in {"stack", "global", "argument"}:
            continue
        obj = objects[key]
        pointer = PointerValue(
            obj.address_space,
            address.width_bits,
            (PointerCandidate(obj.object_id, offset),),
        )
        require(
            address.node_id not in by_node or by_node[address.node_id] == pointer,
            "Conflicting inferred address identity",
        )
        by_node[address.node_id] = pointer
    return (
        tuple(sorted(objects.values(), key=lambda obj: obj.object_id)),
        tuple(PointerSeed(node, by_node[node]) for node in sorted(by_node)),
    )


def build_memory_graph(snapshot: Snapshot) -> MemoryGraphAnalysis:
    """Build an alias-aware query graph; uncertainty remains opaque/partial."""
    base_program = build_ssa(snapshot, storage_model="memory")
    plan = build_memory_plan(base_program)
    objects, pointers = _objects_and_pointers(plan)
    result = analyze_memory(
        plan,
        objects,
        pointers,
        policy=MemoryPolicy(flat_segment_assumption=FLAT_USERSPACE_ASSUMPTION),
    )
    accesses = {access.node_id: access for access in result.accesses}
    steps = {step.node_id: step for step in plan.steps}
    object_by_id = {obj.object_id: obj for obj in result.objects}
    nodes = []
    for node in base_program.graph.nodes:
        access = accesses.get(node.node_id)
        if (
            access is not None
            and len(access.candidates) == 1
            and access.candidates[0].interval is not None
        ):
            candidate = access.candidates[0]
            obj = object_by_id[candidate.object_id]
            node = replace(
                node,
                memory=MemoryReference(
                    candidate.object_id,
                    steps[node.node_id].after
                    if node.kind == "Store"
                    else access.version_id,
                    obj.address_space,
                    candidate.interval,
                    snapshot.identity.environment.data_endian,
                ),
            )
        nodes.append(node)

    edges = {edge.edge_id: edge for edge in base_program.graph.edges}
    evidence = {item.evidence_id: item for item in base_program.graph.evidence}
    for dependency in result.dependencies:
        derivation = Evidence(
            snapshot.snapshot_id,
            dependency.rule_id,
            synthetic=True,
            origins=tuple(sorted((dependency.source, dependency.target))),
            assumptions=tuple(
                sorted(
                    (
                        FLAT_USERSPACE_ASSUMPTION,
                        "automatic object identity is structural and conservative; no ABI argument numbering",
                    )
                )
            ),
            memory_object_id=dependency.object_id,
        )
        evidence[derivation.evidence_id] = derivation
        axes = ResultAxes(
            precision=dependency.precision,
            analysis=result.status,
            alias=(
                "must_alias"
                if dependency.precision == "exact"
                else "may_alias"
                if dependency.precision == "may_alias"
                else "unknown"
            ),
        )
        edge = Edge(
            dependency.source,
            dependency.target,
            "memory_data_dependency",
            tuple(sorted(set(dependency.evidence_ids) | {derivation.evidence_id})),
            axes,
            width_bits=(
                None
                if dependency.interval is None
                else 8 * (dependency.interval.end - dependency.interval.start)
            ),
            interval=dependency.interval,
            memory_object_id=dependency.object_id,
            memory_rule_id=dependency.rule_id,
        )
        edges[edge.edge_id] = edge

    graph = Graph(
        snapshot,
        tuple(sorted(nodes, key=lambda node: node.node_id)),
        tuple(sorted(edges.values(), key=lambda edge: edge.edge_id)),
        tuple(sorted(evidence.values(), key=lambda item: item.evidence_id)),
        replace(base_program.graph.axes, analysis=result.status),
        tuple(
            sorted(
                {
                    obj.object_id: obj
                    for obj in base_program.graph.objects + result.objects
                }.values(),
                key=lambda obj: obj.object_id,
            )
        ),
        tuple(
            sorted(
                {
                    version.version_id: version
                    for version in base_program.graph.versions + plan.versions
                }.values(),
                key=lambda version: version.version_id,
            )
        ),
    )
    program = replace(base_program, graph=graph)
    return MemoryGraphAnalysis(program, plan, result, graph)


__all__ = [
    "FLAT_USERSPACE_ASSUMPTION",
    "MemoryGraphAnalysis",
    "build_memory_graph",
]
