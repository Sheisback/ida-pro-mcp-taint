"""Seed-independent logical memory plan and finite byte-range analysis contracts."""

from dataclasses import dataclass
from typing import Literal

from .contracts import Alias, MemoryObject, MemoryVersion
from .serialization import ContractError, Model, digest
from .ssa import SSAProgram
from .states import (
    BitValue,
    ByteRange,
    Labels,
    PointerValue,
    canonical_set,
    check_id,
    check_digest,
    require,
)


@dataclass(frozen=True)
class MemoryPhiInput(Model):
    predecessor: int
    version_id: str

    def __post_init__(self):
        super().__post_init__()
        require(self.predecessor >= 0, "Negative memory predecessor")
        check_id(self.version_id, "memory")


@dataclass(frozen=True)
class MemoryPhi(Model):
    block: int
    version_id: str
    inputs: tuple[MemoryPhiInput, ...]
    kind: Literal["MemoryPhi"] = "MemoryPhi"
    rule_id: Literal["global-memory-phi-v1"] = "global-memory-phi-v1"

    def __post_init__(self):
        super().__post_init__()
        check_id(self.version_id, "memory")
        require(self.block >= 0 and bool(self.inputs), "Invalid memory phi")
        canonical_set(tuple(i.predecessor for i in self.inputs))


@dataclass(frozen=True)
class MemoryStep(Model):
    node_id: str
    before: str
    after: str
    effect: Literal["load", "store", "havoc"]
    rule_id: Literal["logical-memory-step-v1"] = "logical-memory-step-v1"

    def __post_init__(self):
        super().__post_init__()
        check_id(self.node_id, "node")
        check_id(self.before, "memory")
        check_id(self.after, "memory")
        require(
            (self.before == self.after) == (self.effect == "load"),
            "Memory version effect mismatch",
        )


@dataclass(frozen=True)
class BlockMemory(Model):
    block: int
    entry: str
    exit: str

    def __post_init__(self):
        super().__post_init__()
        require(self.block >= 0, "Negative memory block")
        check_id(self.entry, "memory")
        check_id(self.exit, "memory")


@dataclass(frozen=True)
class MemoryPlan(Model):
    program: SSAProgram
    versions: tuple[MemoryVersion, ...]
    phis: tuple[MemoryPhi, ...]
    steps: tuple[MemoryStep, ...]
    blocks: tuple[BlockMemory, ...]
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        canonical_set(tuple(v.version_id for v in self.versions))
        canonical_set(tuple(p.block for p in self.phis))
        canonical_set(tuple(s.node_id for s in self.steps))
        canonical_set(tuple(b.block for b in self.blocks))
        versions = {v.version_id for v in self.versions}
        nodes = {n.node_id: n for n in self.program.graph.nodes}
        for v in self.versions:
            require(
                v.snapshot_id == self.program.graph.snapshot.snapshot_id,
                "Cross-snapshot memory version",
            )
            require(v.origin is None or v.origin in nodes, "Missing memory origin")
        require(
            tuple(b.block for b in self.blocks) == self.program.dominance.reachable,
            "Memory block coverage mismatch",
        )
        by_block = {b.block: b for b in self.blocks}
        by_phi = {p.block: p for p in self.phis}
        entry = self.program.graph.snapshot.function.entry_block
        require(set(by_phi) == set(by_block) - {entry}, "Memory phi coverage mismatch")
        definitions = {d.node_id: d for d in self.program.definitions}
        require(
            all(
                s.node_id in nodes and s.before in versions and s.after in versions
                for s in self.steps
            ),
            "Dangling memory step",
        )
        for b in self.blocks:
            require(
                b.entry in versions and b.exit in versions, "Missing block memory token"
            )
            if b.block != entry:
                phi = by_phi[b.block]
                require(phi.version_id == b.entry, "Memory phi entry mismatch")
                expected = tuple(
                    (p, by_block[p].exit if p in by_block else by_block[entry].entry)
                    for p in self.program.graph.snapshot.function.blocks[
                        b.block
                    ].predecessors
                )
                require(
                    tuple((i.predecessor, i.version_id) for i in phi.inputs)
                    == expected,
                    "Memory phi predecessor mapping mismatch",
                )
            current = b.entry
            for step in sorted(
                (s for s in self.steps if definitions[s.node_id].block == b.block),
                key=lambda s: definitions[s.node_id].order,
            ):
                require(step.before == current, "Broken memory-order chain")
                current = step.after
            require(current == b.exit, "Memory exit mismatch")
        for step in self.steps:
            require(
                step.node_id in nodes
                and step.before in versions
                and step.after in versions,
                "Dangling memory step",
            )
            expected = _effect(nodes[step.node_id])
            require(step.effect == expected, "Memory step kind mismatch")
        require(
            {s.node_id for s in self.steps}
            == {n.node_id for n in nodes.values() if _effect(n)},
            "Memory step coverage mismatch",
        )

    @property
    def plan_digest(self):
        return digest(self)


def _effect(node):
    if node.kind == "Load":
        return "load"
    if node.kind == "Store":
        return "store"
    if (
        node.kind in {"Call", "Allocation", "Free"}
        or (node.kind == "OpaqueEffect" and node.operation != "nop")
        or (
            node.kind == "UnknownValue"
            and (
                (node.operation or "").startswith("unsupported_opcode:")
                or node.operation == "unknown_memory_width"
            )
        )
    ):
        return "havoc"
    return None


def build_memory_plan(program: SSAProgram) -> MemoryPlan:
    sid = program.graph.snapshot.snapshot_id
    entry = program.graph.snapshot.function.entry_block
    versions, steps, blocks = {}, [], []
    entries = {}
    for b in program.dominance.reachable:
        version = MemoryVersion(
            sid, "memory-entry" if b == entry else f"memory-phi:{b}"
        )
        versions[version.version_id] = version
        entries[b] = version.version_id
    nodes = {n.node_id: n for n in program.graph.nodes}
    for b in program.dominance.reachable:
        current = entries[b]
        for definition in sorted(
            (d for d in program.definitions if d.block == b),
            key=lambda d: (d.order, d.node_id),
        ):
            node = nodes[definition.node_id]
            effect = _effect(node)
            if effect:
                after = current
                if effect != "load":
                    version = MemoryVersion(
                        sid, "memory-write:" + node.node_id, node.node_id
                    )
                    versions[version.version_id] = version
                    after = version.version_id
                steps.append(MemoryStep(node.node_id, current, after, effect))
                current = after
        blocks.append(BlockMemory(b, entries[b], current))
    exits = {b.block: b.exit for b in blocks}
    phis = tuple(
        MemoryPhi(
            b,
            entries[b],
            tuple(
                MemoryPhiInput(p, exits.get(p, entries[entry]))
                for p in program.graph.snapshot.function.blocks[b].predecessors
            ),
        )
        for b in program.dominance.reachable
        if b != entry
    )
    return MemoryPlan(
        program,
        tuple(sorted(versions.values(), key=lambda v: v.version_id)),
        phis,
        tuple(sorted(steps, key=lambda s: s.node_id)),
        tuple(blocks),
    )


@dataclass(frozen=True)
class PointerSeed(Model):
    node_id: str
    pointer: PointerValue

    def __post_init__(self):
        super().__post_init__()
        check_id(self.node_id, "node")


@dataclass(frozen=True)
class MemorySeed(Model):
    object_id: str
    interval: ByteRange
    value: BitValue | PointerValue
    labels: Labels
    point: Literal["entry"] = "entry"

    def __post_init__(self):
        super().__post_init__()
        check_id(self.object_id, "object")
        require(
            self.value.width_bits == 8 * (self.interval.end - self.interval.start),
            "Memory seed width mismatch",
        )


@dataclass(frozen=True)
class AccessCandidate(Model):
    object_id: str
    interval: ByteRange | None

    def __post_init__(self):
        super().__post_init__()
        check_id(self.object_id, "object")


@dataclass(frozen=True)
class MemoryAccess(Model):
    node_id: str
    version_id: str
    address_node: str
    candidates: tuple[AccessCandidate, ...]
    width_bits: int
    alias: Alias
    strong_update: bool
    unresolved: bool
    evidence_ids: tuple[str, ...]
    precision: Literal["exact", "may_alias", "range_widened", "opaque"] = "opaque"

    def __post_init__(self):
        super().__post_init__()
        check_id(self.node_id, "node")
        check_id(self.version_id, "memory")
        check_id(self.address_node, "node")
        canonical_set(
            tuple(
                (
                    c.object_id,
                    c.interval.start if c.interval else -1,
                    c.interval.end if c.interval else -1,
                )
                for c in self.candidates
            )
        )
        canonical_set(self.evidence_ids)
        for eid in self.evidence_ids:
            check_id(eid, "evidence")
        require(
            self.width_bits > 0 and self.width_bits % 8 == 0, "Invalid access width"
        )
        require(
            not self.strong_update
            or (
                len(self.candidates) == 1
                and self.candidates[0].interval is not None
                and not self.unresolved
                and self.alias == "must_alias"
                and self.precision == "exact"
            ),
            "Invalid strong-update claim",
        )


@dataclass(frozen=True)
class MemoryPolicy(Model):
    max_iterations: int = 100
    max_bytes: int = 4096
    max_candidates: int = 32
    max_labels: int = 128
    flat_segment_assumption: str | None = None
    ruleset: Literal["range-memory-v2"] = "range-memory-v2"

    def __post_init__(self):
        super().__post_init__()
        require(
            self.max_iterations > 0
            and self.max_bytes > 0
            and self.max_candidates > 0
            and self.max_labels > 0,
            "Invalid memory budget",
        )
        require(
            self.flat_segment_assumption is None
            or bool(self.flat_segment_assumption.strip()),
            "Empty segment assumption",
        )


@dataclass(frozen=True)
class MemoryFact(Model):
    node_id: str
    value: BitValue | None
    pointer: PointerValue | None
    labels: Labels
    address_labels: Labels = Labels()

    def __post_init__(self):
        super().__post_init__()
        check_id(self.node_id, "node")
        require(
            self.pointer is None
            or (
                self.value is not None
                and self.pointer.width_bits == self.value.width_bits
            ),
            "Pointer fact width mismatch",
        )


@dataclass(frozen=True)
class MemoryDependency(Model):
    source: str
    target: str
    object_id: str
    interval: ByteRange | None
    kind: Literal["memory_data_dependency"] = "memory_data_dependency"
    rule_id: Literal["byte-reaching-store-v1", "unknown-memory-effect-v1"] = (
        "byte-reaching-store-v1"
    )
    evidence_ids: tuple[str, ...] = ()
    precision: Literal["exact", "may_alias", "opaque"] = "opaque"

    def __post_init__(self):
        super().__post_init__()
        check_id(self.source, "node")
        check_id(self.target, "node")
        check_id(self.object_id, "object")
        require(
            self.interval is not None or self.precision == "opaque",
            "Unknown dependency range must be opaque",
        )
        require(bool(self.evidence_ids), "Memory dependency requires evidence")
        canonical_set(self.evidence_ids)
        for eid in self.evidence_ids:
            check_id(eid, "evidence")


@dataclass(frozen=True)
class MemoryResult(Model):
    plan_digest: str
    source_digest: str
    policy_digest: str
    objects: tuple[MemoryObject, ...]
    facts: tuple[MemoryFact, ...]
    accesses: tuple[MemoryAccess, ...]
    dependencies: tuple[MemoryDependency, ...]
    status: Literal["complete_in_scope", "partial"]
    diagnostics: tuple[str, ...]
    frontier: tuple[str, ...]
    iterations: int
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        for value in (self.plan_digest, self.source_digest, self.policy_digest):
            check_digest(value)
        canonical_set(tuple(o.object_id for o in self.objects))
        canonical_set(tuple(f.node_id for f in self.facts))
        canonical_set(tuple(a.node_id for a in self.accesses))
        canonical_set(
            tuple(
                (
                    d.source,
                    d.target,
                    d.object_id,
                    d.interval.start if d.interval else -1,
                    d.interval.end if d.interval else -1,
                )
                for d in self.dependencies
            )
        )
        canonical_set(self.diagnostics)
        canonical_set(self.frontier)
        facts = {f.node_id for f in self.facts}
        objects = {o.object_id: o for o in self.objects}
        require(set(self.frontier) <= facts, "Dangling memory frontier")
        for fact in self.facts:
            if fact.pointer is not None:
                require(
                    all(
                        c.object_id in objects
                        and objects[c.object_id].address_space
                        == fact.pointer.address_space
                        for c in fact.pointer.candidates
                    ),
                    "Dangling fact pointer",
                )
        for access in self.accesses:
            require(
                access.node_id in facts and access.address_node in facts,
                "Dangling access fact",
            )
            for candidate in access.candidates:
                require(candidate.object_id in objects, "Dangling access object")
                obj = objects[candidate.object_id]
                require(
                    candidate.interval is None
                    or obj.size_bytes is None
                    or candidate.interval.end <= obj.size_bytes,
                    "Access outside object extent",
                )
            if access.strong_update:
                require(
                    objects[access.candidates[0].object_id].singleton,
                    "Strong update without singleton proof",
                )
        for dep in self.dependencies:
            require(
                dep.source in facts
                and dep.target in facts
                and dep.object_id in objects,
                "Dangling memory dependency",
            )
        require(
            self.iterations >= 0
            and (self.status != "complete_in_scope" or not self.frontier),
            "Invalid memory completion",
        )

    def validate_plan(self, plan: MemoryPlan):
        require(self.plan_digest == plan.plan_digest, "Stale memory plan")
        nodes = {n.node_id: n for n in plan.program.graph.nodes}
        require(
            {f.node_id for f in self.facts} == set(nodes),
            "Memory fact coverage mismatch",
        )
        steps = {s.node_id: s for s in plan.steps}
        for access in self.accesses:
            node = nodes[access.node_id]
            require(
                node.kind in {"Load", "Store"} and access.node_id in steps,
                "Access is not a memory operation",
            )
            memory_operands = node.memory_operands
            if memory_operands is None:
                raise ContractError("Access is not a memory operation")
            require(
                access.version_id == steps[access.node_id].before
                and access.address_node == memory_operands.address
                and access.width_bits == node.width_bits
                and access.evidence_ids == node.evidence_ids,
                "Access/plan reference mismatch",
            )
            require(
                not access.strong_update or node.kind == "Store",
                "Load cannot strong update",
            )
        evidence = {e.evidence_id for e in plan.program.graph.evidence}
        for dep in self.dependencies:
            require(
                set(dep.evidence_ids) <= evidence, "Dangling memory dependency evidence"
            )
            require(
                nodes[dep.target].kind == "Load"
                and dep.source in steps
                and steps[dep.source].effect != "load",
                "Invalid memory-data dependency",
            )

    @property
    def cache_key(self):
        return digest(
            {
                "plan": self.plan_digest,
                "source": self.source_digest,
                "policy": self.policy_digest,
            }
        )


def alias_relation(
    a: MemoryObject, arange: ByteRange | None, b: MemoryObject, brange: ByteRange | None
) -> Alias:
    if a.address_space != b.address_space:
        return "no_alias"
    if a.object_id != b.object_id:
        return "no_alias" if a.disjoint and b.disjoint else "may_alias"
    if arange is None or brange is None:
        return "unknown"
    if arange.end <= brange.start or brange.end <= arange.start:
        return "no_alias"
    if arange == brange and a.singleton:
        return "must_alias"
    return "may_alias"
