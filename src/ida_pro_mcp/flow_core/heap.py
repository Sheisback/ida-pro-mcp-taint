"""Explicit synthetic heap events and immutable lifetime-plan contracts."""

from dataclasses import dataclass
from typing import Literal

from .contracts import MemoryObject
from .serialization import Model, digest, stable_id
from .ssa import SSAProgram
from .states import (
    Lifetime,
    PointerValue,
    canonical_set,
    check_digest,
    check_id,
    nonempty,
    require,
)

HeapKind = Literal["allocate", "free", "escape", "access", "use", "opaque"]


@dataclass(frozen=True)
class OneShotProof(Model):
    allocation_node: str
    evidence: str
    disjoint_evidence: str | None = None
    kind: Literal["synthetic_one_shot"] = "synthetic_one_shot"

    def __post_init__(self):
        super().__post_init__()
        check_id(self.allocation_node, "node")
        nonempty(self.evidence)
        if self.disjoint_evidence is not None:
            nonempty(self.disjoint_evidence)


@dataclass(frozen=True)
class AllocationSite(Model):
    node_id: str
    object: MemoryObject

    def __post_init__(self):
        super().__post_init__()
        check_id(self.node_id, "node")
        require(self.object.kind == "heap", "Allocation site requires heap object")


@dataclass(frozen=True)
class HeapEvent(Model):
    node_id: str
    kind: HeapKind
    block: int
    order: int
    roots: tuple[str, ...]
    scope: Literal["explicit", "reachable", "all"]
    evidence_ids: tuple[str, ...]
    rule_id: Literal["explicit-heap-events-v2"] = "explicit-heap-events-v2"

    def __post_init__(self):
        super().__post_init__()
        check_id(self.node_id, "node")
        require(self.block >= 0 and self.order >= 0, "Invalid heap event position")
        canonical_set(self.roots)
        canonical_set(self.evidence_ids)
        require(bool(self.evidence_ids), "Heap event requires evidence")
        for root in self.roots:
            check_id(root, "node")
        for evidence in self.evidence_ids:
            check_id(evidence, "evidence")


@dataclass(frozen=True)
class HeapPhi(Model):
    snapshot_id: str
    context_digest: str
    block: int
    predecessors: tuple[int, ...]
    kind: Literal["HeapPhi"] = "HeapPhi"

    def __post_init__(self):
        super().__post_init__()
        check_id(self.snapshot_id, "snapshot")
        check_digest(self.context_digest)
        require(
            self.block >= 0
            and bool(self.predecessors)
            and all(p >= 0 for p in self.predecessors),
            "Invalid heap phi",
        )
        canonical_set(self.predecessors)

    @property
    def phi_id(self):
        return stable_id(
            "memory",
            {
                "domain": "heap-phi-v1",
                "snapshot": self.snapshot_id,
                "context": self.context_digest,
                "block": self.block,
            },
        )


def _cyclic_blocks(program):
    function = program.graph.snapshot.function
    cyclic = set()
    for start in program.dominance.reachable:
        seen = set()
        pending = list(function.blocks[start].successors)
        while pending:
            block = pending.pop()
            if block == start:
                cyclic.add(start)
                break
            if block not in seen:
                seen.add(block)
                pending.extend(function.blocks[block].successors)
    return cyclic


def _event(node, definition, pointer_bits):
    if node.kind == "Allocation":
        require(
            node.width_bits == pointer_bits and len(node.inputs) <= 1,
            "Allocation requires pointer-width result and at most one size input",
        )
        kind, roots, scope = "allocate", (), "explicit"
    elif node.kind == "Free":
        require(
            node.width_bits is None and len(node.inputs) == 1,
            "Free is a one-pointer effect with no result",
        )
        kind, roots, scope = "free", node.inputs, "explicit"
    elif node.kind in {"Load", "Store"}:
        kind, roots, scope = "access", (node.memory_operands.address,), "explicit"
    elif node.kind == "OpaqueEffect" and node.operation in {"heap_escape", "heap_use"}:
        require(
            node.width_bits is None and len(node.inputs) == 1,
            "Heap escape/use requires exactly one pointer and no result",
        )
        kind = "escape" if node.operation == "heap_escape" else "use"
        roots, scope = node.inputs, "explicit"
    elif node.kind == "OpaqueEffect" and node.operation == "heap_opaque_reachable":
        require(
            node.width_bits is None and bool(node.inputs),
            "Reachable opaque event requires roots and no result",
        )
        kind, roots, scope = "opaque", node.inputs, "reachable"
    elif (
        node.kind == "Call"
        or (node.kind == "OpaqueEffect" and node.operation != "nop")
        or (
            node.kind == "UnknownValue"
            and (
                (node.operation or "").startswith("unsupported_opcode:")
                or node.operation == "unknown_memory_width"
            )
        )
    ):
        kind, roots, scope = "opaque", (), "all"
    else:
        return None
    return HeapEvent(
        node.node_id,
        kind,
        definition.block,
        definition.order,
        tuple(sorted(set(roots))),
        scope,
        node.evidence_ids,
    )


def _object(program, node, context, proof):
    nodes = {n.node_id: n for n in program.graph.nodes}
    size = None
    if node.inputs:
        operand = nodes[node.inputs[0]]
        require(
            operand.width_bits is not None, "Allocation size must be a scalar value"
        )
        if operand.kind == "Constant":
            require(
                operand.constant > 0, "Synthetic allocation extent must be positive"
            )
            size = operand.constant
    key = "allocation-site:" + digest({"site": node.node_id, "context": list(context)})
    return MemoryObject(
        program.graph.snapshot.snapshot_id,
        key,
        program.graph.snapshot.identity.environment.address_space,
        size,
        "heap",
        proof is not None,
        proof.evidence if proof else None,
        bool(proof and proof.disjoint_evidence),
        proof.disjoint_evidence if proof else None,
    )


@dataclass(frozen=True)
class HeapPlan(Model):
    program: SSAProgram
    context: tuple[str, ...]
    proofs: tuple[OneShotProof, ...]
    sites: tuple[AllocationSite, ...]
    events: tuple[HeapEvent, ...]
    phis: tuple[HeapPhi, ...]
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        require(
            len(self.context) <= 8, "Explicit heap context exceeds bound; no truncation"
        )
        for item in self.context:
            nonempty(item)
        canonical_set(tuple(p.allocation_node for p in self.proofs))
        canonical_set(tuple(s.node_id for s in self.sites))
        canonical_set(tuple(e.node_id for e in self.events))
        canonical_set(tuple(p.block for p in self.phis))
        nodes = {n.node_id: n for n in self.program.graph.nodes}
        definitions = {d.node_id: d for d in self.program.definitions}
        allocation_ids = {n.node_id for n in nodes.values() if n.kind == "Allocation"}
        require(
            {s.node_id for s in self.sites} == allocation_ids,
            "Heap site coverage mismatch",
        )
        require(
            {p.allocation_node for p in self.proofs} <= allocation_ids,
            "Unknown singleton proof site",
        )
        proofs = {p.allocation_node: p for p in self.proofs}
        cyclic = _cyclic_blocks(self.program)
        for proof in self.proofs:
            require(
                definitions[proof.allocation_node].block not in cyclic,
                "Cyclic allocation site cannot have one-shot proof",
            )
        for site in self.sites:
            require(
                site.object
                == _object(
                    self.program,
                    nodes[site.node_id],
                    self.context,
                    proofs.get(site.node_id),
                ),
                "Heap object identity/proof mismatch",
            )
        bits = self.program.graph.snapshot.identity.environment.bitness
        expected = tuple(
            e
            for n in self.program.graph.nodes
            if (e := _event(n, definitions[n.node_id], bits)) is not None
        )
        require(self.events == expected, "Heap event coverage/order/payload mismatch")
        for event in self.events:
            for root in event.roots:
                require(
                    root in nodes and nodes[root].width_bits == bits,
                    "Heap root must have the profile pointer width",
                )
        function = self.program.graph.snapshot.function
        require(
            not function.blocks[function.entry_block].predecessors,
            "Heap entry needs explicit preheader",
        )
        expected_phis = tuple(
            HeapPhi(
                self.program.graph.snapshot.snapshot_id,
                digest(list(self.context)),
                b,
                function.blocks[b].predecessors,
            )
            for b in self.program.dominance.reachable
            if b != function.entry_block
        )
        require(self.phis == expected_phis, "Heap phi predecessor coverage mismatch")

    @property
    def plan_digest(self):
        return digest(self)


def build_heap_plan(
    program: SSAProgram,
    context: tuple[str, ...] = (),
    proofs: tuple[OneShotProof, ...] = (),
    *,
    max_events: int = 10000,
    max_phi_inputs: int = 128,
) -> HeapPlan:
    require(
        type(max_events) is int
        and max_events > 0
        and type(max_phi_inputs) is int
        and max_phi_inputs > 0,
        "Invalid heap build budget",
    )
    canonical_set(tuple(p.allocation_node for p in proofs))
    proof_map = {p.allocation_node: p for p in proofs}
    definitions = {d.node_id: d for d in program.definitions}
    bits = program.graph.snapshot.identity.environment.bitness
    events = tuple(
        e
        for n in program.graph.nodes
        if (e := _event(n, definitions[n.node_id], bits)) is not None
    )
    require(len(events) <= max_events, "Heap event build budget exceeded")
    function = program.graph.snapshot.function
    phis = tuple(
        HeapPhi(
            program.graph.snapshot.snapshot_id,
            digest(list(context)),
            b,
            function.blocks[b].predecessors,
        )
        for b in program.dominance.reachable
        if b != function.entry_block
    )
    require(
        all(len(p.predecessors) <= max_phi_inputs for p in phis),
        "Heap phi-input budget exceeded",
    )
    sites = tuple(
        AllocationSite(
            n.node_id, _object(program, n, context, proof_map.get(n.node_id))
        )
        for n in program.graph.nodes
        if n.kind == "Allocation"
    )
    return HeapPlan(program, context, proofs, sites, events, phis)


@dataclass(frozen=True)
class HeapSeed(Model):
    object_id: str
    lifetime: Lifetime
    point: Literal["entry"] = "entry"

    def __post_init__(self):
        super().__post_init__()
        check_id(self.object_id, "object")


@dataclass(frozen=True)
class HeapPolicy(Model):
    allocation_nullable: bool = True
    max_iterations: int = 100
    max_event_visits: int = 10000
    max_state_updates: int = 50000
    max_candidates: int = 32
    ruleset: Literal["synthetic-heap-v2"] = "synthetic-heap-v2"

    def __post_init__(self):
        super().__post_init__()
        require(
            all(
                v > 0
                for v in (
                    self.max_iterations,
                    self.max_event_visits,
                    self.max_state_updates,
                    self.max_candidates,
                )
            ),
            "Invalid heap analysis budget",
        )


@dataclass(frozen=True)
class HeapObjectState(Model):
    object_id: str
    lifetime: Lifetime

    def __post_init__(self):
        super().__post_init__()
        check_id(self.object_id, "object")


@dataclass(frozen=True)
class HeapTransition(Model):
    object_id: str
    before: Lifetime
    after: Lifetime
    strong_update: bool

    def __post_init__(self):
        super().__post_init__()
        check_id(self.object_id, "object")


@dataclass(frozen=True)
class HeapObservation(Model):
    node_id: str
    kind: HeapKind
    pointer: PointerValue
    transitions: tuple[HeapTransition, ...]
    precision: Literal["exact", "may_alias", "opaque"]
    unresolved: bool
    evidence_ids: tuple[str, ...]
    rule_id: Literal["synthetic-lifetime-transfer-v2"] = (
        "synthetic-lifetime-transfer-v2"
    )

    def __post_init__(self):
        super().__post_init__()
        check_id(self.node_id, "node")
        canonical_set(tuple(t.object_id for t in self.transitions))
        canonical_set(self.evidence_ids)
        require(bool(self.evidence_ids), "Heap observation requires evidence")
        for evidence in self.evidence_ids:
            check_id(evidence, "evidence")
        for transition in self.transitions:
            if self.kind in {"access", "use"}:
                require(
                    transition.before == transition.after
                    and not transition.strong_update,
                    "Heap observation cannot mutate lifetime",
                )
            if self.kind == "escape":
                require(
                    transition.before.possible == transition.after.possible,
                    "Escape cannot change liveness",
                )
            if transition.strong_update:
                require(
                    self.kind in {"allocate", "free", "escape"},
                    "Invalid strong heap event kind",
                )
                if self.kind == "allocate":
                    require(
                        transition.before.possible == ("not_allocated",)
                        and transition.after.possible == ("live",),
                        "Invalid strong allocation",
                    )
                if self.kind == "free":
                    require(
                        transition.before.possible == ("live",)
                        and transition.after.possible == ("freed",),
                        "Invalid strong free",
                    )
        require(
            not any(t.strong_update for t in self.transitions)
            or (
                self.precision == "exact"
                and not self.unresolved
                and not self.pointer.may_be_null
                and len(self.pointer.candidates) == 1
            ),
            "Invalid strong heap transition",
        )


@dataclass(frozen=True)
class HeapPointerFact(Model):
    node_id: str
    pointer: PointerValue

    def __post_init__(self):
        super().__post_init__()
        check_id(self.node_id, "node")


@dataclass(frozen=True)
class HeapResult(Model):
    plan_digest: str
    source_digest: str
    policy_digest: str
    states: tuple[HeapObjectState, ...]
    pointers: tuple[HeapPointerFact, ...]
    observations: tuple[HeapObservation, ...]
    status: Literal["complete_in_scope", "partial"]
    diagnostics: tuple[str, ...]
    frontier: tuple[str, ...]
    iterations: int
    event_visits: int
    state_updates: int
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        for value in (self.plan_digest, self.source_digest, self.policy_digest):
            check_digest(value)
        canonical_set(tuple(s.object_id for s in self.states))
        canonical_set(tuple(f.node_id for f in self.pointers))
        canonical_set(tuple(o.node_id for o in self.observations))
        canonical_set(self.diagnostics)
        canonical_set(self.frontier)
        require(
            all(
                v >= 0 for v in (self.iterations, self.event_visits, self.state_updates)
            ),
            "Negative heap work count",
        )
        require(
            self.status != "complete_in_scope"
            or (not self.frontier and not self.diagnostics),
            "Incomplete heap result marked complete",
        )
        objects = {s.object_id for s in self.states}
        for pointer in [f.pointer for f in self.pointers] + [
            o.pointer for o in self.observations
        ]:
            require(
                all(c.object_id in objects for c in pointer.candidates),
                "Dangling heap pointer",
            )
        for observation in self.observations:
            require(
                {t.object_id for t in observation.transitions} <= objects,
                "Dangling heap transition",
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

    def validate_plan(self, plan: HeapPlan):
        require(self.plan_digest == plan.plan_digest, "Stale heap plan")
        registry = {s.object.object_id: s.object for s in plan.sites}
        require(
            {s.object_id for s in self.states} == set(registry),
            "Heap state coverage mismatch",
        )
        events = {e.node_id: e for e in plan.events}
        nodes = {n.node_id: n for n in plan.program.graph.nodes}
        reachable_events = {
            e.node_id
            for e in plan.events
            if e.block in plan.program.dominance.reachable
        }
        require(set(self.frontier) <= reachable_events, "Dangling heap frontier")
        require(
            {o.node_id for o in self.observations} == reachable_events,
            "Heap observation coverage mismatch",
        )
        for pointer in [f.pointer for f in self.pointers] + [
            o.pointer for o in self.observations
        ]:
            require(
                pointer.width_bits
                == plan.program.graph.snapshot.identity.environment.bitness,
                "Heap pointer width mismatch",
            )
            require(
                all(
                    registry[c.object_id].address_space == pointer.address_space
                    for c in pointer.candidates
                ),
                "Heap pointer address-space mismatch",
            )
        for fact in self.pointers:
            require(
                fact.node_id in nodes
                and nodes[fact.node_id].width_bits == fact.pointer.width_bits,
                "Heap pointer fact mismatch",
            )
        for observation in self.observations:
            require(observation.node_id in events, "Unknown heap observation")
            event = events[observation.node_id]
            require(
                observation.kind == event.kind
                and observation.evidence_ids == event.evidence_ids,
                "Heap observation evidence/kind mismatch",
            )
            for transition in observation.transitions:
                require(
                    not transition.strong_update
                    or registry[transition.object_id].singleton,
                    "Summary object strongly updated",
                )
