"""Synthetic allocation/lifetime fixed point; does not recognize allocator names."""

from .heap import (
    HeapObjectState,
    HeapObservation,
    HeapPlan,
    HeapPointerFact,
    HeapPolicy,
    HeapResult,
    HeapSeed,
    HeapTransition,
)
from .memory import PointerSeed
from .serialization import digest
from .states import Lifetime, PointerCandidate, PointerValue, canonical_set, require

ALL_LIVENESS = ("freed", "live", "not_allocated")
INITIAL = Lifetime(("not_allocated",), "local")
TOP = Lifetime(ALL_LIVENESS, "unknown")


def allocate_lifetime(before: Lifetime, *, singleton: bool, nullable: bool):
    fresh = singleton and before.possible == ("not_allocated",)
    states = {"live"}
    if nullable:
        states.add("not_allocated")
    if not fresh:
        states.update(before.possible)
    return Lifetime(tuple(sorted(states)), before.escape), fresh and not nullable


def free_lifetime(before: Lifetime, *, definite: bool):
    if definite and before.possible == ("live",):
        return Lifetime(("freed",), before.escape), True, False
    nonlive = bool(set(before.possible) - {"live"})
    states = set(ALL_LIVENESS) if nonlive else set(before.possible) | {"freed"}
    return Lifetime(tuple(sorted(states)), before.escape), False, nonlive


def escape_lifetime(before: Lifetime, *, definite: bool):
    escape = (
        "escaped"
        if definite
        else (before.escape if before.escape == "escaped" else "unknown")
    )
    return Lifetime(before.possible, escape)


def _top(space, bits):
    return PointerValue(space, bits, any_compatible_location=True, may_be_null=True)


def _join_pointer(a, b):
    if a.address_space == b.address_space and a.width_bits == b.width_bits:
        return a.join(b)
    return _top("*", max(a.width_bits, b.width_bits))


class _Engine:
    def __init__(self, plan, pointer_seeds, state_seeds, policy):
        self.plan, self.policy = plan, policy
        self.graph = plan.program.graph
        self.nodes = {n.node_id: n for n in self.graph.nodes}
        self.registry = {s.object.object_id: s.object for s in plan.sites}
        self.site_map = {s.node_id: s.object for s in plan.sites}
        self.events = {e.node_id: e for e in plan.events}
        self.space = self.graph.snapshot.identity.environment.address_space
        self.bits = self.graph.snapshot.identity.environment.bitness
        self.seed_pointers = {s.node_id: s.pointer for s in pointer_seeds}
        self.initial = {oid: INITIAL for oid in self.registry}
        self.initial.update({s.object_id: s.lifetime for s in state_seeds})
        self.facts = {}
        self.outputs = {}
        self.observations = {}
        self.diagnostics = set()
        if self.graph.axes.analysis != "complete_in_scope" or plan.program.diagnostics:
            self.diagnostics.add("partial_input_graph")
        self.visits, self.updates, self.iterations = 0, 0, 0
        self.budget = False

    def bounded(self, pointer):
        if pointer is not None and len(pointer.candidates) > self.policy.max_candidates:
            self.diagnostics.add("heap_candidate_budget_widened")
            return _top(pointer.address_space, pointer.width_bits)
        return pointer

    def pointer_fact(self, node):
        deps = (
            node.inputs
            if node.kind != "Phi"
            else tuple(p.node_id for p in node.phi_inputs)
        )
        ready = [self.facts[d] for d in deps if d in self.facts]
        if deps and (not ready or (node.kind != "Phi" and len(ready) != len(deps))):
            return False, None
        if node.node_id in self.seed_pointers:
            return True, self.bounded(self.seed_pointers[node.node_id])
        if node.kind == "Allocation":
            obj = self.site_map[node.node_id]
            return True, PointerValue(
                obj.address_space,
                self.bits,
                (PointerCandidate(obj.object_id, 0),),
                may_be_null=self.policy.allocation_nullable,
            )
        if (
            node.kind in {"Store", "Free", "Branch", "OpaqueEffect", "InputMemory"}
            or node.width_bits != self.bits
        ):
            return True, None
        if node.kind == "Constant" and node.constant == 0:
            return True, PointerValue(self.space, self.bits, may_be_null=True)
        if node.kind == "Copy" or (
            node.kind == "Unary"
            and node.operation in {"zext", "sext", "trunc", "extract:0"}
        ):
            pointer = ready[0] if ready else None
            return (
                True,
                pointer
                if pointer is not None and pointer.width_bits == self.bits
                else _top(self.space, self.bits),
            )
        if node.kind in {"Phi", "Select"}:
            payload = ready[1:] if node.kind == "Select" else ready
            result = None
            for pointer in payload:
                pointer = pointer or _top(self.space, self.bits)
                result = pointer if result is None else _join_pointer(result, pointer)
            return True, self.bounded(result or _top(self.space, self.bits))
        return True, _top(self.space, self.bits)

    def resolve(self, event, state):
        if event.scope == "all":
            return _top(self.space, self.bits), set(self.registry), False, True
        pointer = None
        for root in event.roots:
            value = self.facts.get(root) or _top(self.space, self.bits)
            pointer = value if pointer is None else _join_pointer(pointer, value)
        pointer = self.bounded(pointer or _top(self.space, self.bits))
        compatible = {
            oid
            for oid, obj in self.registry.items()
            if pointer.address_space == "*"
            or obj.address_space == pointer.address_space
        }
        if pointer.any_compatible_location:
            targets = compatible
        else:
            targets = {c.object_id for c in pointer.candidates}
        unresolved = (
            pointer.any_compatible_location
            or pointer.may_be_null
            or any(c.offset is None for c in pointer.candidates)
        )
        if event.kind == "free" and (
            unresolved
            or not targets
            or any(c.offset != 0 for c in pointer.candidates)
            or any(state[oid].possible != ("live",) for oid in targets)
        ):
            targets = compatible
            unresolved = True
        if event.scope == "reachable":
            # Address disjointness does not rule out pointers stored inside a
            # root object. Until a transitive reachability proof is supplied,
            # include compatible objects and every already-escaped object.
            targets = compatible | {
                oid for oid in self.registry if state[oid].escape != "local"
            }
            unresolved = True
        definite = not unresolved and len(targets) == 1 and len(pointer.candidates) == 1
        return pointer, targets, definite, unresolved

    def observe(self, event, state):
        if self.visits >= self.policy.max_event_visits:
            self.budget = True
            return False
        if event.kind == "allocate":
            obj = self.site_map[event.node_id]
            pointer = self.facts[event.node_id]
            targets = {obj.object_id}
            definite = obj.singleton and not self.policy.allocation_nullable
            unresolved = False
        else:
            pointer, targets, definite, unresolved = self.resolve(event, state)
        if self.updates + len(targets) > self.policy.max_state_updates:
            self.budget = True
            return False
        self.visits += 1
        self.updates += len(targets)
        transitions = []
        for oid in sorted(targets):
            obj = self.registry[oid]
            before = state[oid]
            strong = False
            if event.kind == "allocate":
                after, strong = allocate_lifetime(
                    before,
                    singleton=obj.singleton,
                    nullable=self.policy.allocation_nullable,
                )
                if obj.singleton and before.possible != ("not_allocated",):
                    unresolved = True
                    self.diagnostics.add("allocation_prestate_unresolved")
            elif event.kind == "free":
                after, strong, nonlive = free_lifetime(
                    before, definite=definite and obj.singleton
                )
                if nonlive:
                    unresolved = True
                    self.diagnostics.add("nonlive_free_boundary")
            elif event.kind == "escape":
                strong = definite and obj.singleton
                after = escape_lifetime(before, definite=strong)
            elif event.kind == "opaque":
                after = TOP
                unresolved = True
            else:
                after = before
                if set(before.possible) - {"live"}:
                    self.diagnostics.add("nonlive_access_observation")
            state[oid] = after
            transitions.append(HeapTransition(oid, before, after, strong))
        if event.kind == "opaque":
            self.diagnostics.add("opaque_heap_effect")
        if unresolved:
            self.diagnostics.add("unresolved_heap_event")
        # Summary objects cannot claim an exact mutation even with one abstract ID.
        precision = (
            "opaque"
            if unresolved
            else (
                "exact"
                if definite and all(self.registry[oid].singleton for oid in targets)
                else "may_alias"
            )
        )
        if unresolved:
            transitions = [
                HeapTransition(t.object_id, t.before, t.after, False)
                for t in transitions
            ]
        observation = HeapObservation(
            event.node_id,
            event.kind,
            pointer,
            tuple(transitions),
            precision,
            unresolved,
            event.evidence_ids,
        )
        old = self.observations.get(event.node_id)
        if old is not None:
            old_t = {t.object_id: t for t in old.transitions}
            new_t = {t.object_id: t for t in observation.transitions}
            merged = []
            for oid in sorted(old_t.keys() | new_t.keys()):
                a, b = old_t.get(oid), new_t.get(oid)
                if a is None or b is None:
                    # Earlier passes did not record this object's state at the
                    # event. Do not manufacture an exact historical pre-state.
                    merged.append(HeapTransition(oid, TOP, TOP, False))
                else:
                    merged.append(
                        HeapTransition(
                            oid,
                            a.before.join(b.before),
                            a.after.join(b.after),
                            a.strong_update and b.strong_update,
                        )
                    )
            changed_targets = old_t.keys() != new_t.keys()
            if changed_targets:
                self.diagnostics.add("heap_target_set_widened")
            unresolved = old.unresolved or observation.unresolved or changed_targets
            pointer = self.bounded(_join_pointer(old.pointer, observation.pointer))
            precision = (
                "opaque"
                if unresolved
                else (
                    old.precision
                    if old.precision == observation.precision
                    else "may_alias"
                )
            )
            if (
                precision != "exact"
                or pointer.may_be_null
                or len(pointer.candidates) != 1
            ):
                merged = [
                    HeapTransition(t.object_id, t.before, t.after, False)
                    for t in merged
                ]
            observation = HeapObservation(
                event.node_id,
                event.kind,
                pointer,
                tuple(merged),
                precision,
                unresolved,
                event.evidence_ids,
            )
        self.observations[event.node_id] = observation
        return True

    def run(self):
        entry = self.graph.snapshot.function.entry_block
        schedule = {
            b: sorted(
                (d for d in self.plan.program.definitions if d.block == b),
                key=lambda d: (d.order, d.node_id),
            )
            for b in self.plan.program.dominance.reachable
        }
        changed = True
        while (
            changed and self.iterations < self.policy.max_iterations and not self.budget
        ):
            changed = False
            self.iterations += 1
            for b, definitions in schedule.items():
                if b == entry:
                    state = dict(self.initial)
                else:
                    predecessors = self.graph.snapshot.function.blocks[b].predecessors
                    states = [
                        self.outputs[p] for p in predecessors if p in self.outputs
                    ]
                    if not states:
                        continue
                    state = dict(states[0])
                    for other in states[1:]:
                        state = {
                            oid: state[oid].join(other[oid]) for oid in self.registry
                        }
                complete = True
                for definition in definitions:
                    node = self.nodes[definition.node_id]
                    ready, pointer = self.pointer_fact(node)
                    if not ready:
                        complete = False
                        break
                    old = self.facts.get(node.node_id)
                    if (
                        node.node_id in self.facts
                        and old is not None
                        and pointer is not None
                    ):
                        pointer = self.bounded(_join_pointer(old, pointer))
                    if node.node_id not in self.facts or pointer != old:
                        self.facts[node.node_id] = pointer
                        changed = True
                    if node.node_id in self.events and not self.observe(
                        self.events[node.node_id], state
                    ):
                        complete = False
                        break
                if self.budget:
                    break
                if complete:
                    old = self.outputs.get(b)
                    joined = (
                        state
                        if old is None
                        else {oid: old[oid].join(state[oid]) for oid in self.registry}
                    )
                    if old != joined:
                        self.outputs[b] = joined
                        changed = True
        reachable_events = {
            e.node_id
            for e in self.plan.events
            if e.block in self.plan.program.dominance.reachable
        }
        incomplete = (
            self.budget or changed or not reachable_events <= set(self.observations)
        )
        frontier = set()
        if incomplete:
            frontier = reachable_events
            self.diagnostics.add("heap_budget_or_unresolved_frontier")
            for event in self.plan.events:
                if event.node_id not in reachable_events:
                    continue
                old = self.observations.get(event.node_id)
                targets = (
                    {t.object_id for t in old.transitions}
                    if old
                    else set(self.registry)
                )
                transitions = tuple(
                    HeapTransition(oid, TOP, TOP, False) for oid in sorted(targets)
                )
                self.observations[event.node_id] = HeapObservation(
                    event.node_id,
                    event.kind,
                    _top(self.space, self.bits),
                    transitions,
                    "opaque",
                    True,
                    event.evidence_ids,
                )
            for nid, pointer in list(self.facts.items()):
                if pointer is not None:
                    self.facts[nid] = _top(pointer.address_space, pointer.width_bits)
            final = {oid: TOP for oid in self.registry}
        else:
            exits = [
                b
                for b in self.outputs
                if not self.graph.snapshot.function.blocks[b].successors
            ]
            outputs = [self.outputs[b] for b in (exits or list(self.outputs))]
            final = dict(outputs[0]) if outputs else dict(self.initial)
            for other in outputs[1:]:
                final = {oid: final[oid].join(other[oid]) for oid in self.registry}
        return final, frontier


def analyze_heap(
    plan: HeapPlan,
    pointer_seeds: tuple[PointerSeed, ...] = (),
    state_seeds: tuple[HeapSeed, ...] = (),
    policy: HeapPolicy = HeapPolicy(),
) -> HeapResult:
    canonical_set(tuple(s.node_id for s in pointer_seeds))
    canonical_set(tuple(s.object_id for s in state_seeds))
    nodes = {n.node_id: n for n in plan.program.graph.nodes}
    registry = {s.object.object_id: s.object for s in plan.sites}
    for seed in pointer_seeds:
        require(
            seed.node_id in nodes
            and nodes[seed.node_id].kind in {"InputValue", "UnknownValue"},
            "Heap pointer seed requires an explicit entry/unknown value",
        )
        require(
            nodes[seed.node_id].width_bits
            == seed.pointer.width_bits
            == plan.program.graph.snapshot.identity.environment.bitness,
            "Heap seed pointer width mismatch",
        )
        for candidate in seed.pointer.candidates:
            require(
                candidate.object_id in registry
                and registry[candidate.object_id].address_space
                == seed.pointer.address_space,
                "Dangling heap seed candidate",
            )
    for seed in state_seeds:
        require(seed.object_id in registry, "Unknown heap state seed")
        require(
            not registry[seed.object_id].singleton
            or seed.lifetime.possible == ("not_allocated",),
            "One-shot allocation must start not_allocated",
        )
    engine = _Engine(plan, pointer_seeds, state_seeds, policy)
    final, frontier = engine.run()
    result = HeapResult(
        plan.plan_digest,
        digest(
            {
                "pointers": [s.to_data() for s in pointer_seeds],
                "states": [s.to_data() for s in state_seeds],
            }
        ),
        digest(policy),
        tuple(HeapObjectState(oid, final[oid]) for oid in sorted(final)),
        tuple(
            HeapPointerFact(nid, p)
            for nid, p in sorted(engine.facts.items())
            if p is not None
        ),
        tuple(engine.observations[nid] for nid in sorted(engine.observations)),
        "partial" if engine.diagnostics else "complete_in_scope",
        tuple(sorted(engine.diagnostics)),
        tuple(sorted(frontier)),
        engine.iterations,
        engine.visits,
        engine.updates,
    )
    result.validate_plan(plan)
    return result
