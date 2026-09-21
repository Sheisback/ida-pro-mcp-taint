"""Finite byte-memory fixed point. No heap lifetime, ABI guessing or native lifting."""

from dataclasses import dataclass, replace

from .analysis import Seed, _value
from .contracts import MemoryObject, ValueSource
from .memory import (
    AccessCandidate,
    MemoryAccess,
    MemoryDependency,
    MemoryFact,
    MemoryPlan,
    MemoryPolicy,
    MemoryResult,
    MemorySeed,
    PointerSeed,
    alias_relation,
)
from .serialization import digest
from .states import (
    BitValue,
    ByteRange,
    Labels,
    PointerCandidate,
    PointerValue,
    canonical_set,
    require,
)


@dataclass(frozen=True)
class _Byte:
    value: BitValue = BitValue(8)
    labels: Labels = Labels(unknown_provenance=True)
    definitions: tuple[str, ...] = ()
    pointer: PointerValue | None = None
    pointer_start: int | None = None

    def join(self, other):
        pointer = None
        if self.pointer is not None or other.pointer is not None:
            example = self.pointer or other.pointer
            pointer = (
                _join_pointers(self.pointer, other.pointer)
                if self.pointer is not None and other.pointer is not None
                else PointerValue(
                    example.address_space,
                    example.width_bits,
                    any_compatible_location=True,
                    may_be_null=True,
                )
            )
        start = (
            self.pointer_start if self.pointer_start == other.pointer_start else None
        )
        return _Byte(
            self.value.join(other.value),
            self.labels.join(other.labels),
            tuple(sorted(set(self.definitions) | set(other.definitions))),
            pointer,
            start,
        )


@dataclass
class _State:
    cells: dict
    defaults: dict

    def copy(self):
        return _State(dict(self.cells), dict(self.defaults))

    def read(self, oid, offset):
        return self.cells.get((oid, offset), self.defaults.get(oid, _Byte()))

    def join(self, other):
        defaults = {
            oid: self.defaults.get(oid, _Byte()).join(other.defaults.get(oid, _Byte()))
            for oid in self.defaults.keys() | other.defaults.keys()
        }
        cells = {
            key: self.read(*key).join(other.read(*key))
            for key in self.cells.keys() | other.cells.keys()
        }
        return _State(cells, defaults)


def _top_pointer(space, width):
    return PointerValue(space, width, any_compatible_location=True, may_be_null=True)


def _join_pointers(a, b):
    if a.address_space == b.address_space and a.width_bits == b.width_bits:
        return a.join(b)
    return _top_pointer(
        a.address_space if a.address_space == b.address_space else "*",
        max(a.width_bits, b.width_bits),
    )


def _pointer(node, arguments, width, space):
    pointers = [a.pointer for a in arguments]
    any_pointer = any(p is not None for p in pointers)
    if not any_pointer:
        return None
    if (
        node.kind in {"Copy", "Return"}
        and pointers
        and pointers[0] is not None
        and pointers[0].width_bits == width
    ):
        return pointers[0]
    if (
        node.kind == "Unary"
        and arguments
        and arguments[0].value is not None
        and width == arguments[0].value.width_bits
        and node.operation in {"trunc", "zext", "sext", "extract:0"}
    ):
        return pointers[0]
    if node.kind in {"Phi", "Select"}:
        payload = pointers[1:] if node.kind == "Select" else pointers
        result = None
        for p in payload:
            if p is None or p.width_bits != width or p.address_space != space:
                return _top_pointer(space, width)
            result = p if result is None else result.join(p)
        return result
    if (
        node.kind == "Binary"
        and node.operation in {"add", "sub"}
        and len(arguments) == 2
    ):
        base, index = arguments
        if node.operation == "add" and base.pointer is None:
            base, index = index, base
        if (
            base.pointer is not None
            and index.pointer is None
            and index.value is not None
            and index.value.value is not None
            and index.value.width_bits == width
            and base.pointer.width_bits == width
        ):
            # Interpret the full-width modular displacement in signed form so
            # all-ones add is the same object-relative displacement as -1.
            displacement = index.value.value
            if displacement >= (1 << (width - 1)):
                displacement -= 1 << width
            delta = displacement * (-1 if node.operation == "sub" else 1)
            # Null + a nonzero displacement is not unchanged null. We cannot
            # resolve its resulting location within the object-candidate domain.
            if delta != 0 and (
                base.pointer.may_be_null or base.pointer.any_compatible_location
            ):
                return _top_pointer(base.pointer.address_space, width)
            if base.pointer.any_compatible_location:
                return base.pointer
            candidates = tuple(
                sorted(
                    {
                        PointerCandidate(
                            c.object_id, None if c.offset is None else c.offset + delta
                        )
                        for c in base.pointer.candidates
                    },
                    key=lambda c: (c.object_id, c.offset is None, c.offset or 0),
                )
            )
            return PointerValue(
                base.pointer.address_space,
                width,
                candidates,
                may_be_null=base.pointer.may_be_null,
            )
    return _top_pointer(space, width)


class _Engine:
    def __init__(self, plan, objects, pointer_seeds, memory_seeds, value_seeds, policy):
        self.plan, self.policy = plan, policy
        self.graph = plan.program.graph
        self.nodes = {n.node_id: n for n in self.graph.nodes}
        self.objects = {o.object_id: o for o in objects}
        self.pointer_seeds = {s.node_id: s.pointer for s in pointer_seeds}
        # Repeated reads of the same entry atoms are equal SSA expressions, not
        # separate ABI arguments. This preserves a 64-bit pointer when extraction
        # partitions its entry storage into two 32-bit atoms (e.g. mixed widths).
        signatures = {}
        entry_ids = {e.node_id for e in plan.program.entry_storage}

        def entry_signature(nid, active):
            if nid in signatures:
                return signatures[nid]
            if nid in active:
                return None
            node = self.nodes[nid]
            if nid in entry_ids:
                signature = ("entry", nid)
            elif node.kind == "Copy":
                signature = entry_signature(node.inputs[0], active | {nid})
            elif node.operation == "concat_low" or (
                node.kind == "Unary" and (node.operation or "").startswith("extract:")
            ):
                children = tuple(
                    entry_signature(n, active | {nid}) for n in node.inputs
                )
                signature = (
                    (node.operation, node.width_bits, children)
                    if all(c is not None for c in children)
                    else None
                )
            else:
                signature = None
            signatures[nid] = signature
            return signature

        selected = {}
        for seed in pointer_seeds:
            signature = entry_signature(seed.node_id, set())
            if signature is not None:
                require(
                    signature not in selected or selected[signature] == seed.pointer,
                    "Conflicting equivalent entry pointer seeds",
                )
                selected[signature] = seed.pointer
        for nid in self.nodes:
            signature = entry_signature(nid, set())
            if signature in selected:
                self.pointer_seeds[nid] = selected[signature]
        self.value_seeds = {s.node_id: s.labels for s in value_seeds}
        self.facts, self.accesses, self.dependencies = {}, {}, {}
        self.diagnostics = set()
        self.outputs = {}
        self.steps = {s.node_id: s for s in plan.steps}
        self.entry = self.graph.snapshot.function.entry_block
        self.space = self.graph.snapshot.identity.environment.address_space
        self.endian = self.graph.snapshot.identity.environment.data_endian
        self.initial = _State({}, {})
        resolved_boundaries = {"memory_load_boundary", "memory_store_boundary"}
        if set(plan.program.diagnostics) - resolved_boundaries:
            self.diagnostics.add("partial_scalar_input")
        for seed in memory_seeds:
            self.put(
                self.initial,
                seed.object_id,
                seed.interval,
                seed.value,
                seed.labels,
                (),
                True,
            )
        for seed in memory_seeds:
            other_aliases = self.affected(
                AccessCandidate(seed.object_id, seed.interval)
            ) - {seed.object_id}
            self.havoc(self.initial, other_aliases, seed.labels, ())
        self.enforce_byte_budget(self.initial)

    def bounded_labels(self, labels):
        if len(labels.explicit) + len(labels.control) <= self.policy.max_labels:
            return labels
        self.diagnostics.add("label_budget_widened")
        return Labels(
            unknown_provenance=True,
            any_explicit_source=labels.any_explicit_source or bool(labels.explicit),
            any_control_source=labels.any_control_source or bool(labels.control),
        )

    def enforce_byte_budget(self, state):
        for key, cell in list(state.cells.items()):
            state.cells[key] = replace(cell, labels=self.bounded_labels(cell.labels))
        for key, cell in list(state.defaults.items()):
            state.defaults[key] = replace(cell, labels=self.bounded_labels(cell.labels))
        if len(state.cells) <= self.policy.max_bytes:
            return
        self.diagnostics.add("byte_budget_widened")
        for (oid, _), cell in state.cells.items():
            state.defaults[oid] = state.defaults.get(oid, _Byte()).join(cell)
        state.cells.clear()

    def put(self, state, oid, interval, value, labels, definitions, strong):
        if interval.end - interval.start > self.policy.max_bytes:
            self.havoc(state, {oid}, labels, definitions)
            self.diagnostics.add("access_width_widened")
            return
        for offset in range(interval.start, interval.end):
            index = (
                offset - interval.start
                if self.endian == "little"
                else interval.end - offset - 1
            )
            if isinstance(value, PointerValue):
                cell = _Byte(BitValue(8), labels, definitions, value, interval.start)
            else:
                byte = (
                    None if value.value is None else (value.value >> (8 * index)) & 255
                )
                cell = _Byte(BitValue(8, byte), labels, definitions)
            state.cells[(oid, offset)] = (
                cell if strong else state.read(oid, offset).join(cell)
            )
        self.enforce_byte_budget(state)

    def havoc(self, state, object_ids, labels, definitions):
        unknown = _Byte(
            BitValue(8), labels.join(Labels(unknown_provenance=True)), definitions
        )
        for oid in object_ids:
            state.defaults[oid] = state.defaults.get(oid, _Byte()).join(unknown)
        for key in list(state.cells):
            if key[0] in object_ids:
                state.cells[key] = state.cells[key].join(unknown)

    def resolve(self, node, address):
        pointer = address.pointer or _top_pointer(
            self.space, self.graph.snapshot.identity.environment.bitness
        )
        unresolved = pointer.any_compatible_location or pointer.may_be_null
        if pointer.may_be_null:
            self.diagnostics.add("possible_null_access")
        if (
            node.memory_operands.segment is not None
            and self.policy.flat_segment_assumption is None
        ):
            self.diagnostics.add("unresolved_segment")
            unresolved = True
            pointer = _top_pointer(pointer.address_space, pointer.width_bits)
        candidates = []
        if pointer.any_compatible_location:
            self.diagnostics.add("unknown_address")
            candidates = [
                AccessCandidate(o.object_id, None)
                for o in self.objects.values()
                if pointer.address_space == "*"
                or o.address_space == pointer.address_space
            ]
        else:
            for c in pointer.candidates:
                obj = self.objects[c.object_id]
                interval = None
                if c.offset is not None and (
                    c.offset < 0
                    or (
                        obj.size_bytes is not None
                        and c.offset + node.width_bits // 8 > obj.size_bytes
                    )
                ):
                    # A concrete address outside its claimed object cannot use
                    # that object's disjoint proof to exclude neighboring memory.
                    unresolved = True
                    self.diagnostics.add("out_of_bounds_pointer_widened")
                    candidates.extend(
                        AccessCandidate(other.object_id, None)
                        for other in self.objects.values()
                        if other.address_space == obj.address_space
                    )
                    continue
                if c.offset is not None and c.offset >= 0:
                    end = c.offset + node.width_bits // 8
                    if obj.size_bytes is None or end <= obj.size_bytes:
                        interval = ByteRange(c.offset, end)
                if node.width_bits // 8 > self.policy.max_bytes:
                    interval = None
                    self.diagnostics.add("access_width_widened")
                if interval is None:
                    unresolved = True
                    self.diagnostics.add("offset_or_extent_widened")
                candidates.append(AccessCandidate(c.object_id, interval))
        if not candidates:
            self.diagnostics.add("no_resolved_memory_candidate")
            unresolved = True
        candidates = tuple(
            sorted(
                set(candidates),
                key=lambda c: (
                    c.object_id,
                    c.interval.start if c.interval else -1,
                    c.interval.end if c.interval else -1,
                ),
            )
        )
        strong = (
            len(candidates) == 1
            and candidates[0].interval is not None
            and self.objects[candidates[0].object_id].singleton
            and not unresolved
        )
        alias = "must_alias" if strong else ("unknown" if unresolved else "may_alias")
        access = MemoryAccess(
            node.node_id,
            self.steps[node.node_id].before,
            node.memory_operands.address,
            candidates,
            node.width_bits,
            alias,
            strong and node.kind == "Store",
            unresolved,
            node.evidence_ids,
            precision="range_widened"
            if any(c.interval is None for c in candidates)
            else (
                "opaque"
                if unresolved
                else ("exact" if alias == "must_alias" else "may_alias")
            ),
        )
        self.accesses[node.node_id] = access
        return access

    def affected(self, candidate):
        target = self.objects[candidate.object_id]
        return {
            oid
            for oid, obj in self.objects.items()
            if alias_relation(target, candidate.interval, obj, None) != "no_alias"
        }

    def dependency(self, definition, node, oid, interval, access):
        key = (
            definition,
            node.node_id,
            oid,
            interval.start if interval else -1,
            interval.end if interval else -1,
        )
        evidence = tuple(
            sorted(set(self.nodes[definition].evidence_ids) | set(node.evidence_ids))
        )
        havoc = self.steps[definition].effect == "havoc"
        source_access = self.accesses.get(definition)
        same_object_strong_store = (
            source_access is not None
            and source_access.strong_update
            and any(c.object_id == oid for c in source_access.candidates)
        )
        precision = (
            "opaque"
            if havoc or access.unresolved or interval is None
            else (
                "exact"
                if same_object_strong_store and access.alias == "must_alias"
                else "may_alias"
            )
        )
        old = self.dependencies.get(key)
        if old is not None and old.precision != precision:
            precision = (
                "opaque" if "opaque" in (old.precision, precision) else "may_alias"
            )
        self.dependencies[key] = MemoryDependency(
            definition,
            node.node_id,
            oid,
            interval,
            rule_id="unknown-memory-effect-v1" if havoc else "byte-reaching-store-v1",
            evidence_ids=evidence,
            precision=precision,
        )

    def load(self, state, node, access):
        result_value, result_pointer, result_labels = None, None, Labels()
        pointer_seen = False
        for candidate in access.candidates:
            oid, interval = candidate.object_id, candidate.interval
            if (
                interval is None
                or interval.end - interval.start > self.policy.max_bytes
            ):
                self.diagnostics.add("load_range_widened")
                default = state.defaults.get(oid, _Byte())
                labels = default.labels
                definitions = set(default.definitions)
                for (key, _), cell in state.cells.items():
                    if key == oid:
                        labels = labels.join(cell.labels)
                        definitions.update(cell.definitions)
                for definition in definitions:
                    self.dependency(definition, node, oid, None, access)
                value, pointer = (
                    BitValue(node.width_bits),
                    _top_pointer(self.space, node.width_bits),
                )
                labels = labels.join(Labels(unknown_provenance=True))
            else:
                cells = [
                    state.read(oid, i) for i in range(interval.start, interval.end)
                ]
                labels = Labels()
                integer = 0
                known = True
                for index, cell in enumerate(cells):
                    labels = labels.join(cell.labels)
                    if cell.value.value is None:
                        known = False
                    shift = index if self.endian == "little" else len(cells) - index - 1
                    integer |= (cell.value.value or 0) << (8 * shift)
                    for definition in cell.definitions:
                        self.dependency(
                            definition,
                            node,
                            oid,
                            ByteRange(
                                interval.start + index, interval.start + index + 1
                            ),
                            access,
                        )
                value = BitValue(node.width_bits, integer if known else None)
                pointers = [c.pointer for c in cells]
                if (
                    pointers
                    and pointers[0] is not None
                    and all(p == pointers[0] for p in pointers)
                    and pointers[0].width_bits == node.width_bits
                    and all(c.pointer_start == interval.start for c in cells)
                ):
                    pointer = pointers[0]
                elif any(p is not None for p in pointers):
                    pointer = _top_pointer(self.space, node.width_bits)
                    labels = labels.join(Labels(unknown_provenance=True))
                    self.diagnostics.add("partial_pointer_reload")
                else:
                    pointer = None
            result_value = value if result_value is None else result_value.join(value)
            result_labels = result_labels.join(labels)
            if pointer is not None:
                result_pointer = (
                    pointer
                    if not pointer_seen
                    else (
                        _join_pointers(result_pointer, pointer)
                        if result_pointer is not None
                        else _top_pointer(self.space, node.width_bits)
                    )
                )
            elif pointer_seen and result_pointer is not None:
                result_pointer = _top_pointer(self.space, node.width_bits)
            pointer_seen = True
        if access.unresolved or not access.candidates:
            result_labels = result_labels.join(Labels(unknown_provenance=True))
            result_value = BitValue(node.width_bits)
        return result_value or BitValue(node.width_bits), result_pointer, result_labels

    def store(self, state, node, access, data):
        value = data.pointer or data.value or BitValue(node.width_bits)
        if value.width_bits != node.width_bits:
            value = BitValue(node.width_bits)
            data = replace(
                data, labels=data.labels.join(Labels(unknown_provenance=True))
            )
            self.diagnostics.add("store_value_width_mismatch")
        for candidate in access.candidates:
            affected = self.affected(candidate)
            if candidate.interval is None:
                self.havoc(state, affected, data.labels, (node.node_id,))
            else:
                self.put(
                    state,
                    candidate.object_id,
                    candidate.interval,
                    value,
                    data.labels,
                    (node.node_id,),
                    access.strong_update,
                )
                # Other argument objects may denote the same bytes but their base
                # displacement is unknown. Preserve all possible effects weakly.
                self.havoc(
                    state,
                    affected - {candidate.object_id},
                    data.labels,
                    (node.node_id,),
                )
        if access.unresolved:
            if not access.candidates:
                pointer = self.facts[node.memory_operands.address].pointer
                space = pointer.address_space if pointer is not None else self.space
                compatible = {
                    oid
                    for oid, obj in self.objects.items()
                    if space == "*" or obj.address_space == space
                }
                self.havoc(state, compatible, data.labels, (node.node_id,))
            self.diagnostics.add("unresolved_store")

    def join_fact(self, old, new):
        if old is None:
            return new
        value = (
            old.value.join(new.value)
            if old.value is not None and new.value is not None
            else new.value or old.value
        )
        pointer = None
        if old.pointer is not None or new.pointer is not None:
            example = old.pointer or new.pointer
            pointer = (
                _join_pointers(old.pointer, new.pointer)
                if old.pointer is not None and new.pointer is not None
                else _top_pointer(example.address_space, example.width_bits)
            )
        if pointer is not None and len(pointer.candidates) > self.policy.max_candidates:
            pointer = _top_pointer(pointer.address_space, pointer.width_bits)
            self.diagnostics.add("candidate_budget_widened")
        return MemoryFact(
            new.node_id,
            value,
            pointer,
            self.bounded_labels(old.labels.join(new.labels)),
            self.bounded_labels(old.address_labels.join(new.address_labels)),
        )

    def evaluate(self, node, state):
        deps = (
            node.inputs
            if node.kind != "Phi"
            else tuple(p.node_id for p in node.phi_inputs)
        )
        available = [self.facts[d] for d in deps if d in self.facts]
        if deps and (
            not available or (node.kind != "Phi" and len(available) != len(deps))
        ):
            return None
        labels = self.value_seeds.get(node.node_id, Labels())
        for fact in available[1:] if node.kind == "Select" else available:
            labels = labels.join(fact.labels)
        address_labels = Labels()
        pointer = None
        if node.kind in {"Load", "Store"}:
            address = self.facts[node.memory_operands.address]
            address_labels = address.labels
            if node.memory_operands.segment:
                address_labels = address_labels.join(
                    self.facts[node.memory_operands.segment].labels
                )
            access = self.resolve(node, address)
            if node.kind == "Load":
                value, pointer, labels = self.load(state, node, access)
                labels = labels.join(self.value_seeds.get(node.node_id, Labels()))
            else:
                data = self.facts[node.memory_operands.data]
                self.store(state, node, access, data)
                value, labels = data.value, data.labels
        else:
            vals = [f.value for f in available]
            if any(v is None for v in vals) and node.width_bits is not None:
                value, invalid = BitValue(node.width_bits), True
            else:
                value, invalid = _value(node, vals)
            if node.width_bits:
                pointer = self.pointer_seeds.get(node.node_id) or _pointer(
                    node, available, node.width_bits, self.space
                )
                if (
                    pointer is not None
                    and len(pointer.candidates) > self.policy.max_candidates
                ):
                    pointer = _top_pointer(pointer.address_space, pointer.width_bits)
                    self.diagnostics.add("candidate_budget_widened")
            if (
                pointer is not None
                and pointer.any_compatible_location
                and node.node_id not in self.pointer_seeds
            ):
                self.diagnostics.add("pointer_relation_widened")
                labels = labels.join(Labels(unknown_provenance=True))
            unknown = (
                node.kind
                in {
                    "UnknownValue",
                    "Call",
                    "OpaqueEffect",
                    "InputMemory",
                    "Allocation",
                    "Free",
                }
                and node.operation != "nop"
            )
            if invalid or unknown:
                labels = labels.join(Labels(unknown_provenance=True))
                self.diagnostics.add("unresolved_scalar_effect")
            if (
                node.node_id in self.steps
                and self.steps[node.node_id].effect == "havoc"
            ):
                self.havoc(state, set(self.objects), labels, (node.node_id,))
                self.diagnostics.add("unknown_call_or_write")
        return MemoryFact(
            node.node_id,
            value,
            pointer,
            self.bounded_labels(labels),
            self.bounded_labels(address_labels),
        )

    def run(self):
        schedule = {
            b.block: sorted(
                (d for d in self.plan.program.definitions if d.block == b.block),
                key=lambda d: (d.order, d.node_id),
            )
            for b in self.plan.blocks
        }
        iterations = 0
        changed = True
        while changed and iterations < self.policy.max_iterations:
            changed = False
            iterations += 1
            for b in self.plan.blocks:
                if b.block == self.entry:
                    state = self.initial.copy()
                else:
                    states = [
                        self.outputs[p]
                        for p in self.graph.snapshot.function.blocks[
                            b.block
                        ].predecessors
                        if p in self.outputs
                    ]
                    if not states:
                        continue
                    state = states[0].copy()
                    for other in states[1:]:
                        state = state.join(other)
                complete = True
                for definition in schedule[b.block]:
                    node = self.nodes[definition.node_id]
                    new = self.evaluate(node, state)
                    if new is None:
                        complete = False
                        break
                    new = self.join_fact(self.facts.get(node.node_id), new)
                    if new != self.facts.get(node.node_id):
                        self.facts[node.node_id] = new
                        changed = True
                if complete:
                    old = self.outputs.get(b.block)
                    joined = state if old is None else old.join(state)
                    self.enforce_byte_budget(joined)
                    if old != joined:
                        self.outputs[b.block] = joined
                        changed = True
        frontier = set()
        if changed or len(self.facts) != len(self.nodes):
            self.diagnostics.add("iteration_budget_or_unresolved_cycle")
            frontier = set(self.nodes)
            for nid, node in self.nodes.items():
                old = self.facts.get(
                    nid,
                    MemoryFact(nid, None, None, self.value_seeds.get(nid, Labels())),
                )
                self.facts[nid] = MemoryFact(
                    nid,
                    BitValue(node.width_bits) if node.width_bits else None,
                    _top_pointer(self.space, node.width_bits)
                    if node.width_bits and old.pointer
                    else None,
                    old.labels.join(
                        Labels(unknown_provenance=True, any_explicit_source=True)
                    ),
                    old.address_labels,
                )
        return iterations, frontier


def analyze_memory(
    plan: MemoryPlan,
    objects: tuple[MemoryObject, ...],
    pointer_seeds: tuple[PointerSeed, ...] = (),
    memory_seeds: tuple[MemorySeed, ...] = (),
    value_seeds: tuple[Seed, ...] = (),
    policy: MemoryPolicy = MemoryPolicy(),
) -> MemoryResult:
    canonical_set(tuple(o.object_id for o in objects))
    canonical_set(tuple(s.node_id for s in pointer_seeds))
    canonical_set(tuple(s.node_id for s in value_seeds))
    canonical_set(
        tuple((s.object_id, s.interval.start, s.interval.end) for s in memory_seeds)
    )
    require(
        len({(o.address_space, o.key) for o in objects}) == len(objects),
        "Conflicting memory object identities",
    )
    registry = {o.object_id: o for o in objects}
    nodes = {n.node_id: n for n in plan.program.graph.nodes}
    for obj in objects:
        require(
            obj.snapshot_id == plan.program.graph.snapshot.snapshot_id,
            "Cross-snapshot object",
        )

    def validate_pointer(pointer):
        for c in pointer.candidates:
            require(c.object_id in registry, "Dangling pointer candidate")
            require(
                registry[c.object_id].address_space == pointer.address_space,
                "Pointer address-space mismatch",
            )

    for seed in pointer_seeds:
        plan.program.graph.validate_source(
            ValueSource(plan.program.graph.snapshot.snapshot_id, seed.node_id)
        )
        require(
            nodes[seed.node_id].width_bits == seed.pointer.width_bits,
            "Pointer seed width mismatch",
        )
        require(
            nodes[seed.node_id].kind not in {"Load", "Store", "InputMemory"},
            "Use a memory seed for loaded pointer contents",
        )
        validate_pointer(seed.pointer)
    value_kinds = {
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
    }
    for seed in value_seeds:
        plan.program.graph.validate_source(
            ValueSource(plan.program.graph.snapshot.snapshot_id, seed.node_id)
        )
        require(
            nodes[seed.node_id].kind in value_kinds
            and nodes[seed.node_id].width_bits is not None,
            "Selected node has no seedable scalar value; use MemorySeed for memory contents or the Store data input node",
        )
    ends = {}
    for seed in memory_seeds:
        require(seed.object_id in registry, "Unknown memory seed object")
        obj = registry[seed.object_id]
        require(
            obj.size_bytes is None or seed.interval.end <= obj.size_bytes,
            "Memory seed outside extent",
        )
        require(
            ends.get(seed.object_id, 0) <= seed.interval.start,
            "Overlapping memory seeds",
        )
        ends[seed.object_id] = seed.interval.end
        if isinstance(seed.value, PointerValue):
            validate_pointer(seed.value)
    engine = _Engine(plan, objects, pointer_seeds, memory_seeds, value_seeds, policy)
    iterations, frontier = engine.run()
    source_digest = digest(
        {
            "objects": [o.to_data() for o in objects],
            "pointers": [s.to_data() for s in pointer_seeds],
            "memory": [s.to_data() for s in memory_seeds],
            "values": [s.to_data() for s in value_seeds],
        }
    )
    result = MemoryResult(
        plan.plan_digest,
        source_digest,
        digest(policy),
        objects,
        tuple(engine.facts[n] for n in sorted(engine.facts)),
        tuple(engine.accesses[n] for n in sorted(engine.accesses)),
        tuple(
            sorted(
                engine.dependencies.values(),
                key=lambda d: (
                    d.source,
                    d.target,
                    d.object_id,
                    d.interval.start if d.interval else -1,
                    d.interval.end if d.interval else -1,
                ),
            )
        ),
        "partial" if engine.diagnostics else "complete_in_scope",
        tuple(sorted(engine.diagnostics)),
        tuple(sorted(frontier)),
        iterations,
    )

    result.validate_plan(plan)
    return result
