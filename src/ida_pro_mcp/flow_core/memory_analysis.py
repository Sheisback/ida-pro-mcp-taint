"""Finite byte-memory fixed point. No heap lifetime, ABI guessing or native lifting."""

from collections.abc import Callable
from dataclasses import dataclass, replace

from .analysis import BitSeed, Seed, _label_inputs, _stable_constant, _value
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
    LabelBitRange,
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
    bit_masks: tuple[tuple[str, int], ...] = ()

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
        left_masks = dict(self.bit_masks)
        right_masks = dict(other.bit_masks)
        joined_masks = tuple(
            sorted(
                (
                    name,
                    left_masks.get(name, 255 if name in self.labels.explicit else 0)
                    | right_masks.get(
                        name, 255 if name in other.labels.explicit else 0
                    ),
                )
                for name in left_masks.keys() | right_masks.keys()
            )
        )
        return _Byte(
            self.value.join(other.value),
            self.labels.join(other.labels),
            tuple(sorted(set(self.definitions) | set(other.definitions))),
            pointer,
            start,
            joined_masks,
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


def _finite_values(nodes, node_id, limit, active=frozenset()):
    """Sound bounded values from immutable scalar expressions, or unknown.

    This is not path feasibility. Every value admitted by the expression must
    be included; cycles, unsupported operations and large sets widen to Top.
    """
    if node_id in active or len(active) >= 64:
        return None
    node = nodes[node_id]
    width = node.width_bits
    if width is None:
        return None
    if node.kind == "Constant":
        return (node.constant,)
    active = active | {node_id}
    if node.kind == "Copy" and len(node.inputs) == 1:
        source = nodes[node.inputs[0]]
        return (
            _finite_values(nodes, source.node_id, limit, active)
            if source.width_bits == width
            else None
        )
    if node.kind == "Unary" and len(node.inputs) == 1:
        source = nodes[node.inputs[0]]
        values = _finite_values(nodes, source.node_id, limit, active)
        if values is None:
            return None
        if node.operation == "zext" and width >= source.width_bits:
            return values
        if node.operation in {"trunc", "extract:0"} and width <= source.width_bits:
            return tuple(sorted({value & ((1 << width) - 1) for value in values}))
        if node.operation == "sext" and width >= source.width_bits:
            sign = 1 << (source.width_bits - 1)
            mask = (1 << width) - 1
            return tuple(
                sorted(
                    {
                        (value - (1 << source.width_bits) if value & sign else value)
                        & mask
                        for value in values
                    }
                )
            )
        return None
    if node.kind == "Binary" and len(node.inputs) == 2:
        left, right = (nodes[item] for item in node.inputs)
        if left.width_bits != width or right.width_bits != width:
            return None
        if node.operation == "and":
            constant = next(
                (item.constant for item in (left, right) if item.kind == "Constant"),
                None,
            )
            if constant is not None:
                if (1 << constant.bit_count()) > limit:
                    return None
                values = {0}
                subset = constant
                while subset:
                    values.add(subset)
                    subset = (subset - 1) & constant
                return tuple(sorted(values))
        left_values = _finite_values(nodes, left.node_id, limit, active)
        right_values = _finite_values(nodes, right.node_id, limit, active)
        if (
            left_values is None
            or right_values is None
            or len(left_values) * len(right_values) > limit
        ):
            return None
        mask = (1 << width) - 1
        operation = node.operation
        values = set()
        for left_value in left_values:
            for right_value in right_values:
                if operation == "mul":
                    value = left_value * right_value
                elif operation == "add":
                    value = left_value + right_value
                elif operation == "sub":
                    value = left_value - right_value
                elif operation == "shl" and right_value < width:
                    value = left_value << right_value
                else:
                    return None
                values.add(value & mask)
        return tuple(sorted(values)) if len(values) <= limit else None
    if node.kind == "Select" and len(node.inputs) == 3:
        first, second = (nodes[item] for item in node.inputs[1:])
        if first.width_bits != width or second.width_bits != width:
            return None
        choices = (
            (first.node_id, second.node_id)
            if nodes[node.inputs[0]].kind != "Constant"
            else (first.node_id if nodes[node.inputs[0]].constant else second.node_id,)
        )
        groups = [_finite_values(nodes, item, limit, active) for item in choices]
        if any(group is None for group in groups):
            return None
        result = tuple(sorted({value for group in groups for value in group}))
        return result if len(result) <= limit else None
    if node.kind == "Phi":
        groups = [
            _finite_values(nodes, item.node_id, limit, active)
            for item in node.phi_inputs
        ]
        if not groups or any(group is None for group in groups):
            return None
        result = tuple(sorted({value for group in groups for value in group}))
        return result if len(result) <= limit else None
    return None


def _pointer(node, arguments, width, space, nodes=None, max_candidates=32):
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
        index_id = node.inputs[1]
        if node.operation == "add" and base.pointer is None:
            base, index = index, base
            index_id = node.inputs[0]
        if (
            base.pointer is not None
            and index.pointer is None
            and index.value is not None
            and index.value.width_bits == width
            and base.pointer.width_bits == width
        ):
            # Interpret the full-width modular displacement in signed form so
            # all-ones add is the same object-relative displacement as -1.
            displacements = (
                (index.value.value,)
                if index.value.value is not None
                else _finite_values(nodes, index_id, max_candidates)
                if nodes is not None
                else None
            )
            if displacements is None:
                return _top_pointer(space, width)
            deltas = tuple(
                (value - (1 << width) if value >= (1 << (width - 1)) else value)
                * (-1 if node.operation == "sub" else 1)
                for value in displacements
            )
            # Null + a nonzero displacement is not unchanged null. We cannot
            # resolve its resulting location within the object-candidate domain.
            if any(delta != 0 for delta in deltas) and (
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
                        for delta in deltas
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
    def __init__(
        self,
        plan,
        objects,
        pointer_seeds,
        memory_seeds,
        value_seeds,
        bit_seeds,
        policy,
        checkpoint,
    ):
        self.plan, self.policy = plan, policy
        self.checkpoint = checkpoint
        self.graph = plan.program.graph
        self.nodes = {n.node_id: n for n in self.graph.nodes}
        self.objects = {o.object_id: o for o in objects}
        self.pointer_seeds = {s.node_id: s.pointer for s in pointer_seeds}
        self.pointee_sources = {
            binding.source_node_id: binding for binding in plan.program.pointee_bindings
        }
        self.pointee_pointers = {}
        for binding in plan.program.pointee_bindings:
            require(
                binding.pointer_node_id not in self.pointee_pointers
                or self.pointee_pointers[binding.pointer_node_id] == binding.pointer,
                "Conflicting pointee pointer bindings",
            )
            self.pointee_pointers[binding.pointer_node_id] = binding.pointer
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
        self.bit_seeds: dict[str, dict[str, int]] = {}
        for seed in bit_seeds:
            selected = self.bit_seeds.setdefault(seed.node_id, {})
            for name in seed.labels.explicit:
                selected[name] = selected.get(name, 0) | (
                    ((1 << seed.width_bits) - 1) << seed.bit_offset
                )
        bit_names = {name for seed in bit_seeds for name in seed.labels.explicit}
        bit_names.update(
            name
            for seed in value_seeds
            if seed.node_id in self.pointee_sources
            for name in seed.labels.explicit
        )
        entry_ids = {entry.node_id for entry in plan.program.entry_storage}
        whole_entries = [
            seed
            for seed in value_seeds
            if seed.node_id in entry_ids
            and self.nodes[seed.node_id].width_bits is not None
            and self.nodes[seed.node_id].width_bits <= 4096
            and self.nodes[seed.node_id].width_bits % 8 == 0
            and seed.labels.explicit
        ]
        whole_names = {name for seed in whole_entries for name in seed.labels.explicit}
        if len(bit_names | whole_names) <= 16:
            for seed in whole_entries:
                selected = self.bit_seeds.setdefault(seed.node_id, {})
                full = (1 << self.nodes[seed.node_id].width_bits) - 1
                for name in seed.labels.explicit:
                    selected[name] = selected.get(name, 0) | full
            bit_names.update(whole_names)
        self.bit_names = frozenset(bit_names)
        self.bit_masks: dict[str, dict[str, int]] = {}
        self.bit_mask_changed = False
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

    def project_bit_labels(self, node, label_deps, labels, load_masks=None):
        """Track selected source bits through exact scalar projections only.

        Unsupported value operations widen each named source to the full output.
        Exact byte-memory loads reuse per-byte masks; unresolved bytes widen.
        """
        width = node.width_bits
        if not self.bit_names:
            return labels
        sources = tuple(label_deps)
        if width is None:
            widened = {name: -1 for name in labels.explicit if name in self.bit_names}
            old = self.bit_masks.get(node.node_id, {})
            for name in old:
                widened[name] = -1
            if widened != old:
                self.bit_masks[node.node_id] = widened
                self.bit_mask_changed = True
            return labels
        if width > 4096:
            names = (
                (set(labels.explicit) & self.bit_names)
                | set(self.bit_masks.get(node.node_id, {}))
                | set(self.bit_seeds.get(node.node_id, {}))
                | set(load_masks or {})
                | {
                    name
                    for source_id in sources
                    for name in self.bit_masks.get(source_id, {})
                }
            )
            if not names:
                return labels
            self.diagnostics.add("bit_seed_projection_budget")
            widened = {name: -1 for name in names}
            old = self.bit_masks.get(node.node_id, {})
            if widened != old:
                self.bit_masks[node.node_id] = widened
                self.bit_mask_changed = True
            return labels.join(
                Labels(explicit=tuple(sorted(names)), unknown_provenance=True)
            )
        full = (1 << width) - 1
        projected: dict[str, int] = {}

        def add(source, shift=0, offset=0, limit=full):
            for name, mask in self.bit_masks.get(source, {}).items():
                result = ((mask >> offset) << shift) & limit
                if result:
                    projected[name] = projected.get(name, 0) | result

        if node.kind == "InputValue":
            projected.update(self.bit_seeds.get(node.node_id, {}))
        elif node.kind == "Load":
            projected.update(load_masks or {})
            projected.update(
                {
                    name: full
                    for name in labels.explicit
                    if name in self.bit_names and name not in projected
                }
            )
        elif node.kind in {"Copy", "Return", "Store"} and len(sources) == 1:
            source = self.nodes[sources[0]]
            if source.width_bits == width:
                add(sources[0])
            else:
                for source_id in sources:
                    for name in self.bit_masks.get(source_id, {}):
                        projected[name] = full
        elif node.kind == "Unary" and len(node.inputs) == 1:
            source_id = node.inputs[0]
            source_width = self.nodes[source_id].width_bits
            op = node.operation or ""
            if source_width is not None:
                if op in {"trunc", "extract:0"} and width <= source_width:
                    add(source_id)
                elif op == "zext" and width >= source_width:
                    add(source_id)
                elif op == "high" and width <= source_width:
                    add(source_id, offset=source_width - width)
                elif op.startswith("extract:"):
                    try:
                        offset = int(op.split(":", 1)[1])
                    except ValueError:
                        offset = -1
                    if 0 <= offset and offset + width <= source_width:
                        add(source_id, offset=offset)
                    else:
                        for name in self.bit_masks.get(source_id, {}):
                            projected[name] = full
                elif op == "sext" and width >= source_width:
                    add(source_id)
                    sign = 1 << (source_width - 1)
                    upper = full ^ ((1 << source_width) - 1)
                    for name, mask in self.bit_masks.get(source_id, {}).items():
                        if mask & sign:
                            projected[name] = projected.get(name, 0) | upper
                else:
                    for name in self.bit_masks.get(source_id, {}):
                        projected[name] = full
            else:
                for name in self.bit_masks.get(source_id, {}):
                    projected[name] = full
        elif (
            node.kind == "Binary"
            and node.operation in {"shl", "lshr", "ashr"}
            and len(node.inputs) == 2
        ):
            value_id, count_id = node.inputs
            count = _stable_constant(self.nodes, count_id)
            if (
                self.nodes[value_id].width_bits == width
                and count is not None
                and 0 <= count < width
            ):
                for name, mask in self.bit_masks.get(value_id, {}).items():
                    shifted = (
                        (mask << count) & full
                        if node.operation == "shl"
                        else (mask >> count) & full
                    )
                    if node.operation == "ashr" and mask & (1 << (width - 1)):
                        shifted |= full ^ ((1 << (width - count)) - 1)
                    if shifted:
                        projected[name] = projected.get(name, 0) | shifted
                for name in self.bit_masks.get(count_id, {}):
                    projected[name] = full
            else:
                for source_id in sources:
                    for name in self.bit_masks.get(source_id, {}):
                        projected[name] = full
        elif node.operation == "concat_low" and len(node.inputs) == 2:
            low, high = node.inputs
            low_width = self.nodes[low].width_bits
            high_width = self.nodes[high].width_bits
            if (
                low_width is not None
                and high_width is not None
                and low_width + high_width == width
            ):
                add(low)
                add(high, shift=low_width)
            else:
                for source_id in sources:
                    for name in self.bit_masks.get(source_id, {}):
                        projected[name] = full
        elif node.kind in {"Phi", "Select"} and all(
            self.nodes[source_id].width_bits == width for source_id in sources
        ):
            for source_id in sources:
                add(source_id)
        else:
            for source_id in sources:
                for name in self.bit_masks.get(source_id, {}):
                    projected[name] = full

        old = self.bit_masks.get(node.node_id, {})
        for name, mask in old.items():
            projected[name] = projected.get(name, 0) | mask
        direct = self.value_seeds.get(node.node_id)
        if direct is not None:
            for name in set(direct.explicit) & self.bit_names:
                projected[name] = full
        if projected != old:
            self.bit_masks[node.node_id] = projected
            self.bit_mask_changed = True
        names = (set(labels.explicit) - self.bit_names) | {
            name for name, mask in projected.items() if mask
        }
        return replace(labels, explicit=tuple(sorted(names)))

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

    def put(
        self, state, oid, interval, value, labels, definitions, strong, bit_masks=None
    ):
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
            byte_masks = (
                {
                    name: selected
                    for name, mask in bit_masks.items()
                    if (selected := (mask >> (8 * index)) & 255)
                }
                if bit_masks is not None
                else {}
            )
            cell_labels = (
                replace(
                    labels,
                    explicit=tuple(
                        sorted(
                            (set(labels.explicit) - self.bit_names) | byte_masks.keys()
                        )
                    ),
                )
                if bit_masks is not None
                else labels
            )
            cell_masks = tuple(sorted(byte_masks.items()))
            if isinstance(value, PointerValue):
                cell = _Byte(
                    BitValue(8),
                    cell_labels,
                    definitions,
                    value,
                    interval.start,
                    cell_masks,
                )
            else:
                byte = (
                    None if value.value is None else (value.value >> (8 * index)) & 255
                )
                cell = _Byte(
                    BitValue(8, byte), cell_labels, definitions, bit_masks=cell_masks
                )
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

    def source(self, state, node, labels):
        """Label existing contents, without inventing a target memory write."""
        reference = node.memory
        oid, interval = reference.object_id, reference.interval

        def label(cell, weak=False):
            masks = dict(cell.bit_masks)
            for name in labels.explicit:
                if name in self.bit_names:
                    masks[name] = 255
            return replace(
                cell,
                labels=self.bounded_labels(
                    cell.labels.join(labels).join(
                        Labels(unknown_provenance=True) if weak else Labels()
                    )
                ),
                definitions=tuple(sorted(set(cell.definitions) | {node.node_id})),
                bit_masks=tuple(sorted(masks.items())),
            )

        require(
            interval.end - interval.start <= self.policy.max_bytes,
            "Pointee source exceeds byte budget",
        )
        for offset in range(interval.start, interval.end):
            state.cells[oid, offset] = label(state.read(oid, offset))
        aliases = self.affected(AccessCandidate(oid, interval)) - {oid}
        for other in aliases:
            state.defaults[other] = label(state.defaults.get(other, _Byte()), True)
        for key, cell in list(state.cells.items()):
            if key[0] in aliases:
                state.cells[key] = label(cell, True)
        self.enforce_byte_budget(state)

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
        effect = self.steps[definition].effect
        havoc = effect == "havoc"
        source = effect == "source"
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
                if (
                    same_object_strong_store
                    or (
                        source
                        and self.nodes[definition].memory.object_id == oid
                        and self.nodes[definition].memory.interval.start
                        <= interval.start
                        and interval.end <= self.nodes[definition].memory.interval.end
                    )
                )
                and access.alias == "must_alias"
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
            rule_id=(
                "unknown-memory-effect-v1"
                if havoc
                else "source-range-v1"
                if source
                else "byte-reaching-store-v1"
            ),
            evidence_ids=evidence,
            precision=precision,
        )

    def load(self, state, node, access):
        result_value, result_pointer, result_labels = None, None, Labels()
        result_masks: dict[str, int] = {}
        pointer_seen = False
        for candidate in access.candidates:
            oid, interval = candidate.object_id, candidate.interval
            candidate_masks: dict[str, int] = {}
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
                for name in set(labels.explicit) & self.bit_names:
                    candidate_masks[name] = (1 << node.width_bits) - 1
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
                    cell_masks = dict(cell.bit_masks)
                    for name in set(cell.labels.explicit) & self.bit_names:
                        candidate_masks[name] = candidate_masks.get(name, 0) | (
                            cell_masks.get(name, 255) << (8 * shift)
                        )
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
            for name, mask in candidate_masks.items():
                result_masks[name] = result_masks.get(name, 0) | mask
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
            for name in set(result_labels.explicit) & self.bit_names:
                result_masks[name] = (1 << node.width_bits) - 1
        return (
            result_value or BitValue(node.width_bits),
            result_pointer,
            result_labels,
            result_masks,
        )

    def store(self, state, node, access, data):
        source_masks = self.bit_masks.get(data.node_id, {})
        selected_masks = source_masks
        value = data.pointer or data.value or BitValue(node.width_bits)
        width_mismatch = value.width_bits != node.width_bits
        if width_mismatch:
            value = BitValue(node.width_bits)
            data = replace(
                data, labels=data.labels.join(Labels(unknown_provenance=True))
            )
            self.diagnostics.add("store_value_width_mismatch")
            selected_masks = {}
        precise_bytes = bool(selected_masks) and access.strong_update
        if source_masks and not precise_bytes:
            full = (1 << node.width_bits) - 1 if node.width_bits <= 4096 else None
            if (
                width_mismatch
                or full is None
                or any(mask & full != full for mask in source_masks.values())
            ):
                self.diagnostics.add("bit_seed_byte_store_widened")
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
                    bit_masks=selected_masks if precise_bytes else None,
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
        label_deps, direct_only = _label_inputs(node, self.nodes, deps)
        for dependency in label_deps:
            if dependency in self.facts:
                labels = labels.join(self.facts[dependency].labels)
        for bypassed in direct_only:
            labels = labels.join(self.value_seeds.get(bypassed, Labels()))
        address_labels = Labels()
        pointer = None
        load_masks = None
        if node.node_id in self.pointee_sources:
            value = BitValue(node.width_bits)
            self.source(state, node, labels)
            load_masks = {
                name: (1 << node.width_bits) - 1
                for name in labels.explicit
                if name in self.bit_names
            }
        elif node.kind in {"Load", "Store"}:
            address = self.facts[node.memory_operands.address]
            address_labels = address.labels
            if node.memory_operands.segment:
                address_labels = address_labels.join(
                    self.facts[node.memory_operands.segment].labels
                )
            access = self.resolve(node, address)
            if node.kind == "Load":
                value, pointer, labels, load_masks = self.load(state, node, access)
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
                pointer = self.pointer_seeds.get(node.node_id)
                if pointer is None and not (
                    node.kind == "CallResult"
                    and node.operation == "derived_static_finite_indirect_return"
                ):
                    # The dispatch target is a control input, not the returned
                    # pointer value. Pointer use of this scalar result still
                    # resolves to unknown without a separate identity proof.
                    pointer = _pointer(
                        node,
                        available,
                        node.width_bits,
                        self.space,
                        self.nodes,
                        self.policy.max_candidates,
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
        if node.node_id in self.pointee_pointers:
            pointer = self.pointee_pointers[node.node_id]
        labels = self.project_bit_labels(node, label_deps, labels, load_masks)
        if node.node_id in self.steps and self.steps[node.node_id].effect == "havoc":
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
        processed = 0
        changed = True
        while changed and iterations < self.policy.max_iterations:
            if self.checkpoint is not None:
                self.checkpoint()
            changed = False
            self.bit_mask_changed = False
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
                    if self.checkpoint is not None:
                        self.checkpoint()
                    node = self.nodes[definition.node_id]
                    new = self.evaluate(node, state)
                    processed += 1
                    if self.checkpoint is not None:
                        self.checkpoint()
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
            changed = changed or self.bit_mask_changed
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
    *,
    bit_seeds: tuple[BitSeed, ...] = (),
    checkpoint: Callable[[], None] | None = None,
) -> MemoryResult:
    if checkpoint is not None:
        checkpoint()
    canonical_set(tuple(o.object_id for o in objects))
    canonical_set(tuple(s.node_id for s in pointer_seeds))
    canonical_set(tuple(s.node_id for s in value_seeds))
    canonical_set(tuple((s.node_id, s.bit_offset, s.width_bits) for s in bit_seeds))
    require(len(bit_seeds) <= 16, "Bit-range source budget exceeded")
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
        "CallResult",
        "Return",
    }
    pointee_ids = {b.source_node_id for b in plan.program.pointee_bindings}
    for seed in value_seeds:
        plan.program.graph.validate_source(
            ValueSource(plan.program.graph.snapshot.snapshot_id, seed.node_id)
        )
        require(
            (nodes[seed.node_id].kind in value_kinds or seed.node_id in pointee_ids)
            and nodes[seed.node_id].width_bits is not None,
            "Selected node has no seedable scalar value; use MemorySeed for memory contents or the Store data input node",
        )
    bit_names = {name for seed in bit_seeds for name in seed.labels.explicit}
    source_names = {
        name
        for seed in value_seeds
        if seed.node_id in pointee_ids
        for name in seed.labels.explicit
    }
    require(
        len(bit_names | source_names) <= min(policy.max_labels, 16),
        "Bit-range label budget exceeded",
    )
    require(
        not bit_names.intersection(
            name for seed in value_seeds for name in seed.labels.explicit
        )
        and not bit_names.intersection(
            name for seed in memory_seeds for name in seed.labels.explicit
        ),
        "Bit-range names must not overlap whole-value or memory seeds",
    )
    for seed in bit_seeds:
        plan.program.graph.validate_source(
            ValueSource(plan.program.graph.snapshot.snapshot_id, seed.node_id)
        )
        source = nodes[seed.node_id]
        require(
            source.kind == "InputValue"
            and source.width_bits is not None
            and seed.bit_offset + seed.width_bits <= source.width_bits,
            "Bit-range source must fit an InputValue",
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
    engine = _Engine(
        plan,
        objects,
        pointer_seeds,
        memory_seeds,
        value_seeds,
        bit_seeds,
        policy,
        checkpoint,
    )
    iterations, frontier = engine.run()
    source_description: dict[str, object] = {
        "objects": [o.to_data() for o in objects],
        "pointers": [s.to_data() for s in pointer_seeds],
        "memory": [s.to_data() for s in memory_seeds],
        "values": [s.to_data() for s in value_seeds],
    }
    if bit_seeds:
        source_description["bit_transfer_ruleset"] = "bit-window-v2"
        source_description["bit_values"] = [s.to_data() for s in bit_seeds]
    if plan.program.pointee_bindings:
        source_description["pointee_bindings"] = [
            binding.to_data() for binding in plan.program.pointee_bindings
        ]
    source_digest = digest(source_description)

    def published_fact(identifier):
        fact = engine.facts[identifier]
        spans = []
        if fact.value is not None and fact.value.width_bits <= 4096:
            for name, mask in sorted(engine.bit_masks.get(identifier, {}).items()):
                if name not in fact.labels.explicit:
                    continue
                start = None
                for bit in range(fact.value.width_bits + 1):
                    selected = bit < fact.value.width_bits and (mask >> bit) & 1
                    if selected and start is None:
                        start = bit
                    elif not selected and start is not None:
                        spans.append(LabelBitRange(name, start, bit - start))
                        start = None
        return replace(fact, explicit_bit_ranges=tuple(spans))

    result = MemoryResult(
        plan.plan_digest,
        source_digest,
        digest(policy),
        objects,
        tuple(published_fact(n) for n in sorted(engine.facts)),
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
