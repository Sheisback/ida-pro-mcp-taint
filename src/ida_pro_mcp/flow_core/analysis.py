"""Seeded explicit scalar provenance/value fixed point, separate from graph identity."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from .contracts import Graph, Node, ValueSource
from .serialization import Model, digest
from .states import BitValue, Labels, canonical_set, check_digest, check_id, require


@dataclass(frozen=True)
class Seed(Model):
    node_id: str
    labels: Labels

    def __post_init__(self):
        super().__post_init__()
        check_id(self.node_id, "node")


@dataclass(frozen=True)
class BitSeed(Model):
    """Explicit label on a whole-byte window of one scalar input value."""

    node_id: str
    labels: Labels
    bit_offset: int
    width_bits: int
    kind: Literal["bit_range"] = "bit_range"
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        check_id(self.node_id, "node")
        require(
            self.bit_offset >= 0
            and self.bit_offset % 8 == 0
            and 0 < self.width_bits <= 64
            and self.width_bits % 8 == 0,
            "Invalid whole-byte bit source window",
        )
        require(
            bool(self.labels.explicit)
            and not self.labels.control
            and not self.labels.unknown_provenance
            and not self.labels.any_explicit_source
            and not self.labels.any_control_source,
            "Bit-range seed requires only named explicit labels",
        )


@dataclass(frozen=True)
class ScalarPolicy(Model):
    max_evaluations: int = 100000
    schema_version: Literal[1] = 1
    mode: Literal["explicit"] = "explicit"
    ruleset: Literal["scalar-transfer-v4"] = "scalar-transfer-v4"

    def __post_init__(self):
        super().__post_init__()
        require(self.max_evaluations > 0, "Invalid evaluation budget")


@dataclass(frozen=True)
class Fact(Model):
    node_id: str
    value: BitValue | None
    labels: Labels

    def __post_init__(self):
        super().__post_init__()
        check_id(self.node_id, "node")


@dataclass(frozen=True)
class AnalysisResult(Model):
    graph_digest: str
    source_digest: str
    policy_digest: str
    facts: tuple[Fact, ...]
    status: Literal["complete_in_scope", "partial"]
    frontier: tuple[str, ...]
    diagnostics: tuple[str, ...]
    evaluations: int
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        for d in (self.graph_digest, self.source_digest, self.policy_digest):
            check_digest(d)
        canonical_set(tuple(f.node_id for f in self.facts))
        canonical_set(self.frontier)
        canonical_set(self.diagnostics)
        require(
            set(self.frontier) <= {f.node_id for f in self.facts},
            "Unknown frontier node",
        )
        require(self.evaluations >= 0, "Negative evaluations")
        require(
            self.status != "complete_in_scope" or not self.frontier,
            "Incomplete frontier",
        )

    @property
    def cache_key(self):
        return digest(
            {
                "graph": self.graph_digest,
                "source": self.source_digest,
                "policy": self.policy_digest,
            }
        )


def _signed(value, width):
    return value - (1 << width) if value & (1 << (width - 1)) else value


def _value(node, values):
    """Return value and whether an operation was outside the validated profile."""
    bits = node.width_bits
    if bits is None:
        return None, False
    top = BitValue(bits)
    if node.kind == "Constant":
        return BitValue(bits, node.constant), False
    if node.kind in {
        "InputValue",
        "UnknownValue",
        "Load",
        "Call",
        "CallResult",
        "OpaqueEffect",
        "InputMemory",
        "Allocation",
        "Store",
    }:
        return top, False
    if node.kind == "Phi":
        result = values[0]
        for value in values[1:]:
            result = result.join(value)
        return result, False
    if node.kind in {"Copy", "Return"}:
        return (
            (values[0], False)
            if values and values[0].width_bits == bits
            else (top, True)
        )
    if node.kind == "Select":
        cond, a, b = values
        if a.width_bits != bits or b.width_bits != bits:
            return top, True
        return (
            (a if cond.value else b, False)
            if cond.value is not None
            else (a.join(b), False)
        )
    op = node.operation
    widths = [v.width_bits for v in values]
    if node.kind == "Unary":
        if len(values) != 1:
            return top, True
        source = values[0]
        offset = 0
        if op in {"neg", "not"}:
            valid = bits == source.width_bits
        elif op == "logical_not":
            valid = True
        elif op in {"zext", "sext"}:
            valid = bits >= source.width_bits
        elif op in {"trunc", "high"}:
            valid = bits <= source.width_bits
        elif op and op.startswith("extract:"):
            try:
                offset = int(op.split(":")[1])
            except ValueError:
                return top, True
            valid = offset >= 0 and offset + bits <= source.width_bits
        else:
            return top, True
        if not valid:
            return top, True
        x = source.value
        if x is None:
            return top, False
        if op == "neg":
            out = -x
        elif op == "not":
            out = ~x
        elif op == "logical_not":
            out = int(x == 0)
        elif op == "sext":
            out = _signed(x, source.width_bits)
        elif op == "high":
            out = x >> (source.width_bits - bits)
        elif op.startswith("extract:"):
            out = x >> offset
        else:
            out = x
    elif node.kind in {"Binary", "Compare"}:
        if len(values) != 2:
            return top, True
        allowed = (
            {"eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge"}
            if node.kind == "Compare"
            else {
                "add",
                "sub",
                "mul",
                "and",
                "or",
                "xor",
                "concat_low",
                "shl",
                "lshr",
                "ashr",
            }
        )
        if op not in allowed:
            return top, True
        if op == "concat_low":
            valid = sum(widths) == bits
        elif op in {"shl", "lshr", "ashr"}:
            valid = widths[0] == bits
        elif node.kind == "Compare":
            valid = widths[0] == widths[1]
        else:
            valid = widths[0] == widths[1] == bits
        if not valid:
            return top, True
        a, b = (v.value for v in values)
        # Count validity is a profile precondition, independent of payload value.
        # Top counts cannot establish that precondition in the Const/Top domain.
        if op in {"shl", "lshr", "ashr"} and (b is None or b >= widths[0]):
            return top, True
        if node.kind == "Binary" and (
            (op in {"and", "mul"} and (a == 0 or b == 0))
            or (op in {"xor", "sub"} and node.inputs[0] == node.inputs[1])
        ):
            return BitValue(bits, 0), False
        if a is None or b is None:
            return top, False
        if op == "add":
            out = a + b
        elif op == "sub":
            out = a - b
        elif op == "mul":
            out = a * b
        elif op == "and":
            out = a & b
        elif op == "or":
            out = a | b
        elif op == "xor":
            out = a ^ b
        elif op == "concat_low":
            out = a | (b << widths[0])
        elif op in {"shl", "lshr", "ashr"}:
            out = (
                a << b
                if op == "shl"
                else (_signed(a, widths[0]) if op == "ashr" else a) >> b
            )
        elif op in {"eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge"}:
            if op.startswith("s"):
                a, b = _signed(a, widths[0]), _signed(b, widths[1])
            relation = op[1:] if op[0] in "us" else op
            out = int(
                {
                    "eq": a == b,
                    "ne": a != b,
                    "lt": a < b,
                    "le": a <= b,
                    "gt": a > b,
                    "ge": a >= b,
                }[relation]
            )
        else:
            return top, True
    else:
        return top, True
    return BitValue(bits, out & ((1 << bits) - 1)), False


def _stable_constant(nodes: dict[str, Node], node_id: str) -> int | None:
    """A literal or width-preserving copy is constant before fixed-point joins."""
    seen: set[str] = set()
    while node_id not in seen:
        seen.add(node_id)
        node = nodes[node_id]
        if node.kind == "Constant":
            return node.constant
        if node.kind != "Copy" or len(node.inputs) != 1:
            return None
        source = nodes[node.inputs[0]]
        if node.width_bits != source.width_bits:
            return None
        node_id = source.node_id
    return None


def _slice_inputs(
    nodes: dict[str, Node],
    node_id: str,
    start: int,
    width: int,
    active: frozenset[str] = frozenset(),
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Project a bit window; report bypassed nodes for direct-seed retention."""
    if node_id in active or len(active) >= 64:
        return (node_id,), ()
    node = nodes[node_id]
    if (
        node.width_bits is None
        or start < 0
        or width <= 0
        or start + width > node.width_bits
    ):
        return (node_id,), ()
    active = active | {node_id}
    selected: tuple[str, ...] | None = None
    bypassed: tuple[str, ...] = ()
    if node.kind == "Copy" and len(node.inputs) == 1:
        child = nodes[node.inputs[0]]
        if child.width_bits == node.width_bits:
            selected, bypassed = _slice_inputs(
                nodes, child.node_id, start, width, active
            )
    elif (
        node.kind == "Binary"
        and node.operation == "concat_low"
        and len(node.inputs) == 2
    ):
        low, high = (nodes[item] for item in node.inputs)
        if (
            low.width_bits is not None
            and high.width_bits is not None
            and low.width_bits + high.width_bits == node.width_bits
        ):
            parts, skipped = [], []
            if start < low.width_bits:
                a, b = _slice_inputs(
                    nodes,
                    low.node_id,
                    start,
                    min(width, low.width_bits - start),
                    active,
                )
                parts.extend(a)
                skipped.extend(b)
            if start + width > low.width_bits:
                high_start = max(start, low.width_bits)
                a, b = _slice_inputs(
                    nodes,
                    high.node_id,
                    high_start - low.width_bits,
                    start + width - high_start,
                    active,
                )
                parts.extend(a)
                skipped.extend(b)
            selected, bypassed = tuple(parts), tuple(skipped)
    elif node.kind == "Unary" and len(node.inputs) == 1:
        child = nodes[node.inputs[0]]
        if child.width_bits is not None:
            mapped = None
            if (
                node.operation in {"trunc", "extract:0"}
                and node.width_bits <= child.width_bits
            ):
                mapped = start
            elif node.operation == "high" and node.width_bits <= child.width_bits:
                mapped = child.width_bits - node.width_bits + start
            elif node.operation and node.operation.startswith("extract:"):
                try:
                    offset = int(node.operation.split(":", 1)[1])
                except ValueError:
                    offset = -1
                if offset >= 0 and offset + node.width_bits <= child.width_bits:
                    mapped = offset + start
            elif node.operation == "zext" and node.width_bits >= child.width_bits:
                if start >= child.width_bits:
                    selected = ()
                else:
                    selected, bypassed = _slice_inputs(
                        nodes,
                        child.node_id,
                        start,
                        min(width, child.width_bits - start),
                        active,
                    )
            elif node.operation == "sext" and node.width_bits >= child.width_bits:
                parts, skipped = [], []
                if start < child.width_bits:
                    a, b = _slice_inputs(
                        nodes,
                        child.node_id,
                        start,
                        min(width, child.width_bits - start),
                        active,
                    )
                    parts.extend(a)
                    skipped.extend(b)
                if start + width > child.width_bits:
                    a, b = _slice_inputs(
                        nodes, child.node_id, child.width_bits - 1, 1, active
                    )
                    parts.extend(a)
                    skipped.extend(b)
                selected, bypassed = tuple(parts), tuple(skipped)
            if mapped is not None:
                selected, bypassed = _slice_inputs(
                    nodes, child.node_id, mapped, width, active
                )
    if selected is None:
        return (node_id,), ()
    return tuple(sorted(set(selected))), tuple(sorted(set((*bypassed, node_id))))


def _label_inputs(
    node: Node, nodes: dict[str, Node], deps: tuple[str, ...]
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return proven value dependencies and bypassed direct-seed locations."""
    if (
        node.kind == "CallResult"
        and node.operation == "derived_static_finite_indirect_return"
        and deps
    ):
        # The first input is the finite dispatch target. It selects a callee,
        # but is not a scalar argument copied into the returned value.
        return deps[1:], ()
    if node.kind == "Select":
        condition = _stable_constant(nodes, deps[0])
        if condition is not None and all(
            nodes[dep].width_bits == node.width_bits for dep in deps[1:]
        ):
            return (deps[1] if condition else deps[2],), ()
        return deps[1:], ()
    if node.kind == "Unary" and len(deps) == 1 and node.width_bits is not None:
        source = nodes[deps[0]]
        if source.width_bits is not None:
            offset = None
            if (
                node.operation in {"trunc", "extract:0"}
                and node.width_bits <= source.width_bits
            ):
                offset = 0
            elif node.operation == "high" and node.width_bits <= source.width_bits:
                offset = source.width_bits - node.width_bits
            elif node.operation and node.operation.startswith("extract:"):
                try:
                    candidate = int(node.operation.split(":", 1)[1])
                except ValueError:
                    candidate = -1
                if candidate >= 0 and candidate + node.width_bits <= source.width_bits:
                    offset = candidate
            if offset is not None:
                return _slice_inputs(nodes, deps[0], offset, node.width_bits)
    if (
        node.kind == "Binary"
        and len(deps) == 2
        and all(nodes[dep].width_bits == node.width_bits for dep in deps)
    ):
        if node.operation in {"and", "mul"} and any(
            _stable_constant(nodes, dep) == 0 for dep in deps
        ):
            return (), ()
        if node.operation in {"xor", "sub"} and deps[0] == deps[1]:
            return (), ()
    if node.kind == "Load":
        return (), ()
    if node.kind == "Store":
        data = node.memory_operands.data if node.memory_operands else None
        return ((data,), ()) if data is not None else ((), ())
    return deps, ()


def analyze(
    graph: Graph,
    seeds: tuple[Seed, ...] = (),
    policy: ScalarPolicy = ScalarPolicy(),
    *,
    checkpoint: Callable[[], None] | None = None,
) -> AnalysisResult:
    """Compute scalar facts; checkpoint exceptions abort without a result."""
    if checkpoint is not None:
        checkpoint()
    canonical_set(tuple(s.node_id for s in seeds))
    for seed in seeds:
        if checkpoint is not None:
            checkpoint()
        graph.validate_source(ValueSource(graph.snapshot.snapshot_id, seed.node_id))
    seed_map = {s.node_id: s.labels for s in seeds}
    facts, diagnostics = {}, set()
    if graph.axes.analysis != "complete_in_scope":
        diagnostics.add("partial_input_graph")
    nodes = {n.node_id: n for n in graph.nodes}
    consumers = {nid: set() for nid in nodes}
    memory_label_sources: dict[str, set[str]] = {nid: set() for nid in nodes}
    for node in graph.nodes:
        if checkpoint is not None:
            checkpoint()
        for dep in node.inputs + tuple(p.node_id for p in node.phi_inputs):
            if checkpoint is not None:
                checkpoint()
            consumers[dep].add(node.node_id)
    for edge in graph.edges:
        if checkpoint is not None:
            checkpoint()
        if (
            edge.kind != "memory_data_dependency"
            or edge.memory_object_id is None
            or edge.memory_rule_id != "byte-reaching-store-v1"
            or edge.interval is None
            or edge.axes.precision not in {"exact", "may_alias"}
            or nodes[edge.target].kind != "Load"
        ):
            continue
        source = nodes[edge.source]
        if source.kind in {"Store", "InputMemory"}:
            # Store facts contain data-operand and direct Store seeds, not its
            # address; the memory edge carries those content labels to Load.
            label_source = edge.source
        else:
            continue
        memory_label_sources[edge.target].add(label_source)
        consumers[label_source].add(edge.target)
    pending, evaluations = set(nodes), 0
    while pending and evaluations < policy.max_evaluations:
        if checkpoint is not None:
            checkpoint()
        nid = min(pending)
        pending.remove(nid)
        node = nodes[nid]
        evaluations += 1
        deps = (
            node.inputs
            if node.kind != "Phi"
            else tuple(p.node_id for p in node.phi_inputs)
        )
        available = [facts[d] for d in deps if d in facts]
        # Internal absent fact is lattice bottom, not a published clean/Top fact.
        if deps and (
            not available or (node.kind != "Phi" and len(available) != len(deps))
        ):
            continue
        labels = seed_map.get(nid, Labels())
        label_deps, direct_only = _label_inputs(node, nodes, deps)
        for dep in (*label_deps, *sorted(memory_label_sources[nid])):
            if checkpoint is not None:
                checkpoint()
            if dep in facts:
                labels = labels.join(facts[dep].labels)
        for bypassed in direct_only:
            labels = labels.join(seed_map.get(bypassed, Labels()))
        boundary = (
            node.kind
            in {"UnknownValue", "Load", "Store", "Call", "OpaqueEffect", "InputMemory"}
            and node.operation != "nop"
        )
        if boundary:
            labels = labels.join(Labels(unknown_provenance=True))
            diagnostics.add("unresolved_boundary")
        vals = [f.value for f in available]
        if any(v is None for v in vals) and node.width_bits is not None:
            value, invalid = BitValue(node.width_bits), True
        else:
            value, invalid = _value(node, vals)
        if invalid:
            labels = labels.join(Labels(unknown_provenance=True))
            diagnostics.add("unsupported_value_semantics")
        old = facts.get(nid)
        if old:
            labels = old.labels.join(labels)
            if old.value is not None and value is not None:
                value = old.value.join(value)
        new = Fact(nid, value, labels)
        if old != new:
            facts[nid] = new
            pending.update(consumers[nid])
    unresolved = pending | (set(nodes) - set(facts))
    if unresolved:
        diagnostics.add("evaluation_budget" if pending else "unresolved_cycle")
        # All descendants of unfinished facts remain explicitly unknown, including
        # already visited consumers. Never publish a clean result past a frontier.
        frontier = set(unresolved)
        todo = list(unresolved)
        while todo:
            if checkpoint is not None:
                checkpoint()
            for consumer in consumers[todo.pop()]:
                if checkpoint is not None:
                    checkpoint()
                if consumer not in frontier:
                    frontier.add(consumer)
                    todo.append(consumer)
        for nid in frontier:
            if checkpoint is not None:
                checkpoint()
            node = nodes[nid]
            labels = facts[nid].labels if nid in facts else seed_map.get(nid, Labels())
            facts[nid] = Fact(
                nid,
                BitValue(node.width_bits) if node.width_bits else None,
                labels.join(Labels(unknown_provenance=True, any_explicit_source=True)),
            )
    else:
        frontier = set()
    return AnalysisResult(
        graph.graph_digest,
        digest([s.to_data() for s in seeds]),
        digest(policy),
        tuple(facts[k] for k in sorted(facts)),
        "partial" if diagnostics else "complete_in_scope",
        tuple(sorted(frontier)),
        tuple(sorted(diagnostics)),
        evaluations,
    )


def seeds_for_entry(program, storage, labels: Labels) -> tuple[Seed, ...]:
    """Resolve an exact entry-storage range to validated scalar atom seeds.

    A partial atom cannot be selected without a finer snapshot partition; refuse
    rather than tainting the rest of a register or inferring an ABI argument.
    """
    from .ssa import SSAProgram
    from .states import StorageLocation

    require(
        type(program) is SSAProgram
        and type(storage) is StorageLocation
        and type(labels) is Labels,
        "Invalid entry source contract",
    )
    entries = [
        e
        for e in program.entry_storage
        if (e.storage.address_space, e.storage.name)
        == (storage.address_space, storage.name)
        and storage.bit_offset <= e.storage.bit_offset
        and e.storage.bit_offset + e.storage.width_bits
        <= storage.bit_offset + storage.width_bits
    ]
    require(
        bool(entries)
        and sum(e.storage.width_bits for e in entries) == storage.width_bits,
        "Entry source must cover complete scalar atoms",
    )
    seeds = tuple(
        sorted((Seed(e.node_id, labels) for e in entries), key=lambda s: s.node_id)
    )
    for seed in seeds:
        program.graph.validate_source(
            ValueSource(program.graph.snapshot.snapshot_id, seed.node_id)
        )
    return seeds
