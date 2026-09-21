"""Seeded explicit scalar provenance/value fixed point, separate from graph identity."""

from dataclasses import dataclass
from typing import Literal

from .contracts import Graph, ValueSource
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
class ScalarPolicy(Model):
    max_evaluations: int = 100000
    schema_version: Literal[1] = 1
    mode: Literal["explicit"] = "explicit"
    ruleset: Literal["scalar-transfer-v2"] = "scalar-transfer-v2"

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


def analyze(
    graph: Graph, seeds: tuple[Seed, ...] = (), policy: ScalarPolicy = ScalarPolicy()
) -> AnalysisResult:
    canonical_set(tuple(s.node_id for s in seeds))
    for seed in seeds:
        graph.validate_source(ValueSource(graph.snapshot.snapshot_id, seed.node_id))
    seed_map = {s.node_id: s.labels for s in seeds}
    facts, diagnostics = {}, set()
    if graph.axes.analysis != "complete_in_scope":
        diagnostics.add("partial_input_graph")
    nodes = {n.node_id: n for n in graph.nodes}
    consumers = {nid: set() for nid in nodes}
    for node in graph.nodes:
        for dep in node.inputs + tuple(p.node_id for p in node.phi_inputs):
            consumers[dep].add(node.node_id)
    pending, evaluations = set(nodes), 0
    while pending and evaluations < policy.max_evaluations:
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
        label_deps = deps[1:] if node.kind == "Select" else deps
        for dep in label_deps:
            if dep in facts:
                labels = labels.join(facts[dep].labels)
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
            for consumer in consumers[todo.pop()]:
                if consumer not in frontier:
                    frontier.add(consumer)
                    todo.append(consumer)
        for nid in frontier:
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
