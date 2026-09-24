"""Conservative frontend bridge from extracted SSA memory effects to query edges."""

from dataclasses import dataclass, replace
from collections.abc import Callable, Mapping

from .contracts import (
    Edge,
    Evidence,
    Graph,
    MemoryObject,
    MemoryReference,
    ResultAxes,
    Snapshot,
    StructuredSnapshot,
)
from .memory import (
    MemoryPlan,
    MemoryPolicy,
    MemoryResult,
    MemoryAccess,
    MemoryDependency,
    PointerSeed,
    build_memory_plan,
)
from .memory_analysis import analyze_memory
from .analysis import BitSeed, Seed
from .derived_calls import (
    DerivedIndirectReturnEffect,
    DerivedMemoryWriteEffect,
    DerivedGlobalWriteEffect,
    DerivedReturnEffect,
)
from .serialization import Model, digest
from .ssa import SSAProgram, argument_bindings, build_ssa
from .states import PointerCandidate, PointerValue, StorageLocation, require


FLAT_USERSPACE_ASSUMPTION = (
    "experimental Mach-O flat user-space address model; no TLS or MMIO semantics"
)
RV32_FLAT_USERSPACE_ASSUMPTION = (
    "reviewed RV32 ELF ILP32 flat user-space address model; no TLS or MMIO semantics"
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


def memory_dependency_cause(
    dependency: MemoryDependency,
    accesses: Mapping[str, MemoryAccess],
) -> tuple[str | None, tuple[str, ...]]:
    """Explain a modeled dependency without promoting may-alias to must-alias."""
    source = accesses.get(dependency.source)
    target = accesses.get(dependency.target)
    source_objects = (
        tuple(sorted({candidate.object_id for candidate in source.candidates}))
        if source is not None
        else ()
    )
    if dependency.precision == "may_alias":
        reason = (
            "cross_object_may_alias"
            if source_objects and dependency.object_id not in source_objects
            else "unresolved_load_alias"
            if target is not None and target.unresolved
            else "weak_update_or_join"
        )
    elif dependency.precision == "opaque":
        reason = (
            "unknown_memory_effect"
            if dependency.rule_id == "unknown-memory-effect-v1"
            else "unresolved_access_or_range"
        )
    else:
        reason = None
    return reason, source_objects


def memory_access_reasons(access: MemoryAccess, facts) -> tuple[str, ...]:
    """Local cause codes only; no path-feasibility or vulnerability inference."""
    if not access.unresolved:
        return ()
    pointer = facts[access.address_node].pointer
    reasons = set()
    if pointer is None or pointer.any_compatible_location:
        reasons.add("unknown_address")
    if pointer is not None and pointer.may_be_null:
        reasons.add("possible_null_access")
    if not access.candidates:
        reasons.add("no_resolved_memory_candidate")
    if any(candidate.interval is None for candidate in access.candidates):
        reasons.add("range_widened")
    if not reasons:
        reasons.add("unresolved_access")
    return tuple(sorted(reasons))


def _signed(value, width):
    return value - (1 << width) if value >= (1 << (width - 1)) else value


def _signature_data(value):
    return (
        [_signature_data(item) for item in value] if isinstance(value, tuple) else value
    )


def _address_signature(
    nodes, identifier, typed_entries=frozenset(), active=frozenset()
):
    """Return base/offset/kind; only SDK-bound IDB arglocs are typed entries."""
    if identifier in active:
        return ("cycle", identifier), 0, "unknown"
    node = nodes[identifier]
    active = active | {identifier}
    if node.operation == "stack_address" and node.constant is not None:
        return ("stack-frame",), node.constant, "stack"
    if node.operation == "global_address" and node.constant is not None:
        return ("global", node.constant), 0, "global"
    if node.kind == "InputValue":
        return (
            ("entry", identifier),
            0,
            ("typed_entry" if identifier in typed_entries else "argument"),
        )
    if node.kind == "Copy" and len(node.inputs) == 1:
        return _address_signature(nodes, node.inputs[0], typed_entries, active)
    if (
        node.kind == "Unary"
        and len(node.inputs) == 1
        and node.width_bits == nodes[node.inputs[0]].width_bits
        and node.operation in {"trunc", "zext", "sext", "extract:0"}
    ):
        return _address_signature(nodes, node.inputs[0], typed_entries, active)
    if node.operation == "concat_low" and node.inputs:
        children = tuple(
            _address_signature(nodes, child, typed_entries, active)
            for child in node.inputs
        )
        if all(child[2] == "typed_entry" for child in children):
            kind = "typed_entry"
        elif all(child[2] == "argument" for child in children):
            kind = "argument"
        else:
            kind = "unknown"
        return ("entry-expression", children), 0, kind
    if node.kind == "Binary" and node.operation in {"add", "sub"}:
        left, right = (nodes[value] for value in node.inputs)
        if right.kind == "Constant" and right.constant is not None:
            base, offset, kind = _address_signature(
                nodes, node.inputs[0], typed_entries, active
            )
            delta = _signed(right.constant, right.width_bits)
            return base, offset + (delta if node.operation == "add" else -delta), kind
        if (
            node.operation == "add"
            and left.kind == "Constant"
            and left.constant is not None
        ):
            base, offset, kind = _address_signature(
                nodes, node.inputs[1], typed_entries, active
            )
            return base, offset + _signed(left.constant, left.width_bits), kind
    if node.kind == "Constant" and node.constant is not None:
        return ("literal-address", node.constant), 0, "unknown"
    return ("expression", identifier), 0, "unknown"


def _objects_and_pointers(plan):
    graph = plan.program.graph
    nodes = {node.node_id: node for node in graph.nodes}
    typed_entries = set()
    entry = graph.snapshot.function.entry_block
    for instruction in graph.snapshot.function.blocks[entry].instructions:
        if (
            instruction.opcode != "m_arg"
            or len(instruction.operands) != 2
            or instruction.operands[1].native_kind != "typed_pointer_argument_argloc"
        ):
            continue
        storage = instruction.operands[1].storage
        if storage is None:
            continue
        atoms = [
            atom
            for atom in plan.program.entry_storage
            if (atom.storage.address_space, atom.storage.name)
            == (storage.address_space, storage.name)
            and storage.bit_offset <= atom.storage.bit_offset
            and atom.storage.bit_offset + atom.storage.width_bits
            <= storage.bit_offset + storage.width_bits
        ]
        require(
            bool(atoms)
            and sum(atom.storage.width_bits for atom in atoms) == storage.width_bits,
            "Typed entry pointer lacks exact source atoms",
        )
        typed_entries.update(atom.node_id for atom in atoms)
    typed_entries = frozenset(typed_entries)
    accesses = [
        node
        for node in graph.nodes
        if node.kind in {"Load", "Store"} and node.memory_operands is not None
    ]
    specs = []
    extents = {}
    for node in accesses:
        address = nodes[node.memory_operands.address]
        base, offset, kind = _address_signature(nodes, address.node_id, typed_entries)
        key = f"auto-{kind}:" + digest(_signature_data(base))
        specs.append((address, key, offset, kind))
        if kind in {"stack", "global"} and offset >= 0:
            extents[key] = max(extents.get(key, 0), offset + node.width_bits // 8)
    # An address-of root may be used only through a later symbolic offset.
    # Register it as a pointer origin without inventing an access width or
    # seeding the unresolved final expression as a concrete pointer.
    roots = []
    for node in graph.nodes:
        if node.kind != "Constant" or node.operation not in {
            "stack_address",
            "global_address",
        }:
            continue
        base, offset, kind = _address_signature(nodes, node.node_id, typed_entries)
        key = f"auto-{kind}:" + digest(_signature_data(base))
        roots.append((node, key, offset, kind))
    objects = {}
    for _, key, _, kind in (*specs, *roots):
        if key in objects:
            continue
        singleton = kind in {"stack", "global", "argument", "typed_entry"}
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
    for address, key, offset, kind in (*specs, *roots):
        if kind not in {"stack", "global", "argument", "typed_entry"}:
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


def _whole_width_origin(nodes, identifier):
    seen = set()
    while identifier not in seen:
        seen.add(identifier)
        node = nodes[identifier]
        if node.kind != "Copy" or len(node.inputs) != 1:
            return node
        source = nodes[node.inputs[0]]
        if source.width_bits != node.width_bits:
            return node
        identifier = source.node_id
    return nodes[identifier]


def _spilled_entry_pointer_origin(program, nodes, identifier, bitness):
    """Reassemble only exact contiguous atoms of one IDB-mapped pointer arg."""
    root = _whole_width_origin(nodes, identifier)
    if root.width_bits != bitness:
        return None
    entries = {item.node_id: item.storage for item in program.entry_storage}

    def fragments(node_id, active=frozenset()):
        if node_id in active:
            return None
        node = _whole_width_origin(nodes, node_id)
        if node.kind == "InputValue" and node.node_id in entries:
            return (node.node_id,)
        if (
            node.kind == "Binary"
            and node.operation == "concat_low"
            and len(node.inputs) == 2
            and node.width_bits is not None
            and all(nodes[item].width_bits is not None for item in node.inputs)
            and sum(nodes[item].width_bits for item in node.inputs) == node.width_bits
        ):
            lower = fragments(node.inputs[0], active | {node_id})
            upper = fragments(node.inputs[1], active | {node_id})
            if lower and upper:
                return (*lower, *upper)
        return None

    parts = fragments(root.node_id)
    if not parts or len(set(parts)) != len(parts):
        return None
    locations = [entries[item] for item in parts]
    start = locations[0].bit_offset
    end = start
    for location in locations:
        if (
            location.address_space != locations[0].address_space
            or location.name != locations[0].name
            or location.bit_offset != end
        ):
            return None
        end += location.width_bits
    if end - start != bitness:
        return None
    full = StorageLocation(
        locations[0].address_space, locations[0].name, start, bitness
    )
    bindings = [
        row
        for row in argument_bindings(program)
        if row["idb_pointer_type_assumption"] is True
        if StorageLocation.from_data(row["storage"]) == full
        and set(row["entry_node_ids"]) == set(parts)
    ]
    if len(bindings) > 1 or len(parts) > 1 and len(bindings) != 1:
        return None
    kind = "typed_entry" if bindings else "argument"
    typed = frozenset(parts) if bindings else frozenset()
    base, offset, signature_kind = _address_signature(nodes, root.node_id, typed)
    if offset != 0 or signature_kind != kind:
        return None
    return root.node_id, kind, base


def _recover_spilled_entry_pointers(plan, result, objects, pointers, checkpoint=None):
    """Recover an entry pointer only through one exact full-byte stack spill.

    A may-alias writer, partial overwrite, width change, or unknown load leaves
    the dereference unresolved. This proves provenance of the pointer *value*,
    not disjointness between its pointee and the current stack frame.
    """
    nodes = {node.node_id: node for node in plan.program.graph.nodes}
    accesses = {access.node_id: access for access in result.accesses}
    definitions = {item.node_id: item for item in plan.program.definitions}
    dominators = {
        item.block: set(item.dominators) for item in plan.program.dominance.blocks
    }
    dependencies = {}
    for dependency in result.dependencies:
        dependencies.setdefault(dependency.target, []).append(dependency)
    evidence_objects = {obj.object_id: obj for obj in objects}
    by_object = evidence_objects.copy()
    by_seed = {seed.node_id: seed for seed in pointers}
    bitness = plan.program.graph.snapshot.identity.environment.bitness
    recovered = 0
    for dereference in result.accesses:
        if checkpoint is not None:
            checkpoint()
        node = nodes[dereference.node_id]
        if node.memory_operands is None:
            continue
        carrier = _whole_width_origin(nodes, node.memory_operands.address)
        if carrier.kind != "Load" or carrier.width_bits != bitness:
            continue
        spill_load = accesses.get(carrier.node_id)
        if (
            spill_load is None
            or spill_load.unresolved
            or len(spill_load.candidates) != 1
            or spill_load.candidates[0].interval is None
        ):
            continue
        candidate = spill_load.candidates[0]
        # The confirmation pass analyzes recovered objects but must prove a
        # spill against only the original objects, not one it just inferred.
        evidence_object = evidence_objects.get(candidate.object_id)
        if evidence_object is None or evidence_object.kind != "stack":
            continue
        interval = candidate.interval
        reaching = dependencies.get(carrier.node_id, [])
        if (
            not reaching
            or any(
                item.precision != "exact"
                or item.rule_id != "byte-reaching-store-v1"
                or item.object_id != candidate.object_id
                or item.interval is None
                for item in reaching
            )
            or len({item.source for item in reaching}) != 1
            or {
                byte
                for item in reaching
                for byte in range(item.interval.start, item.interval.end)
            }
            != set(range(interval.start, interval.end))
        ):
            continue
        writer_id = reaching[0].source
        writer = nodes[writer_id]
        writer_access = accesses.get(writer_id)
        writer_definition = definitions[writer_id]
        load_definition = definitions[carrier.node_id]
        if writer_definition.block not in dominators.get(load_definition.block, ()):
            continue
        if (
            writer_definition.block == load_definition.block
            and writer_definition.order >= load_definition.order
        ):
            continue
        if (
            writer.kind != "Store"
            or writer.memory_operands is None
            or writer.memory_operands.data is None
            or writer_access is None
            or not writer_access.strong_update
            or len(writer_access.candidates) != 1
            or writer_access.candidates[0] != candidate
        ):
            continue
        origin = _spilled_entry_pointer_origin(
            plan.program, nodes, writer.memory_operands.data, bitness
        )
        if origin is None:
            continue
        root_id, kind, base = origin
        if root_id in by_seed:
            continue
        recovered += 1
        if recovered > 32:
            # No arbitrary prefix of entries receives stronger semantics.
            return objects, pointers
        key = f"auto-{kind}:" + digest(_signature_data(base))
        obj = MemoryObject(
            plan.program.graph.snapshot.snapshot_id,
            key,
            plan.program.graph.snapshot.identity.environment.address_space,
            None,
            kind,
            True,
            "one canonical entry-pointee abstraction reached through exact full-width stack spill",
            False,
            None,
        )
        by_object[obj.object_id] = obj
        by_seed[root_id] = PointerSeed(
            root_id,
            PointerValue(
                obj.address_space,
                bitness,
                (PointerCandidate(obj.object_id, 0),),
            ),
        )
    return (
        tuple(sorted(by_object.values(), key=lambda obj: obj.object_id)),
        tuple(by_seed[node_id] for node_id in sorted(by_seed)),
    )


def _analyze_plan(plan, policy, *, value_seeds=(), bit_seeds=(), checkpoint=None):
    objects, pointers = _objects_and_pointers(plan)
    provisional = analyze_memory(
        plan, objects, pointers, policy=policy, checkpoint=checkpoint
    )
    recovered_objects, recovered_pointers = _recover_spilled_entry_pointers(
        plan, provisional, objects, pointers, checkpoint
    )
    if (
        not value_seeds
        and not bit_seeds
        and recovered_objects == objects
        and recovered_pointers == pointers
    ):
        return objects, pointers, provisional
    result = analyze_memory(
        plan,
        recovered_objects,
        recovered_pointers,
        value_seeds=value_seeds,
        bit_seeds=bit_seeds,
        policy=policy,
        checkpoint=checkpoint,
    )
    if recovered_objects != objects or recovered_pointers != pointers:
        confirmed_objects, confirmed_pointers = _recover_spilled_entry_pointers(
            plan, result, objects, pointers, checkpoint
        )
        if (
            confirmed_objects != recovered_objects
            or confirmed_pointers != recovered_pointers
        ):
            # A new alias relation invalidated the provisional spill proof.
            # Keep the original conservative graph rather than a circular
            # self-justifying pointer identity.
            if not value_seeds and not bit_seeds:
                return objects, pointers, provisional
            return (
                objects,
                pointers,
                analyze_memory(
                    plan,
                    objects,
                    pointers,
                    value_seeds=value_seeds,
                    bit_seeds=bit_seeds,
                    policy=policy,
                    checkpoint=checkpoint,
                ),
            )
    return recovered_objects, recovered_pointers, result


def build_memory_graph(
    snapshot: Snapshot | StructuredSnapshot,
    *,
    derived_returns: tuple[DerivedReturnEffect, ...] = (),
    derived_indirect_returns: tuple[DerivedIndirectReturnEffect, ...] = (),
    derived_memory_writes: tuple[
        DerivedMemoryWriteEffect | DerivedGlobalWriteEffect, ...
    ] = (),
    checkpoint: Callable[[], None] | None = None,
) -> MemoryGraphAnalysis:
    """Build an alias-aware graph; relation precision is separate from completion."""
    flat_assumption = (
        RV32_FLAT_USERSPACE_ASSUMPTION
        if type(snapshot) is StructuredSnapshot
        else FLAT_USERSPACE_ASSUMPTION
    )
    base_program = build_ssa(
        snapshot,
        storage_model="memory",
        derived_returns=derived_returns,
        derived_indirect_returns=derived_indirect_returns,
        derived_memory_writes=derived_memory_writes,
    )
    plan = build_memory_plan(base_program)
    objects, pointers, result = _analyze_plan(
        plan, MemoryPolicy(flat_segment_assumption=flat_assumption),
        checkpoint=checkpoint,
    )
    accesses = {access.node_id: access for access in result.accesses}
    steps = {step.node_id: step for step in plan.steps}
    object_by_id = {obj.object_id: obj for obj in result.objects}
    nodes = []
    for node in base_program.graph.nodes:
        access = accesses.get(node.node_id)
        if access is not None and len(access.candidates) == 1:
            candidate = access.candidates[0]
            if candidate.interval is not None:
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
        object_kind = object_by_id[dependency.object_id].kind
        derivation = Evidence(
            snapshot.snapshot_id,
            dependency.rule_id,
            synthetic=True,
            origins=tuple(sorted((dependency.source, dependency.target))),
            assumptions=tuple(
                sorted(
                    (
                        flat_assumption,
                        "current IDB type register argloc is an analyst assumption"
                        if object_kind == "typed_entry"
                        else "automatic object identity is structural and conservative; no ABI argument numbering",
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


def analyze_seeded_memory(
    bundle: MemoryGraphAnalysis,
    value_seeds: tuple[Seed, ...],
    *,
    bit_seeds: tuple[BitSeed, ...] = (),
    checkpoint=None,
) -> MemoryResult:
    """Replay the owned plan with labels; never reuse unseeded byte contents.

    A label-only seed must not alter the immutable memory dependency graph. If
    it does, fail closed rather than publishing a result for stale graph edges.
    """
    snapshot = bundle.graph.snapshot
    assumption = (
        RV32_FLAT_USERSPACE_ASSUMPTION
        if type(snapshot) is StructuredSnapshot
        else FLAT_USERSPACE_ASSUMPTION
    )
    _, _, result = _analyze_plan(
        bundle.plan,
        MemoryPolicy(flat_segment_assumption=assumption),
        value_seeds=value_seeds,
        bit_seeds=bit_seeds,
        checkpoint=checkpoint,
    )
    require(result.plan_digest == bundle.result.plan_digest, "Seeded memory plan drift")
    require(result.objects == bundle.result.objects, "Seeded memory object drift")
    require(
        result.dependencies == bundle.result.dependencies,
        "Seeded memory dependency drift",
    )
    return result


def replay_memory_graph(program: SSAProgram) -> MemoryGraphAnalysis:
    """Recompute an owned graph's memory certificate without relifting native IR."""
    snapshot = program.graph.snapshot
    plan = build_memory_plan(program)
    assumption = (
        RV32_FLAT_USERSPACE_ASSUMPTION
        if type(snapshot) is StructuredSnapshot
        else FLAT_USERSPACE_ASSUMPTION
    )
    _, _, result = _analyze_plan(plan, MemoryPolicy(flat_segment_assumption=assumption))
    return bind_memory_graph(program, plan, result)


def bind_memory_graph(
    program: SSAProgram, plan: MemoryPlan, result: MemoryResult
) -> MemoryGraphAnalysis:
    """Validate stored plan/result relation against one immutable SSA graph."""
    require(plan == build_memory_plan(program), "Stored memory plan replay mismatch")

    def relation(source, target, object_id, interval, precision, rule_id):
        return (
            source,
            target,
            object_id,
            None if interval is None else (interval.start, interval.end),
            precision,
            rule_id,
        )

    observed = {
        relation(
            edge.source,
            edge.target,
            edge.memory_object_id,
            edge.interval,
            edge.axes.precision,
            edge.memory_rule_id,
        )
        for edge in program.graph.edges
        if edge.kind == "memory_data_dependency"
        and edge.memory_object_id is not None
        and edge.memory_rule_id is not None
    }
    rebuilt = {
        relation(
            item.source,
            item.target,
            item.object_id,
            item.interval,
            item.precision,
            item.rule_id,
        )
        for item in result.dependencies
    }
    require(observed == rebuilt, "Stored memory dependency replay mismatch")
    require(
        result.status == program.graph.axes.analysis,
        "Stored memory completion replay mismatch",
    )
    require(
        all(item in program.graph.objects for item in result.objects),
        "Stored memory object replay mismatch",
    )
    return MemoryGraphAnalysis(program, plan, result, program.graph)


__all__ = [
    "FLAT_USERSPACE_ASSUMPTION",
    "RV32_FLAT_USERSPACE_ASSUMPTION",
    "MemoryGraphAnalysis",
    "analyze_seeded_memory",
    "bind_memory_graph",
    "replay_memory_graph",
    "build_memory_graph",
]
