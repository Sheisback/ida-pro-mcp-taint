"""Bounded, unreviewed static call-return evidence; never a reviewed summary."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from .contracts import CallInfo, Snapshot
from .serialization import Model, digest
from .states import (
    Labels,
    StorageLocation,
    canonical_set,
    check_digest,
    check_id,
    require,
)

if TYPE_CHECKING:
    from .ssa import SSAProgram


def proves_no_memory_effects(program: "SSAProgram") -> bool:
    """Conservative whole-callee scan; the caller must also check completion."""
    return not any(
        node.kind
        in {
            "Load",
            "Store",
            "Call",
            "CallResult",
            "Allocation",
            "Free",
            "InputMemory",
            "UnknownValue",
        }
        or node.kind == "OpaqueEffect"
        and node.operation != "nop"
        for node in program.graph.nodes
    )


@dataclass(frozen=True)
class DerivedReturnEffect(Model):
    caller_snapshot_id: str
    callee_snapshot_id: str
    callee_ea: int
    block: int
    instruction: int
    return_storage: StorageLocation
    argument_indices: tuple[int, ...]
    proof_digest: str
    memory_effects: Literal["unknown", "none"] = "unknown"
    provenance: Literal["derived_static"] = "derived_static"
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        check_id(self.caller_snapshot_id, "snapshot")
        check_id(self.callee_snapshot_id, "snapshot")
        check_digest(self.proof_digest)
        require(
            self.callee_ea >= 0 and self.block >= 0 and self.instruction >= 0,
            "Invalid derived call site",
        )
        require(
            self.return_storage.address_space == "microregister"
            and self.return_storage.name == "microregister"
            and self.return_storage.bit_offset % 8 == 0
            and 0 < self.return_storage.width_bits <= 64
            and self.return_storage.width_bits % 8 == 0,
            "Derived return requires a bounded whole-byte microregister",
        )
        canonical_set(self.argument_indices)
        require(
            all(index >= 0 for index in self.argument_indices),
            "Negative derived argument index",
        )

    @property
    def sort_key(self) -> tuple[int, int]:
        return self.block, self.instruction


@dataclass(frozen=True)
class DerivedArgumentSlice(Model):
    argument_index: int
    bit_offset: int
    width_bits: int

    def __post_init__(self):
        super().__post_init__()
        require(
            self.argument_index >= 0
            and self.bit_offset >= 0
            and 0 < self.width_bits <= 64
            and self.bit_offset % 8 == 0
            and self.width_bits % 8 == 0,
            "Invalid derived argument bit window",
        )

    @property
    def sort_key(self) -> tuple[int, int, int]:
        return self.argument_index, self.bit_offset, self.width_bits


@dataclass(frozen=True)
class DerivedIndirectReturnEffect(Model):
    """Joined scalar return of every proven target, never a reviewed summary."""

    caller_snapshot_id: str
    block: int
    instruction: int
    target_proof_digest: str
    target_eas: tuple[int, ...]
    callee_snapshot_ids: tuple[str, ...]
    return_storage: StorageLocation
    argument_indices: tuple[int, ...]
    argument_slices: tuple[DerivedArgumentSlice, ...]
    proof_digest: str
    memory_effects: Literal["unknown", "none"] = "unknown"
    provenance: Literal["derived_static_finite_indirect"] = (
        "derived_static_finite_indirect"
    )
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        check_id(self.caller_snapshot_id, "snapshot")
        check_digest(self.target_proof_digest)
        check_digest(self.proof_digest)
        require(self.block >= 0 and self.instruction >= 0, "Invalid indirect site")
        require(
            0 < len(self.target_eas) <= 8
            and self.target_eas == tuple(sorted(set(self.target_eas)))
            and all(ea >= 0 for ea in self.target_eas)
            and len(self.callee_snapshot_ids) == len(self.target_eas),
            "Invalid finite callee set",
        )
        for snapshot_id in self.callee_snapshot_ids:
            check_id(snapshot_id, "snapshot")
        canonical_set(self.argument_indices)
        require(
            all(index >= 0 for index in self.argument_indices),
            "Invalid indirect argument index",
        )
        require(
            tuple(item.sort_key for item in self.argument_slices)
            == tuple(sorted(set(item.sort_key for item in self.argument_slices)))
            and self.argument_indices
            == tuple(sorted({item.argument_index for item in self.argument_slices})),
            "Invalid indirect argument windows",
        )
        require(
            self.return_storage.address_space == "microregister"
            and self.return_storage.name == "microregister"
            and self.return_storage.bit_offset % 8 == 0
            and 0 < self.return_storage.width_bits <= 64
            and self.return_storage.width_bits % 8 == 0,
            "Invalid finite indirect return storage",
        )

    @property
    def sort_key(self) -> tuple[int, int]:
        return self.block, self.instruction


@dataclass(frozen=True)
class DerivedMemoryWriteEffect(Model):
    caller_snapshot_id: str
    callee_snapshot_id: str
    callee_ea: int
    block: int
    instruction: int
    pointer_argument_index: int
    value_argument_index: int
    width_bits: int
    proof_digest: str
    byte_offset: Literal[0] = 0
    provenance: Literal["derived_static"] = "derived_static"
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        check_id(self.caller_snapshot_id, "snapshot")
        check_id(self.callee_snapshot_id, "snapshot")
        check_digest(self.proof_digest)
        require(
            self.callee_ea >= 0
            and self.block >= 0
            and self.instruction >= 0
            and self.pointer_argument_index >= 0
            and self.value_argument_index >= 0
            and self.pointer_argument_index != self.value_argument_index,
            "Invalid derived memory write site/arguments",
        )
        require(
            0 < self.width_bits <= 64 and self.width_bits % 8 == 0,
            "Derived memory write requires bounded whole-byte data",
        )

    @property
    def sort_key(self) -> tuple[int, int]:
        return self.block, self.instruction


def _direct_site_matches(caller, call, block, instruction):
    if block >= len(caller.function.blocks):
        return False
    rows = caller.function.blocks[block].instructions
    if instruction >= len(rows):
        return False
    site = rows[instruction]

    def nested(operand):
        yield operand
        for child in operand.children:
            yield from nested(child)

    operands = [part for operand in site.operands for part in nested(operand)]
    infos = [part.call for part in operands if part.call is not None]
    targets = []
    if site.opcode == "m_call" and site.operands:
        targets.append(site.operands[0])
    elif site.opcode == "m_mov":
        targets.extend(
            part.children[0]
            for part in operands
            if part.kind == "expression"
            and part.operation == "m_call"
            and part.children
        )
    return (
        len(targets) == 1
        and targets[0].kind == "global"
        and targets[0].address == call.callee_ea
        and infos == [call]
    )


def _same_analysis_scope(caller, callee):
    a, b = caller.identity, callee.identity
    return (
        a.binary_digest == b.binary_digest
        and a.profile_digest == b.profile_digest
        and a.rule_digest == b.rule_digest
        and a.policy_digest == b.policy_digest
        and a.environment == b.environment
        and a.summary_digest == b.summary_digest
    )


def _copy_origin(nodes, identifier):
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


@dataclass(frozen=True)
class FiniteIndirectTargets(Model):
    """Candidate addresses from one complete-or-explicitly-partial SSA slice."""

    caller_snapshot_id: str
    graph_digest: str
    block: int
    instruction: int
    target_node_id: str
    targets: tuple[int, ...]
    complete: bool
    reasons: tuple[str, ...]
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        check_id(self.caller_snapshot_id, "snapshot")
        check_digest(self.graph_digest)
        check_id(self.target_node_id, "node")
        require(self.block >= 0 and self.instruction >= 0, "Invalid indirect call site")
        require(
            self.targets == tuple(sorted(set(self.targets)))
            and len(self.targets) <= 8
            and all(target >= 0 for target in self.targets),
            "Invalid finite target candidates",
        )
        canonical_set(self.reasons)
        require(
            self.complete == (bool(self.targets) and not self.reasons),
            "Incomplete target set requires a named remainder",
        )

    @property
    def proof_digest(self) -> str:
        return digest({"rule": "ssa-finite-indirect-targets-v1", **self.to_data()})


def resolve_finite_indirect_targets(
    program: "SSAProgram",
    block: int,
    instruction: int,
    *,
    max_candidates: int = 8,
    max_nodes: int = 128,
) -> FiniteIndirectTargets | None:
    """Prove only address-of/Copy/Phi/Select target sets at one ``m_icall``.

    Unknown input, arithmetic, cycles, and either budget leave an explicit
    remainder. An address candidate is *not* proof of a local executable
    function; the IDA adapter must verify every exact entry separately.
    """
    require(
        type(max_candidates) is int
        and 0 < max_candidates <= 8
        and type(max_nodes) is int
        and 0 < max_nodes <= 512,
        "Invalid finite indirect target budget",
    )
    snapshot = program.graph.snapshot
    if block < 0 or block >= len(snapshot.function.blocks):
        return None
    rows = snapshot.function.blocks[block].instructions
    if instruction < 0 or instruction >= len(rows):
        return None
    site = rows[instruction]
    if site.opcode == "m_icall":
        calls = [site.operands]
    elif site.opcode in {"m_mov", "m_xdu", "m_xds", "m_low", "m_high"}:
        calls = [
            operand.children
            for operand in site.operands
            if operand.kind == "expression" and operand.operation == "m_icall"
        ]
    else:
        return None
    if len(calls) != 1:
        return None
    operands = calls[0]
    if (
        len(operands) != 3
        or tuple(part.role for part in operands) != ("left", "right", "destination")
        or operands[0].kind != "storage"
        or operands[1].kind != "storage"
        or operands[1].width_bits != snapshot.identity.environment.bitness
        or operands[2].kind != "callinfo"
        or operands[2].call is None
        or operands[2].call.callee_ea is not None
    ):
        return None
    site_evidence = {
        evidence.evidence_id
        for evidence in program.graph.evidence
        if any(
            origin.block_index == block and origin.instruction_index == instruction
            for origin in evidence.sites
        )
    }
    nodes = {node.node_id: node for node in program.graph.nodes}
    calls_at_site = [
        node
        for node in nodes.values()
        if node.kind == "Call"
        and set(node.evidence_ids) & site_evidence
        and len(node.inputs) == 3
        and nodes[node.inputs[0]].width_bits == operands[0].width_bits
        and nodes[node.inputs[1]].width_bits == operands[1].width_bits
        and nodes[node.inputs[2]].operation == "unmodeled_callinfo"
    ]
    if len(calls_at_site) != 1:
        return None
    target_node_id = calls_at_site[0].inputs[1]
    visited = 0
    memo: dict[str, tuple[set[int], set[str]]] = {}

    def walk(identifier: str, active: frozenset[str]) -> tuple[set[int], set[str]]:
        nonlocal visited
        if identifier in active:
            return set(), {"cyclic_target_value"}
        if identifier in memo:
            return memo[identifier]
        if visited >= max_nodes:
            return set(), {"node_budget"}
        visited += 1
        node = nodes[identifier]
        next_active = active | {identifier}
        if (
            node.kind == "Constant"
            and node.operation == "global_address"
            and node.width_bits is not None
            and node.width_bits == snapshot.identity.environment.bitness
            and node.constant is not None
            and 0 <= node.constant < 1 << node.width_bits
        ):
            result = ({node.constant}, set())
        elif (
            node.kind == "Copy"
            and len(node.inputs) == 1
            and nodes[node.inputs[0]].width_bits == node.width_bits
        ):
            result = walk(node.inputs[0], next_active)
        elif (
            node.kind == "Unary"
            and node.operation is not None
            and node.operation.startswith("extract:")
            and len(node.inputs) == 1
            and node.width_bits is not None
        ):
            source = nodes[node.inputs[0]]
            try:
                offset = int(node.operation.split(":", 1)[1])
            except ValueError:
                offset = -1
            if (
                source.width_bits is None
                or offset < 0
                or offset + node.width_bits > source.width_bits
            ):
                result = set(), {"unknown_target_fragment"}
            else:
                values, reasons = walk(node.inputs[0], next_active)
                mask = (1 << node.width_bits) - 1
                result = {value >> offset & mask for value in values}, reasons
        elif (
            node.kind == "Binary"
            and node.operation == "concat_low"
            and len(node.inputs) == 2
        ):
            low_width = nodes[node.inputs[0]].width_bits
            high_width = nodes[node.inputs[1]].width_bits
            if (
                low_width is None
                or high_width is None
                or node.width_bits != low_width + high_width
            ):
                result = set(), {"unknown_target_fragment"}
            else:
                low, low_reasons = walk(node.inputs[0], next_active)
                high, high_reasons = walk(node.inputs[1], next_active)
                result = (
                    {first | (second << low_width) for first in low for second in high},
                    low_reasons | high_reasons,
                )
        elif node.kind == "Phi" and node.phi_inputs:
            targets: set[int] = set()
            reasons: set[str] = set()
            for item in node.phi_inputs:
                found, unresolved = walk(item.node_id, next_active)
                targets.update(found)
                reasons.update(unresolved)
            result = targets, reasons
        elif node.kind == "Select" and len(node.inputs) == 3:
            targets = set()
            reasons = set()
            for child in node.inputs[1:]:
                found, unresolved = walk(child, next_active)
                targets.update(found)
                reasons.update(unresolved)
            result = targets, reasons
        else:
            result = set(), {"unknown_target_value"}
        if len(result[0]) > max_candidates:
            result = (
                set(sorted(result[0])[:max_candidates]),
                result[1] | {"candidate_budget"},
            )
        memo[identifier] = result
        return result

    targets, reasons = walk(target_node_id, frozenset())
    if not targets and not reasons:
        reasons.add("unknown_target_value")
    return FiniteIndirectTargets(
        snapshot.snapshot_id,
        program.graph.graph_digest,
        block,
        instruction,
        target_node_id,
        tuple(sorted(targets)),
        bool(targets) and not reasons,
        tuple(sorted(reasons)),
    )


def _prove_callee_return(
    callee: Snapshot,
    call: CallInfo,
    *,
    allow_bounded_narrow: bool = False,
    checkpoint: Callable[[], None] | None = None,
) -> (
    tuple[
        StorageLocation,
        tuple[int, ...],
        Literal["unknown", "none"],
        str,
        tuple[DerivedArgumentSlice, ...],
    ]
    | None
):
    """Prove a complete typed scalar return independently of its call site."""
    if checkpoint is not None:
        checkpoint()
    if (
        call.return_is_void
        or call.return_width_bits is None
        or any(len(item.successors) > 1 for item in callee.function.blocks)
    ):
        return None
    width = call.return_width_bits
    locations = call.return_locations.register_bytes
    if (
        width <= 0
        or width > 64
        or width % 8
        or len(locations) != width // 8
        or locations != tuple(range(locations[0], locations[0] + len(locations)))
    ):
        return None
    storage = StorageLocation("microregister", "microregister", locations[0] * 8, width)

    from .analysis import seeds_for_entry
    from .implicit_analysis import analyze_implicit
    from .memory_graph import build_memory_graph
    from .ssa import argument_bindings

    memory = build_memory_graph(callee, checkpoint=checkpoint)
    if memory.result.status != "complete_in_scope":
        return None
    program = memory.program
    returns = [node for node in program.graph.nodes if node.kind == "Return"]
    if len(returns) != 1 or returns[0].width_bits != width:
        return None
    bindings = argument_bindings(program)
    if tuple(sorted(item["argument_index"] for item in bindings)) != tuple(
        range(len(call.arguments))
    ):
        return None
    seeds = []
    allowed_inputs = set()
    windows = {}
    for item in bindings:
        index = item["argument_index"]
        location = StorageLocation.from_data(item["storage"])
        actual = call.arguments[index]
        if actual.width_bits == location.width_bits:
            bit_offset = 0
        elif allow_bounded_narrow:
            carrier = actual.storage
            if (
                actual.kind != "storage"
                or carrier is None
                or carrier.address_space != "microregister"
                or carrier.name != "microregister"
                or location.address_space != carrier.address_space
                or location.name != carrier.name
                or location.bit_offset < carrier.bit_offset
                or location.bit_offset + location.width_bits
                > carrier.bit_offset + carrier.width_bits
            ):
                return None
            bit_offset = location.bit_offset - carrier.bit_offset
        else:
            return None
        windows[index] = DerivedArgumentSlice(index, bit_offset, location.width_bits)
        label = Labels((f"derived-arg:{index}",))
        selected = seeds_for_entry(program, location, label)
        seeds.extend(selected)
        allowed_inputs.update(seed.node_id for seed in selected)
    seeds = tuple(sorted(seeds, key=lambda seed: seed.node_id))
    # An untyped entry value affecting the return would be an omitted source.
    nodes = {node.node_id: node for node in program.graph.nodes}
    memory_sources = {
        edge.target: set()
        for edge in program.graph.edges
        if edge.kind == "memory_data_dependency"
    }
    for edge in program.graph.edges:
        if edge.kind == "memory_data_dependency":
            memory_sources[edge.target].add(edge.source)
    pending = [returns[0].node_id]
    seen = set()
    while pending:
        if checkpoint is not None:
            checkpoint()
        node_id = pending.pop()
        if node_id in seen:
            continue
        seen.add(node_id)
        node = nodes[node_id]
        if node.kind == "InputValue" and node_id not in allowed_inputs:
            return None
        if node.kind in {"UnknownValue", "Call", "OpaqueEffect", "CallResult"}:
            return None
        pending.extend(node.inputs)
        pending.extend(item.node_id for item in node.phi_inputs)
        pending.extend(memory_sources.get(node_id, ()))
    result = analyze_implicit(
        program, seeds, memory_model=memory, checkpoint=checkpoint
    )
    fact = next(item for item in result.facts if item.node_id == returns[0].node_id)
    labels = fact.labels
    if (
        result.status != "complete_in_scope"
        or labels.unknown_provenance
        or labels.any_explicit_source
        or labels.any_control_source
        or labels.control
    ):
        return None
    indices = tuple(
        item["argument_index"]
        for item in bindings
        if f"derived-arg:{item['argument_index']}" in labels.explicit
    )
    slices = tuple(windows[index] for index in indices)
    # Prove absence of all modeled memory/effect operations in the *whole*
    # callee, not merely the Return's data ancestors. A volatile/global write
    # or an unresolved call still requires conservative caller memory havoc.
    memory_effects = "none" if proves_no_memory_effects(program) else "unknown"
    proof_body = {
        "callee_snapshot": callee.snapshot_id,
        "graph": memory.graph.graph_digest,
        "return_node": returns[0].node_id,
        "implicit_result": result.to_data(),
        "bindings": bindings,
        "memory_effects": memory_effects,
        "provenance": "derived_static_unreviewed",
    }
    if allow_bounded_narrow:
        proof_body["argument_slices"] = [item.to_data() for item in slices]
    return (
        storage,
        indices,
        memory_effects,
        digest(proof_body),
        slices,
    )


def derive_direct_return(
    caller: Snapshot,
    callee: Snapshot,
    call: CallInfo,
    block: int,
    instruction: int,
    *,
    checkpoint: Callable[[], None] | None = None,
) -> DerivedReturnEffect | None:
    """Prove one direct typed return; keep unresolved caller effects separate."""
    if (
        call.callee_ea is None
        or not _direct_site_matches(caller, call, block, instruction)
        or not _same_analysis_scope(caller, callee)
    ):
        return None
    proof = _prove_callee_return(callee, call, checkpoint=checkpoint)
    if proof is None:
        return None
    storage, indices, memory_effects, proof_digest, _ = proof
    return DerivedReturnEffect(
        caller.snapshot_id,
        callee.snapshot_id,
        call.callee_ea,
        block,
        instruction,
        storage,
        indices,
        proof_digest,
        memory_effects,
    )


def derive_finite_indirect_return(
    caller: Snapshot,
    callees: Mapping[int, Snapshot],
    call: CallInfo,
    targets: FiniteIndirectTargets,
    *,
    checkpoint: Callable[[], None] | None = None,
) -> DerivedIndirectReturnEffect | None:
    """Join every exact local scalar callee or retain the unknown call boundary."""
    if (
        not targets.complete
        or targets.caller_snapshot_id != caller.snapshot_id
        or call.callee_ea is not None
        or set(callees) != set(targets.targets)
        or targets.block >= len(caller.function.blocks)
        or targets.instruction
        >= len(caller.function.blocks[targets.block].instructions)
    ):
        return None
    site = caller.function.blocks[targets.block].instructions[targets.instruction]

    def nested(operand):
        yield operand
        for child in operand.children:
            yield from nested(child)

    infos = [
        part.call
        for operand in site.operands
        for part in nested(operand)
        if part.call is not None
    ]
    if infos != [call]:
        return None
    from .ssa import build_ssa

    base = build_ssa(caller, storage_model="memory")
    if (
        resolve_finite_indirect_targets(base, targets.block, targets.instruction)
        != targets
    ):
        return None
    certificates = []
    storage = None
    indices: set[int] = set()
    slices: set[DerivedArgumentSlice] = set()
    memory_effects: Literal["unknown", "none"] = "none"
    for ea in targets.targets:
        if checkpoint is not None:
            checkpoint()
        callee = callees[ea]
        if callee.identity.function_id != "function-entry:" + str(
            ea
        ) or not _same_analysis_scope(caller, callee):
            return None
        certificate = _prove_callee_return(
            callee, call, allow_bounded_narrow=True, checkpoint=checkpoint
        )
        if certificate is None:
            return None
        (
            candidate_storage,
            candidate_indices,
            candidate_memory,
            proof_digest,
            candidate_slices,
        ) = certificate
        if storage is not None and storage != candidate_storage:
            return None
        storage = candidate_storage
        indices.update(candidate_indices)
        slices.update(candidate_slices)
        if candidate_memory != "none":
            memory_effects = "unknown"
        certificates.append(
            {
                "target_ea": ea,
                "callee_snapshot_id": callee.snapshot_id,
                "scalar_certificate": proof_digest,
                "argument_indices": list(candidate_indices),
                "argument_slices": [item.to_data() for item in candidate_slices],
                "memory_effects": candidate_memory,
            }
        )
    if storage is None:
        return None
    return DerivedIndirectReturnEffect(
        caller.snapshot_id,
        targets.block,
        targets.instruction,
        targets.proof_digest,
        targets.targets,
        tuple(callees[ea].snapshot_id for ea in targets.targets),
        storage,
        tuple(sorted(indices)),
        tuple(sorted(slices, key=lambda item: item.sort_key)),
        digest(
            {
                "rule": "derived-finite-indirect-scalar-return-v1",
                "caller_snapshot": caller.snapshot_id,
                "target_proof": targets.proof_digest,
                "certificates": certificates,
                "joined_arguments": sorted(indices),
                "joined_argument_slices": [
                    item.to_data()
                    for item in sorted(slices, key=lambda item: item.sort_key)
                ],
                "memory_effects": memory_effects,
            }
        ),
        memory_effects,
    )


def derive_direct_memory_write(
    caller: Snapshot,
    callee: Snapshot,
    call: CallInfo,
    block: int,
    instruction: int,
    *,
    checkpoint: Callable[[], None] | None = None,
) -> DerivedMemoryWriteEffect | None:
    """Prove one branch-free typed output-pointer identity write.

    All other callee stores must target its current stack. This does not model
    arbitrary arithmetic, multiple outputs, reads, calls, or untyped pointers.
    """
    if checkpoint is not None:
        checkpoint()
    if (
        call.callee_ea is None
        or len(call.arguments) < 2
        or not _direct_site_matches(caller, call, block, instruction)
        or not _same_analysis_scope(caller, callee)
        or any(len(item.successors) > 1 for item in callee.function.blocks)
    ):
        return None

    from .memory_graph import build_memory_graph
    from .ssa import argument_bindings

    memory = build_memory_graph(callee, checkpoint=checkpoint)
    if memory.result.status != "complete_in_scope":
        return None
    program = memory.program
    bindings = argument_bindings(program)
    if tuple(sorted(item["argument_index"] for item in bindings)) != tuple(
        range(len(call.arguments))
    ):
        return None
    if any(
        call.arguments[item["argument_index"]].width_bits
        != item["storage"]["width_bits"]
        or len(item["entry_node_ids"]) != 1
        for item in bindings
    ):
        return None
    nodes = {node.node_id: node for node in program.graph.nodes}
    if any(
        node.kind
        in {
            "Load",
            "Call",
            "CallResult",
            "Allocation",
            "Free",
            "InputMemory",
            "UnknownValue",
        }
        or node.kind == "OpaqueEffect"
        and node.operation != "nop"
        for node in nodes.values()
    ):
        return None
    accesses = {item.node_id: item for item in memory.result.accesses}
    objects = {item.object_id: item for item in memory.result.objects}
    external = []
    for node in nodes.values():
        if checkpoint is not None:
            checkpoint()
        if node.kind != "Store":
            continue
        access = accesses[node.node_id]
        if access.unresolved or len(access.candidates) != 1:
            return None
        candidate = access.candidates[0]
        if candidate.interval is None:
            return None
        kind = objects[candidate.object_id].kind
        if kind == "stack":
            continue
        if (
            kind != "typed_entry"
            or not access.strong_update
            or candidate.interval.start != 0
            or candidate.interval.end * 8 != node.width_bits
        ):
            return None
        external.append((node, access))
    if len(external) != 1:
        return None
    written, access = external[0]
    roles = written.memory_operands
    assert roles is not None and roles.data is not None
    data = _copy_origin(nodes, roles.data)
    address = _copy_origin(nodes, roles.address)
    if data.kind != "InputValue" or address.kind != "InputValue":
        return None
    by_entry = {item["entry_node_ids"][0]: item["argument_index"] for item in bindings}
    if data.node_id not in by_entry or address.node_id not in by_entry:
        return None
    value_index = by_entry[data.node_id]
    pointer_index = by_entry[address.node_id]
    width = written.width_bits
    if (
        pointer_index == value_index
        or width is None
        or width > 64
        or width % 8
        or data.width_bits != width
        or address.width_bits != caller.identity.environment.bitness
        or call.arguments[value_index].width_bits != width
        or call.arguments[pointer_index].width_bits
        != caller.identity.environment.bitness
    ):
        return None
    return DerivedMemoryWriteEffect(
        caller.snapshot_id,
        callee.snapshot_id,
        call.callee_ea,
        block,
        instruction,
        pointer_index,
        value_index,
        width,
        digest(
            {
                "callee_snapshot": callee.snapshot_id,
                "graph": memory.graph.graph_digest,
                "result": memory.result.to_data(),
                "store_node": written.node_id,
                "store_access": access.to_data(),
                "bindings": bindings,
                "rule": "single_typed_entry_identity_write_v1",
            }
        ),
    )


@dataclass(frozen=True)
class DerivedGlobalWriteEffect(Model):
    """One exact fixed-global write, not a purity or scalar-return certificate."""

    caller_snapshot_id: str
    callee_snapshot_id: str
    callee_ea: int
    block: int
    instruction: int
    global_address: int
    value_argument_index: int | None
    constant_value: int | None
    width_bits: int
    proof_digest: str
    value_width_bits: int | None = None
    value_argument_width_bits: int | None = None
    provenance: Literal["derived_static"] = "derived_static"
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        check_id(self.caller_snapshot_id, "snapshot")
        check_id(self.callee_snapshot_id, "snapshot")
        check_digest(self.proof_digest)
        require(
            min(self.callee_ea, self.block, self.instruction, self.global_address) >= 0
            and 0 < self.width_bits <= 64
            and self.width_bits % 8 == 0,
            "Invalid derived global write site/range",
        )
        require(
            (self.value_argument_index is None and self.value_width_bits is None)
            or (
                self.value_argument_index is not None
                and self.value_width_bits is not None
                and 0 < self.value_width_bits <= self.width_bits
                and self.value_width_bits % 8 == 0
            ),
            "Invalid derived global data width",
        )
        require(
            self.value_argument_width_bits is None
            or (
                self.value_width_bits is not None
                and self.value_width_bits < self.value_argument_width_bits <= 64
                and self.value_argument_width_bits % 8 == 0
            ),
            "Invalid derived global argument carrier width",
        )
        require(
            (self.value_argument_index is None) != (self.constant_value is None)
            and (self.value_argument_index is None or self.value_argument_index >= 0)
            and (
                self.constant_value is None
                or 0 <= self.constant_value < 1 << self.width_bits
            ),
            "Derived global write requires exactly one bounded data source",
        )

    @property
    def sort_key(self) -> tuple[int, int]:
        return self.block, self.instruction


def derive_direct_global_write(
    caller: Snapshot,
    callee: Snapshot,
    call: CallInfo,
    block: int,
    instruction: int,
    *,
    checkpoint: Callable[[], None] | None = None,
) -> DerivedGlobalWriteEffect | None:
    """Prove a straight-line same-binary single fixed-global scalar write.

    Reject external reads, calls, unknown effects, other external writes, and
    computed data. Other memory accesses must be exact current-frame stack accesses.
    This deliberately does not discharge scalar return uncertainty.
    """
    if checkpoint is not None:
        checkpoint()
    if (
        call.callee_ea is None
        or callee.identity.function_id != "function-entry:" + str(call.callee_ea)
        or not _direct_site_matches(caller, call, block, instruction)
        or not _same_analysis_scope(caller, callee)
        or caller.identity.namespace != callee.identity.namespace
    ):
        return None
    # A single acyclic chain must visit every block; no conditional/loop path
    # can skip the write or bypass normal completion.
    visited = set()
    chain = []
    current = callee.function.entry_block
    while current not in visited:
        visited.add(current)
        chain.append(current)
        successors = callee.function.blocks[current].successors
        if not successors:
            break
        if len(successors) != 1:
            return None
        current = successors[0]
    else:
        return None
    if len(visited) != len(callee.function.blocks):
        return None
    from .memory_graph import build_memory_graph
    from .ssa import argument_bindings

    memory = build_memory_graph(callee, checkpoint=checkpoint)
    if memory.result.status != "complete_in_scope":
        return None
    program = memory.program
    nodes = {node.node_id: node for node in program.graph.nodes}
    if any(
        node.kind
        in {
            "Call",
            "CallResult",
            "Allocation",
            "Free",
            "InputMemory",
            "UnknownValue",
        }
        or node.kind == "OpaqueEffect"
        and node.operation != "nop"
        for node in nodes.values()
    ):
        return None
    accesses = {item.node_id: item for item in memory.result.accesses}
    objects = {item.object_id: item for item in memory.result.objects}
    stores = []
    for node in nodes.values():
        if checkpoint is not None:
            checkpoint()
        if node.kind not in {"Load", "Store"}:
            continue
        access = accesses[node.node_id]
        if access.unresolved or len(access.candidates) != 1:
            return None
        candidate = access.candidates[0]
        if (
            candidate.interval is None
            or access.alias != "must_alias"
            or access.precision != "exact"
            or node.kind == "Store"
            and not access.strong_update
        ):
            return None
        if objects[candidate.object_id].kind == "stack":
            continue
        if node.kind == "Load":
            return None
        stores.append(node)
    exits = [node for node in nodes.values() if node.kind in {"Return", "Exit"}]
    if len(stores) != 1 or len(exits) != 1:
        return None
    definitions = {item.node_id: item for item in program.definitions}
    terminal = definitions[exits[0].node_id]
    if terminal.block != chain[-1]:
        return None
    if any(
        definitions[node.node_id].block == terminal.block
        and definitions[node.node_id].order >= terminal.order
        for node in nodes.values()
        if node.kind == "Store"
    ):
        return None
    store = stores[0]
    width = store.width_bits
    if width is None or width > 64 or width % 8:
        return None
    roles = store.memory_operands
    if roles is None or roles.data is None:
        return None
    address = _copy_origin(nodes, roles.address)
    data = _copy_origin(nodes, roles.data)
    if (
        address.kind != "Constant"
        or address.operation != "global_address"
        or address.constant is None
        or address.constant < 0
        or address.constant + width // 8 > 1 << caller.identity.environment.bitness
        or data.width_bits != width
    ):
        return None
    access = next(
        item for item in memory.result.accesses if item.node_id == store.node_id
    )
    if access.unresolved or not access.strong_update or len(access.candidates) != 1:
        return None
    objects = {item.object_id: item for item in memory.result.objects}
    if objects[access.candidates[0].object_id].kind != "global":
        return None
    bindings = argument_bindings(program)
    if tuple(sorted(item["argument_index"] for item in bindings)) != tuple(
        range(len(call.arguments))
    ):
        return None
    if any(
        call.arguments[item["argument_index"]].width_bits
        != item["storage"]["width_bits"]
        for item in bindings
    ):
        return None
    by_entry = {
        entry: item["argument_index"]
        for item in bindings
        for entry in item["entry_node_ids"]
    }
    if data.kind == "Unary" and data.operation == "zext" and len(data.inputs) == 1:
        source = _copy_origin(nodes, data.inputs[0])
        if (
            source.width_bits is None
            or not 0 < source.width_bits < width
            or source.width_bits % 8
        ):
            return None
        data = source
    if data.kind == "Load":
        # Recover only one full-width current-frame spill, using the memory
        # engine's reaching-store proof rather than guessing from addresses.
        load_access = accesses[data.node_id]
        candidate = load_access.candidates[0]
        interval = candidate.interval
        reaching = tuple(
            item for item in memory.result.dependencies if item.target == data.node_id
        )
        if (
            interval is None
            or objects[candidate.object_id].kind != "stack"
            or not reaching
            or any(
                item.precision != "exact"
                or item.rule_id != "byte-reaching-store-v1"
                or item.object_id != candidate.object_id
                or item.interval is None
                for item in reaching
            )
            or len({item.source for item in reaching}) != 1
        ):
            return None
        covered = [
            byte
            for item in reaching
            if item.interval is not None
            for byte in range(item.interval.start, item.interval.end)
        ]
        if sorted(covered) != list(range(interval.start, interval.end)):
            return None
        writer = nodes[reaching[0].source]
        writer_access = accesses.get(writer.node_id)
        writer_definition = definitions[writer.node_id]
        load_definition = definitions[data.node_id]
        dominators = next(
            item.dominators
            for item in program.dominance.blocks
            if item.block == load_definition.block
        )
        if (
            writer.kind != "Store"
            or writer.width_bits != data.width_bits
            or writer.memory_operands is None
            or writer.memory_operands.data is None
            or writer_access is None
            or not writer_access.strong_update
            or writer_access.candidates != (candidate,)
            or writer_definition.block not in dominators
            or (
                writer_definition.block == load_definition.block
                and writer_definition.order >= load_definition.order
            )
        ):
            return None
        # Deliberately stop after one spill: Copy(InputValue/Constant) is handled
        # below; another Load or a computed expression is not accepted.
        data = _copy_origin(nodes, writer.memory_operands.data)
        if data.width_bits != writer.width_bits:
            return None
    index = by_entry.get(data.node_id) if data.kind == "InputValue" else None
    carrier_width = None
    if index is not None:
        binding = next(item for item in bindings if item["argument_index"] == index)
        location = StorageLocation.from_data(binding["storage"])
        atom = next(
            item.storage
            for item in program.entry_storage
            if item.node_id == data.node_id
        )
        if atom != location:
            actual = call.arguments[index]
            children = tuple(child for child in actual.children if child.kind != "void")
            # CallInfo argument position binds values, not caller/callee storage
            # identities. A caller spill is valid when its exact-width value is
            # zero-extended into the formal carrier; SSA uses the actual argument.
            if (
                atom.address_space != "microregister"
                or atom.name != "microregister"
                or atom.address_space != location.address_space
                or atom.name != location.name
                or atom.bit_offset != location.bit_offset
                or not 0 < atom.width_bits < location.width_bits <= 64
                or atom.width_bits % 8
                or not (
                    actual.kind == "storage"
                    and actual.storage == location
                    or actual.kind == "expression"
                    and actual.operation == "m_xdu"
                    and len(children) == 1
                    and children[0].kind == "storage"
                    and children[0].storage is not None
                    and children[0].storage.width_bits == atom.width_bits
                    and children[0].width_bits == atom.width_bits
                )
            ):
                return None
            carrier_width = location.width_bits
    constant = (
        data.constant if data.kind == "Constant" and data.operation is None else None
    )
    if index is None and (constant is None or not 0 <= constant < 1 << width):
        return None
    return DerivedGlobalWriteEffect(
        caller.snapshot_id,
        callee.snapshot_id,
        call.callee_ea,
        block,
        instruction,
        address.constant,
        index,
        constant,
        width,
        digest(
            {
                "callee_snapshot": callee.snapshot_id,
                "graph": memory.graph.graph_digest,
                "result": memory.result.to_data(),
                "store_node": store.node_id,
                "bindings": bindings,
                "rule": "single_fixed_global_scalar_write_v1",
            }
        ),
        value_width_bits=data.width_bits if index is not None else None,
        value_argument_width_bits=carrier_width,
    )
