"""Pure reviewed-summary composition over call, byte-memory, and heap state.

The composer consumes an already-bound :class:`CallPlan`; it never selects a
summary by name.  Known candidate branches are evaluated independently and
joined, while an explicit unknown remainder havocs reachable state and keeps
the result partial.
"""

from dataclasses import dataclass
from typing import Literal

from .contracts import MemoryObject
from .heap import HeapObjectState, HeapTransition
from .heap_analysis import (
    ALL_LIVENESS,
    allocate_lifetime,
    escape_lifetime,
    free_lifetime,
)
from .interproc import CallBranch, CallPlan
from .serialization import Model, digest, stable_id
from .states import (
    BitValue,
    ByteRange,
    Labels,
    Lifetime,
    PointerCandidate,
    PointerValue,
    canonical_set,
    check_digest,
    check_id,
    nonempty,
    require,
)
from .summaries import MemoryEffect, ReturnEffect


@dataclass(frozen=True)
class CallValue(Model):
    value: BitValue
    labels: Labels = Labels()
    pointer: PointerValue | None = None

    def __post_init__(self):
        super().__post_init__()
        require(
            self.pointer is None or self.pointer.width_bits == self.value.width_bits,
            "Call pointer/value width mismatch",
        )

    def join(self, other: "CallValue") -> "CallValue":
        require(
            self.value.width_bits == other.value.width_bits,
            "Cannot join unlike call-value widths",
        )
        pointer = None
        if self.pointer is not None or other.pointer is not None:
            example = self.pointer or other.pointer
            assert example is not None
            if self.pointer is None or other.pointer is None:
                pointer = PointerValue(
                    example.address_space,
                    example.width_bits,
                    any_compatible_location=True,
                    may_be_null=True,
                )
            elif (
                self.pointer.address_space,
                self.pointer.width_bits,
            ) == (other.pointer.address_space, other.pointer.width_bits):
                pointer = self.pointer.join(other.pointer)
            else:
                pointer = PointerValue(
                    "*",
                    self.value.width_bits,
                    any_compatible_location=True,
                    may_be_null=True,
                )
        return CallValue(
            self.value.join(other.value), self.labels.join(other.labels), pointer
        )


@dataclass(frozen=True)
class CallMemoryByte(Model):
    object_id: str
    offset: int
    value: BitValue
    labels: Labels = Labels()

    def __post_init__(self):
        super().__post_init__()
        check_id(self.object_id, "object")
        require(self.offset >= 0, "Negative call-memory offset")
        require(self.value.width_bits == 8, "Call memory is byte materialized")

    def join(self, other: "CallMemoryByte") -> "CallMemoryByte":
        require(
            (self.object_id, self.offset) == (other.object_id, other.offset),
            "Cannot join different call-memory bytes",
        )
        return CallMemoryByte(
            self.object_id,
            self.offset,
            self.value.join(other.value),
            self.labels.join(other.labels),
        )


@dataclass(frozen=True)
class CallGlobalBinding(Model):
    rva: int
    object_id: str
    object_offset: int = 0

    def __post_init__(self):
        super().__post_init__()
        require(self.rva >= 0 and self.object_offset >= 0, "Invalid global binding")
        check_id(self.object_id, "object")


@dataclass(frozen=True)
class CallState(Model):
    objects: tuple[MemoryObject, ...] = ()
    memory: tuple[CallMemoryByte, ...] = ()
    havoced_objects: tuple[str, ...] = ()
    heap: tuple[HeapObjectState, ...] = ()
    globals: tuple[CallGlobalBinding, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        canonical_set(tuple(item.object_id for item in self.objects))
        canonical_set(tuple((item.object_id, item.offset) for item in self.memory))
        canonical_set(self.havoced_objects)
        canonical_set(tuple(item.object_id for item in self.heap))
        canonical_set(tuple(item.rva for item in self.globals))
        objects = {item.object_id: item for item in self.objects}
        require(set(self.havoced_objects) <= objects.keys(), "Unknown havoc object")
        for byte in self.memory:
            require(byte.object_id in objects, "Unknown call-memory object")
            size = objects[byte.object_id].size_bytes
            require(
                size is None or byte.offset < size, "Call-memory byte out of bounds"
            )
        for item in self.heap:
            require(
                item.object_id in objects and objects[item.object_id].kind == "heap",
                "Heap state needs a heap object",
            )
        for item in self.globals:
            require(
                item.object_id in objects and objects[item.object_id].kind == "global",
                "Global binding needs a global object",
            )


@dataclass(frozen=True)
class CallAllocationProof(Model):
    summary_digest: str
    context_digest: str
    effect_index: int
    singleton_evidence: str | None = None
    disjoint_evidence: str | None = None
    non_null_evidence: str | None = None

    def __post_init__(self):
        super().__post_init__()
        check_digest(self.summary_digest)
        check_digest(self.context_digest)
        require(self.effect_index >= 0, "Negative allocation-effect index")
        for value in (
            self.singleton_evidence,
            self.disjoint_evidence,
            self.non_null_evidence,
        ):
            if value is not None:
                nonempty(value)

    @property
    def sort_key(self) -> tuple[str, str, int]:
        return self.summary_digest, self.context_digest, self.effect_index


@dataclass(frozen=True)
class CallInputs(Model):
    arguments: tuple[CallValue, ...]
    state: CallState = CallState()
    allocation_proofs: tuple[CallAllocationProof, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        keys = tuple(item.sort_key for item in self.allocation_proofs)
        canonical_set(keys)
        objects = {item.object_id for item in self.state.objects}
        for argument in self.arguments:
            if argument.pointer is not None:
                require(
                    {item.object_id for item in argument.pointer.candidates} <= objects,
                    "Call argument points outside input state",
                )


@dataclass(frozen=True)
class CallCompositionPolicy(Model):
    address_space: str = "ram"
    pointer_width_bits: int = 64
    endian: Literal["little", "big"] = "little"
    max_effect_bytes: int = 4096
    unknown_return_width_bits: int | None = None
    ruleset: Literal["reviewed-call-composition-v1"] = "reviewed-call-composition-v1"

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.address_space)
        require(
            self.pointer_width_bits > 0 and self.max_effect_bytes > 0,
            "Invalid call-composition policy",
        )
        require(
            self.unknown_return_width_bits is None
            or self.unknown_return_width_bits > 0,
            "Invalid unknown return width",
        )


EvidenceKind = Literal[
    "call_argument", "call_return", "summary_effect", "opaque_effect"
]


@dataclass(frozen=True)
class CallEvidence(Model):
    kind: EvidenceKind
    plan_digest: str
    detail: str
    branch_context_digest: str | None = None
    summary_digest: str | None = None
    argument_index: int | None = None
    effect_index: int | None = None
    reasons: tuple[str, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        check_digest(self.plan_digest)
        nonempty(self.detail)
        for value in (self.branch_context_digest, self.summary_digest):
            if value is not None:
                check_digest(value)
        require(
            self.argument_index is None or self.argument_index >= 0,
            "Negative call argument index",
        )
        require(
            self.effect_index is None or self.effect_index >= 0,
            "Negative summary effect index",
        )
        canonical_set(self.reasons)
        require(
            self.kind != "opaque_effect" or bool(self.reasons),
            "Opaque call evidence needs a reason",
        )

    @property
    def evidence_id(self) -> str:
        return stable_id("evidence", self.to_data())


@dataclass(frozen=True)
class CallMemoryTarget(Model):
    object_id: str
    interval: ByteRange | None

    def __post_init__(self):
        super().__post_init__()
        check_id(self.object_id, "object")


@dataclass(frozen=True)
class CallMemoryObservation(Model):
    operation: Literal["copy", "fill", "output", "global_write", "reachable_havoc"]
    targets: tuple[CallMemoryTarget, ...]
    strong_update: bool
    unresolved: bool
    precision: Literal["exact", "may_alias", "opaque"]
    evidence_id: str

    def __post_init__(self):
        super().__post_init__()
        canonical_set(
            tuple(
                (
                    item.object_id,
                    item.interval.start if item.interval else -1,
                    item.interval.end if item.interval else -1,
                )
                for item in self.targets
            )
        )
        check_id(self.evidence_id, "evidence")
        require(
            not self.strong_update
            or (
                len(self.targets) == 1
                and self.targets[0].interval is not None
                and not self.unresolved
                and self.precision == "exact"
            ),
            "Invalid strong summary-memory update",
        )


@dataclass(frozen=True)
class CallHeapObservation(Model):
    kind: Literal["allocate", "free", "escape", "opaque"]
    pointer: PointerValue | None
    transitions: tuple[HeapTransition, ...]
    precision: Literal["exact", "may_alias", "opaque"]
    unresolved: bool
    evidence_id: str

    def __post_init__(self):
        super().__post_init__()
        canonical_set(tuple(item.object_id for item in self.transitions))
        check_id(self.evidence_id, "evidence")
        require(
            not any(item.strong_update for item in self.transitions)
            or (
                self.pointer is not None
                and not self.pointer.may_be_null
                and len(self.pointer.candidates) == 1
                and self.precision == "exact"
                and not self.unresolved
            ),
            "Invalid strong summary-heap transition",
        )


@dataclass(frozen=True)
class CallBranchResult(Model):
    summary_digest: str
    context_digest: str
    state: CallState
    return_value: CallValue | None
    memory_observations: tuple[CallMemoryObservation, ...]
    heap_observations: tuple[CallHeapObservation, ...]
    evidence: tuple[CallEvidence, ...]
    diagnostics: tuple[str, ...]

    def __post_init__(self):
        super().__post_init__()
        check_digest(self.summary_digest)
        check_digest(self.context_digest)
        canonical_set(tuple(item.evidence_id for item in self.evidence))
        canonical_set(self.diagnostics)


@dataclass(frozen=True)
class CallCompositionResult(Model):
    plan_digest: str
    source_digest: str
    policy_digest: str
    branches: tuple[CallBranchResult, ...]
    state: CallState
    return_value: CallValue | None
    memory_observations: tuple[CallMemoryObservation, ...]
    heap_observations: tuple[CallHeapObservation, ...]
    evidence: tuple[CallEvidence, ...]
    status: Literal["complete_in_scope", "partial"]
    diagnostics: tuple[str, ...]
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        for value in (self.plan_digest, self.source_digest, self.policy_digest):
            check_digest(value)
        canonical_set(tuple(item.context_digest for item in self.branches))
        canonical_set(tuple(item.evidence_id for item in self.evidence))
        canonical_set(self.diagnostics)
        require(
            self.status != "complete_in_scope" or not self.diagnostics,
            "Incomplete call composition marked complete",
        )

    @property
    def cache_key(self) -> str:
        return digest(
            {
                "plan": self.plan_digest,
                "source": self.source_digest,
                "policy": self.policy_digest,
            }
        )


def _unknown_at(object_id: str, offset: int) -> CallMemoryByte:
    return CallMemoryByte(
        object_id, offset, BitValue(8), Labels(unknown_provenance=True)
    )


class _State:
    def __init__(self, state: CallState):
        self.objects = {item.object_id: item for item in state.objects}
        self.memory = {(item.object_id, item.offset): item for item in state.memory}
        self.havoced = set(state.havoced_objects)
        self.heap = {item.object_id: item.lifetime for item in state.heap}
        self.globals = {item.rva: item for item in state.globals}

    def copy(self) -> "_State":
        return _State(self.finish())

    def finish(self) -> CallState:
        return CallState(
            tuple(sorted(self.objects.values(), key=lambda item: item.object_id)),
            tuple(
                sorted(
                    self.memory.values(), key=lambda item: (item.object_id, item.offset)
                )
            ),
            tuple(sorted(self.havoced)),
            tuple(
                HeapObjectState(object_id, lifetime)
                for object_id, lifetime in sorted(self.heap.items())
            ),
            tuple(sorted(self.globals.values(), key=lambda item: item.rva)),
        )

    def read(self, object_id: str, offset: int) -> CallMemoryByte:
        item = self.memory.get((object_id, offset), _unknown_at(object_id, offset))
        return (
            item.join(_unknown_at(object_id, offset))
            if object_id in self.havoced
            else item
        )

    def write(self, item: CallMemoryByte, *, strong: bool):
        key = item.object_id, item.offset
        self.memory[key] = item if strong else self.read(*key).join(item)

    def havoc(self, object_ids: set[str]):
        self.havoced.update(object_ids)
        for key, item in tuple(self.memory.items()):
            if key[0] in object_ids:
                self.memory[key] = item.join(_unknown_at(*key))


def _join_state_pair(left: CallState, right: CallState) -> CallState:
    a, b = _State(left), _State(right)
    objects = dict(a.objects)
    for object_id, item in b.objects.items():
        require(
            object_id not in objects or objects[object_id] == item,
            "Conflicting call-state object identity",
        )
        objects[object_id] = item
    globals_ = dict(a.globals)
    for rva, item in b.globals.items():
        require(
            rva not in globals_ or globals_[rva] == item,
            "Conflicting call-state global binding",
        )
        globals_[rva] = item
    memory = {}
    for key in sorted(a.memory.keys() | b.memory.keys()):
        memory[key] = a.read(*key).join(b.read(*key))
    heap = {}
    for object_id in sorted(a.heap.keys() | b.heap.keys()):
        missing = Lifetime(("not_allocated",), "local")
        heap[object_id] = a.heap.get(object_id, missing).join(
            b.heap.get(object_id, missing)
        )
    return CallState(
        tuple(sorted(objects.values(), key=lambda item: item.object_id)),
        tuple(memory.values()),
        tuple(sorted(a.havoced | b.havoced)),
        tuple(HeapObjectState(key, value) for key, value in sorted(heap.items())),
        tuple(sorted(globals_.values(), key=lambda item: item.rva)),
    )


def join_call_states(states: tuple[CallState, ...]) -> CallState:
    """Join caller states without discarding branch-local heap objects."""

    require(bool(states), "Call-state join needs an input")
    result = states[0]
    for state in states[1:]:
        result = _join_state_pair(result, state)
    return result


def _proof(inputs: CallInputs, branch: CallBranch, effect_index: int):
    key = branch.summary.summary_digest, branch.context.context_digest, effect_index
    return next(
        (item for item in inputs.allocation_proofs if item.sort_key == key), None
    )


def _argument(inputs: CallInputs, index: int | None, diagnostics: set[str]):
    if index is None or index >= len(inputs.arguments):
        diagnostics.add("summary_argument_missing")
        return None
    return inputs.arguments[index]


def _extent(
    effect: MemoryEffect,
    inputs: CallInputs,
    policy: CallCompositionPolicy,
    diagnostics: set[str],
):
    if effect.extent.fixed_bytes is not None:
        size = effect.extent.fixed_bytes
    else:
        argument = _argument(inputs, effect.extent.argument_index, diagnostics)
        size = None if argument is None else argument.value.value
    if size is None or size <= 0:
        diagnostics.add("summary_extent_unresolved")
        return None
    if size > policy.max_effect_bytes:
        diagnostics.add("summary_extent_budget_widened")
        return None
    return size


def _pointer_targets(state: _State, pointer: PointerValue | None, size: int | None):
    if pointer is None:
        return (
            tuple(CallMemoryTarget(item, None) for item in sorted(state.objects)),
            True,
        )
    compatible = {
        object_id
        for object_id, item in state.objects.items()
        if pointer.address_space == "*" or item.address_space == pointer.address_space
    }
    if pointer.any_compatible_location:
        return tuple(CallMemoryTarget(item, None) for item in sorted(compatible)), True
    targets: set[CallMemoryTarget] = set()
    unresolved = pointer.may_be_null
    for candidate in pointer.candidates:
        item = state.objects[candidate.object_id]
        interval = None
        if candidate.offset is not None and size is not None:
            end = candidate.offset + size
            if candidate.offset >= 0 and (
                item.size_bytes is None or end <= item.size_bytes
            ):
                interval = ByteRange(candidate.offset, end)
        if interval is None:
            unresolved = True
            targets.update(
                CallMemoryTarget(object_id, None)
                for object_id, other in state.objects.items()
                if other.address_space == item.address_space
            )
        else:
            targets.add(CallMemoryTarget(candidate.object_id, interval))
    if not targets:
        targets.update(CallMemoryTarget(object_id, None) for object_id in compatible)
    return tuple(
        sorted(
            targets,
            key=lambda item: (
                item.object_id,
                item.interval.start if item.interval else -1,
                item.interval.end if item.interval else -1,
            ),
        )
    ), unresolved


def _global_target(state: _State, rva: int | None, size: int | None):
    if rva is None or rva not in state.globals:
        return (
            tuple(
                CallMemoryTarget(object_id, None)
                for object_id, item in sorted(state.objects.items())
                if item.kind == "global"
            ),
            True,
        )
    binding = state.globals[rva]
    item = state.objects[binding.object_id]
    interval = None
    if size is not None:
        end = binding.object_offset + size
        if item.size_bytes is None or end <= item.size_bytes:
            interval = ByteRange(binding.object_offset, end)
    if interval is not None:
        return (CallMemoryTarget(binding.object_id, interval),), False
    return (
        tuple(
            CallMemoryTarget(object_id, None)
            for object_id, other in sorted(state.objects.items())
            if other.address_space == item.address_space
        ),
        True,
    )


def _scalar_bytes(value: CallValue, size: int, endian: str):
    result = []
    for offset in range(size):
        index = offset if endian == "little" else size - offset - 1
        byte = (
            None
            if value.value.value is None
            else (value.value.value >> (8 * index)) & 255
        )
        result.append((BitValue(8, byte), value.labels))
    return result


def _source_bytes(
    state: _State,
    effect: MemoryEffect,
    inputs: CallInputs,
    size: int,
    policy: CallCompositionPolicy,
    diagnostics: set[str],
):
    if effect.source == "argument":
        argument = _argument(inputs, effect.source_index, diagnostics)
        if effect.operation == "fill" and argument is not None:
            byte = None if argument.value.value is None else argument.value.value & 255
            return [(BitValue(8, byte), argument.labels)] * size
        data = (
            [(BitValue(8), Labels(unknown_provenance=True))] * size
            if argument is None
            else _scalar_bytes(argument, size, policy.endian)
        )
        return data
    if effect.source == "constant":
        constant = effect.constant
        assert constant is not None
        if effect.operation == "fill":
            return [(BitValue(8, constant & 255), Labels())] * size
        value = CallValue(BitValue(max(8, size * 8), constant))
        return _scalar_bytes(value, size, policy.endian)
    if effect.source == "unknown":
        diagnostics.add("reviewed_summary_unknown_memory_source")
        return [(BitValue(8), Labels(unknown_provenance=True))] * size
    if effect.source == "global":
        targets, unresolved = _global_target(state, effect.source_rva, size)
    else:
        argument = _argument(inputs, effect.source_index, diagnostics)
        targets, unresolved = _pointer_targets(
            state, None if argument is None else argument.pointer, size
        )
    if unresolved or not targets or any(item.interval is None for item in targets):
        diagnostics.add("summary_memory_source_unresolved")
    output = []
    for index in range(size):
        values: list[tuple[BitValue, Labels]] = []
        for target in targets:
            if target.interval is not None:
                item = state.read(target.object_id, target.interval.start + index)
                values.append((item.value, item.labels))
        if unresolved:
            values.append((BitValue(8), Labels(unknown_provenance=True)))
        if not values:
            output.append((BitValue(8), Labels(unknown_provenance=True)))
            continue
        joined_value, joined_labels = values[0]
        for value, labels in values[1:]:
            joined_value = joined_value.join(value)
            joined_labels = joined_labels.join(labels)
        output.append((joined_value, joined_labels))
    return output


def _memory_effect(
    plan: CallPlan,
    branch: CallBranch,
    index: int,
    effect: MemoryEffect,
    inputs: CallInputs,
    state: _State,
    policy: CallCompositionPolicy,
    diagnostics: set[str],
):
    evidence = CallEvidence(
        "summary_effect",
        plan.plan_digest,
        f"memory:{effect.operation}",
        branch.context.context_digest,
        branch.summary.summary_digest,
        effect_index=index,
    )
    size = _extent(effect, inputs, policy, diagnostics)
    if effect.target == "global":
        targets, unresolved = _global_target(state, effect.target_rva, size)
    else:
        argument = _argument(inputs, effect.target_index, diagnostics)
        targets, unresolved = _pointer_targets(
            state, None if argument is None else argument.pointer, size
        )
    strong = (
        not unresolved
        and len(targets) == 1
        and targets[0].interval is not None
        and state.objects[targets[0].object_id].singleton
    )
    if unresolved:
        diagnostics.add("summary_memory_target_unresolved")
    if size is None or not targets or any(item.interval is None for item in targets):
        state.havoc({item.object_id for item in targets})
        unresolved = True
    else:
        source = _source_bytes(state, effect, inputs, size, policy, diagnostics)
        for target in targets:
            interval = target.interval
            assert interval is not None
            for byte_index, (value, labels) in enumerate(source):
                state.write(
                    CallMemoryByte(
                        target.object_id,
                        interval.start + byte_index,
                        value,
                        labels,
                    ),
                    strong=strong,
                )
    precision = "opaque" if unresolved else ("exact" if strong else "may_alias")
    observation = CallMemoryObservation(
        effect.operation,
        targets,
        strong,
        unresolved,
        precision,
        evidence.evidence_id,
    )
    heap_observation = None
    global_targets = tuple(
        item for item in targets if state.objects[item.object_id].kind == "global"
    )
    if global_targets and effect.source == "argument":
        argument = _argument(inputs, effect.source_index, diagnostics)
        pointer = None if argument is None else argument.pointer
        pointer_preserving = (
            pointer is not None
            and effect.operation != "fill"
            and size is not None
            and size * 8 >= pointer.width_bits
        )
        definite_publication = (
            pointer_preserving
            and not unresolved
            and bool(targets)
            and len(global_targets) == len(targets)
        )
        heap_observation = _escape_heap(
            pointer,
            state,
            evidence.evidence_id,
            definite_publication=definite_publication,
        )
        if heap_observation is not None and heap_observation.unresolved:
            diagnostics.add("summary_escape_unresolved")
    return evidence, observation, heap_observation


def _escape_heap(
    pointer: PointerValue | None,
    state: _State,
    evidence_id: str,
    *,
    definite_publication: bool,
):
    targets, pointer_unresolved = _heap_targets(pointer, state)
    unresolved = pointer_unresolved or not definite_publication
    definite = (
        definite_publication
        and pointer is not None
        and not pointer_unresolved
        and len(targets) == 1
        and len(pointer.candidates) == 1
        and state.objects[next(iter(targets))].singleton
    )
    transitions = []
    for object_id in sorted(targets):
        before = state.heap[object_id]
        after = escape_lifetime(before, definite=definite)
        state.heap[object_id] = after
        transitions.append(HeapTransition(object_id, before, after, definite))
    if not transitions:
        return None
    return CallHeapObservation(
        "escape",
        pointer,
        tuple(transitions),
        "exact" if definite else ("opaque" if unresolved else "may_alias"),
        unresolved,
        evidence_id,
    )


def _heap_targets(pointer: PointerValue | None, state: _State):
    compatible = {
        object_id
        for object_id in state.heap
        if pointer is None
        or pointer.address_space == "*"
        or state.objects[object_id].address_space == pointer.address_space
    }
    if pointer is None or pointer.any_compatible_location:
        return compatible, True
    targets = {
        item.object_id for item in pointer.candidates if item.object_id in state.heap
    }
    unresolved = (
        pointer.may_be_null
        or not targets
        or any(item.offset != 0 for item in pointer.candidates)
    )
    return (compatible if unresolved and not targets else targets), unresolved


def _allocate(
    plan: CallPlan,
    branch: CallBranch,
    index: int,
    inputs: CallInputs,
    state: _State,
    policy: CallCompositionPolicy,
    diagnostics: set[str],
):
    effect = branch.summary.lifetime_effects[index]
    proof = _proof(inputs, branch, index)
    size = None
    if effect.size_argument_index is not None:
        argument = _argument(inputs, effect.size_argument_index, diagnostics)
        size = None if argument is None else argument.value.value
        if size is not None and size <= 0:
            size = None
            diagnostics.add("allocation_extent_unresolved")
    key = "summary-allocation:" + digest(
        {
            "summary": branch.summary.summary_digest,
            "context": branch.context.context_digest,
            "effect": index,
        }
    )
    obj = MemoryObject(
        plan.site.caller_snapshot_id,
        key,
        policy.address_space,
        size,
        "heap",
        bool(proof and proof.singleton_evidence),
        proof.singleton_evidence if proof else None,
        bool(proof and proof.disjoint_evidence),
        proof.disjoint_evidence if proof else None,
    )
    state.objects[obj.object_id] = obj
    before = state.heap.get(obj.object_id, Lifetime(("not_allocated",), "local"))
    nullable = effect.nullable and not bool(proof and proof.non_null_evidence)
    after, strong = allocate_lifetime(
        before, singleton=obj.singleton, nullable=nullable
    )
    state.heap[obj.object_id] = after
    pointer = PointerValue(
        policy.address_space,
        policy.pointer_width_bits,
        (PointerCandidate(obj.object_id, 0),),
        may_be_null=nullable,
    )
    evidence = CallEvidence(
        "summary_effect",
        plan.plan_digest,
        "lifetime:allocate",
        branch.context.context_digest,
        branch.summary.summary_digest,
        effect_index=index,
    )
    observation = CallHeapObservation(
        "allocate",
        pointer,
        (HeapTransition(obj.object_id, before, after, strong),),
        "exact" if strong else "may_alias",
        False,
        evidence.evidence_id,
    )
    return obj, pointer, evidence, observation


def _free(
    plan: CallPlan,
    branch: CallBranch,
    index: int,
    inputs: CallInputs,
    state: _State,
    diagnostics: set[str],
):
    effect = branch.summary.lifetime_effects[index]
    argument = _argument(inputs, effect.pointer_argument_index, diagnostics)
    pointer = None if argument is None else argument.pointer
    targets, unresolved = _heap_targets(pointer, state)
    definite = (
        pointer is not None
        and not unresolved
        and len(targets) == 1
        and len(pointer.candidates) == 1
    )
    transitions = []
    for object_id in sorted(targets):
        before = state.heap[object_id]
        after, strong, nonlive = free_lifetime(
            before, definite=definite and state.objects[object_id].singleton
        )
        unresolved = unresolved or nonlive
        state.heap[object_id] = after
        transitions.append(HeapTransition(object_id, before, after, strong))
    if unresolved:
        diagnostics.add("summary_free_unresolved")
    evidence = CallEvidence(
        "summary_effect",
        plan.plan_digest,
        "lifetime:free",
        branch.context.context_digest,
        branch.summary.summary_digest,
        argument_index=effect.pointer_argument_index,
        effect_index=index,
    )
    observation = CallHeapObservation(
        "free",
        pointer,
        tuple(transitions),
        "opaque" if unresolved else ("exact" if definite else "may_alias"),
        unresolved,
        evidence.evidence_id,
    )
    return evidence, observation


def _read_global_return(
    effect: ReturnEffect,
    state: _State,
    policy: CallCompositionPolicy,
    diagnostics: set[str],
):
    if effect.width_bits % 8:
        diagnostics.add("summary_global_return_width_unresolved")
        return CallValue(BitValue(effect.width_bits), Labels(unknown_provenance=True))
    targets, unresolved = _global_target(
        state, effect.global_rva, effect.width_bits // 8
    )
    if unresolved or not targets or targets[0].interval is None:
        diagnostics.add("summary_global_return_unresolved")
        return CallValue(BitValue(effect.width_bits), Labels(unknown_provenance=True))
    target = targets[0]
    interval = target.interval
    assert interval is not None
    cells = [
        state.read(target.object_id, offset)
        for offset in range(interval.start, interval.end)
    ]
    labels = Labels()
    value = 0
    concrete = True
    for index, item in enumerate(cells):
        labels = labels.join(item.labels)
        if item.value.value is None:
            concrete = False
        else:
            shift = index if policy.endian == "little" else len(cells) - index - 1
            value |= item.value.value << (8 * shift)
    return CallValue(BitValue(effect.width_bits, value if concrete else None), labels)


def _return_effect(
    plan: CallPlan,
    branch: CallBranch,
    index: int,
    effect: ReturnEffect,
    inputs: CallInputs,
    state: _State,
    allocations: tuple[PointerValue, ...],
    policy: CallCompositionPolicy,
    diagnostics: set[str],
):
    if effect.source == "argument":
        argument = _argument(inputs, effect.argument_index, diagnostics)
        if argument is None:
            result = CallValue(
                BitValue(effect.width_bits), Labels(unknown_provenance=True)
            )
        elif argument.value.width_bits == effect.width_bits:
            result = argument
        else:
            value = argument.value.value
            result = CallValue(
                BitValue(
                    effect.width_bits,
                    None if value is None else value & ((1 << effect.width_bits) - 1),
                ),
                argument.labels,
            )
    elif effect.source == "constant":
        result = CallValue(BitValue(effect.width_bits, effect.constant))
    elif effect.source == "global":
        result = _read_global_return(effect, state, policy, diagnostics)
    elif effect.source == "allocation" and allocations:
        pointer = allocations[0]
        for item in allocations[1:]:
            pointer = pointer.join(item)
        result = CallValue(BitValue(effect.width_bits), pointer=pointer)
    else:
        diagnostics.add("reviewed_summary_unknown_return")
        result = CallValue(BitValue(effect.width_bits), Labels(unknown_provenance=True))
    evidence = CallEvidence(
        "call_return",
        plan.plan_digest,
        f"return:{effect.source}",
        branch.context.context_digest,
        branch.summary.summary_digest,
        argument_index=effect.argument_index,
        effect_index=index,
    )
    return result, evidence


def _compose_branch(
    plan: CallPlan,
    branch: CallBranch,
    inputs: CallInputs,
    policy: CallCompositionPolicy,
):
    state = _State(inputs.state)
    evidence = [
        CallEvidence(
            "call_argument",
            plan.plan_digest,
            "reviewed_argument",
            branch.context.context_digest,
            branch.summary.summary_digest,
            argument_index=index,
        )
        for index in range(len(inputs.arguments))
    ]
    memory_observations = []
    heap_observations = []
    diagnostics = set()
    allocations = []
    for index, effect in enumerate(branch.summary.lifetime_effects):
        if effect.operation == "allocate":
            _, pointer, item, observation = _allocate(
                plan, branch, index, inputs, state, policy, diagnostics
            )
            allocations.append(pointer)
        else:
            item, observation = _free(plan, branch, index, inputs, state, diagnostics)
        evidence.append(item)
        heap_observations.append(observation)
    for index, effect in enumerate(branch.summary.memory_effects):
        item, observation, heap_observation = _memory_effect(
            plan, branch, index, effect, inputs, state, policy, diagnostics
        )
        evidence.append(item)
        memory_observations.append(observation)
        if heap_observation is not None:
            heap_observations.append(heap_observation)
    returns = []
    for index, effect in enumerate(branch.summary.return_effects):
        value, item = _return_effect(
            plan,
            branch,
            index,
            effect,
            inputs,
            state,
            tuple(allocations),
            policy,
            diagnostics,
        )
        returns.append(value)
        evidence.append(item)
    return_value = None
    if returns:
        return_value = returns[0]
        for value in returns[1:]:
            return_value = return_value.join(value)
    return CallBranchResult(
        branch.summary.summary_digest,
        branch.context.context_digest,
        state.finish(),
        return_value,
        tuple(memory_observations),
        tuple(heap_observations),
        tuple(sorted(evidence, key=lambda item: item.evidence_id)),
        tuple(sorted(diagnostics)),
    )


def _reachable(inputs: CallInputs, state: _State):
    root_spaces = {
        item.address_space for item in state.objects.values() if item.kind == "global"
    }
    root_spaces.update(
        state.objects[object_id].address_space
        for object_id, lifetime in state.heap.items()
        if lifetime.escape != "local"
    )
    # Call memory does not encode pointers stored inside globals.  Treat every
    # compatible object as transitively reachable from a pointer-bearing root.
    object_ids = {
        object_id
        for object_id, item in state.objects.items()
        if item.address_space in root_spaces
    }
    for argument in inputs.arguments:
        pointer = argument.pointer
        if pointer is None:
            continue
        object_ids.update(
            object_id
            for object_id, item in state.objects.items()
            if pointer.address_space == "*"
            or item.address_space == pointer.address_space
        )
    return object_ids


def _unknown_width(plan: CallPlan, policy: CallCompositionPolicy):
    widths = {
        effect.width_bits
        for branch in plan.branches
        for effect in branch.summary.return_effects
    }
    if len(widths) == 1:
        return next(iter(widths))
    return policy.unknown_return_width_bits


def _opaque_branch(
    plan: CallPlan,
    inputs: CallInputs,
    policy: CallCompositionPolicy,
):
    state = _State(inputs.state)
    remainder = plan.unknown_remainder
    assert remainder is not None
    reasons = remainder.reasons
    evidence = [
        CallEvidence(
            "call_argument",
            plan.plan_digest,
            "opaque_argument",
            argument_index=index,
            reasons=reasons,
        )
        for index in range(len(inputs.arguments))
    ]
    opaque = CallEvidence(
        "opaque_effect", plan.plan_digest, "unknown_remainder", reasons=reasons
    )
    evidence.append(opaque)
    reachable = _reachable(inputs, state)
    state.havoc(reachable)
    transitions = []
    for object_id in sorted(reachable & state.heap.keys()):
        before = state.heap[object_id]
        after = Lifetime(ALL_LIVENESS, "unknown")
        state.heap[object_id] = after
        transitions.append(HeapTransition(object_id, before, after, False))
    memory_targets = tuple(CallMemoryTarget(item, None) for item in sorted(reachable))
    memory = CallMemoryObservation(
        "reachable_havoc", memory_targets, False, True, "opaque", opaque.evidence_id
    )
    heap = CallHeapObservation(
        "opaque", None, tuple(transitions), "opaque", True, opaque.evidence_id
    )
    width = _unknown_width(plan, policy)
    return_value = None
    diagnostics: set[str] = set(reasons)
    if width is None:
        diagnostics.add("unknown_return_width")
    else:
        return_value = CallValue(BitValue(width), Labels(unknown_provenance=True))
        evidence.append(
            CallEvidence(
                "call_return",
                plan.plan_digest,
                "unknown_return",
                reasons=reasons,
            )
        )
    return (
        state.finish(),
        return_value,
        memory,
        heap,
        tuple(sorted(evidence, key=lambda item: item.evidence_id)),
        diagnostics,
    )


def compose_call(
    plan: CallPlan,
    inputs: CallInputs,
    policy: CallCompositionPolicy = CallCompositionPolicy(),
) -> CallCompositionResult:
    """Apply reviewed branches and conservatively join the call boundary."""

    branches = tuple(
        sorted(
            (_compose_branch(plan, branch, inputs, policy) for branch in plan.branches),
            key=lambda item: item.context_digest,
        )
    )
    states = [item.state for item in branches]
    returns = [item.return_value for item in branches]
    memory = [item for branch in branches for item in branch.memory_observations]
    heap = [item for branch in branches for item in branch.heap_observations]
    evidence = [item for branch in branches for item in branch.evidence]
    diagnostics = {item for branch in branches for item in branch.diagnostics}
    if plan.unknown_remainder is not None:
        (
            opaque_state,
            opaque_return,
            opaque_memory,
            opaque_heap,
            opaque_evidence,
            opaque_diagnostics,
        ) = _opaque_branch(plan, inputs, policy)
        states.append(opaque_state)
        returns.append(opaque_return)
        memory.append(opaque_memory)
        heap.append(opaque_heap)
        evidence.extend(opaque_evidence)
        diagnostics.update(opaque_diagnostics)
    state = join_call_states(tuple(states)) if states else inputs.state
    values = [item for item in returns if item is not None]
    return_value = None
    if values:
        return_value = values[0]
        for item in values[1:]:
            return_value = return_value.join(item)
        if len(values) != len(returns):
            diagnostics.add("mixed_void_and_value_return")
            return_value = CallValue(
                BitValue(return_value.value.width_bits),
                return_value.labels.join(Labels(unknown_provenance=True)),
                return_value.pointer,
            )
    status = (
        "partial"
        if diagnostics or plan.unknown_remainder is not None
        else "complete_in_scope"
    )
    return CallCompositionResult(
        plan.plan_digest,
        digest(inputs),
        digest(policy),
        branches,
        state,
        return_value,
        tuple(memory),
        tuple(heap),
        tuple(
            sorted(
                {item.evidence_id: item for item in evidence}.values(),
                key=lambda item: item.evidence_id,
            )
        ),
        status,
        tuple(sorted(diagnostics)),
    )
