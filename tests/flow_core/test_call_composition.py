"""C01-C04 and call-shaped H01-H04 pure composition tests."""

from dataclasses import fields

from ida_pro_mcp.flow_core import canonical_json, digest, stable_id
from ida_pro_mcp.flow_core.call_composition import (
    CallAllocationProof,
    CallCompositionPolicy,
    CallCompositionResult,
    CallGlobalBinding,
    CallInputs,
    CallMemoryByte,
    CallMemoryTarget,
    CallState,
    CallValue,
    compose_call,
    join_call_states,
)
from ida_pro_mcp.flow_core.contracts import MemoryObject
from ida_pro_mcp.flow_core.heap import HeapObjectState, HeapResult
from ida_pro_mcp.flow_core.interproc import (
    CallContext,
    CallPolicy,
    CallSite,
    plan_direct_call,
    plan_indirect_call,
)
from ida_pro_mcp.flow_core.states import (
    BitValue,
    Labels,
    Lifetime,
    PointerCandidate,
    PointerValue,
)
from ida_pro_mcp.flow_core.summaries import (
    LifetimeEffect,
    MemoryEffect,
    MemoryExtent,
    ReturnEffect,
    ReviewedSummary,
    SummaryCatalog,
    SummaryIdentity,
)

SNAPSHOT = stable_id("snapshot", "call-composition-caller")
POLICY = CallPolicy(max_context_depth=4, max_recursion_depth=1)


def identity(name: str, rva: int) -> SummaryIdentity:
    return SummaryIdentity(
        digest("call-composition-fixture").split(":", 1)[1],
        rva,
        stable_id("snapshot", {"callee": name, "rva": rva}),
        digest("profile-v1"),
        "darwin-aarch64",
        digest({"signature": name}),
    )


def summary(
    name: str,
    rva: int,
    kind: str,
    returns=(),
    memory=(),
    lifetime=(),
) -> ReviewedSummary:
    return ReviewedSummary(
        identity(name, rva),
        name,
        kind,
        tuple(returns),
        tuple(memory),
        tuple(lifetime),
        "fixture-review",
        digest({"review": name, "rva": rva}),
    )


def catalog(*items: ReviewedSummary) -> SummaryCatalog:
    return SummaryCatalog(tuple(sorted(items, key=lambda item: item.identity.sort_key)))


def direct(item: ReviewedSummary, caller: str, rva: int):
    site = CallSite(SNAPSHOT, caller, rva, "direct")
    return plan_direct_call(catalog(item), site, CallContext(), item.identity, POLICY)


def value(bits: int, number=None, label=None, pointer=None) -> CallValue:
    return CallValue(
        BitValue(bits, number),
        Labels((label,) if label else ()),
        pointer,
    )


def object_(key: str, size: int, kind="argument", address_space="ram") -> MemoryObject:
    return MemoryObject(
        SNAPSHOT,
        key,
        address_space,
        size,
        kind,
        True,
        "fixture singleton proof",
        True,
        "fixture disjoint identity",
    )


def pointer(item: MemoryObject, *, nullable=False) -> PointerValue:
    return PointerValue(
        "ram", 64, (PointerCandidate(item.object_id, 0),), may_be_null=nullable
    )


def state(objects, memory=(), globals_=(), heap=()) -> CallState:
    return CallState(
        tuple(sorted(objects, key=lambda item: item.object_id)),
        tuple(sorted(memory, key=lambda item: (item.object_id, item.offset))),
        (),
        tuple(sorted(heap, key=lambda item: item.object_id)),
        tuple(sorted(globals_, key=lambda item: item.rva)),
    )


def bytes_for(result, item):
    return [byte for byte in result.state.memory if byte.object_id == item.object_id]


def heap_lifetime(result, object_id):
    return next(
        item.lifetime for item in result.state.heap if item.object_id == object_id
    )


def allocation_proof(plan, item):
    return CallAllocationProof(
        item.summary_digest,
        plan.branches[0].context.context_digest,
        0,
        "acyclic one-shot fixture call",
        "distinct fixture allocation call",
        "non-null observation branch",
    )


def test_c01_identity_copy_fill_output_and_global_remain_distinct():
    identity_summary = summary(
        "call_identity",
        0x100,
        "identity",
        (ReturnEffect("argument", 32, argument_index=0),),
    )
    identity_result = compose_call(
        direct(identity_summary, "identity-caller", 0x200),
        CallInputs((value(32, label="X"),)),
    )
    assert identity_result.return_value.labels.explicit == ("X",)
    assert {item.kind for item in identity_result.evidence} == {
        "call_argument",
        "call_return",
    }

    destination, source = object_("destination", 4), object_("source", 4)
    seeded = state(
        (destination, source),
        tuple(
            CallMemoryByte(
                source.object_id, offset, BitValue(8, offset), Labels(("Y",))
            )
            for offset in range(4)
        ),
    )
    copy = summary(
        "call_copy",
        0x120,
        "copy",
        memory=(
            MemoryEffect(
                "copy",
                "argument",
                "argument_memory",
                MemoryExtent(fixed_bytes=4),
                target_index=0,
                source_index=1,
            ),
        ),
    )
    copied = compose_call(
        direct(copy, "copy-caller", 0x220),
        CallInputs(
            (
                value(64, pointer=pointer(destination)),
                value(64, pointer=pointer(source)),
            ),
            seeded,
        ),
    )
    assert [item.value.value for item in bytes_for(copied, destination)] == [0, 1, 2, 3]
    assert all(
        item.labels.explicit == ("Y",) for item in bytes_for(copied, destination)
    )
    assert copied.return_value is None

    fill = summary(
        "call_fill",
        0x140,
        "fill",
        memory=(
            MemoryEffect(
                "fill",
                "argument",
                "argument",
                MemoryExtent(fixed_bytes=4),
                target_index=0,
                source_index=1,
            ),
        ),
    )
    filled = compose_call(
        direct(fill, "fill-caller", 0x240),
        CallInputs(
            (
                value(64, pointer=pointer(destination)),
                value(8, 0x5A, "Z"),
            ),
            state((destination,)),
        ),
    )
    assert [item.value.value for item in bytes_for(filled, destination)] == [0x5A] * 4
    assert all(
        item.labels.explicit == ("Z",) for item in bytes_for(filled, destination)
    )

    output = summary(
        "call_output",
        0x160,
        "output",
        memory=(
            MemoryEffect(
                "output",
                "argument",
                "argument",
                MemoryExtent(fixed_bytes=4),
                target_index=0,
                source_index=1,
            ),
        ),
    )
    output_result = compose_call(
        direct(output, "output-caller", 0x260),
        CallInputs(
            (
                value(64, pointer=pointer(destination)),
                value(32, 0x44332211, "O"),
            ),
            state((destination,)),
        ),
    )
    assert [item.value.value for item in bytes_for(output_result, destination)] == [
        0x11,
        0x22,
        0x33,
        0x44,
    ]
    assert output_result.return_value is None

    global_object = object_("call_global_value", 4, "global")
    global_summary = summary(
        "call_global",
        0x180,
        "global",
        returns=(ReturnEffect("global", 32, global_rva=0x4000),),
        memory=(
            MemoryEffect(
                "global_write",
                "global",
                "argument",
                MemoryExtent(fixed_bytes=4),
                target_rva=0x4000,
                source_index=0,
            ),
        ),
    )
    global_result = compose_call(
        direct(global_summary, "global-caller", 0x280),
        CallInputs(
            (value(32, 7, "G"),),
            state(
                (global_object,),
                globals_=(CallGlobalBinding(0x4000, global_object.object_id),),
            ),
        ),
    )
    assert global_result.return_value.value.value == 7
    assert global_result.return_value.labels.explicit == ("G",)
    assert global_result.memory_observations[0].operation == "global_write"


def test_copy_joins_source_values_without_requiring_one_memory_location():
    destination = object_("joined-copy-destination", 1)
    first = object_("joined-copy-first", 2)
    second = object_("joined-copy-second", 1)
    item = summary(
        "joined_copy",
        0x190,
        "copy",
        memory=(
            MemoryEffect(
                "copy",
                "argument",
                "argument_memory",
                MemoryExtent(fixed_bytes=1),
                target_index=0,
                source_index=1,
            ),
        ),
    )

    def copied(source_pointer, source_memory):
        return compose_call(
            direct(item, "joined-copy-caller", 0x290),
            CallInputs(
                (
                    value(64, pointer=pointer(destination)),
                    value(64, pointer=source_pointer),
                ),
                state((destination, first, second), source_memory),
            ),
        )

    different_objects = copied(
        PointerValue(
            "ram",
            64,
            tuple(
                sorted(
                    (
                        PointerCandidate(first.object_id, 0),
                        PointerCandidate(second.object_id, 0),
                    ),
                    key=lambda candidate: candidate.object_id,
                )
            ),
        ),
        (
            CallMemoryByte(first.object_id, 0, BitValue(8, 0x11), Labels(("A",))),
            CallMemoryByte(second.object_id, 0, BitValue(8, 0x22), Labels(("B",))),
        ),
    )
    byte = bytes_for(different_objects, destination)[0]
    assert byte.value.value is None
    assert byte.labels == Labels(("A", "B"))

    different_offsets = copied(
        PointerValue(
            "ram",
            64,
            (
                PointerCandidate(first.object_id, 0),
                PointerCandidate(first.object_id, 1),
            ),
        ),
        (
            CallMemoryByte(first.object_id, 0, BitValue(8, 0x33), Labels(("C",))),
            CallMemoryByte(first.object_id, 1, BitValue(8, 0x33), Labels(("D",))),
        ),
    )
    byte = bytes_for(different_offsets, destination)[0]
    assert byte.value.value == 0x33
    assert byte.labels == Labels(("C", "D"))


def test_copy_keeps_known_source_and_widens_unknown_offset_alternative():
    destination = object_("partial-copy-destination", 1)
    source = object_("partial-copy-source", 1)
    item = summary(
        "partial_copy",
        0x1A0,
        "copy",
        memory=(
            MemoryEffect(
                "copy",
                "argument",
                "argument_memory",
                MemoryExtent(fixed_bytes=1),
                target_index=0,
                source_index=1,
            ),
        ),
    )
    result = compose_call(
        direct(item, "partial-copy-caller", 0x2A0),
        CallInputs(
            (
                value(64, pointer=pointer(destination)),
                value(
                    64,
                    pointer=PointerValue(
                        "ram",
                        64,
                        (
                            PointerCandidate(source.object_id, 0),
                            PointerCandidate(source.object_id, None),
                        ),
                    ),
                ),
            ),
            state(
                (destination, source),
                (
                    CallMemoryByte(
                        source.object_id,
                        0,
                        BitValue(8, 0x44),
                        Labels(("KNOWN",)),
                    ),
                ),
            ),
        ),
    )
    byte = bytes_for(result, destination)[0]
    assert byte.value.value is None
    assert byte.labels.explicit == ("KNOWN",)
    assert byte.labels.unknown_provenance
    assert result.status == "partial"
    assert "summary_memory_source_unresolved" in result.diagnostics


def test_unresolved_destinations_are_partial_and_conservatively_havoced():
    destination = object_("unresolved-destination", 1)
    item = summary(
        "unresolved_output",
        0x1B0,
        "output",
        memory=(
            MemoryEffect(
                "output",
                "argument",
                "argument",
                MemoryExtent(fixed_bytes=1),
                target_index=0,
                source_index=1,
            ),
        ),
    )
    seeded = state(
        (destination,),
        (
            CallMemoryByte(
                destination.object_id, 0, BitValue(8, 0x11), Labels(("OLD",))
            ),
        ),
    )
    non_pointer = compose_call(
        direct(item, "unresolved-output-caller", 0x2B0),
        CallInputs((value(64), value(8, 0x22)), seeded),
    )
    assert non_pointer.status == "partial"
    assert "summary_memory_target_unresolved" in non_pointer.diagnostics
    assert non_pointer.state.havoced_objects == (destination.object_id,)
    assert bytes_for(non_pointer, destination)[0].labels.unknown_provenance

    nullable = compose_call(
        direct(item, "nullable-output-caller", 0x2B4),
        CallInputs(
            (
                value(64, pointer=pointer(destination, nullable=True)),
                value(8, 0x22),
            ),
            seeded,
        ),
    )
    assert nullable.status == "partial"
    assert nullable.memory_observations[0].unresolved
    assert not nullable.memory_observations[0].strong_update
    assert "summary_memory_target_unresolved" in nullable.diagnostics

    unknown_offset = compose_call(
        direct(item, "unknown-offset-output-caller", 0x2B8),
        CallInputs(
            (
                value(
                    64,
                    pointer=PointerValue(
                        "ram",
                        64,
                        (PointerCandidate(destination.object_id, None),),
                    ),
                ),
                value(8, 0x22),
            ),
            seeded,
        ),
    )
    assert unknown_offset.status == "partial"
    assert unknown_offset.state.havoced_objects == (destination.object_id,)


def test_oob_destination_widens_same_space_and_deduplicates_targets():
    destination = object_("oob-destination", 1)
    compatible = object_("oob-compatible", 1)
    isolated = object_("oob-isolated", 1, address_space="io")
    item = summary(
        "oob_output",
        0x1B8,
        "output",
        memory=(
            MemoryEffect(
                "output",
                "argument",
                "argument",
                MemoryExtent(fixed_bytes=1),
                target_index=0,
                source_index=1,
            ),
        ),
    )
    target_pointer = PointerValue(
        "ram",
        64,
        (
            PointerCandidate(destination.object_id, 1),
            PointerCandidate(destination.object_id, 2),
        ),
    )
    result = compose_call(
        direct(item, "oob-output-caller", 0x2BC),
        CallInputs(
            (
                value(64, pointer=target_pointer),
                value(8, 0x22),
            ),
            state(
                (destination, compatible, isolated),
                (
                    CallMemoryByte(
                        destination.object_id,
                        0,
                        BitValue(8, 0x11),
                        Labels(("DESTINATION",)),
                    ),
                    CallMemoryByte(
                        compatible.object_id,
                        0,
                        BitValue(8, 0x33),
                        Labels(("COMPATIBLE",)),
                    ),
                    CallMemoryByte(
                        isolated.object_id,
                        0,
                        BitValue(8, 0x44),
                        Labels(("ISOLATED",)),
                    ),
                ),
            ),
        ),
    )

    assert result.status == "partial"
    assert result.state.havoced_objects == tuple(
        sorted((destination.object_id, compatible.object_id))
    )
    assert result.memory_observations[0].targets == tuple(
        CallMemoryTarget(object_id, None)
        for object_id in sorted((destination.object_id, compatible.object_id))
    )
    assert result.memory_observations[0].unresolved
    assert not result.memory_observations[0].strong_update
    assert bytes_for(result, isolated)[0].value.value == 0x44
    assert not bytes_for(result, isolated)[0].labels.unknown_provenance
    assert CallCompositionResult.from_json(canonical_json(result)) == result


def test_oob_global_destination_widens_same_address_space():
    global_object = object_("oob-global", 1, "global")
    compatible = object_("oob-global-compatible", 1)
    isolated = object_("oob-global-isolated", 1, address_space="io")
    item = summary(
        "oob_global",
        0x1BC,
        "global",
        memory=(
            MemoryEffect(
                "global_write",
                "global",
                "argument",
                MemoryExtent(fixed_bytes=2),
                target_rva=0xB000,
                source_index=0,
            ),
        ),
    )
    result = compose_call(
        direct(item, "oob-global-caller", 0x2BE),
        CallInputs(
            (value(16, 0x2211),),
            state(
                (global_object, compatible, isolated),
                globals_=(CallGlobalBinding(0xB000, global_object.object_id),),
            ),
        ),
    )

    assert result.status == "partial"
    assert result.state.havoced_objects == tuple(
        sorted((global_object.object_id, compatible.object_id))
    )
    assert result.memory_observations[0].targets == tuple(
        CallMemoryTarget(object_id, None)
        for object_id in sorted((global_object.object_id, compatible.object_id))
    )
    assert result.memory_observations[0].unresolved
    assert not result.memory_observations[0].strong_update


def test_missing_global_destination_havocs_compatible_globals():
    global_object = object_("unresolved-global", 1, "global")
    item = summary(
        "unresolved_global",
        0x1C0,
        "global",
        memory=(
            MemoryEffect(
                "global_write",
                "global",
                "argument",
                MemoryExtent(fixed_bytes=1),
                target_rva=0xDEAD,
                source_index=0,
            ),
        ),
    )
    result = compose_call(
        direct(item, "unresolved-global-caller", 0x2C0),
        CallInputs(
            (value(8, 0x55),),
            state(
                (global_object,),
                (
                    CallMemoryByte(
                        global_object.object_id, 0, BitValue(8, 0x11), Labels()
                    ),
                ),
            ),
        ),
    )
    assert result.status == "partial"
    assert result.state.havoced_objects == (global_object.object_id,)
    assert "summary_memory_target_unresolved" in result.diagnostics


def test_big_endian_fill_repeats_scalar_low_byte():
    destination = object_("big-endian-fill", 4)
    argument_fill = summary(
        "big_endian_argument_fill",
        0x1D0,
        "fill",
        memory=(
            MemoryEffect(
                "fill",
                "argument",
                "argument",
                MemoryExtent(fixed_bytes=4),
                target_index=0,
                source_index=1,
            ),
        ),
    )
    argument_result = compose_call(
        direct(argument_fill, "big-endian-fill-caller", 0x2D0),
        CallInputs(
            (
                value(64, pointer=pointer(destination)),
                value(32, 0x12345678, "FILL"),
            ),
            state((destination,)),
        ),
        CallCompositionPolicy(endian="big"),
    )
    assert [item.value.value for item in bytes_for(argument_result, destination)] == [
        0x78
    ] * 4
    assert all(
        item.labels.explicit == ("FILL",)
        for item in bytes_for(argument_result, destination)
    )

    constant_fill = summary(
        "big_endian_constant_fill",
        0x1E0,
        "fill",
        memory=(
            MemoryEffect(
                "fill",
                "argument",
                "constant",
                MemoryExtent(fixed_bytes=4),
                target_index=0,
                constant=0x12345678,
            ),
        ),
    )
    constant_result = compose_call(
        direct(constant_fill, "big-endian-fill-caller", 0x2E0),
        CallInputs((value(64, pointer=pointer(destination)),), state((destination,))),
        CallCompositionPolicy(endian="big"),
    )
    assert [item.value.value for item in bytes_for(constant_result, destination)] == [
        0x78
    ] * 4


def test_c02_contexts_do_not_mix_shared_callee_arguments():
    item = summary(
        "call_identity",
        0x100,
        "identity",
        (ReturnEffect("argument", 32, argument_index=0),),
    )
    left = compose_call(
        direct(item, "call_context_left", 0x300),
        CallInputs((value(32, label="LEFT"),)),
    )
    right = compose_call(
        direct(item, "call_context_right", 0x340),
        CallInputs((value(32, label="RIGHT"),)),
    )
    assert left.branches[0].context_digest != right.branches[0].context_digest
    assert left.return_value.labels.explicit == ("LEFT",)
    assert right.return_value.labels.explicit == ("RIGHT",)


def test_c03_recursion_boundary_is_partial_and_opaque():
    recursive = summary(
        "call_recursive",
        0x300,
        "identity",
        (ReturnEffect("argument", 32, argument_index=0),),
    )
    base = direct(recursive, "call_recursive", 0x318)
    limited = plan_direct_call(
        catalog(recursive),
        base.site,
        base.branches[0].context,
        recursive.identity,
        POLICY,
    )
    result = compose_call(
        limited,
        CallInputs((value(32, label="X"),)),
        CallCompositionPolicy(unknown_return_width_bits=32),
    )
    assert result.status == "partial"
    assert "recursion_limit" in result.diagnostics
    assert result.return_value.labels.unknown_provenance
    assert {item.kind for item in result.evidence} == {
        "call_argument",
        "call_return",
        "opaque_effect",
    }


def test_c04_candidate_join_is_order_independent_and_retains_distinct_effects():
    destination = object_("candidate-join-destination", 1)
    first = summary(
        "call_candidate_first",
        0x400,
        "identity",
        (ReturnEffect("argument", 32, argument_index=0),),
        memory=(
            MemoryEffect(
                "output",
                "argument",
                "constant",
                MemoryExtent(fixed_bytes=1),
                target_index=2,
                constant=0x11,
            ),
        ),
    )
    second = summary(
        "call_candidate_second",
        0x440,
        "identity",
        (ReturnEffect("argument", 32, argument_index=1),),
        memory=(
            MemoryEffect(
                "output",
                "argument",
                "constant",
                MemoryExtent(fixed_bytes=1),
                target_index=2,
                constant=0x22,
            ),
        ),
    )

    def composed(candidates, *, exhaustive):
        plan = plan_indirect_call(
            catalog(first, second),
            CallSite(SNAPSHOT, "call_indirect", 0x480, "indirect"),
            CallContext(),
            tuple(item.identity for item in candidates),
            exhaustive=exhaustive,
            policy=POLICY,
        )
        return compose_call(
            plan,
            CallInputs(
                (
                    value(32, 0x11, "FIRST"),
                    value(32, 0x22, "SECOND"),
                    value(64, pointer=pointer(destination)),
                ),
                state((destination,)),
            ),
        )

    forward = composed((first, second), exhaustive=True)
    reverse = composed((second, first), exhaustive=True)
    assert forward == reverse
    assert len(forward.branches) == 2
    assert forward.return_value.value.value is None
    assert forward.return_value.labels == Labels(("FIRST", "SECOND"))
    assert bytes_for(forward, destination)[0].value.value is None
    assert {
        bytes_for(branch, destination)[0].value.value for branch in forward.branches
    } == {0x11, 0x22}
    assert forward.status == "complete_in_scope"

    partial_forward = composed((first, second), exhaustive=False)
    partial_reverse = composed((second, first), exhaustive=False)
    assert partial_forward == partial_reverse
    assert partial_forward.return_value.labels.explicit == ("FIRST", "SECOND")
    assert partial_forward.return_value.labels.unknown_provenance
    assert partial_forward.status == "partial"
    assert any(item.kind == "opaque_effect" for item in partial_forward.evidence)
    assert CallCompositionResult.from_json(canonical_json(partial_forward)) == (
        partial_forward
    )


def test_unknown_call_havocs_globals_without_pointer_arguments():
    global_object = object_("opaque-call-global", 1, "global")
    unknown = plan_indirect_call(
        SummaryCatalog(()),
        CallSite(SNAPSHOT, "opaque-global-caller", 0x4A0, "indirect"),
        CallContext(),
        (),
        exhaustive=False,
        policy=POLICY,
    )
    result = compose_call(
        unknown,
        CallInputs(
            (),
            state(
                (global_object,),
                (
                    CallMemoryByte(
                        global_object.object_id,
                        0,
                        BitValue(8, 0xAA),
                        Labels(("GLOBAL",)),
                    ),
                ),
                (CallGlobalBinding(0xA000, global_object.object_id),),
            ),
        ),
    )
    assert result.state.havoced_objects == (global_object.object_id,)
    byte = bytes_for(result, global_object)[0]
    assert byte.value.value is None
    assert byte.labels.explicit == ("GLOBAL",)
    assert byte.labels.unknown_provenance
    assert result.memory_observations[0].targets == (
        CallMemoryTarget(global_object.object_id, None),
    )


def test_unknown_call_conservatively_havocs_transitive_compatible_state():
    root = object_("opaque-call-root", 1)
    indirect = object_("opaque-call-indirect", 1, "heap")
    unknown = plan_indirect_call(
        SummaryCatalog(()),
        CallSite(SNAPSHOT, "opaque-transitive-caller", 0x4B0, "indirect"),
        CallContext(),
        (),
        exhaustive=False,
        policy=POLICY,
    )
    result = compose_call(
        unknown,
        CallInputs(
            (value(64, pointer=pointer(root)),),
            state(
                (root, indirect),
                (
                    CallMemoryByte(
                        indirect.object_id,
                        0,
                        BitValue(8, 0xBB),
                        Labels(("INDIRECT",)),
                    ),
                ),
                heap=(HeapObjectState(indirect.object_id, Lifetime()),),
            ),
        ),
    )
    assert result.state.havoced_objects == tuple(
        sorted((root.object_id, indirect.object_id))
    )
    byte = bytes_for(result, indirect)[0]
    assert byte.value.value is None and byte.labels.unknown_provenance
    lifetime = heap_lifetime(result, indirect.object_id)
    assert {"live", "freed", "not_allocated"} <= set(lifetime.possible)
    assert lifetime.escape == "unknown"


def test_unknown_call_havocs_compatible_children_of_nonlocal_heap_roots():
    root = object_("opaque-call-nonlocal-root", 1, "heap")
    compatible = object_("opaque-call-compatible-child", 1, "heap")
    isolated = object_("opaque-call-isolated-child", 1, "heap", "io")
    unknown = plan_indirect_call(
        SummaryCatalog(()),
        CallSite(SNAPSHOT, "opaque-nonlocal-caller", 0x4B8, "indirect"),
        CallContext(),
        (),
        exhaustive=False,
        policy=POLICY,
    )

    for escape in ("escaped", "unknown"):
        result = compose_call(
            unknown,
            CallInputs(
                (),
                state(
                    (root, compatible, isolated),
                    (
                        CallMemoryByte(
                            root.object_id,
                            0,
                            BitValue(8, 0xAA),
                            Labels(("ROOT",)),
                        ),
                        CallMemoryByte(
                            compatible.object_id,
                            0,
                            BitValue(8, 0xBB),
                            Labels(("CHILD",)),
                        ),
                        CallMemoryByte(
                            isolated.object_id,
                            0,
                            BitValue(8, 0xCC),
                            Labels(("ISOLATED",)),
                        ),
                    ),
                    heap=(
                        HeapObjectState(root.object_id, Lifetime(("live",), escape)),
                        HeapObjectState(compatible.object_id, Lifetime()),
                        HeapObjectState(isolated.object_id, Lifetime()),
                    ),
                ),
            ),
        )

        reachable = tuple(sorted((root.object_id, compatible.object_id)))
        assert result.state.havoced_objects == reachable
        assert result.memory_observations[0].targets == tuple(
            CallMemoryTarget(object_id, None) for object_id in reachable
        )
        for item, label in ((root, "ROOT"), (compatible, "CHILD")):
            byte = bytes_for(result, item)[0]
            assert byte.value.value is None
            assert byte.labels.explicit == (label,)
            assert byte.labels.unknown_provenance
            assert heap_lifetime(result, item.object_id) == Lifetime(
                ("freed", "live", "not_allocated"), "unknown"
            )
        isolated_byte = bytes_for(result, isolated)[0]
        assert isolated_byte.value.value == 0xCC
        assert isolated_byte.labels == Labels(("ISOLATED",))
        assert heap_lifetime(result, isolated.object_id) == Lifetime()


def test_argument_resolved_global_publication_escapes_and_is_reachable():
    global_object = object_("argument-published-global", 8, "global")
    published_heap = object_("argument-published-heap", 8, "heap")
    compatible = object_("argument-published-compatible", 8)
    isolated = object_("argument-published-isolated", 1, address_space="io")
    publish = summary(
        "argument_publish",
        0x4C0,
        "output",
        memory=(
            MemoryEffect(
                "output",
                "argument",
                "argument",
                MemoryExtent(fixed_bytes=8),
                target_index=0,
                source_index=1,
            ),
        ),
    )
    initial_state = state(
        (global_object, published_heap, compatible, isolated),
        (
            CallMemoryByte(
                published_heap.object_id,
                0,
                BitValue(8, 0x55),
                Labels(("HEAP",)),
            ),
            CallMemoryByte(
                compatible.object_id,
                0,
                BitValue(8, 0x66),
                Labels(("COMPATIBLE",)),
            ),
            CallMemoryByte(
                isolated.object_id,
                0,
                BitValue(8, 0x77),
                Labels(("ISOLATED",)),
            ),
        ),
        heap=(HeapObjectState(published_heap.object_id, Lifetime()),),
    )
    published = compose_call(
        direct(publish, "argument-publish-caller", 0x4D0),
        CallInputs(
            (
                value(64, pointer=pointer(global_object)),
                value(64, 0x1234, pointer=pointer(published_heap)),
            ),
            initial_state,
        ),
    )
    assert heap_lifetime(published, published_heap.object_id).escape == "escaped"
    assert any(item.kind == "escape" for item in published.heap_observations)

    ambiguous_destination = PointerValue(
        "ram",
        64,
        tuple(
            sorted(
                (
                    PointerCandidate(global_object.object_id, 0),
                    PointerCandidate(compatible.object_id, 0),
                ),
                key=lambda item: item.object_id,
            )
        ),
    )
    ambiguous = compose_call(
        direct(publish, "argument-publish-caller", 0x4D8),
        CallInputs(
            (
                value(64, pointer=ambiguous_destination),
                value(64, 0x1234, pointer=pointer(published_heap)),
            ),
            initial_state,
        ),
    )
    assert heap_lifetime(ambiguous, published_heap.object_id).escape == "unknown"
    assert ambiguous.heap_observations[0].unresolved
    assert ambiguous.heap_observations[0].precision == "opaque"
    assert not ambiguous.heap_observations[0].transitions[0].strong_update
    assert ambiguous.status == "partial"
    assert "summary_escape_unresolved" in ambiguous.diagnostics

    partial_publish = summary(
        "partial_argument_publish",
        0x4C8,
        "output",
        memory=(
            MemoryEffect(
                "output",
                "argument",
                "argument",
                MemoryExtent(fixed_bytes=1),
                target_index=0,
                source_index=1,
            ),
        ),
    )
    partial = compose_call(
        direct(partial_publish, "argument-publish-caller", 0x4DC),
        CallInputs(
            (
                value(64, pointer=pointer(global_object)),
                value(64, 0x1234, pointer=pointer(published_heap)),
            ),
            initial_state,
        ),
    )
    assert heap_lifetime(partial, published_heap.object_id).escape == "unknown"
    assert partial.heap_observations[0].unresolved
    assert partial.heap_observations[0].precision == "opaque"
    assert not partial.heap_observations[0].transitions[0].strong_update
    assert partial.status == "partial"
    assert "summary_escape_unresolved" in partial.diagnostics

    fill_publish = summary(
        "fill_argument_publish",
        0x4CC,
        "fill",
        memory=(
            MemoryEffect(
                "fill",
                "argument",
                "argument",
                MemoryExtent(fixed_bytes=8),
                target_index=0,
                source_index=1,
            ),
        ),
    )
    filled = compose_call(
        direct(fill_publish, "argument-publish-caller", 0x4DE),
        CallInputs(
            (
                value(64, pointer=pointer(global_object)),
                value(64, 0x1234, pointer=pointer(published_heap)),
            ),
            initial_state,
        ),
    )
    assert heap_lifetime(filled, published_heap.object_id).escape == "unknown"
    assert filled.heap_observations[0].unresolved
    assert filled.heap_observations[0].precision == "opaque"
    assert not filled.heap_observations[0].transitions[0].strong_update
    assert filled.status == "partial"
    assert "summary_escape_unresolved" in filled.diagnostics

    unknown_source = compose_call(
        direct(publish, "argument-publish-caller", 0x4DF),
        CallInputs(
            (
                value(64, pointer=pointer(global_object)),
                CallValue(BitValue(64), Labels(unknown_provenance=True)),
            ),
            initial_state,
        ),
    )
    assert heap_lifetime(unknown_source, published_heap.object_id).escape == "unknown"
    assert unknown_source.heap_observations[0].unresolved
    assert unknown_source.heap_observations[0].precision == "opaque"
    assert not unknown_source.heap_observations[0].transitions[0].strong_update
    assert unknown_source.status == "partial"
    assert "summary_escape_unresolved" in unknown_source.diagnostics

    unknown = plan_indirect_call(
        SummaryCatalog(()),
        CallSite(SNAPSHOT, "argument-publish-caller", 0x4E0, "indirect"),
        CallContext(),
        (),
        exhaustive=False,
        policy=POLICY,
    )
    widened = compose_call(unknown, CallInputs((), published.state))
    assert widened.state.havoced_objects == tuple(
        sorted(
            (
                global_object.object_id,
                published_heap.object_id,
                compatible.object_id,
            )
        )
    )
    assert bytes_for(widened, published_heap)[0].labels.unknown_provenance
    assert bytes_for(widened, compatible)[0].labels.unknown_provenance
    assert bytes_for(widened, isolated)[0].value.value == 0x77
    assert not bytes_for(widened, isolated)[0].labels.unknown_provenance
    assert heap_lifetime(widened, published_heap.object_id) == Lifetime(
        ("freed", "live", "not_allocated"), "unknown"
    )


def test_h01_h02_allocation_and_free_use_explicit_context_proofs():
    alloc = summary(
        "call_alloc",
        0x500,
        "alloc",
        returns=(ReturnEffect("allocation", 64),),
        lifetime=(LifetimeEffect("allocate", size_argument_index=0),),
    )
    free = summary(
        "call_free",
        0x540,
        "free",
        lifetime=(LifetimeEffect("free", pointer_argument_index=0),),
    )
    alloc_plan = direct(alloc, "call_heap_h01", 0x600)
    allocated = compose_call(
        alloc_plan,
        CallInputs(
            (value(64, 1),),
            allocation_proofs=(allocation_proof(alloc_plan, alloc),),
        ),
    )
    object_id = allocated.return_value.pointer.candidates[0].object_id
    assert heap_lifetime(allocated, object_id) == Lifetime(("live",), "local")
    freed = compose_call(
        direct(free, "call_heap_h01", 0x620),
        CallInputs((allocated.return_value,), allocated.state),
    )
    assert heap_lifetime(freed, object_id) == Lifetime(("freed",), "local")
    assert freed.heap_observations[0].transitions[0].strong_update

    left_plan = direct(alloc, "call_heap_h02", 0x700)
    left = compose_call(
        left_plan,
        CallInputs(
            (value(64, 1),),
            allocation_proofs=(allocation_proof(left_plan, alloc),),
        ),
    )
    right_plan = direct(alloc, "call_heap_h02", 0x720)
    right = compose_call(
        right_plan,
        CallInputs(
            (value(64, 1),),
            left.state,
            (allocation_proof(right_plan, alloc),),
        ),
    )
    left_id = left.return_value.pointer.candidates[0].object_id
    right_id = right.return_value.pointer.candidates[0].object_id
    assert left_id != right_id
    after_left_free = compose_call(
        direct(free, "call_heap_h02", 0x740),
        CallInputs((left.return_value,), right.state),
    )
    assert heap_lifetime(after_left_free, left_id).possible == ("freed",)
    assert heap_lifetime(after_left_free, right_id).possible == ("live",)

    without_proof = compose_call(
        direct(alloc, "looping-caller", 0x760),
        CallInputs((value(64, 1),)),
    )
    unproven = next(
        item
        for item in without_proof.state.objects
        if item.object_id == without_proof.return_value.pointer.candidates[0].object_id
    )
    assert not unproven.singleton


def test_h03_h04_escape_unknown_effect_and_branch_join_are_conservative():
    alloc = summary(
        "call_alloc",
        0x800,
        "alloc",
        returns=(ReturnEffect("allocation", 64),),
        lifetime=(LifetimeEffect("allocate", size_argument_index=0),),
    )
    free = summary(
        "call_free",
        0x840,
        "free",
        lifetime=(LifetimeEffect("free", pointer_argument_index=0),),
    )
    alloc_plan = direct(alloc, "call_heap_h03", 0x900)
    allocated = compose_call(
        alloc_plan,
        CallInputs(
            (value(64, 1),),
            allocation_proofs=(allocation_proof(alloc_plan, alloc),),
        ),
    )
    object_id = allocated.return_value.pointer.candidates[0].object_id
    global_object = object_("call_escaped_heap", 8, "global")
    escaped_state = CallState(
        tuple(
            sorted(
                allocated.state.objects + (global_object,),
                key=lambda item: item.object_id,
            )
        ),
        allocated.state.memory,
        allocated.state.havoced_objects,
        allocated.state.heap,
        (CallGlobalBinding(0xA000, global_object.object_id),),
    )
    escape = summary(
        "call_publish",
        0x880,
        "global",
        memory=(
            MemoryEffect(
                "global_write",
                "global",
                "argument",
                MemoryExtent(fixed_bytes=8),
                target_rva=0xA000,
                source_index=0,
            ),
        ),
    )
    escaped = compose_call(
        direct(escape, "call_heap_h03", 0x920),
        CallInputs((allocated.return_value,), escaped_state),
    )
    assert heap_lifetime(escaped, object_id).escape == "escaped"
    assert any(item.kind == "escape" for item in escaped.heap_observations)

    unknown = plan_indirect_call(
        SummaryCatalog(()),
        CallSite(SNAPSHOT, "call_heap_h03", 0x940, "indirect"),
        CallContext(),
        (),
        exhaustive=False,
        policy=POLICY,
    )
    widened = compose_call(
        unknown,
        CallInputs((allocated.return_value,), escaped.state),
    )
    assert {"live", "freed"} <= set(heap_lifetime(widened, object_id).possible)
    assert heap_lifetime(widened, object_id).escape == "unknown"
    assert widened.status == "partial"

    free_branch = compose_call(
        direct(free, "call_heap_h04", 0x980),
        CallInputs((allocated.return_value,), allocated.state),
    )
    joined = join_call_states((allocated.state, free_branch.state))
    lifetime = next(
        item.lifetime for item in joined.heap if item.object_id == object_id
    )
    assert lifetime == Lifetime(("freed", "live"), "local")

    text = canonical_json(widened).lower()
    assert not any(word in text for word in ("vulnerable", "safe", "cwe", "severity"))
    assert not any(
        word in {item.name for item in fields(HeapResult)}
        for word in ("vulnerable", "safe", "cwe", "severity")
    )
