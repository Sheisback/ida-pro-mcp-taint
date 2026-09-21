"""Semantic G011 replay over licensed static extraction receipts; never run targets."""

import hashlib
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path

from ida_pro_mcp.flow_core import canonical_json, digest
from ida_pro_mcp.flow_core.call_composition import (
    CallAllocationProof,
    CallCompositionResult,
    CallGlobalBinding,
    CallInputs,
    CallMemoryByte,
    CallState,
    CallValue,
    compose_call,
    join_call_states,
)
from ida_pro_mcp.flow_core.contracts import MemoryObject
from ida_pro_mcp.flow_core.interproc import CallContext, CallSite, plan_direct_call
from ida_pro_mcp.flow_core.states import (
    BitValue,
    Labels,
    Lifetime,
    PointerCandidate,
    PointerValue,
)
from ida_pro_mcp.flow_core.summaries import SummaryCatalog

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "tests/flow_fixtures/manifests/calls"


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load module: " + str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


EXTRACTOR_PATH = ROOT / "src/ida_pro_mcp/ida_mcp/flow/extractor.py"
CATALOG_PATH = ROOT / "src/ida_pro_mcp/ida_mcp/flow/summary_catalog.py"
extractor = load(EXTRACTOR_PATH, "g011_replay_extractor")
catalog_module = load(CATALOG_PATH, "g011_replay_catalog")


def value(bits, number=None, label=None, pointer=None):
    return CallValue(
        BitValue(bits, number),
        Labels((label,) if label else ()),
        pointer,
    )


def memory_object(snapshot_id, key, size, kind="argument"):
    return MemoryObject(
        snapshot_id,
        key,
        "ram",
        size,
        kind,
        True,
        "receipt singleton proof",
        True,
        "receipt disjoint identity",
    )


def pointer(item):
    return PointerValue("ram", 64, (PointerCandidate(item.object_id, 0),))


def state(objects, memory=(), globals_=(), heap=()):
    return CallState(
        tuple(sorted(objects, key=lambda item: item.object_id)),
        tuple(sorted(memory, key=lambda item: (item.object_id, item.offset))),
        (),
        tuple(sorted(heap, key=lambda item: item.object_id)),
        tuple(sorted(globals_, key=lambda item: item.rva)),
    )


def allocation_proof(binding):
    branch = binding.plan.branches[0]
    return CallAllocationProof(
        branch.summary.summary_digest,
        branch.context.context_digest,
        0,
        "static non-null one-shot observation path",
        "distinct extracted allocation call site",
        "non-null observation branch",
    )


def heap_lifetime(result, object_id):
    return next(
        item.lifetime for item in result.state.heap if item.object_id == object_id
    )


def memory_bytes(result, item):
    return [
        byte
        for byte in result.state.memory
        if byte.object_id == item.object_id
    ]


def binding_for(functions, function_name, summary_name=None, *, unknown=False, index=0):
    _, runtime, bindings, _ = functions[function_name]
    selected = []
    for binding in bindings:
        branch_names = tuple(
            branch.summary.display_name for branch in binding.plan.branches
        )
        if summary_name is not None and summary_name not in branch_names:
            continue
        if unknown and binding.plan.unknown_remainder is None:
            continue
        selected.append(binding)
    if index >= len(selected):
        raise ValueError(
            f"Missing extracted binding {function_name}:{summary_name}:{unknown}:{index}"
        )
    return runtime, selected[index]


def _reachable(blocks, start, target):
    pending = [start]
    visited = set()
    while pending:
        block_index = pending.pop()
        if block_index == target:
            return True
        if block_index in visited:
            continue
        visited.add(block_index)
        pending.extend(blocks[block_index].successors)
    return False


def _dominators(function):
    blocks = {block.index: block for block in function.blocks}
    all_blocks = set(blocks)
    dominators = {
        index: ({index} if index == function.entry_block else set(all_blocks))
        for index in blocks
    }
    changed = True
    while changed:
        changed = False
        for index, block in blocks.items():
            if index == function.entry_block:
                continue
            inherited = (
                set.intersection(*(dominators[value] for value in block.predecessors))
                if block.predecessors
                else set()
            )
            updated = {index} | inherited
            if updated != dominators[index]:
                dominators[index] = updated
                changed = True
    return dominators


def h02_proven_left_free(functions):
    """Select the H02 normal-path left free from static CFG evidence."""

    _, runtime, bindings, _ = functions["call_heap_h02"]
    blocks = {block.index: block for block in runtime.snapshot.function.blocks}
    allocations = [
        binding
        for binding in bindings
        if any(
            branch.summary.display_name == "call_alloc"
            for branch in binding.plan.branches
        )
    ]
    frees = [
        binding
        for binding in bindings
        if any(
            branch.summary.display_name == "call_free"
            for branch in binding.plan.branches
        )
    ]
    if len(allocations) != 2 or len(frees) != 4:
        raise ValueError("H02 needs exactly two allocations and four static frees")
    cleanup = [
        binding
        for binding in frees
        if len(blocks[binding.observation["block_index"]].predecessors) > 1
    ]
    if len(cleanup) != 1:
        raise ValueError("H02 cleanup convergence is not uniquely proven")
    cleanup_block = cleanup[0].observation["block_index"]
    normal_frees = [
        binding
        for binding in frees
        if not _reachable(
            blocks, cleanup_block, binding.observation["block_index"]
        )
    ]
    if len(normal_frees) != 2:
        raise ValueError("H02 normal two-free path is not uniquely proven")
    first = [
        binding
        for binding in normal_frees
        if any(
            other is not binding
            and _reachable(
                blocks,
                binding.observation["block_index"],
                other.observation["block_index"],
            )
            for other in normal_frees
        )
    ]
    if len(first) != 1:
        raise ValueError("H02 left-before-right free order is not uniquely proven")
    selected = first[0]
    later = next(binding for binding in normal_frees if binding is not selected)
    dominators = _dominators(runtime.snapshot.function)
    allocation_blocks = {
        binding.observation["block_index"] for binding in allocations
    }
    if not allocation_blocks <= dominators[selected.observation["block_index"]]:
        raise ValueError("H02 selected free is not dominated by both allocations")
    return runtime, selected, {
        "selection": "two_allocations_dominate_and_cleanup_path_excluded",
        "allocation_instruction_rvas": sorted(
            binding.site.instruction_rva for binding in allocations
        ),
        "cleanup_first_free_instruction_rva": cleanup[0].site.instruction_rva,
        "selected_left_free_instruction_rva": selected.site.instruction_rva,
        "later_right_free_instruction_rva": later.site.instruction_rva,
        "selected_block_index": selected.observation["block_index"],
    }


def entrypoint_plan(functions, catalog, summary_name):
    _, function, _, _ = functions[summary_name]
    matches = tuple(
        summary for summary in catalog.summaries if summary.display_name == summary_name
    )
    if len(matches) != 1:
        raise ValueError("Reviewed entrypoint identity is not unique: " + summary_name)
    summary = matches[0]
    site = CallSite(
        function.snapshot.snapshot_id,
        function.snapshot.function.function_id,
        function.function_rva,
        "direct",
    )
    return plan_direct_call(
        catalog,
        site,
        CallContext(),
        summary.identity,
        catalog_module.DEFAULT_CALL_POLICY,
    )


def semantic_cases(functions, catalog):
    callee_snapshots = {
        baseline.function_rva: baseline.snapshot
        for baseline, _, _, _ in functions.values()
    }

    def compose(function, binding, **kwargs):
        return catalog_module.compose_binding(
            function,
            binding,
            catalog,
            callee_snapshots=callee_snapshots,
            **kwargs,
        )

    # C01 identity is an actual extracted direct call. Copy/fill/output/global have
    # no native callers in this fixture, so their reviewed entrypoint identities
    # are composed explicitly and reported as such rather than mislabeled as calls.
    identity_function, identity_binding = binding_for(
        functions, "call_context_left", "call_identity"
    )
    identity = compose(
        identity_function,
        identity_binding,
        inputs=CallInputs((value(32, label="X"),)),
    )
    if identity.return_value.labels.explicit != ("X",):
        raise ValueError("C01 identity return provenance mismatch")

    _, copy_function, _, _ = functions["call_copy"]
    destination = memory_object(copy_function.snapshot.snapshot_id, "c01-destination", 4)
    source = memory_object(copy_function.snapshot.snapshot_id, "c01-source", 4)
    seeded = state(
        (destination, source),
        tuple(
            CallMemoryByte(
                source.object_id,
                offset,
                BitValue(8, offset),
                Labels(("Y",)),
            )
            for offset in range(4)
        ),
    )
    copied = compose_call(
        entrypoint_plan(functions, catalog, "call_copy"),
        CallInputs(
            (
                value(64, pointer=pointer(destination)),
                value(64, pointer=pointer(source)),
                value(64, 4),
            ),
            seeded,
        ),
    )
    copied_bytes = memory_bytes(copied, destination)
    if [item.value.value for item in copied_bytes] != [0, 1, 2, 3] or not all(
        item.labels.explicit == ("Y",) for item in copied_bytes
    ):
        raise ValueError("C01 copy semantics mismatch")

    _, fill_function, _, _ = functions["call_fill"]
    fill_destination = memory_object(
        fill_function.snapshot.snapshot_id, "c01-fill-destination", 4
    )
    filled = compose_call(
        entrypoint_plan(functions, catalog, "call_fill"),
        CallInputs(
            (
                value(64, pointer=pointer(fill_destination)),
                value(8, 0x5A, "Z"),
                value(64, 4),
            ),
            state((fill_destination,)),
        ),
    )
    filled_bytes = memory_bytes(filled, fill_destination)
    if [item.value.value for item in filled_bytes] != [0x5A] * 4 or not all(
        item.labels.explicit == ("Z",) for item in filled_bytes
    ):
        raise ValueError("C01 fill semantics mismatch")

    _, output_function, _, _ = functions["call_output"]
    output = memory_object(output_function.snapshot.snapshot_id, "c01-output", 4)
    output_result = compose_call(
        entrypoint_plan(functions, catalog, "call_output"),
        CallInputs(
            (
                value(64, pointer=pointer(output)),
                value(32, 0x44332211, "O"),
            ),
            state((output,)),
        ),
    )
    output_bytes = memory_bytes(output_result, output)
    if [item.value.value for item in output_bytes] != [0x11, 0x22, 0x33, 0x44]:
        raise ValueError("C01 output memory semantics mismatch")
    if output_result.return_value is not None:
        raise ValueError("C01 output invented a return value")

    global_plan = entrypoint_plan(functions, catalog, "call_global")
    global_effect = global_plan.branches[0].summary.memory_effects[0]
    global_rva = global_effect.target_rva
    if global_rva is None:
        raise ValueError("C01 global summary lost its target RVA")
    _, global_function, _, _ = functions["call_global"]
    global_object = memory_object(
        global_function.snapshot.snapshot_id,
        "c01-global",
        4,
        "global",
    )
    global_result = compose_call(
        global_plan,
        CallInputs(
            (value(32, 7, "G"),),
            state(
                (global_object,),
                globals_=(CallGlobalBinding(global_rva, global_object.object_id),),
            ),
        ),
    )
    if (
        global_result.return_value.value.value != 7
        or global_result.return_value.labels.explicit != ("G",)
        or global_result.memory_observations[0].operation != "global_write"
    ):
        raise ValueError("C01 global write/read semantics mismatch")

    left_function, left_binding = binding_for(
        functions, "call_context_left", "call_identity"
    )
    right_function, right_binding = binding_for(
        functions, "call_context_right", "call_identity"
    )
    left = compose(
        left_function,
        left_binding,
        inputs=CallInputs((value(32, label="LEFT"),)),
    )
    right = compose(
        right_function,
        right_binding,
        inputs=CallInputs((value(32, label="RIGHT"),)),
    )
    if left.branches[0].context_digest == right.branches[0].context_digest:
        raise ValueError("C02 call contexts collapsed")
    if left.return_value.labels.explicit != ("LEFT",):
        raise ValueError("C02 left return provenance mixed")
    if right.return_value.labels.explicit != ("RIGHT",):
        raise ValueError("C02 right return provenance mixed")

    base_function, base_binding = binding_for(
        functions, "call_recursive", "call_identity"
    )
    base = compose(
        base_function,
        base_binding,
        inputs=CallInputs((value(32, label="X"),)),
    )
    recursive_function, recursive_binding = binding_for(
        functions, "call_recursive", unknown=True
    )
    recursive = compose(
        recursive_function,
        recursive_binding,
        inputs=CallInputs(
            (value(32, label="X"), value(32, label="DEPTH"))
        ),
    )
    if base.return_value.labels.explicit != ("X",):
        raise ValueError("C03 base return provenance mismatch")
    if recursive.status != "partial" or not recursive.return_value.labels.unknown_provenance:
        raise ValueError("C03 recursive remainder was not composed as partial")
    if "missing_reviewed_summary" not in recursive.diagnostics:
        raise ValueError("C03 recursive boundary disappeared")

    indirect_function, indirect_binding = binding_for(
        functions, "call_indirect", unknown=True
    )
    indirect_width = indirect_function.calls[
        tuple(indirect_function.calls).index(
            next(
                observation
                for observation in indirect_function.calls
                if observation.to_data() == indirect_binding.observation
            )
        )
    ].call.arguments[0].width_bits
    if indirect_width is None:
        raise ValueError("C04 extracted argument width unavailable")
    indirect = compose(
        indirect_function,
        indirect_binding,
        inputs=CallInputs((value(indirect_width, label="X"),)),
    )
    if indirect.status != "partial" or not indirect.return_value.labels.unknown_provenance:
        raise ValueError("C04 unknown remainder was not composed")
    if indirect_binding.plan.branches:
        raise ValueError("C04 incompatible reviewed candidates were not rejected")
    if indirect.return_value.labels.explicit:
        raise ValueError("C04 unknown return retained rejected-candidate provenance")

    h01_function, h01_alloc_binding = binding_for(
        functions, "call_heap_h01", "call_alloc"
    )
    h01_allocated = compose(
        h01_function,
        h01_alloc_binding,
        inputs=CallInputs(
            (value(64, 1),),
            allocation_proofs=(allocation_proof(h01_alloc_binding),),
        ),
    )
    h01_id = h01_allocated.return_value.pointer.candidates[0].object_id
    h01_free_function, h01_free_binding = binding_for(
        functions, "call_heap_h01", "call_free"
    )
    h01_freed = compose(
        h01_free_function,
        h01_free_binding,
        inputs=CallInputs((h01_allocated.return_value,), h01_allocated.state),
    )
    if heap_lifetime(h01_freed, h01_id) != Lifetime(("freed",), "local"):
        raise ValueError("H01 allocation was not freed")

    h02_function, h02_left_binding = binding_for(
        functions, "call_heap_h02", "call_alloc", index=0
    )
    _, h02_right_binding = binding_for(
        functions, "call_heap_h02", "call_alloc", index=1
    )
    h02_left = compose(
        h02_function,
        h02_left_binding,
        inputs=CallInputs(
            (value(64, 1),),
            allocation_proofs=(allocation_proof(h02_left_binding),),
        ),
    )
    h02_right = compose(
        h02_function,
        h02_right_binding,
        inputs=CallInputs(
            (value(64, 1),),
            h02_left.state,
            (allocation_proof(h02_right_binding),),
        ),
    )
    h02_left_id = h02_left.return_value.pointer.candidates[0].object_id
    h02_right_id = h02_right.return_value.pointer.candidates[0].object_id
    if h02_left_id == h02_right_id:
        raise ValueError("H02 allocation contexts collapsed")
    h02_free_function, h02_free_binding, h02_free_proof = h02_proven_left_free(
        functions
    )
    h02_after_left_free = compose(
        h02_free_function,
        h02_free_binding,
        inputs=CallInputs((h02_left.return_value,), h02_right.state),
    )
    if heap_lifetime(h02_after_left_free, h02_left_id).possible != ("freed",):
        raise ValueError("H02 left allocation was not freed")
    if heap_lifetime(h02_after_left_free, h02_right_id).possible != ("live",):
        raise ValueError("H02 right allocation lifetime mixed with left")

    h03_function, h03_alloc_binding = binding_for(
        functions, "call_heap_h03", "call_alloc"
    )
    h03_allocated = compose(
        h03_function,
        h03_alloc_binding,
        inputs=CallInputs(
            (value(64, 1),),
            allocation_proofs=(allocation_proof(h03_alloc_binding),),
        ),
    )
    h03_id = h03_allocated.return_value.pointer.candidates[0].object_id
    h03_unknown_function, h03_unknown_binding = binding_for(
        functions, "call_heap_h03", unknown=True
    )
    h03_unknown = compose(
        h03_unknown_function,
        h03_unknown_binding,
        inputs=CallInputs((h03_allocated.return_value,), h03_allocated.state),
    )
    h03_lifetime = heap_lifetime(h03_unknown, h03_id)
    if not {"live", "freed"} <= set(h03_lifetime.possible):
        raise ValueError("H03 unknown call did not widen heap lifetime")
    if h03_lifetime.escape != "unknown" or h03_unknown.status != "partial":
        raise ValueError("H03 unknown reachable effect lost escape/partial state")

    h04_function, h04_alloc_binding = binding_for(
        functions, "call_heap_h04", "call_alloc"
    )
    h04_allocated = compose(
        h04_function,
        h04_alloc_binding,
        inputs=CallInputs(
            (value(64, 1),),
            allocation_proofs=(allocation_proof(h04_alloc_binding),),
        ),
    )
    h04_id = h04_allocated.return_value.pointer.candidates[0].object_id
    h04_free_function, h04_free_binding = binding_for(
        functions, "call_heap_h04", "call_free"
    )
    h04_freed = compose(
        h04_free_function,
        h04_free_binding,
        inputs=CallInputs((h04_allocated.return_value,), h04_allocated.state),
    )
    h04_joined = join_call_states((h04_allocated.state, h04_freed.state))
    h04_lifetime = next(
        item.lifetime for item in h04_joined.heap if item.object_id == h04_id
    )
    if h04_lifetime != Lifetime(("freed", "live"), "local"):
        raise ValueError("H04 live/free branch join mismatch")

    return {
        "C01": {
            "identity_return_labels": list(identity.return_value.labels.explicit),
            "copy_destination_values": [item.value.value for item in copied_bytes],
            "copy_destination_labels": sorted(
                {label for item in copied_bytes for label in item.labels.explicit}
            ),
            "fill_destination_values": [item.value.value for item in filled_bytes],
            "fill_destination_labels": sorted(
                {label for item in filled_bytes for label in item.labels.explicit}
            ),
            "output_values": [item.value.value for item in output_bytes],
            "output_return": None,
            "global_return_value": global_result.return_value.value.value,
            "global_return_labels": list(global_result.return_value.labels.explicit),
            "global_memory_operation": global_result.memory_observations[0].operation,
            "reviewed_entrypoint_only": [
                "call_copy",
                "call_fill",
                "call_output",
                "call_global",
            ],
            "composition_digests": {
                "identity": digest(identity),
                "copy": digest(copied),
                "fill": digest(filled),
                "output": digest(output_result),
                "global": digest(global_result),
            },
        },
        "C02": {
            "left_context": left.branches[0].context_digest,
            "right_context": right.branches[0].context_digest,
            "left_return_labels": list(left.return_value.labels.explicit),
            "right_return_labels": list(right.return_value.labels.explicit),
            "composition_digests": [digest(left), digest(right)],
        },
        "C03": {
            "base_return_labels": list(base.return_value.labels.explicit),
            "recursive_status": recursive.status,
            "recursive_diagnostics": list(recursive.diagnostics),
            "recursive_unknown_provenance": recursive.return_value.labels.unknown_provenance,
            "composition_digests": [digest(base), digest(recursive)],
        },
        "C04": {
            "reviewed_branches": [
                branch.summary.display_name for branch in indirect_binding.plan.branches
            ],
            "status": indirect.status,
            "return_labels": list(indirect.return_value.labels.explicit),
            "unknown_provenance": indirect.return_value.labels.unknown_provenance,
            "diagnostics": list(indirect.diagnostics),
            "composition_digest": digest(indirect),
        },
        "H01": {
            "object_id": h01_id,
            "post_free_lifetime": list(heap_lifetime(h01_freed, h01_id).possible),
            "composition_digests": [digest(h01_allocated), digest(h01_freed)],
        },
        "H02": {
            "left_object_id": h02_left_id,
            "right_object_id": h02_right_id,
            "after_left_free": {
                "left": list(heap_lifetime(h02_after_left_free, h02_left_id).possible),
                "right": list(heap_lifetime(h02_after_left_free, h02_right_id).possible),
            },
            "composition_digests": [
                digest(h02_left),
                digest(h02_right),
                digest(h02_after_left_free),
            ],
            "selected_free_site": h02_free_proof,
        },
        "H03": {
            "object_id": h03_id,
            "post_call_lifetime": list(h03_lifetime.possible),
            "post_call_escape": h03_lifetime.escape,
            "status": h03_unknown.status,
            "havoced_objects": list(h03_unknown.state.havoced_objects),
            "composition_digests": [digest(h03_allocated), digest(h03_unknown)],
        },
        "H04": {
            "object_id": h04_id,
            "join_lifetime": list(h04_lifetime.possible),
            "composition_digests": [digest(h04_allocated), digest(h04_freed)],
        },
    }


def receipt(arch):
    extraction_path = BASE / f"extraction_{arch}.json"
    extraction = json.loads(extraction_path.read_text())
    if extraction["target_executed"] is not False:
        raise ValueError("Static extraction receipt executed the target")
    if extraction["extractor_sha256"] != hashlib.sha256(
        EXTRACTOR_PATH.read_bytes()
    ).hexdigest():
        raise ValueError("Stale call extractor receipt")
    if extraction["catalog_module_sha256"] != hashlib.sha256(
        CATALOG_PATH.read_bytes()
    ).hexdigest():
        raise ValueError("Stale call catalog receipt")
    catalog = SummaryCatalog.from_data(extraction["catalog"])
    if catalog.catalog_digest != extraction["catalog_digest"]:
        raise ValueError("Catalog digest mismatch")
    callee_snapshots = {
        record["rva"]: extractor.ExtractedFunction.from_data(
            record["baseline"]
        ).snapshot
        for record in extraction["functions"]
    }
    functions = {}
    actual_compositions = []
    for record in extraction["functions"]:
        baseline = extractor.ExtractedFunction.from_data(record["baseline"])
        runtime = extractor.ExtractedFunction.from_data(record["runtime"])
        if digest(baseline) != record["baseline_digest"]:
            raise ValueError("Baseline extraction digest mismatch")
        if digest(runtime) != record["runtime_digest"]:
            raise ValueError("Runtime extraction digest mismatch")
        if runtime.snapshot.identity.summary_digest != catalog.catalog_digest:
            raise ValueError("Runtime snapshot/catalog mismatch")
        if extractor.ExtractedFunction.from_json(canonical_json(runtime)) != runtime:
            raise ValueError("Runtime extraction roundtrip failed")
        bindings = tuple(
            catalog_module.CallBinding.from_data(value)
            for value in record["bindings"]
        )
        if any(binding.plan.catalog_digest != catalog.catalog_digest for binding in bindings):
            raise ValueError("Call plan/catalog mismatch")
        compositions = tuple(
            CallCompositionResult.from_data(value)
            for value in record["compositions"]
        )
        if len(bindings) != len(compositions):
            raise ValueError("Extracted binding/composition count mismatch")
        for binding, stored in zip(bindings, compositions):
            recomputed = catalog_module.compose_binding(
                runtime,
                binding,
                catalog,
                callee_snapshots=callee_snapshots,
            )
            if recomputed != stored:
                raise ValueError("Stored extracted-call composition mismatch")
            actual_compositions.append(stored)
        functions[record["name"]] = (baseline, runtime, bindings, compositions)

    left = functions["call_context_left"][2][0].plan.branches[0]
    right = functions["call_context_right"][2][0].plan.branches[0]
    if left.context.context_digest == right.context.context_digest:
        raise ValueError("C02 call contexts collapsed")
    recursive = functions["call_recursive"][2]
    recursive_reasons = sorted(
        {
            reason
            for binding in recursive
            if binding.plan.unknown_remainder is not None
            for reason in binding.plan.unknown_remainder.reasons
        }
    )
    if "missing_reviewed_summary" not in recursive_reasons:
        raise ValueError("C03 recursive boundary disappeared")
    indirect = functions["call_indirect"][2]
    if not indirect or not all(
        binding.plan.unknown_remainder is not None
        and "nonexhaustive_indirect" in binding.plan.unknown_remainder.reasons
        for binding in indirect
    ):
        raise ValueError("C04 unknown remainder disappeared")
    indirect_branches = sorted(
        {
            branch.summary.display_name
            for binding in indirect
            for branch in binding.plan.branches
        }
    )
    if indirect_branches:
        raise ValueError("C04 incompatible reviewed branch was accepted")

    plans = [
        binding.plan
        for _, _, bindings, _ in functions.values()
        for binding in bindings
    ]
    branch_counts = Counter(
        branch.summary.display_name for plan in plans for branch in plan.branches
    )
    remainder_counts = Counter(
        reason
        for plan in plans
        if plan.unknown_remainder is not None
        for reason in plan.unknown_remainder.reasons
    )
    heap_sequences = {
        name: [
            [branch.summary.display_name for branch in binding.plan.branches]
            for binding in functions[name][2]
        ]
        for name in ("call_heap_h01", "call_heap_h02", "call_heap_h03", "call_heap_h04")
    }
    if heap_sequences["call_heap_h01"] != [["call_alloc"], ["call_free"]]:
        raise ValueError("H01 allocation/free binding mismatch")
    if sum(row == ["call_alloc"] for row in heap_sequences["call_heap_h02"]) != 2:
        raise ValueError("H02 allocation contexts missing")
    if not any(not row for row in heap_sequences["call_heap_h03"]):
        raise ValueError("H03 unknown indirect effect missing")
    if heap_sequences["call_heap_h04"] != [["call_alloc"], ["call_free"]]:
        raise ValueError("H04 allocation/free binding mismatch")

    cases = semantic_cases(functions, catalog)
    return {
        "schema_version": "flow-call-replay/2",
        "arch": arch,
        "extraction_file": str(extraction_path.relative_to(ROOT)),
        "extraction_file_sha256": hashlib.sha256(extraction_path.read_bytes()).hexdigest(),
        "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "catalog_digest": catalog.catalog_digest,
        "reviewed_summaries": [
            {
                "display_name": summary.display_name,
                "identity_digest": summary.identity.identity_digest,
                "summary_digest": summary.summary_digest,
                "kind": summary.kind,
            }
            for summary in catalog.summaries
        ],
        "function_count": len(functions),
        "call_plan_count": len(plans),
        "actual_composition_count": len(actual_compositions),
        "actual_composition_status_counts": dict(
            sorted(Counter(item.status for item in actual_compositions).items())
        ),
        "actual_composition_digests": [digest(item) for item in actual_compositions],
        "branch_counts": dict(sorted(branch_counts.items())),
        "remainder_counts": dict(sorted(remainder_counts.items())),
        "c02_contexts": {
            "left": left.context.context_digest,
            "right": right.context.context_digest,
            "distinct": True,
        },
        "c03_remainder_reasons": recursive_reasons,
        "c04_reviewed_branches": indirect_branches,
        "c04_unknown_remainder": True,
        "heap_call_sequences": heap_sequences,
        "semantic_cases": cases,
        "closure": extraction["closure"],
        "repeat_equal": True,
        "roundtrip_equal": True,
        "target_executed": False,
        "fresh_static_ida_extraction": True,
        "release_support_claim": False,
        "limitations": extraction["limitations"]
        + [
            "C01 copy/fill/output/global summaries have no native callers in this fixture; their fully pinned reviewed entrypoint plans are composed without claiming extracted call origins."
        ],
    }


def main():
    output = Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=True)
    for arch in ("x86_64", "arm64"):
        (output / f"{arch}_analysis.json").write_text(
            json.dumps(receipt(arch), indent=2, sort_keys=True) + "\n"
        )


if __name__ == "__main__":
    main()
