"""Pure G007 replay over actual product-extractor snapshots, not target execution."""

import hashlib
import json
from pathlib import Path
import sys

from ida_pro_mcp.flow_core import canonical_json, digest
from ida_pro_mcp.flow_core.contracts import MemoryObject, Snapshot
from ida_pro_mcp.flow_core.memory import (
    MemoryPlan,
    MemoryPolicy,
    MemoryResult,
    MemorySeed,
    PointerSeed,
    build_memory_plan,
)
from ida_pro_mcp.flow_core.memory_analysis import analyze_memory
from ida_pro_mcp.flow_core.ssa import build_ssa
from ida_pro_mcp.flow_core.states import (
    BitValue,
    ByteRange,
    Labels,
    PointerCandidate,
    PointerValue,
)

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "tests/flow_fixtures/manifests/memory"
FUNCTIONS = (
    "memory_before_after",
    "memory_alias",
    "memory_global_roundtrip",
    "memory_stack_roundtrip",
)


def receipt(arch, function):
    path = BASE / (arch + "_" + function + ".json")
    extraction = json.loads(path.read_text())
    snapshot = Snapshot.from_data(extraction["snapshot"])
    if digest(snapshot) != extraction["canonical_digest"]:
        raise ValueError("Stale extracted snapshot")
    program = build_ssa(snapshot, storage_model="memory")
    plan = build_memory_plan(program)
    nodes = {n.node_id: n for n in program.graph.nodes}
    definitions = {d.node_id: d for d in program.definitions}
    operations = sorted(
        (n for n in nodes.values() if n.kind in {"Load", "Store"}),
        key=lambda n: (definitions[n.node_id].block, definitions[n.node_id].order),
    )
    native = [n for n in operations if n.memory_operands.segment is not None]
    loads = [n for n in native if n.kind == "Load"]
    objects = []
    pointer_map = {}
    assumptions = [
        "Valid fixture objects; sequential recovered CFG; ordinary flat user-space C data accesses, no TLS/MMIO"
    ]

    def make_object(key, kind, size):
        obj = MemoryObject(
            snapshot.snapshot_id,
            key,
            "ram",
            size,
            kind,
            True,
            "fixture single object / invocation",
            True,
            "fixture current frame, designated buffer and global identities are disjoint",
        )
        objects.append(obj)
        return obj

    def point(node, obj, offset):
        pointer = PointerValue(
            "ram", node.width_bits, (PointerCandidate(obj.object_id, offset),)
        )
        if node.node_id in pointer_map and pointer_map[node.node_id] != pointer:
            raise ValueError("Conflicting source selector")
        pointer_map[node.node_id] = pointer

    stack_addresses = [n for n in nodes.values() if n.operation == "stack_address"]
    stack = None
    if stack_addresses:
        extent = max(
            n.constant
            + max(
                (
                    op.width_bits // 8
                    for op in operations
                    if op.memory_operands.address == n.node_id
                ),
                default=1,
            )
            for n in stack_addresses
        )
        stack = make_object("fixture-frame", "stack", extent)
        for n in stack_addresses:
            point(n, stack, n.constant)
    global_object = None
    globals_ = [n for n in nodes.values() if n.operation == "global_address"]
    if globals_:
        global_object = make_object("memory_global", "global", 1)
        for n in globals_:
            if n.constant != extraction["global_symbol"]["ea"]:
                raise ValueError("Not fixture global symbol")
            point(n, global_object, 0)
    selected_source = None
    if function in {"memory_before_after", "memory_alias"}:
        target = make_object("fixture-buffer", "argument", 1)
        selected_source = nodes[native[0].memory_operands.address]
        point(selected_source, target, 0)
        target_offset = 0
    elif function == "memory_global_roundtrip":
        target = global_object
        target_offset = 0
        selected_source = nodes[loads[0].memory_operands.address]
        point(selected_source, target, 0)
        assumptions.append(
            "Caller p == &memory_global, source-level fixture precondition; not inferred ABI numbering"
        )
    else:
        target = stack
        # The independently authored source stores literal 43 into local[0].
        destinations = [
            o.storage
            for b in snapshot.function.blocks
            for ins in b.instructions
            if any(o.constant == 43 for o in ins.operands if o.kind == "constant")
            for o in ins.operands
            if o.role == "destination"
            and o.storage
            and o.storage.address_space == "stack"
        ]
        if len(destinations) != 1:
            raise ValueError("Local[0] structural store selector unavailable")
        target_offset = destinations[0].bit_offset // 8
        selected_source = nodes[loads[0].memory_operands.address]
        point(selected_source, target, target_offset)
        assumptions.append(
            "index == 0; analyst-selected computed address points to source local[0]; no ABI argument inference or path proof"
        )
    pointers = tuple(PointerSeed(nid, pointer_map[nid]) for nid in sorted(pointer_map))
    memory = (
        MemorySeed(
            target.object_id,
            ByteRange(target_offset, target_offset + 1),
            BitValue(8),
            Labels(("X",)),
        ),
    )
    objects = tuple(sorted(objects, key=lambda o: o.object_id))
    policy = MemoryPolicy(flat_segment_assumption=assumptions[0])
    result = analyze_memory(plan, objects, pointers, memory, policy=policy)
    if analyze_memory(plan, objects, pointers, memory, policy=policy) != result:
        raise ValueError("Nondeterministic memory analysis")
    if (
        MemoryPlan.from_json(canonical_json(plan)) != plan
        or MemoryResult.from_json(canonical_json(result)) != result
    ):
        raise ValueError("Roundtrip failed")
    facts = {f.node_id: f for f in result.facts}
    accesses = {a.node_id: a for a in result.accesses}
    observations = []
    for node in loads:
        observations.append(
            {
                "node_id": node.node_id,
                "fact": facts[node.node_id].to_data(),
                "access": accesses[node.node_id].to_data(),
            }
        )
    if function == "memory_before_after":
        assert len(observations) == 2
        assert facts[loads[0].node_id].labels == Labels(("X",))
        assert (
            facts[loads[1].node_id].labels == Labels()
            and facts[loads[1].node_id].value.value == 0
        )
    else:
        expected = {
            "memory_alias": 37,
            "memory_global_roundtrip": 41,
            "memory_stack_roundtrip": 43,
        }[function]
        assert len(observations) == 1
        assert facts[loads[0].node_id].value.value == expected
        assert facts[loads[0].node_id].labels == Labels()
    target_stores = [
        a
        for a in result.accesses
        if nodes[a.node_id].kind == "Store"
        and any(
            c.object_id == target.object_id
            and c.interval is not None
            and c.interval.start <= target_offset < c.interval.end
            for c in a.candidates
        )
    ]
    assert target_stores and all(a.strong_update for a in target_stores)
    return {
        "schema_version": "flow-memory-receipt/1",
        "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "extraction_file": str(path.relative_to(ROOT)),
        "extraction_file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "snapshot_digest": digest(snapshot),
        "function": function,
        "arch": arch,
        "implementation_sha256": {
            name: hashlib.sha256(
                (ROOT / "src/ida_pro_mcp/flow_core" / name).read_bytes()
            ).hexdigest()
            for name in (
                "contracts.py",
                "states.py",
                "cfg.py",
                "ssa.py",
                "analysis.py",
                "memory.py",
                "memory_analysis.py",
            )
        },
        "graph_digest": program.graph.graph_digest,
        "plan_digest": plan.plan_digest,
        "cache_key": result.cache_key,
        "source_digest": result.source_digest,
        "policy_digest": result.policy_digest,
        "objects": [o.to_data() for o in objects],
        "pointer_seeds": [s.to_data() for s in pointers],
        "memory_seeds": [s.to_data() for s in memory],
        "selected_source_id": selected_source.node_id,
        "assumptions": assumptions,
        "load_observations": observations,
        "target_stores": [s.to_data() for s in target_stores],
        "dependencies": [d.to_data() for d in result.dependencies],
        "memory_order_step_count": len(plan.steps),
        "memory_phi_count": len(plan.phis),
        "node_count": len(nodes),
        "memory_version_count": len(plan.versions),
        "analysis_status": result.status,
        "diagnostics": list(result.diagnostics),
        "iterations": result.iterations,
        "repeat_equal": True,
        "roundtrip_equal": True,
        "target_executed": False,
        "fresh_static_ida_extraction": True,
        "release_support_claim": False,
    }


if __name__ == "__main__":
    output = Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=True)
    for arch in ("x86_64", "arm64"):
        for function in FUNCTIONS:
            (output / (arch + "_" + function + "_analysis.json")).write_text(
                json.dumps(receipt(arch, function), indent=2, sort_keys=True) + "\n"
            )
