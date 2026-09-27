"""Windowed memory analysis: fan-out repro baseline and job phase timing.

Phase 0 locks the pre-windowing behavior: a synthetic loop CFG whose weak
stores and wide loads reproduce the per-byte dependency explosion, plus
durable extract/analyze timing on every job. No IDA, no target binaries.
"""

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path

import pytest

from ida_pro_mcp.flow_core import ContractError, digest
from ida_pro_mcp.flow_core.contracts import (
    Block,
    Edge,
    Evidence,
    FunctionInput,
    Instruction,
    MemoryObject,
    Operand,
    Snapshot,
)
from ida_pro_mcp.flow_core.memory import (
    MemoryPolicy,
    MemoryResult,
    PointerSeed,
    build_memory_plan,
    plan_windows,
)
from ida_pro_mcp.flow_core.memory_analysis import analyze_memory
from ida_pro_mcp.flow_core.memory_graph import (
    analyze_seeded_memory,
    build_memory_graph_from_program,
    build_window_manifest,
    build_window_slices,
    reassemble_graph,
    strip_memory_derivations,
    verify_window_slices,
)
from ida_pro_mcp.flow_core.path_conditions import path_bindings
from ida_pro_mcp.flow_core.persistence import Store
from ida_pro_mcp.flow_core.query import Queries
from ida_pro_mcp.flow_core.refine import validate_memory_refinement
from ida_pro_mcp.flow_core.runtime import Handler, Runtime
from ida_pro_mcp.flow_core.runtime_contracts import RuntimeScope
from ida_pro_mcp.flow_core.ssa import build_ssa
from ida_pro_mcp.flow_core.states import (
    PointerCandidate,
    PointerValue,
    StorageLocation,
)

ROOT = Path(__file__).resolve().parents[2]
FLAT = MemoryPolicy(flat_segment_assumption="hand-authored flat ram fixture")
OWNER = "owner-secret-not-a-binary-hash-0002"
ANCHOR = json.loads(
    (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
)["snapshot"]


def reg(offset=0, bits=64, role="left"):
    return Operand(
        "storage",
        bits,
        storage=StorageLocation("microregister", "bank", offset, bits),
        role=role,
    )


def const(value, bits=8, role="left"):
    return Operand("constant", bits, constant=value, role=role)


def fanout_plan(n_stores, n_loads, n_blocks=4, load_bits=8):
    """Loop CFG with weak stores then loads to force per-byte fan-out."""
    per_store = [
        n_stores // n_blocks + (1 if i < n_stores % n_blocks else 0)
        for i in range(n_blocks)
    ]
    per_load = [
        n_loads // n_blocks + (1 if i < n_loads % n_blocks else 0)
        for i in range(n_blocks)
    ]
    blocks = []
    for b in range(n_blocks):
        idx = 0
        insns = []
        for _ in range(per_store[b]):
            insns.append(
                Instruction(
                    idx,
                    "m_stx",
                    (const(0), const(0, 16, "right"), reg(role="destination")),
                )
            )
            idx += 1
        for _ in range(per_load[b]):
            insns.append(
                Instruction(
                    idx,
                    "m_ldx",
                    (
                        const(0, 16),
                        reg(role="right"),
                        reg(128, load_bits, "destination"),
                    ),
                )
            )
            idx += 1
        if b == 0:
            preds = ()
        elif b == n_blocks - 1 and n_blocks > 1:
            preds = (n_blocks - 2, n_blocks - 1)
        else:
            preds = (b - 1,)
        blocks.append(Block(b, preds, tuple(insns)))
    blocks = tuple(
        replace(
            blk,
            successors=tuple(
                cand.index for cand in blocks if blk.index in cand.predecessors
            ),
        )
        for blk in blocks
    )
    original = Snapshot.from_data(ANCHOR)
    function = FunctionInput("windowed-memory-fixture", 0, blocks)
    identity = replace(
        original.identity,
        function_id=function.function_id,
        input_digest=digest(function),
    )
    return build_memory_plan(build_ssa(Snapshot(identity, function, identity.snapshot_id)))


def fanout_objects(plan):
    snap = plan.program.graph.snapshot.snapshot_id
    objects = tuple(
        sorted(
            (
                MemoryObject(
                    snap, key, "ram", 64, "argument", False, None, False, None
                )
                for key in ("A", "B")
            ),
            key=lambda o: o.object_id,
        )
    )
    entry = min(plan.program.entry_storage, key=lambda e: e.storage.bit_offset)
    candidates = tuple(
        sorted(
            (
                PointerCandidate(objects[0].object_id, 0),
                PointerCandidate(objects[1].object_id, 0),
            ),
            key=lambda p: (p.object_id, p.offset is None, p.offset or 0),
        )
    )
    seed = PointerSeed(
        entry.node_id,
        PointerValue("ram", entry.storage.width_bits, candidates),
    )
    return objects, (seed,)


def make_store(tmp_path):
    snapshot = Snapshot.from_data(ANCHOR)
    identity = snapshot.identity
    scope = RuntimeScope(
        identity.namespace,
        identity.semantic_digest,
        identity.binary_digest,
        identity.profile_digest,
        identity.rule_digest,
        identity.summary_digest,
        identity.policy_digest,
    )
    return Store(tmp_path / "store", scope, OWNER)


def test_fanout_fixture_reproduces_per_byte_dependency_explosion():
    plan = fanout_plan(24, 24)
    objects, pointers = fanout_objects(plan)
    result = analyze_memory(plan, objects, pointers, policy=FLAT)
    assert result.status == "complete_in_scope"
    assert result.diagnostics == ()
    assert result.iterations == 2
    # Every load byte reaches every weak store: strictly more dependencies
    # than store-load pairs proves the per-byte fan-out shape.
    assert len(result.dependencies) >= 24 * 24
    assert {d.rule_id for d in result.dependencies} == {"byte-reaching-store-v1"}
    assert all(
        d.interval is not None and d.interval.end - d.interval.start == 1
        for d in result.dependencies
    )


def test_fanout_result_is_deterministic():
    plan = fanout_plan(24, 24)
    objects, pointers = fanout_objects(plan)
    first = analyze_memory(plan, objects, pointers, policy=FLAT)
    second = analyze_memory(plan, objects, pointers, policy=FLAT)
    assert first.status == second.status
    assert first.dependencies == second.dependencies
    assert first.accesses == second.accesses


def test_runtime_records_phase_times_on_success(tmp_path):
    store = make_store(tmp_path)
    runtime = Runtime(store, {"pure": Handler(lambda ctx, x: x, lambda ctx, x: x)})
    try:
        job = runtime.submit("pure", {"x": 1}, "timed")
        assert runtime.wait(job)
        row = store.job(job)
        assert row["state"] == "complete"
        spans = row["progress"]["phase_times_ms"]
        assert set(spans) == {"setup_ms", "extract_ms", "analyze_ms"}
        assert all(type(v) is int and v >= 0 for v in spans.values())
    finally:
        runtime.shutdown()
        store.close()


def test_runtime_records_failed_phase_on_failure(tmp_path):
    store = make_store(tmp_path)

    def fail(ctx, value):
        raise ValueError("not serialized")

    runtime = Runtime(store, {"fail": Handler(fail, fail)})
    try:
        job = runtime.submit("fail", {}, "failing")
        assert runtime.wait(job)
        row = store.job(job)
        assert row["state"] == "failed"
        assert row["error"]["phase"] == "extract"
        assert row["progress"]["failed_phase"] == "extract"
        assert set(row["progress"]["phase_times_ms"]) == {"setup_ms"}
    finally:
        runtime.shutdown()
        store.close()


def window_of(plan, window_steps):
    definitions = {d.node_id: d.block for d in plan.program.definitions}
    step_counts: dict[int, int] = {}
    for step in plan.steps:
        block = definitions[step.node_id]
        step_counts[block] = step_counts.get(block, 0) + 1
    windows = plan_windows(
        tuple(b.block for b in plan.blocks), step_counts, window_steps
    )
    block_window = {b: i for i, w in enumerate(windows) for b in w}
    return windows, {
        node_id: block_window[block] for node_id, block in definitions.items()
    }


@pytest.mark.parametrize("window_steps", [1, 8, 24, 64, 120, 240, 1000000])
def test_window_sizes_agree_when_budgets_hold(window_steps):
    plan = fanout_plan(24, 24)
    objects, pointers = fanout_objects(plan)
    policy = replace(FLAT, window_steps=window_steps, window_max_dependencies=10**6)
    result = analyze_memory(plan, objects, pointers, policy=policy)
    assert result.status == "complete_in_scope"
    assert result.diagnostics == ()
    assert result.iterations == 2
    assert len(result.dependencies) == 720
    assert result.window_steps == window_steps
    assert result.window_max_dependencies == 10**6
    baseline = analyze_memory(plan, objects, pointers, policy=FLAT)
    assert result.dependencies == baseline.dependencies
    assert result.accesses == baseline.accesses
    assert result.facts == baseline.facts


@pytest.mark.parametrize("window_steps", [1, 64, 1000000])
def test_windowed_graph_build_matches_batch(window_steps):
    plan = fanout_plan(24, 24)
    bundle = build_memory_graph_from_program(
        plan.program, window_steps=window_steps, window_max_dependencies=10**6
    )
    batch = build_memory_graph_from_program(
        plan.program, window_steps=1000000, window_max_dependencies=10**6
    )
    assert bundle.graph == batch.graph
    assert bundle.result.dependencies == batch.result.dependencies
    assert bundle.result.accesses == batch.result.accesses
    assert bundle.result.status == batch.result.status == "complete_in_scope"


def test_recorded_window_config_roundtrips():
    plan = fanout_plan(24, 24)
    objects, pointers = fanout_objects(plan)
    result = analyze_memory(plan, objects, pointers, policy=FLAT)
    assert (result.window_steps, result.window_max_dependencies) == (64, 16384)
    data = result.to_data()
    assert data["window_steps"] == 64
    assert data["window_max_dependencies"] == 16384
    back = MemoryResult.from_data(data)
    assert (back.window_steps, back.window_max_dependencies) == (64, 16384)
    legacy = dict(data)
    del legacy["window_steps"]
    del legacy["window_max_dependencies"]
    old = MemoryResult.from_data(legacy)
    assert old.window_steps is None
    assert old.window_max_dependencies is None


def test_seeded_replay_reuses_stored_window_config():
    plan = fanout_plan(24, 24)
    tight = build_memory_graph_from_program(plan.program, window_max_dependencies=10)
    assert tight.result.status == "partial"
    assert "window_dependency_budget_widened" in tight.result.diagnostics
    assert tight.result.window_max_dependencies == 10
    replayed = analyze_seeded_memory(tight, ())
    assert replayed.dependencies == tight.result.dependencies
    loose = build_memory_graph_from_program(
        plan.program, window_max_dependencies=10**6
    )
    assert loose.result.status == "complete_in_scope"
    assert loose.result.dependencies != tight.result.dependencies


def test_tight_window_budget_widens_honestly():
    plan = fanout_plan(24, 24)
    objects, pointers = fanout_objects(plan)
    budget = 50
    result = analyze_memory(
        plan, objects, pointers, policy=replace(FLAT, window_max_dependencies=budget)
    )
    assert result.status == "partial"
    assert result.diagnostics == ("window_dependency_budget_widened",)
    windows, node_window = window_of(plan, 64)
    fine_per_window = [0] * len(windows)
    coarse = 0
    for dep in result.dependencies:
        if dep.interval is None:
            coarse += 1
            assert dep.precision == "opaque"
            assert dep.rule_id == "byte-reaching-store-v1"
        else:
            fine_per_window[node_window[dep.target]] += 1
    assert coarse > 0
    assert all(count <= budget for count in fine_per_window)
    assert sum(fine_per_window) == budget * len(windows)
    loose = analyze_memory(plan, objects, pointers, policy=FLAT)
    assert len(loose.dependencies) == 720


def test_wide_load_overflow_collapses_bytes_to_coarse():
    plan = fanout_plan(24, 24, load_bits=64)
    objects, pointers = fanout_objects(plan)
    loose = analyze_memory(plan, objects, pointers, policy=FLAT)
    assert len(loose.dependencies) == 5760
    tight = analyze_memory(
        plan, objects, pointers, policy=replace(FLAT, window_max_dependencies=50)
    )
    assert tight.status == "partial"
    fine = sum(1 for d in tight.dependencies if d.interval is not None)
    assert fine == 50
    assert len(tight.dependencies) < len(loose.dependencies)


def test_invalid_window_options_fail_closed():
    plan = fanout_plan(24, 24)
    objects, pointers = fanout_objects(plan)
    result = analyze_memory(plan, objects, pointers, policy=FLAT)
    with pytest.raises(ContractError, match="Invalid memory budget"):
        MemoryPolicy(window_steps=0)
    with pytest.raises(ContractError, match="Invalid memory budget"):
        MemoryPolicy(window_max_dependencies=-1)
    with pytest.raises(ContractError, match="Invalid window steps"):
        plan_windows((0,), {}, 0)
    with pytest.raises(ContractError, match="Invalid recorded window budget"):
        replace(result, window_steps=0)
    with pytest.raises(ContractError, match="Invalid recorded window budget"):
        replace(result, window_max_dependencies=-5)


def sliced_bundle(window_steps=12):
    plan = fanout_plan(24, 24)
    bundle = build_memory_graph_from_program(plan.program)
    return bundle, build_window_slices(bundle, window_steps)


def memory_edge_ids(graph):
    return {
        edge.edge_id
        for edge in graph.edges
        if edge.kind == "memory_data_dependency"
        and edge.memory_object_id is not None
        and edge.memory_rule_id is not None
    }


def test_window_slices_partition_cover_and_verify():
    bundle, slices = sliced_bundle(12)
    assert len(slices) == 4
    assert all(s["window_count"] == 4 and s["window_steps"] == 12 for s in slices)
    assert [s["window_index"] for s in slices] == [0, 1, 2, 3]
    assert [tuple(s["blocks"]) for s in slices] == [(0,), (1,), (2,), (3,)]
    seen: set[str] = set()
    for body in slices:
        ids = [Edge.from_data(edge).edge_id for edge in body["edges"]]
        assert not (set(ids) & seen)
        seen.update(ids)
        cited = {eid for edge in body["edges"] for eid in edge["evidence_ids"]}
        stored = {
            Evidence.from_data(item).evidence_id for item in body["evidence"]
        }
        assert cited <= stored
    assert seen == memory_edge_ids(bundle.graph)
    assert slices[0]["prev_digest"] == bundle.graph.graph_digest
    head = verify_window_slices(slices, bundle.graph.graph_digest)
    assert head == slices[-1]["slice_digest"]
    assert len({s["slice_digest"] for s in slices}) == 4


def test_window_chain_tamper_fails_closed():
    bundle, slices = sliced_bundle(12)
    graph_digest = bundle.graph.graph_digest
    full = [edge for body in slices for edge in body["edges"]]
    assert len(full) > 1
    tampered = deepcopy(list(slices))
    victim = next(body for body in tampered if body["edges"])
    victim["edges"][0] = {**victim["edges"][0], "target": "node:tampered"}
    with pytest.raises(ContractError, match="Window slice digest mismatch"):
        verify_window_slices(tampered, graph_digest)
    with pytest.raises(ContractError, match="Window chain count mismatch"):
        verify_window_slices(slices[:-1], graph_digest)
    swapped = [slices[1], slices[0], *slices[2:]]
    with pytest.raises(ContractError, match="Window chain order mismatch"):
        verify_window_slices(swapped, graph_digest)
    with pytest.raises(ContractError, match="Window chain linkage mismatch"):
        verify_window_slices(slices, digest("foreign-graph"))
    with pytest.raises(ContractError, match="Empty window chain"):
        verify_window_slices([], graph_digest)


def test_reassemble_matches_enriched_graph():
    bundle, slices = sliced_bundle(12)
    base = strip_memory_derivations(bundle.graph)
    assert memory_edge_ids(base) == set()
    assert len(base.nodes) == len(bundle.graph.nodes)
    rebuilt = reassemble_graph(base, slices)
    assert rebuilt == bundle.graph
    assert reassemble_graph(base, list(slices)) == bundle.graph


def test_empty_slice_verifies_and_manifest_rejects_bad_refs():
    bundle, _ = sliced_bundle(12)
    body = {
        "schema_version": "flow-window-slice/1",
        "snapshot_id": bundle.graph.snapshot.snapshot_id,
        "window_index": 0,
        "window_count": 1,
        "window_steps": 64,
        "blocks": [0],
        "edges": [],
        "evidence": [],
        "prev_digest": bundle.graph.graph_digest,
    }
    body["slice_digest"] = digest(body)
    assert verify_window_slices([body], bundle.graph.graph_digest) == body["slice_digest"]
    manifest = build_window_manifest(
        bundle.graph.snapshot.snapshot_id,
        "artifact_graph",
        "artifact_base",
        bundle.graph.graph_digest,
        64,
        [{"window_index": 0, "artifact_id": "artifact_s0", "slice_digest": "d0"}],
        "d0",
    )
    assert manifest["schema_version"] == "flow-window-chain/1"
    assert manifest["window_count"] == 1
    with pytest.raises(ContractError, match="Window chain order mismatch"):
        build_window_manifest(
            bundle.graph.snapshot.snapshot_id,
            "artifact_graph",
            "artifact_base",
            bundle.graph.graph_digest,
            64,
            [
                {"window_index": 1, "artifact_id": "a1", "slice_digest": "d1"},
                {"window_index": 0, "artifact_id": "a0", "slice_digest": "d0"},
            ],
            "d1",
        )
    with pytest.raises(ContractError, match="Invalid window chain"):
        build_window_manifest(
            bundle.graph.snapshot.snapshot_id,
            "artifact_graph",
            "artifact_base",
            bundle.graph.graph_digest,
            64,
            [{"window_index": 0, "artifact_id": "a0"}],
            "d0",
        )


def stored_chain(tmp_path, window_steps=12):
    bundle, slices = sliced_bundle(window_steps)
    store = make_store(tmp_path)
    gid = store.put_artifact("graph", bundle.graph)
    base_id = store.put_artifact("graph", strip_memory_derivations(bundle.graph))
    refs = []
    for body in slices:
        refs.append(
            {
                "window_index": body["window_index"],
                "artifact_id": store.put_artifact("analysis", body),
                "slice_digest": body["slice_digest"],
            }
        )
    manifest = build_window_manifest(
        bundle.graph.snapshot.snapshot_id,
        gid,
        base_id,
        bundle.graph.graph_digest,
        window_steps,
        refs,
        slices[-1]["slice_digest"],
    )
    chain_id = store.put_artifact("analysis", manifest)
    return bundle, store, chain_id


def test_graph_from_chain_roundtrips_and_matches_direct_graph(tmp_path):
    bundle, store, chain_id = stored_chain(tmp_path)
    try:
        queries = Queries(store)
        reassembled = queries.graph_from_chain(chain_id)
        assert reassembled == bundle.graph
        assert path_bindings(reassembled) == path_bindings(bundle.graph)
    finally:
        store.close()


def test_graph_from_chain_rejects_tampered_slice(tmp_path):
    bundle, store, chain_id = stored_chain(tmp_path)
    try:
        manifest = store.artifact(chain_id)
        victim_ref = manifest["slices"][1]
        victim = store.artifact(victim_ref["artifact_id"])
        assert victim["edges"], "tamper test needs a non-empty slice"
        victim = deepcopy(victim)
        victim["edges"][0] = {**victim["edges"][0], "target": "node:tampered"}
        manifest = deepcopy(manifest)
        manifest["slices"][1] = {
            **victim_ref,
            "artifact_id": store.put_artifact("analysis", victim),
        }
        forged_id = store.put_artifact("analysis", manifest)
        with pytest.raises(ContractError, match="Window slice digest mismatch"):
            Queries(store).graph_from_chain(forged_id)
    finally:
        store.close()


def test_refine_replay_accepts_tuned_window_config():
    plan = fanout_plan(24, 24)
    tight = build_memory_graph_from_program(
        plan.program, window_steps=24, window_max_dependencies=10
    )
    assert tight.result.status == "partial"
    assert (tight.result.window_steps, tight.result.window_max_dependencies) == (24, 10)
    kinds = {node.node_id: node.kind for node in tight.program.graph.nodes}
    load_id = next(a.node_id for a in tight.result.accesses if kinds[a.node_id] == "Load")
    store_id = next(
        a.node_id for a in tight.result.accesses if kinds[a.node_id] == "Store"
    )
    validate_memory_refinement(
        tight.program, tight.plan, tight.result, load_id, store_id
    )


def test_graph_from_chain_rejects_swapped_base(tmp_path):
    bundle, store, chain_id = stored_chain(tmp_path)
    try:
        foreign_plan = fanout_plan(8, 8)
        foreign = build_memory_graph_from_program(foreign_plan.program)
        assert foreign.graph.graph_digest != bundle.graph.graph_digest
        foreign_base = store.put_artifact(
            "graph", strip_memory_derivations(foreign.graph)
        )
        manifest = deepcopy(store.artifact(chain_id))
        manifest["base_graph_artifact"] = foreign_base
        forged_id = store.put_artifact("analysis", manifest)
        with pytest.raises(ContractError):
            Queries(store).graph_from_chain(forged_id)
        base_edges = strip_memory_derivations(bundle.graph).edges
        assert len(base_edges) > 1
        pruned = replace(
            strip_memory_derivations(bundle.graph),
            edges=base_edges[1:],
        )
        pruned_id = store.put_artifact("graph", pruned)
        manifest = deepcopy(store.artifact(chain_id))
        manifest["base_graph_artifact"] = pruned_id
        pruned_chain = store.put_artifact("analysis", manifest)
        with pytest.raises(ContractError, match="Window chain graph mismatch"):
            Queries(store).graph_from_chain(pruned_chain)
    finally:
        store.close()
