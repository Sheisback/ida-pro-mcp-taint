"""Deterministic pure-Python workloads for the B01-B03 performance gates.

These workloads consume only synthetic IR and committed static extraction receipts.
They never load or execute a target binary and never import an IDA SDK module.
"""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import threading
import time
from typing import Any, Literal, cast

from ida_pro_mcp.flow_core import digest
from ida_pro_mcp.flow_core.analysis import ScalarPolicy, Seed, analyze
from ida_pro_mcp.flow_core.contracts import (
    Block,
    FunctionInput,
    Instruction,
    MemoryObject,
    Operand,
    Snapshot,
)
from ida_pro_mcp.flow_core.memory import (
    MemoryPolicy,
    MemorySeed,
    PointerSeed,
    build_memory_plan,
)
from ida_pro_mcp.flow_core.memory_analysis import analyze_memory
from ida_pro_mcp.flow_core.persistence import PAGE_HARD_CHARS, Store
from ida_pro_mcp.flow_core.query import Queries
from ida_pro_mcp.flow_core.runtime_contracts import RuntimeScope
from ida_pro_mcp.flow_core.ssa import SSAProgram, build_ssa
from ida_pro_mcp.flow_core.states import (
    BitValue,
    ByteRange,
    Labels,
    PointerCandidate,
    PointerValue,
    StorageLocation,
)

ROOT = Path(__file__).resolve().parents[2]
OWNER = "benchmark-owner-key-not-a-binary-hash"
OperandRole = Literal[
    "unspecified", "left", "right", "destination", "argument", "return"
]


def _register(
    offset: int = 0, *, bits: int = 64, role: OperandRole = "left"
) -> Operand:
    return Operand(
        "storage",
        bits,
        storage=StorageLocation("microregister", "bank", offset, bits),
        role=role,
    )


def _constant(value: int, *, bits: int = 64, role: OperandRole = "right") -> Operand:
    return Operand("constant", bits, constant=value, role=role)


def _anchor_snapshot(anchor: str) -> tuple[Snapshot, dict[str, Any]]:
    path = ROOT / f"tests/flow_fixtures/manifests/extraction_{anchor}.json"
    receipt = json.loads(path.read_text())
    snapshot = cast(Snapshot, Snapshot.from_data(receipt["snapshot"]))
    if digest(snapshot) != receipt["canonical_digest"]:
        raise AssertionError(f"stale static {anchor} anchor receipt")
    return snapshot, receipt


def _synthetic_snapshot(size: int) -> Snapshot:
    if size <= 0:
        raise ValueError("synthetic workload size must be positive")
    original, _ = _anchor_snapshot("x64")
    instructions: list[Instruction] = []
    source = _register()
    for index in range(size):
        destination = _register((index + 1) * 64, role="destination")
        instructions.append(
            Instruction(index, "m_add", (source, _constant(1), destination))
        )
        source = _register((index + 1) * 64)
    instructions.append(Instruction(size, "m_ret", (source,)))
    function = FunctionInput(
        f"benchmark-scalar-{size}", 0, (Block(0, (), tuple(instructions)),)
    )
    identity = replace(
        original.identity,
        function_id=function.function_id,
        input_digest=digest(function),
    )
    return Snapshot(identity, function, identity.snapshot_id)


def _seeded_scalar(program: SSAProgram):
    entry = min(program.entry_storage, key=lambda item: item.storage.bit_offset)
    result = analyze(program.graph, (Seed(entry.node_id, Labels(("BENCH",))),))
    returned = next(
        (node for node in program.graph.nodes if node.kind == "Return"), None
    )
    target = returned.node_id if returned is not None else entry.node_id
    fact = next(item for item in result.facts if item.node_id == target)
    if "BENCH" not in fact.labels.explicit:
        raise AssertionError("B01 scalar provenance was not preserved")
    return result


def run_b01() -> dict[str, Any]:
    """Exercise small/medium/large scalar SSA and both committed anchors."""

    synthetic: list[dict[str, Any]] = []
    for size in (8, 64, 256):
        program = build_ssa(_synthetic_snapshot(size))
        result = _seeded_scalar(program)
        synthetic.append(
            {
                "size": size,
                "graph_digest": program.graph.graph_digest,
                "nodes": len(program.graph.nodes),
                "edges": len(program.graph.edges),
                "evaluations": result.evaluations,
                "status": result.status,
                "provenance_preserved": True,
            }
        )

    anchors: list[dict[str, Any]] = []
    for anchor in ("x64", "a64"):
        snapshot, receipt = _anchor_snapshot(anchor)
        program = build_ssa(snapshot)
        result = _seeded_scalar(program)
        kinds = {node.kind for node in program.graph.nodes}
        if not {"Phi", "Load", "Store"} <= kinds or result.status != "partial":
            raise AssertionError(f"B01 {anchor} semantic anchor drift")
        anchors.append(
            {
                "anchor": anchor,
                "binary_digest": snapshot.identity.binary_digest,
                "canonical_digest": receipt["canonical_digest"],
                "graph_digest": program.graph.graph_digest,
                "nodes": len(program.graph.nodes),
                "edges": len(program.graph.edges),
                "evaluations": result.evaluations,
                "status": result.status,
                "required_kinds": sorted({"Phi", "Load", "Store"} & kinds),
                "provenance_preserved": True,
            }
        )

    return {
        "gate": "B01",
        "synthetic": synthetic,
        "anchors": anchors,
        "semantics_passed": True,
        "target_executed": False,
        "input_preserved": True,
    }


def _load(index: int, *, output: int = 128) -> Instruction:
    return Instruction(
        index,
        "m_ldx",
        (
            _constant(0, bits=16, role="left"),
            _register(role="right"),
            _register(output, bits=8, role="destination"),
        ),
    )


def _store(index: int) -> Instruction:
    return Instruction(
        index,
        "m_stx",
        (
            _constant(0, bits=8, role="left"),
            _constant(0, bits=16),
            _register(role="destination"),
        ),
    )


def _return(index: int, *, offset: int = 128) -> Instruction:
    return Instruction(index, "m_ret", (_register(offset, bits=8),))


def _memory_plan(*, loop: bool):
    original, _ = _anchor_snapshot("x64")
    if loop:
        blocks = (
            Block(0, (), ()),
            Block(1, (0, 1), (_load(0), _store(1))),
            Block(2, (1,), (_load(0, output=136), _return(1, offset=136))),
        )
    else:
        blocks = (Block(0, (), (_load(0), _return(1))),)
    blocks = tuple(
        replace(
            block,
            successors=tuple(
                candidate.index
                for candidate in blocks
                if block.index in candidate.predecessors
            ),
        )
        for block in blocks
    )
    function = FunctionInput("benchmark-memory", 0, blocks)
    identity = replace(
        original.identity,
        function_id=function.function_id,
        input_digest=digest(function),
    )
    return build_memory_plan(
        build_ssa(Snapshot(identity, function, identity.snapshot_id))
    )


def _memory_object(plan, key: str) -> MemoryObject:
    return MemoryObject(
        plan.program.graph.snapshot.snapshot_id,
        key,
        "ram",
        8,
        "argument",
        True,
        "benchmark singleton",
        True,
        "benchmark disjoint",
    )


def _entry_pointer(plan, objects: tuple[MemoryObject, ...]) -> PointerSeed:
    entry = min(plan.program.entry_storage, key=lambda item: item.storage.bit_offset)
    candidates = tuple(
        sorted(
            (PointerCandidate(obj.object_id, 0) for obj in objects),
            key=lambda item: item.object_id,
        )
    )
    return PointerSeed(entry.node_id, PointerValue("ram", 64, candidates))


def _memory_seed(obj: MemoryObject, label: str) -> MemorySeed:
    return MemorySeed(
        obj.object_id,
        ByteRange(0, 1),
        BitValue(8),
        Labels((label,)),
    )


def _return_fact(result, plan):
    node = next(item for item in plan.program.graph.nodes if item.kind == "Return")
    return next(item for item in result.facts if item.node_id == node.node_id)


def _scope(snapshot: Any) -> RuntimeScope:
    identity = snapshot.identity
    return RuntimeScope(
        identity.namespace,
        identity.semantic_digest,
        identity.binary_digest,
        identity.profile_digest,
        identity.rule_digest,
        identity.summary_digest,
        identity.policy_digest,
    )


def _cancellation_workload(program: SSAProgram) -> dict[str, Any]:
    # Store rejects world-writable ancestors; repo-local scratch is ignored by Git.
    with tempfile.TemporaryDirectory(prefix=".flow-b02-cancel-", dir=ROOT) as directory:
        store = Store(Path(directory) / "store", _scope(program.graph.snapshot), OWNER)
        try:
            snapshot_id = store.put_artifact("snapshot", program.graph.snapshot)
            graph_id = store.put_artifact("graph", program.graph)
            source = min(
                program.entry_storage, key=lambda item: item.storage.bit_offset
            )
            query = Queries(store)
            page = query.start(
                snapshot_id,
                graph_id,
                {"kind": "value", "node_id": source.node_id},
                "forward",
                "b02-budget",
                budget=1,
                limit=1,
            )
            if page["status"] != "budget_exceeded" or page["frontier_remaining"] <= 0:
                raise AssertionError("B02 budget did not retain a frontier")
            started = time.perf_counter_ns()
            cancelled = query.continue_trace(
                page["trace_id"],
                page["revision"],
                page["cursor"],
                "b02-cancel",
                cancel=True,
            )
            elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
            replay = query.continue_trace(
                page["trace_id"],
                page["revision"],
                page["cursor"],
                "b02-cancel",
                cancel=True,
            )
            if cancelled["status"] != "cancelled" or replay != cancelled:
                raise AssertionError("B02 cancellation was not terminal and replayable")
            return {
                "budget_status": page["status"],
                "frontier_remaining": page["frontier_remaining"],
                "cancel_status": cancelled["status"],
                "cancel_replay_equal": True,
                "cancellation_latency_ms": elapsed_ms,
            }
        finally:
            store.close()


def run_b02() -> dict[str, Any]:
    """Exercise alias widening, loop budget exhaustion, and cancellation."""

    alias_plan = _memory_plan(loop=False)
    objects = tuple(
        sorted(
            (_memory_object(alias_plan, "A"), _memory_object(alias_plan, "B")),
            key=lambda item: item.object_id,
        )
    )
    alias = analyze_memory(
        alias_plan,
        objects,
        (_entry_pointer(alias_plan, objects),),
        tuple(_memory_seed(obj, obj.key) for obj in objects),
        (),
        MemoryPolicy(
            flat_segment_assumption="benchmark flat RAM",
            max_candidates=1,
        ),
    )
    alias_fact = _return_fact(alias, alias_plan)
    if (
        alias.status != "partial"
        or not alias_fact.labels.unknown_provenance
        or set(alias_fact.labels.explicit) != {"A", "B"}
    ):
        raise AssertionError("B02 alias budget lost conservative Unknown/provenance")

    loop_plan = _memory_plan(loop=True)
    loop_object = _memory_object(loop_plan, "LOOP")
    loop = analyze_memory(
        loop_plan,
        (loop_object,),
        (_entry_pointer(loop_plan, (loop_object,)),),
        (_memory_seed(loop_object, "LOOP"),),
        (),
        MemoryPolicy(
            flat_segment_assumption="benchmark flat RAM",
            max_iterations=1,
        ),
    )
    if loop.status != "partial" or not loop.frontier:
        raise AssertionError("B02 loop budget was falsely reported complete")
    if not _return_fact(loop, loop_plan).labels.unknown_provenance:
        raise AssertionError("B02 loop frontier was not conservatively Unknown")

    scalar = build_ssa(_synthetic_snapshot(32))
    bounded = analyze(
        scalar.graph,
        (
            Seed(
                min(
                    scalar.entry_storage, key=lambda item: item.storage.bit_offset
                ).node_id,
                Labels(("BUDGET",)),
            ),
        ),
        ScalarPolicy(max_evaluations=1),
    )
    if bounded.status != "partial" or not bounded.frontier:
        raise AssertionError("B02 scalar evaluation budget was falsely complete")

    cancellation = _cancellation_workload(scalar)
    return {
        "gate": "B02",
        "alias": {
            "status": alias.status,
            "candidate_count": len(objects),
            "interval_count": sum(
                1
                for access in alias.accesses
                for candidate in access.candidates
                if candidate.interval is not None
            ),
            "iterations": alias.iterations,
            "frontier_count": len(alias.frontier),
            "unknown_preserved": True,
            "labels": sorted(alias_fact.labels.explicit),
        },
        "loop": {
            "status": loop.status,
            "iterations": loop.iterations,
            "frontier_count": len(loop.frontier),
            "unknown_preserved": True,
        },
        "scalar_budget": {
            "status": bounded.status,
            "evaluations": bounded.evaluations,
            "frontier_count": len(bounded.frontier),
            "unknown_preserved": all(
                fact.labels.unknown_provenance
                for fact in bounded.facts
                if fact.node_id in bounded.frontier
            ),
        },
        "cancellation": cancellation,
        "semantics_passed": True,
        "target_executed": False,
        "input_preserved": True,
    }


def _reachable(program: SSAProgram, source: str) -> set[str]:
    adjacency: dict[str, list[str]] = {node.node_id: [] for node in program.graph.nodes}
    for edge in program.graph.edges:
        if edge.kind in {"value_dependency", "phi_input"}:
            adjacency[edge.source].append(edge.target)
    reached: set[str] = set()
    pending = [source]
    while pending:
        node = pending.pop()
        if node in reached:
            continue
        reached.add(node)
        pending.extend(adjacency[node])
    return reached


def run_b03() -> dict[str, Any]:
    """Exercise bounded pages, concurrent continuation, and restart replay."""

    program = build_ssa(_synthetic_snapshot(64))
    source = min(
        program.entry_storage, key=lambda item: item.storage.bit_offset
    ).node_id
    expected = _reachable(program, source)
    # Store rejects world-writable ancestors; repo-local scratch is ignored by Git.
    with tempfile.TemporaryDirectory(prefix=".flow-b03-page-", dir=ROOT) as directory:
        root = Path(directory) / "store"
        scope = _scope(program.graph.snapshot)
        store = Store(root, scope, OWNER)
        view: Store | None = None
        try:
            snapshot_id = store.put_artifact("snapshot", program.graph.snapshot)
            graph_id = store.put_artifact("graph", program.graph)
            query = Queries(store)
            latencies: list[float] = []
            started = time.perf_counter_ns()
            page = query.start(
                snapshot_id,
                graph_id,
                {"kind": "value", "node_id": source},
                "forward",
                "b03-pages",
                limit=7,
            )
            latencies.append((time.perf_counter_ns() - started) / 1_000_000)
            items: list[str] = []
            max_chars = 0
            page_count = 0
            while True:
                page_count += 1
                max_chars = max(max_chars, len(json.dumps(page, ensure_ascii=False)))
                items.extend(item["node_id"] for item in page["items"])
                if page["status"] == "frontier_exhausted":
                    break
                args = (page["trace_id"], page["revision"], page["cursor"])
                started = time.perf_counter_ns()
                page = query.continue_trace(
                    *args,
                    f"b03-page-{page['revision']}",
                    limit=7,
                )
                latencies.append((time.perf_counter_ns() - started) / 1_000_000)
            if set(items) != expected or len(items) != len(expected):
                raise AssertionError("B03 pages lost or duplicated reachable nodes")
            if max_chars > PAGE_HARD_CHARS:
                raise AssertionError("B03 page exceeded the wire hard limit")

            concurrent = query.start(
                snapshot_id,
                graph_id,
                {"kind": "value", "node_id": source},
                "forward",
                "b03-concurrent",
                limit=1,
            )
            continuation = (
                concurrent["trace_id"],
                concurrent["revision"],
                concurrent["cursor"],
                "b03-same-continuation",
            )
            view = Store(root, scope, OWNER, recover=False)
            barrier = threading.Barrier(3)
            outputs: list[dict[str, Any]] = []
            failures: list[str] = []

            def continue_once(client: Store) -> None:
                barrier.wait()
                try:
                    outputs.append(
                        Queries(client).continue_trace(*continuation, limit=1)
                    )
                except Exception as exc:  # pragma: no cover - asserted below
                    failures.append(f"{type(exc).__name__}: {exc}")

            threads = [
                threading.Thread(target=continue_once, args=(client,))
                for client in (store, view)
            ]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(5)
                if thread.is_alive():
                    raise AssertionError(
                        "B03 concurrent continuation did not terminate"
                    )
            if failures or len(outputs) != 2 or outputs[0] != outputs[1]:
                raise AssertionError(f"B03 concurrent replay drift: {failures!r}")
            winner = outputs[0]
            view.close()
            view = None
            store.close()

            recovered = Store(root, scope, OWNER)
            try:
                replay = Queries(recovered).continue_trace(*continuation, limit=1)
                if replay != winner:
                    raise AssertionError(
                        "B03 restart replay changed the committed page"
                    )
                revision = recovered.trace(concurrent["trace_id"])["revision"]
                if revision != winner["revision"]:
                    raise AssertionError("B03 restart replay advanced the trace")
            finally:
                recovered.close()

            return {
                "gate": "B03",
                "page_count": page_count,
                "reachable_nodes": len(expected),
                "unique_nodes": len(set(items)),
                "max_json_chars": max_chars,
                "page_latencies_ms": latencies,
                "concurrent_clients": 2,
                "concurrent_replay_equal": True,
                "restart_replay_equal": True,
                "terminal_status": page["status"],
                "semantics_passed": True,
                "target_executed": False,
                "input_preserved": True,
            }
        finally:
            if view is not None:
                view.close()
            store.close()


WORKLOADS = {"b01": run_b01, "b02": run_b02, "b03": run_b03}
