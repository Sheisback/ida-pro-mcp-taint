"""A09: refinement through public job/poll/page/cancel and ownership bounds.

The service handlers are thin IDA-context wrappers over the same
``run_*_refinement`` runners exercised here through ``Runtime`` + ``Store``
+ ``artifact_page``. IDA scope resolution itself is covered by licensed
smoke, not here. Fake runners execute under the test interpreter; no angr
install needed.
"""

import threading

import pytest

from ida_pro_mcp.flow_core.path_conditions import PathSelector, path_bindings
from ida_pro_mcp.flow_core.persistence import PersistenceError, Store
from ida_pro_mcp.flow_core.query import artifact_page
from ida_pro_mcp.flow_core.refine import (
    RefinementSpec,
    check_refined_memory_artifact,
    check_refined_path_artifact,
    refined_memory_page,
    refined_path_page,
    run_memory_refinement,
    run_path_refinement,
)
from ida_pro_mcp.flow_core.runtime import Handler, Runtime
from ida_pro_mcp.flow_core.runtime_contracts import RuntimeScope
from ida_pro_mcp.flow_core.serialization import digest, ensure_wire_v1_safe
from test_memory import load as mem_load
from test_memory import obj, plan as mem_plan, ptrseed, run, store as mem_store
from test_refine import (
    DIGEST,
    access_ids,
    angr_branch_graph,
    branch_graph,
    write_runner,
)
from test_ssa import Block, Operand, const, ins, reg, snapshot

OWNER = "owner-secret-not-a-binary-hash-0002"


def scope_of(snapshot):
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


def branch_program(*, bits=8, const_value=3):
    from ida_pro_mcp.flow_core.ssa import build_ssa

    left = const(const_value, bits=bits)
    return build_ssa(
        snapshot(
            (
                Block(
                    0,
                    (),
                    (
                        ins(
                            0,
                            "m_jz",
                            left,
                            const(const_value, bits=bits, role="right"),
                            Operand("block", None, block_index=1, role="destination"),
                        ),
                    ),
                ),
                Block(1, (0,), ()),
                Block(2, (0,), ()),
            )
        )
    )


def setup_path(tmp_path):
    program = branch_program()
    graph = program.graph
    store = Store(tmp_path / "store", scope_of(graph.snapshot), OWNER)
    store.put_artifact("snapshot", graph.snapshot)
    gid = store.put_artifact("graph", graph)
    return store, graph, gid


def test_path_refinement_job_default_never_solves(tmp_path):
    store, graph, gid = setup_path(tmp_path)

    def analyze(ctx, value):
        _store, request = value
        return run_path_refinement(
            _store, request, cancelled=ctx.cancel.is_set,
        )

    runtime = Runtime(
        store, {"refine_path_proof_v1": Handler(lambda ctx, v: (store, v), analyze)}
    )
    selector = PathSelector(path_bindings(graph), (0, 1))
    job = runtime.submit(
        "refine_path_proof_v1",
        {
            "graph_artifact": gid,
            "path": selector.to_data(),
            "refinement": RefinementSpec().to_data(),
        },
        "refine-default",
    )
    assert runtime.wait(job)
    row = store.job(job)
    assert row["state"] == "complete"
    result = row["result"]
    assert result["baseline_status"] == "feasible"
    assert result["refined_attempted"] is False
    assert result["agreement"] == "consistent"
    raw = store.artifact(result["refined_path_proof_artifact"])
    check_refined_path_artifact(raw)
    ensure_wire_v1_safe(raw)
    # Poll shape mirrors flow_get_job's public fields.
    status = runtime.status(job)
    assert status["state"] == "complete"
    assert status["result"]["refined_path_proof_artifact"]
    runtime.shutdown()
    store.close()


def test_path_refinement_job_angr_tier_and_page(tmp_path):
    graph = angr_branch_graph()
    store = Store(tmp_path / "store", scope_of(graph.snapshot), OWNER)
    store.put_artifact("snapshot", graph.snapshot)
    gid = store.put_artifact("graph", graph)
    sidecar = write_runner(tmp_path, "infeasible")

    def analyze(ctx, value):
        _store, request = value
        return run_path_refinement(
            _store, request, angr_sidecar=sidecar,
            cancelled=ctx.cancel.is_set,
        )

    runtime = Runtime(
        store, {"refine_path_proof_v1": Handler(lambda ctx, v: (store, v), analyze)}
    )
    selector = PathSelector(path_bindings(graph), (0, 1))
    job = runtime.submit(
        "refine_path_proof_v1",
        {
            "graph_artifact": gid,
            "path": selector.to_data(),
            "refinement": RefinementSpec(symbolic_angr=True).to_data(),
            "angr_binary": {"path": "/fake/probe.elf", "sha256": DIGEST, "image_base": 0x0},
        },
        "refine-angr",
    )
    assert runtime.wait(job)
    row = store.job(job)
    assert row["state"] == "complete"
    assert row["result"]["baseline_status"] == "unknown"
    assert row["result"]["refined_status"] == "infeasible_angr_v1"
    assert row["result"]["agreement"] == "refined"
    artifact_id = row["result"]["refined_path_proof_artifact"]
    raw = store.artifact(artifact_id)
    items, metadata = refined_path_page(raw)
    assert metadata["agreement"] == "refined"
    assert metadata["solver_stamp"]
    # Cursor walk reassembles the full item list; bad cursors refuse.
    seen, cursor = [], None
    while True:
        page = artifact_page(artifact_id, "refined_path_proof", items, metadata,
                             cursor, 2)
        assert page["schema_version"] == "flow-page/1"
        seen.extend(page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == items
    with pytest.raises(PersistenceError, match="invalid_cursor"):
        artifact_page(artifact_id, "refined_path_proof", items, metadata,
                      "0/bad-token", 2)
    ensure_wire_v1_safe(raw)
    ensure_wire_v1_safe(page)
    runtime.shutdown()
    store.close()


def test_path_refinement_job_missing_binary_stays_baseline(tmp_path):
    """Opt-in without binary context: explicit reason, v1 verdict kept."""
    graph = angr_branch_graph()
    store = Store(tmp_path / "store", scope_of(graph.snapshot), OWNER)
    store.put_artifact("snapshot", graph.snapshot)
    gid = store.put_artifact("graph", graph)
    sidecar = write_runner(tmp_path, "feasible")

    def analyze(ctx, value):
        _store, request = value
        return run_path_refinement(
            _store, request, angr_sidecar=sidecar,
            cancelled=ctx.cancel.is_set,
        )

    runtime = Runtime(
        store, {"refine_path_proof_v1": Handler(lambda ctx, v: (store, v), analyze)}
    )
    selector = PathSelector(path_bindings(graph), (0, 1))
    job = runtime.submit(
        "refine_path_proof_v1",
        {
            "graph_artifact": gid,
            "path": selector.to_data(),
            "refinement": RefinementSpec(symbolic_angr=True).to_data(),
        },
        "refine-no-binary",
    )
    assert runtime.wait(job)
    row = store.job(job)
    assert row["state"] == "complete"
    assert row["result"]["refined_attempted"] is False
    raw = store.artifact(row["result"]["refined_path_proof_artifact"])
    assert raw["refined"]["reason"] == "angr_binary_unavailable"
    runtime.shutdown()
    store.close()


def test_refinement_job_cancel_is_cooperative(tmp_path):
    store, graph, gid = setup_path(tmp_path)
    entered, release = threading.Event(), threading.Event()

    def gated(ctx, value):
        entered.set()
        assert release.wait(10)
        ctx.check()
        return store, value

    def analyze(ctx, value):
        _store, request = value
        return run_path_refinement(
            _store, request, cancelled=ctx.cancel.is_set,
        )

    runtime = Runtime(store, {"refine_path_proof_v1": Handler(gated, analyze)})
    selector = PathSelector(path_bindings(graph), (0, 1))
    job = runtime.submit(
        "refine_path_proof_v1",
        {
            "graph_artifact": gid,
            "path": selector.to_data(),
            "refinement": RefinementSpec().to_data(),
        },
        "refine-cancel",
    )
    assert entered.wait(10)
    assert runtime.cancel(job) == "cancel_requested"
    release.set()
    assert runtime.wait(job)
    assert store.job(job)["state"] == "cancelled"
    runtime.shutdown()
    store.close()


def test_refined_artifact_is_namespace_owned(tmp_path):
    store, _graph, gid = setup_path(tmp_path)
    # A separate database never sees this artifact.
    other = Store(tmp_path / "other", store.scope, OWNER)
    with pytest.raises(PersistenceError, match="not_found"):
        other.artifact(gid)
    other.close()
    # The same database file refuses a different owner.
    with pytest.raises(PersistenceError, match="wrong_database_owner"):
        Store(
            tmp_path / "store",
            store.scope,
            "different-owner-with-at-least-32-chars",
        )
    store.close()


def setup_memory(tmp_path):
    memory_plan = mem_plan((
        mem_store(0, reg(8, 8), reg(0, 64, "destination")),
        mem_load(1, bits=8, address=reg(0, 64, "right")),
    ))
    # test_ssa.reg and test_memory.reg share (offset, bits, role) order.
    graph = memory_plan.program.graph
    first, second = obj(memory_plan, key="A"), obj(memory_plan, key="B")
    facts = run(memory_plan, (first, second),
                (ptrseed(memory_plan, first, register=0),))
    stores, loads = access_ids(memory_plan, graph)
    store_db = Store(tmp_path / "mstore", scope_of(graph.snapshot), OWNER)
    store_db.put_artifact("snapshot", graph.snapshot)
    return store_db, memory_plan.program, memory_plan, facts, loads[0], stores[0]


def test_memory_refinement_job_default_quotes_v1(tmp_path):
    store, program, plan, facts, load_id, store_id = setup_memory(tmp_path)
    sid = store.put_artifact("analysis", program.to_data())
    pid = store.put_artifact("analysis", plan.to_data())
    rid = store.put_artifact("analysis", facts.to_data())

    def analyze(ctx, value):
        _store, request = value
        return run_memory_refinement(_store, request, cancelled=ctx.cancel.is_set)

    runtime = Runtime(
        store, {"refine_memory_proof_v1": Handler(lambda ctx, v: (store, v), analyze)}
    )
    selector = PathSelector(path_bindings(program.graph), (0,))
    job = runtime.submit(
        "refine_memory_proof_v1",
        {
            "ssa_artifact": sid,
            "memory_plan_artifact": pid,
            "memory_result_artifact": rid,
            "path": selector.to_data(),
            "load_id": load_id,
            "store_id": store_id,
            "refinement": RefinementSpec().to_data(),
        },
        "refine-memory-default",
    )
    assert runtime.wait(job)
    row = store.job(job)
    assert row["state"] == "complete"
    assert row["result"]["refined_attempted"] is False
    raw = store.artifact(row["result"]["refined_memory_proof_artifact"])
    check_refined_memory_artifact(raw)
    assert raw["baseline"]["result_digest"] == digest(facts.to_data())
    assert raw["refined"]["reason"] == "evidence_only"
    items, metadata = refined_memory_page(raw)
    page = artifact_page(
        row["result"]["refined_memory_proof_artifact"],
        "refined_memory_proof", items, metadata, None, 50,
    )
    assert page["schema_version"] == "flow-page/1"
    assert metadata["refined_attempted"] is False
    ensure_wire_v1_safe(raw)
    runtime.shutdown()
    store.close()


def test_inline_requests_refused(tmp_path):
    """The retired inline protocol refuses loudly instead of mis-solving."""
    from ida_pro_mcp.flow_core.serialization import ContractError

    store, graph, gid = setup_path(tmp_path)
    selector = PathSelector(path_bindings(graph), (0, 1))
    with pytest.raises(ContractError, match="refine_inline_retired"):
        run_path_refinement(
            store,
            {
                "graph_artifact": gid,
                "path": selector.to_data(),
                "refinement": RefinementSpec().to_data(),
                "inline": [{"call_id": "call-v1:deadbeef"}],
            },
        )
    store.close()


def test_wide_witness_stays_wire_safe(tmp_path):
    graph = angr_branch_graph()
    store = Store(tmp_path / "store", scope_of(graph.snapshot), OWNER)
    store.put_artifact("snapshot", graph.snapshot)
    gid = store.put_artifact("graph", graph)
    huge = 2**64 - 1
    witness = ({"name": "rdi", "width_bits": 64, "value_hex": hex(huge)},)
    sidecar = write_runner(tmp_path, "feasible", witness=witness)

    def analyze(ctx, value):
        _store, request = value
        return run_path_refinement(
            _store, request, angr_sidecar=sidecar,
            cancelled=ctx.cancel.is_set,
        )

    runtime = Runtime(
        store, {"refine_path_proof_v1": Handler(lambda ctx, v: (store, v), analyze)}
    )
    selector = PathSelector(path_bindings(graph), (0, 1))
    job = runtime.submit(
        "refine_path_proof_v1",
        {
            "graph_artifact": gid,
            "path": selector.to_data(),
            "refinement": RefinementSpec(symbolic_angr=True).to_data(),
            "angr_binary": {"path": "/fake/probe.elf", "sha256": DIGEST, "image_base": 0x0},
        },
        "refine-wide",
    )
    assert runtime.wait(job)
    row = store.job(job)
    assert row["state"] == "complete"
    assert row["result"]["refined_status"] == "feasible_angr_v1"
    raw = store.artifact(row["result"]["refined_path_proof_artifact"])
    (binding,) = raw["refined"]["witness"]
    assert binding["width_bits"] == 64
    assert int(binding["value_hex"], 16) == huge
    assert huge > 2**53 - 1
    ensure_wire_v1_safe(raw)
    runtime.shutdown()
    store.close()


def test_cancelled_refinement_reports_unknown():
    from ida_pro_mcp.flow_core.refine import refine_path_proof

    graph = branch_graph()
    selector = PathSelector(path_bindings(graph), (0, 1))
    refined = refine_path_proof(
        graph, selector, RefinementSpec(), cancelled=lambda: True
    )
    assert refined["baseline"]["status"] == "unknown"
