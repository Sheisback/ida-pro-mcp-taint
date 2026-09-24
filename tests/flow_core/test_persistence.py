"""Atomic persistence/race tests, no IDA, polling sleeps or external processes."""

from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import sqlite3
import threading

import pytest

from ida_pro_mcp.flow_core import ContractError, digest, stable_id
import ida_pro_mcp.flow_core.persistence as persistence_module
from ida_pro_mcp.flow_core.contracts import Node, NodeKey, ValueSource
from ida_pro_mcp.flow_core.persistence import (
    PAGE_HARD_CHARS,
    PersistenceError,
    Store,
)
from ida_pro_mcp.flow_core.runtime import Handler, JobCancelled, JobDeadline, Runtime
from ida_pro_mcp.flow_core.ssa import build_ssa
from ida_pro_mcp.flow_core.runtime_contracts import RuntimeScope, TraceSpec, TraceState
from ida_pro_mcp.worker_lifecycle import WorkerLifecycle
from test_contracts import sample_graph

ROOT = Path(__file__).resolve().parents[2]
OWNER = "owner-secret-not-a-binary-hash-0001"


def scope_of(snapshot):
    i = snapshot.identity
    return RuntimeScope(
        i.namespace,
        i.semantic_digest,
        i.binary_digest,
        i.profile_digest,
        i.rule_digest,
        i.summary_digest,
        i.policy_digest,
    )


def graph():
    g = sample_graph()
    other = Node(
        NodeKey(
            g.snapshot.snapshot_id, g.snapshot.function.function_id, synthetic="other"
        ),
        "InputValue",
        8,
        g.nodes[0].evidence_ids,
    )
    return replace(g, nodes=tuple(sorted(g.nodes + (other,), key=lambda n: n.node_id)))


def setup(tmp_path):
    g = graph()
    store = Store(tmp_path.resolve() / "store", scope_of(g.snapshot), OWNER)
    sid = store.put_artifact("snapshot", g.snapshot)
    gid = store.put_artifact("graph", g)
    source = ValueSource(g.snapshot.snapshot_id, g.nodes[0].node_id).to_data()
    spec = TraceSpec(
        sid,
        digest("trace-policy"),
        digest(source),
        "function",
        "forward",
        ("value_dependency",),
        gid,
    )
    state = TraceState(frontier=tuple(n.node_id for n in g.nodes), budget_remaining=10)
    tid = store.create_trace(spec, source, state, "trace-request")
    return store, g, tid


def next_state(g):
    a, b = (n.node_id for n in g.nodes)
    return TraceState(frontier=(b,), visited=(a,), emitted=(a,), budget_remaining=9)


def test_trace_atomic_page_replay_and_conflicting_request(tmp_path):
    store, g, tid = setup(tmp_path)
    try:
        first = store.commit_page(
            tid,
            0,
            "page-key",
            {"limit": 1},
            [{"node": g.nodes[0].node_id}],
            next_state(g),
        )
        assert first["revision"] == 1 and store.trace(tid)["revision"] == 1
        assert (
            store.commit_page(tid, 0, "page-key", {"limit": 1}, [], TraceState())
            == first
        )
        assert store.trace(tid)["state"] == next_state(g)
        with pytest.raises(PersistenceError, match="idempotency_conflict"):
            store.commit_page(tid, 0, "page-key", {"limit": 2}, [], next_state(g))
        with pytest.raises(PersistenceError, match="revision_conflict"):
            store.commit_page(tid, 0, "different-key", {"limit": 1}, [], next_state(g))
    finally:
        store.close()


@pytest.mark.parametrize("phase,revision", [("before_commit", 0), ("after_commit", 1)])
def test_crash_before_after_commit_recovery(tmp_path, phase, revision):
    store, g, tid = setup(tmp_path)

    def crash(at):
        if at == phase:
            raise ConnectionError("simulated disconnected client")

    with pytest.raises(ConnectionError):
        store.commit_page(tid, 0, "page", {}, ["one"], next_state(g), _fault=crash)
    root, scope = store.root, store.scope
    store.close()
    recovered = Store(root, scope, OWNER)
    try:
        assert recovered.trace(tid)["revision"] == revision
        response = recovered.commit_page(tid, 0, "page", {}, ["one"], next_state(g))
        assert response["revision"] == 1
        assert recovered.trace(tid)["state"] == next_state(g)
        assert recovered.integrity_check()
        recovered.recover_blobs()
        assert recovered.integrity_check()
    finally:
        recovered.close()


def test_concurrent_continue_has_one_revision_winner(tmp_path):
    store, g, tid = setup(tmp_path)
    view = Store(store.root, store.scope, OWNER, recover=False)
    gate = threading.Barrier(3)
    outputs = []

    def commit(client, key):
        gate.wait()
        try:
            outputs.append(client.commit_page(tid, 0, key, {}, [key], next_state(g)))
        except PersistenceError as exc:
            outputs.append(str(exc))

    threads = [
        threading.Thread(target=commit, args=(store, "a")),
        threading.Thread(target=commit, args=(view, "b")),
    ]
    for t in threads:
        t.start()
    gate.wait()
    for t in threads:
        t.join(5)
        assert not t.is_alive()
    assert sum(isinstance(x, dict) for x in outputs) == 1
    assert outputs.count("revision_conflict") == 1
    assert store.trace(tid)["revision"] == 1
    view.close()
    store.close()


def test_namespace_owner_and_same_binary_do_not_grant_trace_access(tmp_path):
    store, g, tid = setup(tmp_path)
    with pytest.raises(PersistenceError, match="wrong_database_owner"):
        Store(
            store.root,
            store.scope,
            "wrong-owner-key-with-thirty-two-chars",
            recover=False,
        )
    other = Store(
        store.root,
        replace(store.scope, namespace="different-database"),
        "other-owner-key-with-thirty-two-chars",
    )
    try:
        assert other.scope.binary_digest == store.scope.binary_digest
        with pytest.raises(PersistenceError, match="wrong_database"):
            other.trace(tid)
        with pytest.raises(PersistenceError, match="snapshot_scope_mismatch"):
            other.put_artifact("snapshot", g.snapshot)
    finally:
        other.close()
        store.close()


def test_fingerprint_change_invalidates_old_views_without_reattaching(tmp_path):
    store, g, tid = setup(tmp_path)
    old = Store(store.root, store.scope, OWNER, recover=False)
    changed = replace(store.scope, fingerprint=digest("changed IDB"))
    with pytest.raises(PersistenceError, match="stale_context"):
        Store(store.root, changed, OWNER, recover=False)
    store.invalidate_context(changed)
    try:
        with pytest.raises(PersistenceError, match="stale_context"):
            old.trace(tid)
        with pytest.raises(PersistenceError, match="stale_context"):
            store.trace(tid)
    finally:
        old.close()
        store.close()


def test_size_uses_rpc_json_characters_and_no_frontier_advance(tmp_path):
    store, g, tid = setup(tmp_path)
    try:
        huge = "한" * 7000
        assert len(huge.encode("utf-8")) < PAGE_HARD_CHARS < len(json.dumps(huge))
        with pytest.raises(PersistenceError, match="item_too_large"):
            store.commit_page(tid, 0, "large", {}, [huge], next_state(g))
        assert store.trace(tid)["revision"] == 0
        response = store.commit_page(tid, 0, "small", {}, ["한" * 2000], next_state(g))
        assert len(json.dumps(response)) <= PAGE_HARD_CHARS < 40000
        aid = store.put_artifact("evidence", "한" * 10000)
        p = store.evidence_page(aid, 0, 2048)
        assert p["text"] == "한" * 2048 and p["next_offset"] == 2048
        assert store.evidence_page(aid, 2048, 100)["offset"] == 2048
        with pytest.raises(PersistenceError, match="item_too_large"):
            store.evidence_page(aid, 0, 10000)
    finally:
        store.close()


def test_blob_integrity_permissions_and_narrow_cleanup(tmp_path):
    store, g, tid = setup(tmp_path)
    try:
        referenced = store.trace(tid)["state_blob"]
        orphan, _ = store.blobs.put({"orphan": True})
        temporary = store.blobs.path / (".tmp-" + "a" * 32 + ".json")
        temporary.write_text("temporary")
        temporary.chmod(0o600)
        unrelated = store.blobs.path / "keep.txt"
        unrelated.write_text("not ours")
        removed = store.recover_blobs()
        assert orphan.split(":")[1] + ".json" in removed and temporary.name in removed
        assert unrelated.exists() and store.blobs.read(referenced)
        path = store.blobs._path(referenced)
        original = path.read_bytes()
        path.write_bytes(b"{}")
        path.chmod(0o600)
        with pytest.raises(PersistenceError, match="corrupt_blob"):
            store.integrity_check()
        with pytest.raises(PersistenceError, match="corrupt_blob"):
            store.recover_blobs()
        assert path.exists()
        path.write_bytes(original)
        path.chmod(0o644)
        with pytest.raises(PersistenceError, match="insecure_file"):
            store.blobs.read(referenced)
        path.chmod(0o600)
        with pytest.raises(PersistenceError, match="invalid_blob_id"):
            store.blobs.read("../../secret")
    finally:
        store.close()


def test_symlink_root_blob_and_database_fail_closed(tmp_path):
    target = tmp_path / "real"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(PersistenceError, match="symlink"):
        Store(link, scope_of(graph().snapshot), OWNER)
    store, g, tid = setup(tmp_path)
    ref = store.trace(tid)["state_blob"]
    path = store.blobs._path(ref)
    path.unlink()
    path.symlink_to(tmp_path / "outside")
    with pytest.raises(PersistenceError):
        store.blobs.read(ref)
    store.close()
    path.unlink()
    db = store.db
    db.unlink()
    db.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(PersistenceError):
        Store(store.root, store.scope, OWNER)


@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
def test_disappearing_sqlite_sidecar_does_not_break_file_check(
    tmp_path, monkeypatch, suffix
):
    store, _, _ = setup(tmp_path)
    connection = sqlite3.connect(store.db)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("SELECT count(*) FROM sqlite_master")
    sidecar = Path(str(store.db) + suffix)
    assert sidecar.exists()
    original_check = persistence_module._file_check
    disappeared = False

    def close_before_lstat(path):
        nonlocal disappeared
        if path == sidecar and not disappeared:
            disappeared = True
            connection.close()
            assert not sidecar.exists()
        return original_check(path)

    monkeypatch.setattr(persistence_module, "_file_check", close_before_lstat)
    try:
        store._check_files()
        assert disappeared
    finally:
        if not disappeared:
            connection.close()
        store.close()


def test_sqlite_sidecar_symlink_and_disappearing_main_db_still_fail(
    tmp_path, monkeypatch
):
    store, _, _ = setup(tmp_path)
    sidecar = Path(str(store.db) + "-shm")
    outside = tmp_path / "outside"
    outside.write_text("not an SQLite sidecar")
    sidecar.symlink_to(outside)
    try:
        with pytest.raises(PersistenceError, match="insecure_file"):
            store._check_files()
        sidecar.unlink()
        original_check = persistence_module._file_check

        def remove_main_before_lstat(path):
            if path == store.db:
                store.db.unlink()
            return original_check(path)

        monkeypatch.setattr(persistence_module, "_file_check", remove_main_before_lstat)
        with pytest.raises(FileNotFoundError):
            store._check_files()
    finally:
        store.close()


def test_sqlite_corruption_and_schema_version_rejected(tmp_path):
    store, g, tid = setup(tmp_path)
    root, scope = store.root, store.scope
    store.close()
    with sqlite3.connect(root / "metadata.sqlite") as conn:
        conn.execute("PRAGMA user_version=99")
    conn.close()
    with pytest.raises(PersistenceError, match="unsupported_schema_version"):
        Store(root, scope, OWNER)
    (root / "metadata.sqlite").write_bytes(b"not a sqlite database")
    with pytest.raises(PersistenceError, match="sqlite_failure"):
        Store(root, scope, OWNER)


def test_job_recovery_terminal_immutability_and_safe_retry(tmp_path):
    store, g, _ = setup(tmp_path)
    job = store.create_job("pure", {"x": 1}, "create")
    assert store.create_job("pure", {"x": 1}, "create") == job
    with pytest.raises(PersistenceError, match="idempotency_conflict"):
        store.create_job("pure", {"x": 2}, "create")
    store.transition_job(job, "queued", "extracting", owner="owner")
    store.checkpoint_job(job, "owner", {"count": 1}, {"safe_point": 1})
    root, scope = store.root, store.scope
    store.close()
    store = Store(root, scope, OWNER)
    try:
        row = store.job(job)
        assert row["state"] == "interrupted" and row["result"] == {"safe_point": 1}
        with pytest.raises(PersistenceError, match="invalid_job_transition"):
            store.transition_job(job, "interrupted", "queued")
        retry = store.create_job("pure", {"x": 1}, "retry", retry_of=job)
        assert retry != job and store.job(retry)["state"] == "queued"
        with pytest.raises(PersistenceError, match="retry_input_changed"):
            store.create_job("pure", {"x": 2}, "bad-retry", retry_of=job)
    finally:
        store.close()


def test_owner_recovery_lock_cannot_interrupt_live_store(tmp_path):
    store, g, _ = setup(tmp_path)
    job = store.create_job("pure", {}, "j")
    with pytest.raises(PersistenceError, match="runtime_already_owned"):
        Store(store.root, store.scope, OWNER)
    assert store.job(job)["state"] == "queued"
    view = Store(store.root, store.scope, OWNER, recover=False)
    assert view.job(job)["state"] == "queued"
    view.close()
    store.close()


def test_completion_cancellation_has_one_terminal_winner(tmp_path):
    store, g, _ = setup(tmp_path)
    job = store.create_job("pure", {}, "j")
    for a, b in (
        ("queued", "extracting"),
        ("extracting", "analyzing"),
        ("analyzing", "committing"),
    ):
        store.transition_job(job, a, b)
    barrier = threading.Barrier(3)
    answers = []

    def complete():
        barrier.wait()
        try:
            store.transition_job(job, "committing", "complete", result={"ok": True})
            answers.append("complete")
        except PersistenceError:
            answers.append("lost")

    def cancel():
        barrier.wait()
        answers.append(store.request_cancel(job))

    threads = [threading.Thread(target=complete), threading.Thread(target=cancel)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(5)
        assert not thread.is_alive()
    state = store.job(job)["state"]
    assert state in {"complete", "cancel_requested"}
    if state == "cancel_requested":
        store.transition_job(job, state, "cancelled")
    terminal = store.job(job)["state"]
    assert store.request_cancel(job) == terminal
    store.close()


def test_runtime_fixed_registry_progress_and_success(tmp_path):
    store, g, _ = setup(tmp_path)
    calls = []

    def extract(ctx, value):
        ctx.check()
        calls.append(value)
        ctx.report({"phase": "extract"}, {"saved": True})
        return value["x"]

    runtime = Runtime(
        store, {"pure": Handler(extract, lambda ctx, value: {"answer": value + 1})}
    )
    job = runtime.submit("pure", {"x": 4}, "job")
    assert runtime.wait(job)
    assert store.job(job)["state"] == "complete" and store.job(job)["result"] == {
        "answer": 5
    }
    assert runtime.submit("pure", {"x": 4}, "job") == job and len(calls) == 1
    with pytest.raises(PersistenceError, match="unknown_handler"):
        runtime.submit("os.system", {}, "bad")
    assert runtime.active_job_count == 0
    runtime.shutdown()
    store.close()


def test_long_job_busy_lease_expiry_and_bounded_shutdown(tmp_path):
    store, g, _ = setup(tmp_path)
    now = [0.0]
    entered = threading.Event()
    release = threading.Event()

    def blocked(ctx, value):
        entered.set()
        assert release.wait(5)
        ctx.check()
        return value

    runtime = Runtime(
        store,
        {"pure": Handler(blocked, lambda ctx, value: value)},
        clock=lambda: now[0],
    )
    job = runtime.submit("pure", {}, "j", timeout=10)
    assert entered.wait(5)
    life = WorkerLifecycle(idle_ttl_sec=1)
    life._last_request_at = 0
    life.set_busy_probe(lambda: runtime.active_job_count > 0)
    assert life.check_shutdown_reason() is None
    now[0] = 11
    assert runtime.active_job_count == 0 and store.job(job)["state"] == "interrupted"
    assert life.check_shutdown_reason() is not None
    runtime.shutdown(0)
    with pytest.raises(PersistenceError, match="runtime_closing"):
        runtime.submit("pure", {}, "next")
    release.set()
    assert runtime.wait(job)
    assert store.job(job)["state"] == "interrupted"
    store.close()


def test_cooperative_cancel_and_no_late_completion(tmp_path):
    store, g, _ = setup(tmp_path)
    entered = threading.Event()
    release = threading.Event()

    def work(ctx, value):
        entered.set()
        assert release.wait(5)
        ctx.check()
        return value

    runtime = Runtime(store, {"pure": Handler(work, work)})
    job = runtime.submit("pure", {}, "j")
    assert entered.wait(5)
    assert runtime.cancel(job) == "cancel_requested"
    release.set()
    assert runtime.wait(job)
    assert store.job(job)["state"] == "cancelled"
    runtime.shutdown()
    store.close()


def test_worker_runtime_factory_is_private_and_owner_checked(tmp_path):
    path = ROOT / "src/ida_pro_mcp/ida_mcp/flow/runtime.py"
    spec = importlib.util.spec_from_file_location("standalone_flow_runtime", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    scope = scope_of(graph().snapshot)
    handlers = {"pure": Handler(lambda ctx, x: x, lambda ctx, x: x)}
    runtime = module.configure_runtime(
        tmp_path.resolve() / "runtime", scope, OWNER, handlers
    )
    assert (
        module.configure_runtime(runtime.store.root, scope, OWNER, handlers) is runtime
    )
    with pytest.raises(PersistenceError, match="wrong_database_owner"):
        module.configure_runtime(
            runtime.store.root,
            scope,
            "different-owner-with-at-least-32-chars",
            handlers,
        )
    assert module.active_job_count() == 0
    module.shutdown(0)
    with pytest.raises(PersistenceError, match="runtime_closing"):
        module.configure_runtime(runtime.store.root, scope, OWNER, handlers)
    assert "@tool" not in path.read_text().split('"""', 2)[-1]


def test_trace_contract_rejects_other_snapshot_and_dangling_frontier(tmp_path):
    store, g, tid = setup(tmp_path)
    try:
        with pytest.raises(PersistenceError, match="dangling_trace_node"):
            store.commit_page(
                tid,
                0,
                "bad",
                {},
                [],
                TraceState(frontier=(stable_id("node", "missing"),)),
            )
        with pytest.raises(ContractError):
            TraceState(frontier=("../../not-a-node",))
        assert store.trace(tid)["revision"] == 0
        original = store.trace(tid)
        wrong = ValueSource(
            stable_id("snapshot", "wrong"), g.nodes[0].node_id
        ).to_data()
        spec = replace(original["spec"], source_digest=digest(wrong))
        with pytest.raises(ContractError, match="Cross-snapshot"):
            store.create_trace(spec, wrong, original["state"], "wrong")
    finally:
        store.close()


def test_same_key_concurrent_continue_replays_identical_page(tmp_path):
    store, g, tid = setup(tmp_path)
    barrier = threading.Barrier(3)
    results = []

    def commit():
        barrier.wait()
        results.append(
            store.commit_page(tid, 0, "same", {"limit": 1}, ["item"], next_state(g))
        )

    threads = [threading.Thread(target=commit) for _ in range(2)]
    for t in threads:
        t.start()
    barrier.wait()
    for t in threads:
        t.join(5)
        assert not t.is_alive()
    assert len(results) == 2 and results[0] == results[1]
    assert store.trace(tid)["revision"] == 1
    store.close()


def test_cancelled_trace_retains_frontier_and_terminal_replay(tmp_path):
    store, g, tid = setup(tmp_path)
    state = replace(store.trace(tid)["state"], status="cancelled")
    response = store.commit_page(tid, 0, "cancel", {"cancel": True}, [], state)
    assert store.trace(tid)["state"].frontier == state.frontier
    assert store.commit_page(tid, 0, "cancel", {"cancel": True}, [], state) == response
    with pytest.raises(PersistenceError, match="terminal_trace"):
        store.commit_page(tid, 1, "next", {}, [], state)
    store.close()


def test_page_target_limit_rejects_without_advancing(tmp_path):
    store, g, tid = setup(tmp_path)
    with pytest.raises(PersistenceError, match="page_target_exceeded"):
        store.commit_page(
            tid, 0, "large-batch", {}, ["x" * 9000, "y" * 9000], next_state(g)
        )
    assert store.trace(tid)["revision"] == 0
    single = store.commit_page(tid, 0, "single", {}, ["x" * 20000], next_state(g))
    assert len(json.dumps(single)) < 40000
    store.close()


def test_blob_dedup_missing_referenced_blob_and_hardlink_rejected(tmp_path):
    import os

    store, g, tid = setup(tmp_path)
    first = store.put_artifact("evidence", "same")
    second = store.put_artifact("evidence", "same")
    assert first != second and store.artifact(first) == store.artifact(second)
    with store._transaction() as conn:
        a = store._row(conn, "artifacts", first)["blob"]
        b = store._row(conn, "artifacts", second)["blob"]
    assert a == b
    path = store.blobs._path(a)
    hard = tmp_path / "hardlink"
    os.link(path, hard)
    with pytest.raises(PersistenceError, match="insecure_file"):
        store.artifact(first)
    hard.unlink()
    path.unlink()
    with pytest.raises(PersistenceError, match="missing_or_corrupt_blob"):
        store.artifact(first)
    with pytest.raises(PersistenceError):
        store.recover_blobs()
    store.close()


def test_failed_recovery_releases_owner_lease(tmp_path):
    store, g, tid = setup(tmp_path)
    blob = store.trace(tid)["state_blob"]
    path = store.blobs._path(blob)
    original = path.read_bytes()
    root, scope = store.root, store.scope
    store.close()
    path.write_bytes(b"corruption")
    with pytest.raises(PersistenceError):
        Store(root, scope, OWNER)
    path.write_bytes(original)
    recovered = Store(root, scope, OWNER)
    assert recovered.integrity_check()
    recovered.close()


def test_invalid_request_values_and_schema_contracts(tmp_path):
    store, g, tid = setup(tmp_path)
    for value in (float("nan"), float("inf"), object()):
        with pytest.raises(ContractError):
            store.put_artifact("analysis", {"value": value})
    with pytest.raises(ContractError):
        replace(store.scope, schema_version=2)
    with pytest.raises(ContractError):
        replace(store.trace(tid)["spec"], direction="sideways")
    with pytest.raises(PersistenceError):
        store.create_job("../../command", {}, "r")
    with pytest.raises(PersistenceError):
        store.create_job("pure", {}, "r", budget=[])
    store.close()


def test_queued_recovery_and_all_terminal_states_immutable(tmp_path):
    store, g, _ = setup(tmp_path)
    queued = store.create_job("pure", {}, "queued")
    failed = store.create_job("pure", {}, "failed")
    store.transition_job(failed, "queued", "failed", error={"code": "test"})
    root, scope = store.root, store.scope
    store.close()
    recovered = Store(root, scope, OWNER)
    assert recovered.job(queued)["state"] == "interrupted"
    assert recovered.job(failed)["state"] == "failed"
    for terminal in ("complete", "cancelled", "failed", "stale", "interrupted"):
        with pytest.raises(PersistenceError, match="invalid_job_transition"):
            recovered.transition_job(failed, terminal, "queued")
    recovered.close()


def test_runtime_failure_null_result_budget_and_owner_lease(tmp_path):
    store, g, _ = setup(tmp_path)

    def fail(ctx, value):
        raise ValueError("not serialized user/private error text")

    def report(ctx, value):
        assert ctx.budget["nodes"] == 10
        ctx.report({"count": 1}, {"checkpoint": True})
        return None

    runtime = Runtime(
        store, {"fail": Handler(fail, fail), "null": Handler(lambda ctx, x: x, report)}
    )
    failed = runtime.submit("fail", {}, "fail")
    assert runtime.wait(failed) and store.job(failed)["state"] == "failed"
    assert store.job(failed)["error"] == {
        "code": "handler_failed",
        "phase": "extract",
        "reason": "invalid_handler_value",
        "type": "ValueError",
    }
    job = runtime.submit("null", {}, "null", budget={"nodes": 10})
    assert runtime.wait(job)
    assert store.job(job)["state"] == "complete" and store.job(job)["result"] is None
    view = Store(store.root, store.scope, OWNER, recover=False)
    with pytest.raises(PersistenceError, match="owner_lease"):
        Runtime(view, {})
    view.close()
    runtime.shutdown()
    store.close()


def test_runtime_failure_reasons_are_phase_bound_allowlisted_and_path_free(tmp_path):
    store, graph_value, _ = setup(tmp_path)

    def microcode_fail(ctx, value):
        raise RuntimeError(
            "gen_microcode failed: code=123, ea=0x401000 /Users/private/secret.i64"
        )

    def stale_fail(ctx, value):
        raise PersistenceError("stale_database")

    class PrivateInternalName(Exception):
        pass

    def private_fail(ctx, value):
        raise PrivateInternalName("/Users/private/secret.i64")

    handlers = {
        "budget": Handler(
            lambda ctx, value: value,
            lambda ctx, value: build_ssa(graph_value.snapshot, max_nodes=1),
        ),
        "native": Handler(microcode_fail, lambda ctx, value: value),
        "stale": Handler(lambda ctx, value: value, stale_fail),
        "internal": Handler(private_fail, lambda ctx, value: value),
    }
    runtime = Runtime(store, handlers)
    expected = {
        "budget": ("analyze", "ssa_node_budget_exceeded", "ContractError"),
        "native": ("extract", "microcode_generation_failed", "RuntimeError"),
        "stale": ("analyze", "stale_database", "PersistenceError"),
        "internal": ("extract", "internal_error", "InternalError"),
    }
    for name, (phase, reason, kind) in expected.items():
        identifier = runtime.submit(name, {}, name)
        assert runtime.wait(identifier)
        row = store.job(identifier)
        assert row["state"] == "failed"
        assert row["error"] == {
            "code": "handler_failed",
            "phase": phase,
            "reason": reason,
            "type": kind,
        }
        assert "secret" not in json.dumps(row["error"])
        assert "/Users" not in json.dumps(row["error"])
        assert "401000" not in json.dumps(row["error"])
    runtime.shutdown()
    store.close()


def test_runtime_cancel_and_deadline_errors_keep_safe_phase_codes(tmp_path):
    store, _, _ = setup(tmp_path)

    def cancel(ctx, value):
        raise JobCancelled()

    def deadline(ctx, value):
        raise JobDeadline()

    runtime = Runtime(
        store,
        {
            "cancel": Handler(cancel, lambda ctx, value: value),
            "deadline": Handler(deadline, lambda ctx, value: value),
        },
    )
    cancelled = runtime.submit("cancel", {}, "cancel")
    interrupted = runtime.submit("deadline", {}, "deadline")
    assert runtime.wait(cancelled) and runtime.wait(interrupted)
    assert store.job(cancelled)["error"] == {
        "code": "cancelled",
        "phase": "extract",
        "reason": "cancelled",
    }
    assert store.job(interrupted)["error"] == {
        "code": "lease_expired",
        "phase": "extract",
        "reason": "deadline_exceeded",
    }
    runtime.shutdown()
    store.close()


def test_stuck_shutdown_is_bounded_and_retired_job_cannot_commit(tmp_path):
    store, g, _ = setup(tmp_path)
    entered = threading.Event()
    release = threading.Event()

    def uncooperative(ctx, value):
        entered.set()
        assert release.wait(5)
        return {"late": True}

    runtime = Runtime(store, {"pure": Handler(uncooperative, lambda ctx, x: x)})
    job = runtime.submit("pure", {}, "j")
    assert entered.wait(5)
    assert runtime.shutdown(0) == (job,)
    assert runtime.active_job_count == 0 and store.job(job)["state"] == "interrupted"
    release.set()
    assert runtime.wait(job)
    assert store.job(job)["state"] == "interrupted"
    store.close()


def test_supervisor_detach_shutdown_leave_live_runtime_but_owned_close_stops_it(
    tmp_path,
):
    support_spec = importlib.util.spec_from_file_location(
        "flow_supervisor_test_support", ROOT / "tests/test_idalib_supervisor.py"
    )
    support = importlib.util.module_from_spec(support_spec)
    support_spec.loader.exec_module(support)
    from ida_pro_mcp import idalib_supervisor as supmod

    store, g, _ = setup(tmp_path)
    entered = threading.Event()
    release = threading.Event()

    def work(ctx, value):
        entered.set()
        assert release.wait(5)
        ctx.check()
        return value

    runtime = Runtime(store, {"pure": Handler(work, lambda ctx, x: x)})
    job = runtime.submit("pure", {}, "j")
    assert entered.wait(5)

    class Process(support._FakeProcess):
        def terminate(self):
            runtime.shutdown(0)
            super().terminate()

    sup = support._FakeSupervisor()
    path = str((tmp_path / "sample.bin").resolve())
    adopted = supmod.WorkerSession(
        session_id="adopted",
        input_path=path,
        filename="sample.bin",
        process=Process(),
        owned=False,
    )
    with sup._lock:
        sup._register_session_locked(adopted, path)
    sup.close_session("adopted", save=False)
    assert runtime.active_job_count == 1 and adopted.process.returncode is None
    owned = supmod.WorkerSession(
        session_id="owned",
        input_path=path,
        filename="sample.bin",
        process=Process(),
        owned=True,
    )
    with sup._lock:
        sup._register_session_locked(owned, path)
    sup.shutdown()
    assert runtime.active_job_count == 1 and owned.process.returncode is None
    with sup._lock:
        sup._register_session_locked(owned, path)
    sup.close_session("owned", save=False)
    assert runtime.active_job_count == 0 and store.job(job)["state"] == "interrupted"
    release.set()
    assert runtime.wait(job)
    store.close()


def test_worker_busy_hook_and_shutdown_are_wired_without_public_tools():
    import ast

    source = (ROOT / "src/ida_pro_mcp/idalib_server.py").read_text()
    tree = ast.parse(source)
    call = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "set_busy_probe"
    )
    body = call.args[0].body
    assert isinstance(body, ast.BoolOp) and isinstance(body.op, ast.Or)
    names = {n.attr for n in ast.walk(body) if isinstance(n, ast.Attribute)}
    assert {"busy_status", "active_job_count"} <= names
    assert source.count("_FLOW_RUNTIME.shutdown(timeout=2.0)") == 3
    assert "_FLOW_RUNTIME.begin_close()" in source
    assert "with _FLOW_RUNTIME.database_switch():" in source
    assert not any(
        "flow_job" in n.name for n in tree.body if isinstance(n, ast.FunctionDef)
    )


def test_foreign_private_directory_is_not_claimed_or_cleaned(tmp_path):
    root = tmp_path.resolve() / "foreign"
    root.mkdir(mode=0o700)
    unrelated = root / "important.json"
    unrelated.write_text("keep me")
    with pytest.raises(PersistenceError, match="unrecognized_store_root"):
        Store(root, scope_of(graph().snapshot), OWNER)
    assert unrelated.read_text() == "keep me"
    assert not (root / "metadata.sqlite").exists()


def test_store_marker_tampering_and_identical_scope_noop(tmp_path):
    store, g, tid = setup(tmp_path)
    assert store.invalidate_context(store.scope) is False
    assert store.trace(tid)["revision"] == 0
    store.marker.write_text("foreign")
    with pytest.raises(PersistenceError, match="invalid_store_marker"):
        store.trace(tid)
    store.close()


def test_shutdown_does_not_wait_for_contended_sqlite_writer(tmp_path):
    store, g, _ = setup(tmp_path)
    entered = threading.Event()
    work_release = threading.Event()

    def work(ctx, value):
        entered.set()
        assert work_release.wait(5)
        ctx.check()
        return value

    runtime = Runtime(store, {"pure": Handler(work, lambda ctx, x: x)})
    job = runtime.submit("pure", {}, "j")
    assert entered.wait(5)
    locked = threading.Event()
    db_release = threading.Event()
    shutdown_done = threading.Event()

    def hold():
        with store._transaction():
            locked.set()
            assert db_release.wait(5)

    holder = threading.Thread(target=hold)
    holder.start()
    assert locked.wait(5)

    def shut():
        runtime.shutdown(0)
        shutdown_done.set()

    closer = threading.Thread(target=shut)
    closer.start()
    try:
        assert shutdown_done.wait(2), "shutdown waited for SQLite busy timeout"
    finally:
        db_release.set()
        holder.join(5)
        closer.join(5)
    assert runtime.active_job_count == 0
    work_release.set()
    assert runtime.wait(job)
    assert store.job(job)["state"] in {"cancelled", "interrupted"}
    store.close()


def test_half_cleaned_orphan_metadata_does_not_block_recovery(tmp_path):
    store, g, tid = setup(tmp_path)
    with store._transaction() as conn:
        orphan = store._blob(conn, {"unreferenced": True})
    store.blobs._path(orphan).unlink()  # Crash after unlink, before orphan-row cleanup.
    root, scope = store.root, store.scope
    store.close()
    recovered = Store(root, scope, OWNER)
    assert recovered.trace(tid)["revision"] == 0
    recovered.recover_blobs()
    with recovered._transaction() as conn:
        assert (
            conn.execute(
                "SELECT digest FROM blobs WHERE digest=?", (orphan,)
            ).fetchone()
            is None
        )
    recovered.close()


def test_stale_invalidation_keeps_terminal_state_immutable(tmp_path):
    store, g, _ = setup(tmp_path)
    done = store.create_job("pure", {}, "done")
    for before, after in (
        ("queued", "extracting"),
        ("extracting", "analyzing"),
        ("analyzing", "committing"),
    ):
        store.transition_job(done, before, after)
    store.transition_job(done, "committing", "complete", result={"done": True})
    running = store.create_job("pure", {}, "running")
    store.transition_job(running, "queued", "extracting")
    store.invalidate_context(replace(store.scope, profile_digest=digest("new-profile")))
    with store._transaction(check_scope=False) as conn:
        completed = conn.execute(
            "SELECT state,stale FROM jobs WHERE id=?", (done,)
        ).fetchone()
        active = conn.execute(
            "SELECT state,stale FROM jobs WHERE id=?", (running,)
        ).fetchone()
    assert tuple(completed) == ("complete", 1)
    assert tuple(active) == ("stale", 1)
    with pytest.raises(PersistenceError, match="stale_context"):
        store.job(done)
    store.close()


def test_native_runtime_receipt_and_rpc_limit_are_current():
    import ast
    import hashlib

    receipt = json.loads(
        (ROOT / "tests/flow_fixtures/manifests/runtime_smoke.json").read_text()
    )
    assert receipt["ida_version"] == "9.3"
    assert (
        receipt["busy_guard_passed"]
        and receipt["idempotent_replay"]
        and receipt["integrity_passed"]
    )
    assert receipt["job_terminal"] == "complete" and receipt["result"] == {"answer": 5}
    assert not receipt["target_executed"]
    for path, expected in receipt["implementation_sha256"].items():
        assert hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == expected
    tree = ast.parse((ROOT / "src/ida_pro_mcp/ida_mcp/rpc.py").read_text())
    limit = next(
        n.value.value
        for n in tree.body
        if isinstance(n, ast.Assign)
        and any(
            isinstance(t, ast.Name) and t.id == "OUTPUT_LIMIT_MAX_CHARS"
            for t in n.targets
        )
    )
    assert PAGE_HARD_CHARS < 40000 < limit == 50000


@pytest.mark.parametrize(
    "operation",
    ("snapshot", "graph", "job", "trace", "page", "job_replay", "page_replay"),
)
@pytest.mark.parametrize("peer_wins", (False, True))
@pytest.mark.parametrize("repeat", range(3))
def test_scope_invalidation_fences_every_public_publisher(
    tmp_path, monkeypatch, operation, peer_wins, repeat
):
    from contextlib import contextmanager

    store, g, tid = setup(tmp_path)
    old = store.scope
    new = replace(old, fingerprint=digest(("new-fingerprint-" + str(repeat))))
    trace = store.trace(tid)
    if operation == "job_replay":
        store.create_job("pure", {}, "race-job")
    if operation == "page_replay":
        store.commit_page(tid, 0, "race-page", {}, ["page"], next_state(g))

    def publish():
        if operation == "snapshot":
            return store.put_artifact("snapshot", g.snapshot)
        if operation == "graph":
            return store.put_artifact("graph", g)
        if operation in {"job", "job_replay"}:
            return store.create_job("pure", {}, "race-job")
        if operation == "trace":
            return store.create_trace(
                trace["spec"], trace["source"], trace["state"], "race-trace"
            )
        return store.commit_page(tid, 0, "race-page", {}, ["page"], next_state(g))

    validated = threading.Event()
    release = threading.Event()
    invalidating = threading.Event()
    original = store._transaction

    @contextmanager
    def paused(*args, **kwargs):
        if threading.current_thread().name == "old-publisher":
            validated.set()
            assert release.wait(5)
        with original(*args, **kwargs) as conn:
            yield conn

    monkeypatch.setattr(store, "_transaction", paused)
    result = []
    errors = []

    def writer():
        try:
            result.append(publish())
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=writer, name="old-publisher")
    thread.start()
    assert validated.wait(5)
    peer = Store(store.root, old, OWNER, recover=False) if peer_wins else store

    def invalidate():
        invalidating.set()
        try:
            peer.invalidate_context(new)
        except Exception as exc:
            errors.append(exc)

    invalidator = threading.Thread(target=invalidate)
    invalidator.start()
    assert invalidating.wait(5)
    if peer_wins:
        invalidator.join(5)
        assert not invalidator.is_alive()
    release.set()
    thread.join(5)
    invalidator.join(5)
    assert not thread.is_alive() and not invalidator.is_alive()
    if peer_wins:
        assert not result and len(errors) == 1 and str(errors[0]) == "stale_context"
    else:
        assert result and not errors
    assert store.scope == old and peer.scope == old  # Neither old handle is rebound.
    with pytest.raises(AttributeError):
        store.scope = new
    fresh = Store(store.root, new, OWNER, recover=False)
    with fresh._transaction() as conn:
        for table in ("artifacts", "jobs", "traces"):
            rows = conn.execute(f"SELECT scope_digest,stale FROM {table}").fetchall()
            assert rows or table == "jobs"
            assert all(
                row["scope_digest"] == old.scope_digest and row["stale"] == 1
                for row in rows
            )
    with pytest.raises(PersistenceError, match="stale_context"):
        store.create_job("pure", {}, "after-invalidate")
    fresh.close()
    if peer is not store:
        peer.close()
    store.close()


def test_recovery_transaction_failure_releases_acquired_flock(tmp_path, monkeypatch):
    from contextlib import contextmanager

    store, g, _ = setup(tmp_path)
    job = store.create_job("pure", {}, "queued")
    root, scope = store.root, store.scope
    store.close()
    original = Store._transaction

    class RecoveryFailure:
        def __init__(self, conn):
            self.conn = conn

        def execute(self, sql, *args):
            if sql.startswith("UPDATE jobs SET state='interrupted'"):
                raise RuntimeError("injected recovery transaction failure")
            return self.conn.execute(sql, *args)

    @contextmanager
    def failing(self, *args, **kwargs):
        with original(self, *args, **kwargs) as conn:
            yield RecoveryFailure(conn) if self._lease is not None else conn

    with monkeypatch.context() as patch:
        patch.setattr(Store, "_transaction", failing)
        with pytest.raises(RuntimeError, match="injected recovery"):
            Store(root, scope, OWNER)
    view = Store(root, scope, OWNER, recover=False)
    assert view.job(job)["state"] == "queued"
    view.close()
    recovered = Store(root, scope, OWNER)
    assert recovered.job(job)["state"] == "interrupted"
    recovered.close()


def _factory_module():
    path = ROOT / "src/ida_pro_mcp/ida_mcp/flow/runtime.py"
    spec = importlib.util.spec_from_file_location("admission_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("repeat", range(3))
def test_database_switch_blocks_submit_before_any_job_persistence(tmp_path, repeat):
    module = _factory_module()
    handlers = {"pure": Handler(lambda ctx, x: x, lambda ctx, x: x)}
    runtime = module.configure_runtime(
        tmp_path.resolve() / "admission", scope_of(graph().snapshot), OWNER, handlers
    )
    entered = threading.Event()
    release = threading.Event()
    out = []

    def switch():
        with module.database_switch():
            entered.set()
            assert release.wait(5)

    thread = threading.Thread(target=switch)
    thread.start()
    assert entered.wait(5)
    try:
        with pytest.raises(PersistenceError, match="database_admission_busy"):
            runtime.submit("pure", {}, "must-not-persist")
        with runtime.store._transaction() as conn:
            assert conn.execute("SELECT count(*) FROM jobs").fetchone()[0] == 0
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive()
    job = runtime.submit("pure", {}, "after-switch")
    assert runtime.wait(job)
    with module.database_switch():
        out.append("opened")
    assert out == ["opened"]
    module.shutdown(0)


@pytest.mark.parametrize("repeat", range(3))
def test_submit_admission_and_active_jobs_exclude_database_switch(
    tmp_path, monkeypatch, repeat
):
    module = _factory_module()
    entered = threading.Event()
    publish = threading.Event()
    working = threading.Event()
    finish = threading.Event()

    def handler(ctx, value):
        working.set()
        assert finish.wait(5)
        ctx.check()
        return value

    runtime = module.configure_runtime(
        tmp_path.resolve() / "admission",
        scope_of(graph().snapshot),
        OWNER,
        {"pure": Handler(handler, lambda ctx, x: x)},
    )
    original = runtime.store.create_job

    def paused(*args, **kwargs):
        entered.set()
        assert publish.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(runtime.store, "create_job", paused)
    jobs = []
    thread = threading.Thread(
        target=lambda: jobs.append(runtime.submit("pure", {}, "job"))
    )
    thread.start()
    assert entered.wait(5)
    with pytest.raises(PersistenceError, match="database_admission_busy"):
        with module.database_switch():
            raise AssertionError("opened during admission")
    publish.set()
    thread.join(5)
    assert not thread.is_alive()
    assert working.wait(5)
    with pytest.raises(PersistenceError, match="internal flow jobs are active"):
        with module.database_switch():
            raise AssertionError("opened with active job")
    finish.set()
    assert runtime.wait(jobs[0])
    with module.database_switch():
        pass
    module.shutdown(0)


def test_admission_error_cleanup_and_close_during_switch(tmp_path):
    module = _factory_module()
    runtime = module.configure_runtime(
        tmp_path.resolve() / "admission",
        scope_of(graph().snapshot),
        OWNER,
        {"pure": Handler(lambda ctx, x: x, lambda ctx, x: x)},
    )
    with pytest.raises(RuntimeError, match="open failed"):
        with module.database_switch():
            raise RuntimeError("open failed")
    job = runtime.submit("pure", {}, "after-error")
    assert runtime.wait(job)
    entered = threading.Event()
    release = threading.Event()
    closed = threading.Event()

    def switch():
        with module.database_switch():
            entered.set()
            assert release.wait(5)

    thread = threading.Thread(target=switch)
    thread.start()
    assert entered.wait(5)
    closer = threading.Thread(target=lambda: (module.begin_close(), closed.set()))
    closer.start()
    assert closed.wait(2)
    release.set()
    thread.join(5)
    closer.join(5)
    with pytest.raises(PersistenceError, match="runtime_closing"):
        runtime.submit("pure", {}, "closed")
    with pytest.raises(PersistenceError, match="runtime_closing"):
        with module.database_switch():
            pass
    module.shutdown(0)


def test_close_during_admission_prevents_thread_launch(tmp_path, monkeypatch):
    module = _factory_module()
    called = []
    runtime = module.configure_runtime(
        tmp_path.resolve() / "admission",
        scope_of(graph().snapshot),
        OWNER,
        {"pure": Handler(lambda ctx, x: called.append(x), lambda ctx, x: x)},
    )
    entered = threading.Event()
    release = threading.Event()
    errors = []
    original = runtime.store.create_job

    def paused(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(runtime.store, "create_job", paused)

    def submit():
        try:
            runtime.submit("pure", {}, "closing")
        except PersistenceError as exc:
            errors.append(str(exc))

    thread = threading.Thread(target=submit)
    thread.start()
    assert entered.wait(5)
    module.begin_close()
    release.set()
    thread.join(5)
    assert not thread.is_alive() and errors == ["runtime_closing"] and not called
    with runtime.store._transaction() as conn:
        assert conn.execute("SELECT state FROM jobs").fetchone()[0] == "interrupted"
    module.shutdown(0)


def test_worker_database_admission_fence_contains_complete_switch_section():
    import ast

    tree = ast.parse((ROOT / "src/ida_pro_mcp/idalib_server.py").read_text())
    function = next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "idb_open"
    )
    fence = next(
        n
        for n in ast.walk(function)
        if isinstance(n, ast.With)
        and any(
            isinstance(i.context_expr, ast.Call)
            and isinstance(i.context_expr.func, ast.Attribute)
            and i.context_expr.func.attr == "database_switch"
            for i in n.items
        )
    )
    called = {
        n.func.attr if isinstance(n.func, ast.Attribute) else n.func.id
        for n in ast.walk(fence)
        if isinstance(n, ast.Call) and isinstance(n.func, (ast.Attribute, ast.Name))
    }
    assert {
        "open_binary",
        "activate_session",
        "server_warmup",
        "set_idle_ttl",
        "_register_in_discovery",
    } <= called
    assert any(isinstance(n, ast.Return) for n in ast.walk(fence))
    assert not any(
        isinstance(n, ast.Attribute) and n.attr == "active_job_count"
        for n in ast.walk(function)
    )


def test_store_close_cancels_inflight_commit_and_releases_lease_after_rollback(
    tmp_path, monkeypatch
):
    store, g, tid = setup(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    errors = []
    original = store._blob

    def paused(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "_blob", paused)

    def writer():
        try:
            store.commit_page(tid, 0, "closing", {}, ["one"], next_state(g))
        except PersistenceError as exc:
            errors.append(str(exc))

    thread = threading.Thread(target=writer)
    thread.start()
    assert entered.wait(5)
    store.close()
    assert store.closed and store._lease is not None
    release.set()
    thread.join(5)
    assert not thread.is_alive() and errors == ["store_closed"] and store._lease is None
    recovered = Store(store.root, store.scope, OWNER)
    assert recovered.trace(tid)["revision"] == 0
    recovered.close()


def test_expired_but_unfinished_callback_still_fences_database_switch(tmp_path):
    module = _factory_module()
    entered = threading.Event()
    release = threading.Event()
    now = [0.0]

    def work(ctx, value):
        entered.set()
        assert release.wait(5)
        ctx.check()
        return value

    runtime = module.configure_runtime(
        tmp_path.resolve() / "admission",
        scope_of(graph().snapshot),
        OWNER,
        {"pure": Handler(work, lambda ctx, x: x)},
    )
    runtime.clock = lambda: now[0]
    job = runtime.submit("pure", {}, "expiring", timeout=1)
    assert entered.wait(5)
    now[0] = 2
    assert runtime.active_job_count == 0 and runtime.inflight_job_count == 1
    with pytest.raises(PersistenceError, match="internal flow jobs are active"):
        with module.database_switch():
            raise AssertionError("expired SDK callback may still run")
    release.set()
    assert runtime.wait(job)
    with module.database_switch():
        pass
    module.shutdown(0)


@pytest.mark.parametrize("repeat", range(3))
def test_cancel_store_contention_never_holds_runtime_mutex(
    tmp_path, monkeypatch, repeat
):
    store, g, _ = setup(tmp_path)
    entered = threading.Event()
    observed = threading.Event()
    work_release = threading.Event()

    def work(ctx, value):
        entered.set()
        assert ctx.cancel.wait(5)
        observed.set()
        assert work_release.wait(5)
        ctx.check()
        return value

    runtime = Runtime(store, {"pure": Handler(work, lambda ctx, x: x)})
    job = runtime.submit("pure", {}, "job")
    assert entered.wait(5)
    locked = threading.Event()
    db_release = threading.Event()
    cancel_entered = threading.Event()
    shutdown_done = threading.Event()

    def hold():
        with store._transaction():
            locked.set()
            assert db_release.wait(5)

    holder = threading.Thread(target=hold)
    holder.start()
    assert locked.wait(5)
    original = store.request_cancel

    def record(*args, **kwargs):
        cancel_entered.set()
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "request_cancel", record)
    outcomes = []

    def cancel():
        try:
            outcomes.append(runtime.cancel(job))
        except PersistenceError as exc:
            outcomes.append(str(exc))

    canceller = threading.Thread(target=cancel)
    canceller.start()
    assert cancel_entered.wait(5)
    closer = threading.Thread(target=lambda: (runtime.shutdown(0), shutdown_done.set()))
    closer.start()
    try:
        assert observed.wait(2), (
            "worker did not see cancellation before database release"
        )
        assert shutdown_done.wait(2), "cancel held runtime lock during Store wait"
    finally:
        db_release.set()
        holder.join(5)
        canceller.join(5)
        closer.join(5)
        work_release.set()
    assert all(not t.is_alive() for t in (holder, canceller, closer))
    assert runtime.wait(job) and runtime.active_job_count == 0
    assert store.job(job)["state"] in {"cancelled", "interrupted"}
    assert outcomes and outcomes[0] in {"cancel_requested", "cancelled", "interrupted"}
    store.close()


@pytest.mark.parametrize("repeat", range(3))
def test_submit_waiting_on_store_does_not_block_shutdown(tmp_path, monkeypatch, repeat):
    store, g, _ = setup(tmp_path)
    calls = []
    runtime = Runtime(
        store, {"pure": Handler(lambda ctx, x: calls.append(x), lambda ctx, x: x)}
    )
    locked = threading.Event()
    db_release = threading.Event()
    submitting = threading.Event()
    shutdown_done = threading.Event()

    def hold():
        with store._transaction():
            locked.set()
            assert db_release.wait(5)

    holder = threading.Thread(target=hold)
    holder.start()
    assert locked.wait(5)
    original = store.create_job

    def record(*args, **kwargs):
        submitting.set()
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "create_job", record)
    errors = []

    def submit():
        try:
            runtime.submit("pure", {}, "blocked-submit")
        except PersistenceError as exc:
            errors.append(str(exc))

    submitter = threading.Thread(target=submit)
    submitter.start()
    assert submitting.wait(5)
    closer = threading.Thread(target=lambda: (runtime.shutdown(0), shutdown_done.set()))
    closer.start()
    try:
        assert shutdown_done.wait(2), (
            "submit held runtime mutex across Store publication"
        )
    finally:
        db_release.set()
        holder.join(5)
        submitter.join(5)
        closer.join(5)
    assert not calls and errors == ["runtime_closing"]
    with store._transaction() as conn:
        assert conn.execute("SELECT state FROM jobs").fetchone()[0] == "interrupted"
    store.close()


@pytest.mark.parametrize("repeat", range(3))
def test_expiration_bookkeeping_is_outside_runtime_mutex(tmp_path, monkeypatch, repeat):
    store, g, _ = setup(tmp_path)
    now = [0.0]
    entered = threading.Event()
    work_release = threading.Event()

    def work(ctx, value):
        entered.set()
        assert work_release.wait(5)
        ctx.check()
        return value

    runtime = Runtime(
        store, {"pure": Handler(work, lambda ctx, x: x)}, clock=lambda: now[0]
    )
    job = runtime.submit("pure", {}, "expired", timeout=1)
    assert entered.wait(5)
    locked = threading.Event()
    db_release = threading.Event()
    observing = threading.Event()
    finish_release = threading.Event()
    shutdown_done = threading.Event()

    def hold():
        with store._transaction():
            locked.set()
            assert db_release.wait(5)

    holder = threading.Thread(target=hold)
    holder.start()
    assert locked.wait(5)
    original = store.job

    def slow_observer(*args, **kwargs):
        if threading.current_thread().name == "lease-observer":
            observing.set()
            assert finish_release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "job", slow_observer)
    now[0] = 2
    counts = []
    observer = threading.Thread(
        target=lambda: counts.append(runtime.active_job_count), name="lease-observer"
    )
    observer.start()
    assert observing.wait(5)
    closer = threading.Thread(target=lambda: (runtime.shutdown(0), shutdown_done.set()))
    closer.start()
    try:
        assert runtime._jobs[job][1].is_set()
        assert shutdown_done.wait(2), "expiration held runtime mutex across finish I/O"
    finally:
        db_release.set()
        finish_release.set()
        holder.join(5)
        observer.join(5)
        closer.join(5)
        work_release.set()
    assert counts == [0] and runtime.wait(job)
    assert store.job(job)["state"] in {"cancelled", "interrupted"}
    store.close()


def test_cancel_signals_even_when_persistence_fails_and_reports_failure(
    tmp_path, monkeypatch
):
    store, g, _ = setup(tmp_path)
    entered = threading.Event()
    release = threading.Event()

    def work(ctx, value):
        entered.set()
        assert release.wait(5)
        ctx.check()
        return value

    runtime = Runtime(store, {"pure": Handler(work, lambda ctx, x: x)})
    job = runtime.submit("pure", {}, "job")
    assert entered.wait(5)
    original = store.request_cancel

    def fail(*args, **kwargs):
        raise PersistenceError("injected_cancel_failure")

    with monkeypatch.context() as patch:
        patch.setattr(store, "request_cancel", fail)
        with pytest.raises(PersistenceError, match="injected_cancel_failure"):
            runtime.cancel(job)
        assert runtime._jobs[job][1].is_set()
    monkeypatch.setattr(store, "request_cancel", original)
    release.set()
    assert runtime.wait(job)
    assert store.job(job)["state"] == "cancelled"
    runtime.shutdown()
    store.close()


def test_factory_slow_initialization_does_not_block_shutdown(tmp_path, monkeypatch):
    module = _factory_module()
    entered = threading.Event()
    release = threading.Event()
    stopped = threading.Event()
    real_store = module.Store

    def blocked_store(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return real_store(*args, **kwargs)

    monkeypatch.setattr(module, "Store", blocked_store)
    scope = scope_of(graph().snapshot)
    errors = []

    def configure():
        try:
            module.configure_runtime(
                tmp_path.resolve() / "initializing",
                scope,
                OWNER,
                {"pure": Handler(lambda ctx, x: x, lambda ctx, x: x)},
            )
        except PersistenceError as exc:
            errors.append(str(exc))

    starter = threading.Thread(target=configure)
    starter.start()
    assert entered.wait(5)
    closer = threading.Thread(target=lambda: (module.shutdown(0), stopped.set()))
    closer.start()
    try:
        assert stopped.wait(2), "factory held registry lock during store initialization"
    finally:
        release.set()
        starter.join(5)
        closer.join(5)
    assert errors == ["runtime_closing"] and module.active_job_count() == 0
    # A discarded late initialization releases its recovery lease.
    recovered = real_store(tmp_path.resolve() / "initializing", scope, OWNER)
    recovered.close()


def test_runtime_and_factory_locks_do_not_contain_store_calls():
    import ast

    paths = (
        ROOT / "src/ida_pro_mcp/flow_core/runtime.py",
        ROOT / "src/ida_pro_mcp/ida_mcp/flow/runtime.py",
    )
    for path in paths:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.With):
                continue
            locked = any(
                (
                    isinstance(i.context_expr, ast.Attribute)
                    and i.context_expr.attr == "_lock"
                )
                or (
                    isinstance(i.context_expr, ast.Name)
                    and i.context_expr.id == "_lock"
                )
                for i in node.items
            )
            if not locked:
                continue
            for call in (n for n in ast.walk(node) if isinstance(n, ast.Call)):
                assert not (
                    isinstance(call.func, ast.Attribute)
                    and isinstance(call.func.value, ast.Attribute)
                    and call.func.value.attr == "store"
                ), ast.unparse(call)
                assert not (
                    isinstance(call.func, ast.Attribute) and call.func.attr == "_finish"
                ), ast.unparse(call)


def test_concurrent_submit_retries_are_idempotent_without_duplicate_threads(
    tmp_path, monkeypatch
):
    store, g, _ = setup(tmp_path)
    publishing = threading.Event()
    publish_release = threading.Event()
    working = threading.Event()
    work_release = threading.Event()
    calls = []

    def handler(ctx, value):
        calls.append(value)
        working.set()
        assert work_release.wait(5)
        ctx.check()
        return value

    runtime = Runtime(store, {"pure": Handler(handler, lambda ctx, x: x)})
    original = store.create_job

    def paused(*args, **kwargs):
        publishing.set()
        assert publish_release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "create_job", paused)
    ids = []
    thread = threading.Thread(
        target=lambda: ids.append(runtime.submit("pure", {}, "same"))
    )
    thread.start()
    assert publishing.wait(5)
    with pytest.raises(PersistenceError, match="job_admission_busy"):
        runtime.submit("pure", {}, "same")
    publish_release.set()
    thread.join(5)
    assert not thread.is_alive()
    assert working.wait(5)
    assert runtime.submit("pure", {}, "same") == ids[0]
    work_release.set()
    assert runtime.wait(ids[0])
    assert len(calls) == 1
    runtime.shutdown()
    store.close()


def test_factory_invalid_handler_releases_store_lease_and_admission(tmp_path):
    module = _factory_module()
    scope = scope_of(graph().snapshot)
    root = tmp_path.resolve() / "bad-handler"
    with pytest.raises(PersistenceError, match="invalid_handler_registry"):
        module.configure_runtime(root, scope, OWNER, {"bad": object()})
    recovered = Store(root, scope, OWNER)
    recovered.close()
    runtime = module.configure_runtime(
        root, scope, OWNER, {"pure": Handler(lambda ctx, x: x, lambda ctx, x: x)}
    )
    job = runtime.submit("pure", {}, "valid")
    assert runtime.wait(job)
    module.shutdown(0)


def test_runtime_recovers_terminal_write_after_sqlite_lock(tmp_path, monkeypatch):
    store, _, _ = setup(tmp_path)
    entered = threading.Event()
    release = threading.Event()

    def analyze(ctx, value):
        entered.set()
        assert release.wait(5)
        raise ValueError("handler failed")

    runtime = Runtime(store, {"pure": Handler(lambda ctx, x: x, analyze)})
    job = runtime.submit("pure", {}, "terminal-lock")
    assert entered.wait(5)
    # Exercise actual SQLite BUSY without waiting for the default five seconds.
    original = store.job

    def immediate_job(identifier, **kwargs):
        return original(identifier, _busy_timeout_ms=0)

    monkeypatch.setattr(store, "job", immediate_job)
    with sqlite3.connect(store.db, isolation_level=None) as conn:
        conn.execute("BEGIN IMMEDIATE")
        release.set()
        assert runtime._jobs[job][2].wait(5)
        assert not runtime.wait(job, timeout=0)
        conn.execute("ROLLBACK")
    assert runtime.wait(job)
    assert store.job(job)["state"] == "failed"
    runtime.shutdown()
    store.close()


def test_runtime_cancel_recovers_finished_worker_after_sqlite_lock(tmp_path):
    store, _, _ = setup(tmp_path)
    runtime = Runtime(store, {"pure": Handler(lambda ctx, x: x, lambda ctx, x: x)})
    job = store.create_job("pure", {}, "cancel-finished")
    store.transition_job(job, "queued", "extracting", owner=runtime.owner)
    store.transition_job(job, "extracting", "analyzing", owner=runtime.owner)
    done = threading.Event()
    done.set()
    runtime._jobs[job] = (threading.current_thread(), threading.Event(), done, 0)
    with sqlite3.connect(store.db, isolation_level=None) as conn:
        conn.execute("BEGIN IMMEDIATE")
        runtime._finish(job, "failed", {"code": "handler_failed"}, nonblocking=True)
        conn.execute("ROLLBACK")
    assert runtime.cancel(job) == "failed"
    assert store.job(job)["state"] == "failed"
    assert store.job(job)["error"] == {"code": "handler_failed"}
    runtime.shutdown()
    store.close()


def test_runtime_finish_retries_cancel_transition_race(tmp_path, monkeypatch):
    store, _, _ = setup(tmp_path)
    runtime = Runtime(store, {"pure": Handler(lambda ctx, x: x, lambda ctx, x: x)})
    job = store.create_job("pure", {}, "finish-race")
    original = store.transition_job
    raced = False

    def transition(identifier, expected, state, **kwargs):
        nonlocal raced
        if not raced:
            raced = True
            store.request_cancel(identifier)
        return original(identifier, expected, state, **kwargs)

    monkeypatch.setattr(store, "transition_job", transition)
    runtime._finish(job, "failed", {"code": "handler_failed"})
    assert store.job(job)["state"] == "cancelled"
    runtime.shutdown()
    store.close()


def test_runtime_finish_retries_transient_store_busy(tmp_path, monkeypatch):
    store, _, _ = setup(tmp_path)
    runtime = Runtime(store, {})
    job = store.create_job("pure", {}, "transient-finish")
    original = store.job
    calls = 0

    def busy_once(identifier, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise PersistenceError("store_busy")
        return original(identifier, **kwargs)

    monkeypatch.setattr(store, "job", busy_once)
    runtime._finish(job, "failed", {"code": "handler_failed"})
    assert calls == 2
    assert store.job(job)["state"] == "failed"
    assert not runtime._pending_finish
    store.close()


@pytest.mark.parametrize(
    "code", ["stale_context", "wrong_database_owner", "store_closed", "sqlite_failure"]
)
def test_runtime_finish_does_not_retry_nontransient_failure(
    tmp_path, monkeypatch, code
):
    store, _, _ = setup(tmp_path)
    runtime = Runtime(store, {})
    job = store.create_job("pure", {}, "permanent-finish")
    calls = 0

    def fail(identifier, **kwargs):
        nonlocal calls
        calls += 1
        raise PersistenceError(code)

    monkeypatch.setattr(store, "job", fail)
    runtime._finish(job, "failed", {"code": "handler_failed"})
    runtime._recover_finishes()
    assert calls == 1
    assert not runtime._pending_finish
    store.close()


def test_runtime_finish_never_cancels_another_executor_job(tmp_path):
    store, _, _ = setup(tmp_path)
    runtime = Runtime(store, {})
    job = store.create_job("pure", {}, "foreign-finish")
    store.transition_job(job, "queued", "extracting", owner="other-executor")
    runtime._finish(job, "cancelled", {"code": "cancelled"})
    assert store.job(job)["state"] == "extracting"
    assert not runtime._pending_finish
    store.close()


def test_runtime_status_recovers_pending_terminal_state(tmp_path):
    store, _, _ = setup(tmp_path)
    runtime = Runtime(store, {})
    job = store.create_job("pure", {}, "status-finish")
    with sqlite3.connect(store.db, isolation_level=None) as conn:
        conn.execute("BEGIN IMMEDIATE")
        runtime._finish(job, "interrupted", {"code": "lease_expired"}, nonblocking=True)
        conn.execute("ROLLBACK")
    assert runtime.active_job_count == 0
    assert store.job(job)["state"] == "interrupted"
    assert not runtime._pending_finish
    store.close()


def test_runtime_finish_bounds_retries_and_preserves_winning_terminal(
    tmp_path, monkeypatch
):
    store, _, _ = setup(tmp_path)
    runtime = Runtime(store, {})
    job = store.create_job("pure", {}, "bounded-finish")
    original = store.job
    calls = 0

    def busy(identifier, **kwargs):
        nonlocal calls
        calls += 1
        raise PersistenceError("store_busy")

    monkeypatch.setattr(store, "job", busy)
    runtime._finish(job, "failed", {"code": "handler_failed"})
    assert calls == 3
    assert job in runtime._pending_finish
    monkeypatch.setattr(store, "job", original)
    store.transition_job(job, "queued", "interrupted", owner=runtime.owner)
    before = store.job(job)
    runtime._recover_finishes()
    assert store.job(job) == before
    assert not runtime._pending_finish
    store.close()


@pytest.mark.parametrize("terminal", ["failed", "interrupted", "stale"])
@pytest.mark.parametrize("first_recovery_busy", [False, True])
def test_late_cancel_preserves_pending_terminal_diagnostics(
    tmp_path, monkeypatch, terminal, first_recovery_busy
):
    store, _, _ = setup(tmp_path)
    runtime = Runtime(store, {})
    job = store.create_job("pure", {}, "late-cancel")
    done = threading.Event()
    done.set()
    runtime._jobs[job] = (threading.current_thread(), threading.Event(), done, 0)
    error = {"code": "original_failure", "detail": "preserve me"}
    with sqlite3.connect(store.db, isolation_level=None) as conn:
        conn.execute("BEGIN IMMEDIATE")
        runtime._finish(job, terminal, error, nonblocking=True)
        conn.execute("ROLLBACK")
    original = store.job
    calls = 0

    def read(identifier, **kwargs):
        nonlocal calls
        calls += 1
        if first_recovery_busy and calls == 1:
            raise PersistenceError("store_busy")
        return original(identifier, **kwargs)

    monkeypatch.setattr(store, "job", read)
    expected = "cancelled" if terminal == "failed" and first_recovery_busy else terminal
    assert runtime.cancel(job) == expected
    assert store.job(job)["error"] == error
    assert runtime.wait(job)
    store.close()


@pytest.mark.parametrize("sqlite_code", [sqlite3.SQLITE_FULL, sqlite3.SQLITE_IOERR])
def test_wait_surfaces_nonretryable_terminal_persistence_failure(
    tmp_path, monkeypatch, sqlite_code
):
    store, _, _ = setup(tmp_path)
    runtime = Runtime(store, {})
    job = store.create_job("pure", {}, "terminal-write-failure")
    done = threading.Event()
    done.set()
    runtime._jobs[job] = (threading.current_thread(), threading.Event(), done, 0)
    calls = 0

    def fail(*args, **kwargs):
        nonlocal calls
        calls += 1
        cause = sqlite3.OperationalError("injected storage failure")
        cause.sqlite_errorcode = sqlite_code
        raise PersistenceError("sqlite_failure") from cause

    monkeypatch.setattr(store, "transition_job", fail)
    runtime._finish(job, "failed", {"code": "handler_failed"})
    assert store.job(job)["state"] == "queued"
    with pytest.raises(PersistenceError, match="sqlite_failure"):
        runtime.wait(job)
    with pytest.raises(PersistenceError, match="sqlite_failure"):
        runtime.cancel(job)
    with pytest.raises(PersistenceError, match="sqlite_failure"):
        runtime.status(job)
    assert store.job(job)["state"] == "queued"
    assert calls == 1
    store.close()


def test_runtime_status_record_recovers_only_requested_pending_job(tmp_path):
    store, _, _ = setup(tmp_path)
    runtime = Runtime(store, {})
    jobs = [store.create_job("pure", {}, key) for key in ("status-one", "status-two")]
    error = {"code": "handler_failed"}
    with sqlite3.connect(store.db, isolation_level=None) as conn:
        conn.execute("BEGIN IMMEDIATE")
        for job in jobs:
            runtime._finish(job, "failed", error, nonblocking=True)
        with pytest.raises(PersistenceError, match="sqlite_failure"):
            runtime.status(jobs[0])
        conn.execute("ROLLBACK")
    row = runtime.status(jobs[0])
    assert row["state"] == "failed" and row["error"] == error
    assert store.job(jobs[1])["state"] == "queued"
    assert jobs[1] in runtime._pending_finish
    store.close()


def test_runtime_finish_cancel_owner_claim_race_is_atomic(tmp_path, monkeypatch):
    store, _, _ = setup(tmp_path)
    runtime = Runtime(store, {})
    job = store.create_job("pure", {}, "owner-claim-race")
    original = store.job
    claimed = False

    def claim_after_read(identifier, **kwargs):
        nonlocal claimed
        row = original(identifier, **kwargs)
        if not claimed:
            claimed = True
            store.transition_job(
                identifier, "queued", "extracting", owner="other-executor"
            )
        return row

    monkeypatch.setattr(store, "job", claim_after_read)
    runtime._finish(job, "cancelled", {"code": "cancelled"})
    row = store.job(job)
    assert row["state"] == "extracting"
    assert row["owner"] == "other-executor"
    assert row["error"] is None
    assert runtime._finish_failures[job] == "wrong_job_owner"
    store.close()
