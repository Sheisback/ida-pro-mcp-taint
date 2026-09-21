"""Internal worker-owned runtime factory. Deliberately no public @tool surface."""

import threading
from contextlib import contextmanager
from pathlib import Path
from ida_pro_mcp.flow_core import digest

from ida_pro_mcp.flow_core.persistence import PersistenceError, Store, require
from ida_pro_mcp.flow_core.runtime import Runtime

# Lock order: admission -> short registry/runtime locks -> Store -> SQLite.
# Close signals first and never waits on admission/native DB opening.
_lock = threading.RLock()
_admission_lock = threading.Lock()
_runtimes = {}
_closing = threading.Event()


@contextmanager
def job_admission():
    require(_admission_lock.acquire(blocking=False), "database_admission_busy")
    try:
        require(not _closing.is_set(), "runtime_closing")
        yield
    finally:
        _admission_lock.release()


@contextmanager
def database_switch():
    with job_admission():
        with _lock:
            runtimes = tuple(_runtimes.values())
        require(
            not any(runtime.inflight_job_count for runtime in runtimes),
            "Cannot switch databases while internal flow jobs are active",
        )
        yield


def configure_runtime(root, scope, owner_key, handlers, *, replace_stale=False):
    """Trusted host inputs only; owner key is not an IDB/session/content hash."""
    with job_admission():
        with _lock:
            existing = _runtimes.get(scope.namespace)
        if existing is not None:
            require(existing.store.scope == scope, "stale_context")
            require(
                existing.store.owner_digest == digest({"owner_key": owner_key}),
                "wrong_database_owner",
            )
            require(
                existing.store.root == Path(root).absolute(), "runtime_root_conflict"
            )
            require(dict(existing.handlers) == handlers, "handler_registry_conflict")
            return existing
        # Admission deliberately spans initialization, but shutdown never waits
        # for admission and the registry mutex is not held during filesystem I/O.
        store = Store(root, scope, owner_key, replace_stale=replace_stale)
        try:
            runtime = Runtime(store, handlers, admission=job_admission)
        except BaseException:
            store.close()
            raise
        with _lock:
            publish = not _closing.is_set()
            if publish:
                _runtimes[scope.namespace] = runtime
        if not publish:
            runtime.shutdown(0)
            store.close()
            raise PersistenceError("runtime_closing")
        return runtime


def active_job_count():
    with _lock:
        runtimes = tuple(_runtimes.values())
    return sum(runtime.active_job_count for runtime in runtimes)


def begin_close():
    _closing.set()
    with _lock:
        runtimes = tuple(_runtimes.values())
    for runtime in runtimes:
        runtime.begin_close()


def shutdown(timeout=2.0):
    import time

    begin_close()
    with _lock:
        runtimes = tuple(_runtimes.values())
    end = time.monotonic() + timeout
    pending = []
    for runtime in runtimes:
        pending.extend(runtime.shutdown(max(0, end - time.monotonic())))
        runtime.store.close()
    return tuple(sorted(pending))


def refresh_runtime(root, scope, owner_key, handlers):
    """Explicit DB mutation fence: invalidate old artifacts before scope reopen."""
    with job_admission():
        with _lock:
            existing = _runtimes.get(scope.namespace)
        if existing is not None and existing.store.scope != scope:
            require(not existing.inflight_job_count, "database_changed_during_flow_job")
            require(
                existing.store.owner_digest == digest({"owner_key": owner_key}),
                "wrong_database_owner",
            )
            require(
                existing.store.root == Path(root).absolute(), "runtime_root_conflict"
            )
            existing.store.invalidate_context(scope)
            existing.shutdown(0)
            existing.store.close()
            with _lock:
                del _runtimes[scope.namespace]
    return configure_runtime(root, scope, owner_key, handlers, replace_stale=True)
