"""Internal worker-owned runtime factory. Deliberately no public @tool surface."""

import json
import os
import re
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import cast

from ida_pro_mcp.flow_core import canonical_json, digest

from ida_pro_mcp.flow_core.persistence import (
    PersistenceError,
    Store,
    _directory,
    _file_check,
    _sync_directory,
    require,
)
from ida_pro_mcp.flow_core.runtime import Runtime

# Lock order: admission -> short registry/runtime locks -> Store -> SQLite.
# Close signals first and never waits on admission/native DB opening.
_lock = threading.RLock()
_admission_lock = threading.Lock()
_runtimes = {}
_closing = threading.Event()

_ROUTING_SELECTION = "routing-selection.json"


def _read_json(path: Path) -> object:
    original = _file_check(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            require(
                (opened.st_dev, opened.st_ino) == (original.st_dev, original.st_ino),
                "replaced_routing_selection",
            )
            raw = stream.read()
        value = json.loads(raw.decode("utf-8"))
        require(
            canonical_json(value).encode("utf-8") == raw, "invalid_routing_selection"
        )
        return value
    except (OSError, ValueError, UnicodeError) as exc:
        if isinstance(exc, PersistenceError):
            raise
        raise PersistenceError("invalid_routing_selection") from exc


def _existing_identity(root, database_path) -> tuple[str, str] | None:
    """Read an existing trusted host identity without creating registry state."""

    root = Path(root).absolute()
    if not root.exists() and not root.is_symlink():
        return None
    _directory(root)
    registry = root / "registry.json"
    if not registry.exists() and not registry.is_symlink():
        return None
    raw_data = _read_json(registry)
    require(
        type(raw_data) is dict and set(raw_data) == {"version", "owner", "databases"},
        "invalid_host_registry",
    )
    data = cast(dict[str, object], raw_data)
    require(
        data["version"] == 1
        and type(data["owner"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", data["owner"]) is not None
        and type(data["databases"]) is dict,
        "invalid_host_registry",
    )
    databases = cast(dict[object, object], data["databases"])
    require(
        all(
            type(key) is str
            and re.fullmatch(r"sha256-v1:[0-9a-f]{64}", key) is not None
            and type(value) is str
            and re.fullmatch(r"database_[0-9a-f]{48}", value) is not None
            for key, value in databases.items()
        ),
        "invalid_host_namespaces",
    )
    key = digest({"database_path": str(Path(database_path).absolute())})
    namespace = databases.get(key)
    if namespace is None:
        return None
    return cast(str, namespace), cast(str, data["owner"])


def load_routing_selection(root, database_path) -> tuple[str, dict[str, object]] | None:
    """Load the owned per-database selection without opening or recovering a Store."""

    existing = _existing_identity(root, database_path)
    if existing is None:
        return None
    namespace, owner_key = existing
    store_root = Path(root).absolute() / namespace
    if not store_root.exists() and not store_root.is_symlink():
        return None
    _directory(store_root)
    path = store_root / _ROUTING_SELECTION
    if not path.exists() and not path.is_symlink():
        return None
    raw_envelope = _read_json(path)
    require(
        type(raw_envelope) is dict
        and set(raw_envelope)
        == {
            "schema_version",
            "namespace",
            "owner_digest",
            "selection",
        },
        "invalid_routing_selection",
    )
    envelope = cast(dict[str, object], raw_envelope)
    require(
        envelope["schema_version"] == "flow-routing-selection-envelope/1"
        and envelope["namespace"] == namespace
        and envelope["owner_digest"] == digest({"owner_key": owner_key})
        and type(envelope["selection"]) is dict,
        "invalid_routing_selection",
    )
    return namespace, cast(dict[str, object], envelope["selection"])


def persist_routing_selection(
    store: Store, database_path: str, selection: dict[str, object]
) -> None:
    """Atomically publish a validated selection after runtime admission succeeds."""

    require(type(store) is Store and not store.closed, "store_closed")
    require(type(selection) is dict, "invalid_routing_selection")
    require(selection.get("namespace") == store.scope.namespace, "wrong_database")
    require(
        selection.get("database_path_digest")
        == digest({"database_path": str(Path(database_path).absolute())}),
        "wrong_database",
    )
    envelope = {
        "schema_version": "flow-routing-selection-envelope/1",
        "namespace": store.scope.namespace,
        "owner_digest": store.owner_digest,
        "selection": selection,
    }
    raw = canonical_json(envelope).encode("utf-8")
    with _lock:
        _, current_identity = _directory(store.root)
        require(current_identity == store.identity, "replaced_store_directory")
        path = store.root / _ROUTING_SELECTION
        if path.exists() or path.is_symlink():
            raw_current = _read_json(path)
            require(type(raw_current) is dict, "invalid_routing_selection")
            current = cast(dict[str, object], raw_current)
            require(
                current.get("owner_digest") == store.owner_digest
                and current.get("namespace") == store.scope.namespace,
                "invalid_routing_selection",
            )
        temporary = store.root / (".routing-" + uuid.uuid4().hex + ".tmp")
        fd = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            require(temporary.read_bytes() == raw, "routing_selection_write_mismatch")
            os.replace(temporary, path)
            _sync_directory(store.root)
            require(_read_json(path) == envelope, "routing_selection_write_mismatch")
        finally:
            temporary.unlink(missing_ok=True)


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
