"""Private durable flow metadata and immutable canonical JSON blobs (POSIX v1)."""

from contextlib import contextmanager
from functools import wraps
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
import uuid

from .contracts import Graph, MemorySource, Snapshot, ValueSource
from .runtime_contracts import (
    RuntimeScope,
    TERMINAL,
    TRANSITIONS,
    TraceSpec,
    TraceState,
)
from .serialization import ContractError, canonical_json, digest

_MISSING = object()
PAGE_TARGET_CHARS = 16000
PAGE_HARD_CHARS = 39999


class PersistenceError(ContractError):
    pass


def require(value, code):
    if not value:
        raise PersistenceError(code)


def _token(prefix):
    return prefix + "_" + uuid.uuid4().hex


def _file_check(path):
    info = path.lstat()
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and info.st_uid == os.getuid()
        and not (info.st_mode & 0o077),
        "insecure_file",
    )
    return info


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _directory(path, create=False):
    path = Path(path).absolute()
    for parent in reversed((path,) + tuple(path.parents)):
        if parent.exists() or parent.is_symlink():
            require(
                not parent.is_symlink() and parent.is_dir(),
                "symlink_or_invalid_directory",
            )
    if create:
        try:
            path.mkdir(mode=0o700)
            _sync_directory(path.parent)
        except FileExistsError:
            pass
    info = path.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.getuid()
        and not (info.st_mode & 0o077),
        "insecure_directory",
    )
    return path, (info.st_dev, info.st_ino)


class BlobStore:
    def __init__(self, path):
        self.path, self.identity = _directory(path, True)

    def _check(self):
        _, identity = _directory(self.path)
        require(identity == self.identity, "replaced_blob_directory")

    def _path(self, key):
        require(
            type(key) is str
            and re.fullmatch(r"sha256-v1:[0-9a-f]{64}", key) is not None,
            "invalid_blob_id",
        )
        return self.path / (key.split(":")[1] + ".json")

    def put(self, value):
        self._check()
        raw = canonical_json(value).encode("utf-8")
        key = "sha256-v1:" + hashlib.sha256(raw).hexdigest()
        final = self._path(key)
        if final.exists() or final.is_symlink():
            self.read(key)
            return key, len(raw)
        temporary = self.path / (".tmp-" + uuid.uuid4().hex + ".json")
        fd = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            require(temporary.read_bytes() == raw, "blob_write_mismatch")
            self._check()
            # The SQLite writer transaction serializes publication/recovery.
            require(
                not final.exists() and not final.is_symlink(),
                "blob_publication_conflict",
            )
            os.replace(temporary, final)
            directory_fd = os.open(
                self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            self.read(key)
            return key, len(raw)
        finally:
            if temporary.exists():
                temporary.unlink()

    def read(self, key):
        self._check()
        path = self._path(key)
        try:
            original = _file_check(path)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                require(
                    (opened.st_dev, opened.st_ino)
                    == (original.st_dev, original.st_ino),
                    "replaced_blob_file",
                )
                raw = stream.read()
            require(
                "sha256-v1:" + hashlib.sha256(raw).hexdigest() == key,
                "corrupt_blob_digest",
            )
            value = json.loads(raw.decode("utf-8"))
            require(canonical_json(value).encode("utf-8") == raw, "noncanonical_blob")
            return value
        except (OSError, ValueError, UnicodeError) as exc:
            if isinstance(exc, PersistenceError):
                raise
            raise PersistenceError("missing_or_corrupt_blob") from exc


DDL = """
CREATE TABLE namespaces(namespace TEXT PRIMARY KEY, owner_digest TEXT NOT NULL, scope TEXT NOT NULL, scope_digest TEXT NOT NULL);
CREATE TABLE blobs(digest TEXT PRIMARY KEY, length INTEGER NOT NULL CHECK(length>=0));
CREATE TABLE artifacts(id TEXT PRIMARY KEY,namespace TEXT NOT NULL REFERENCES namespaces(namespace),scope_digest TEXT NOT NULL,scope TEXT NOT NULL,kind TEXT NOT NULL,blob TEXT NOT NULL REFERENCES blobs(digest),stale INTEGER NOT NULL DEFAULT 0);
CREATE TABLE jobs(id TEXT PRIMARY KEY,namespace TEXT NOT NULL REFERENCES namespaces(namespace),scope_digest TEXT NOT NULL,scope TEXT NOT NULL,handler TEXT NOT NULL,input_blob TEXT NOT NULL REFERENCES blobs(digest),state TEXT NOT NULL CHECK(state IN ('queued','extracting','analyzing','committing','complete','cancel_requested','cancelled','failed','stale','interrupted')),revision INTEGER NOT NULL DEFAULT 0,progress TEXT NOT NULL,budget TEXT NOT NULL,error TEXT,last_commit TEXT REFERENCES blobs(digest),owner TEXT,deadline REAL,stale INTEGER NOT NULL DEFAULT 0,retry_of TEXT REFERENCES jobs(id));
CREATE TABLE traces(id TEXT PRIMARY KEY,namespace TEXT NOT NULL REFERENCES namespaces(namespace),scope_digest TEXT NOT NULL,scope TEXT NOT NULL,snapshot_artifact TEXT NOT NULL REFERENCES artifacts(id),spec TEXT NOT NULL,source_blob TEXT NOT NULL REFERENCES blobs(digest),state_blob TEXT NOT NULL REFERENCES blobs(digest),revision INTEGER NOT NULL DEFAULT 0,stale INTEGER NOT NULL DEFAULT 0);
CREATE TABLE requests(namespace TEXT NOT NULL REFERENCES namespaces(namespace),operation TEXT NOT NULL,request_key TEXT NOT NULL,request_digest TEXT NOT NULL,response_blob TEXT NOT NULL REFERENCES blobs(digest),PRIMARY KEY(namespace,operation,request_key));
CREATE TABLE pages(trace_id TEXT NOT NULL REFERENCES traces(id),revision INTEGER NOT NULL,response_blob TEXT NOT NULL REFERENCES blobs(digest),state_blob TEXT NOT NULL REFERENCES blobs(digest),PRIMARY KEY(trace_id,revision));
"""


def _scope_operation(method):
    @wraps(method)
    def guarded(self, *args, **kwargs):
        with self._operation_lock(kwargs.get("_busy_timeout_ms", 5000)):
            require(not self.closed, "store_closed")
            return method(self, *args, **kwargs)

    return guarded


class Store:
    """One authenticated owner namespace; recovery is an explicit runtime action.

    Owner keys must originate from trusted host configuration, never request data.
    POSIX permission checks intentionally fail closed on unsupported platforms.
    """

    def __init__(
        self,
        root,
        scope: RuntimeScope,
        owner_key: str,
        *,
        recover=True,
        replace_stale=False,
    ):
        require(os.name == "posix", "unsupported_permission_model")
        require(type(scope) is RuntimeScope, "invalid_runtime_scope")
        require(type(owner_key) is str and len(owner_key) >= 32, "invalid_owner_key")
        self.root, self.identity = _directory(root, True)
        self.marker = self.root / ".flow-store-v1"
        self.marker_bytes = b"ida-pro-mcp private flow store v1\n"
        if not self.marker.exists() and not self.marker.is_symlink():
            require(not any(self.root.iterdir()), "unrecognized_store_root")
            fd = os.open(
                self.marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
            with os.fdopen(fd, "wb") as stream:
                stream.write(self.marker_bytes)
                stream.flush()
                os.fsync(stream.fileno())
            _sync_directory(self.root)
        _file_check(self.marker)
        require(self.marker.read_bytes() == self.marker_bytes, "invalid_store_marker")
        self._scope = scope
        self.owner_digest = digest({"owner_key": owner_key})
        self.closed = False
        self._lease = None
        self._lock = threading.RLock()
        self.blobs = BlobStore(self.root / "blobs")
        self.db = self.root / "metadata.sqlite"
        try:
            fd = os.open(
                self.db, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600
            )
            os.close(fd)
        except FileExistsError:
            pass
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                version = conn.execute("PRAGMA user_version").fetchone()[0]
                if version == 0:
                    require(
                        not conn.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        ).fetchall(),
                        "unrecognized_schema",
                    )
                    for statement in DDL.split(";"):
                        if statement.strip():
                            conn.execute(statement)
                    conn.execute("PRAGMA user_version=1")
                require(
                    conn.execute("PRAGMA user_version").fetchone()[0] == 1,
                    "unsupported_schema_version",
                )
                tables = {
                    r[0]
                    for r in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                require(
                    tables
                    == {
                        "namespaces",
                        "blobs",
                        "artifacts",
                        "jobs",
                        "traces",
                        "requests",
                        "pages",
                    },
                    "invalid_schema_tables",
                )
                require(
                    conn.execute("PRAGMA quick_check").fetchone()[0] == "ok",
                    "sqlite_integrity_failure",
                )
                require(
                    not conn.execute("PRAGMA foreign_key_check").fetchall(),
                    "sqlite_reference_failure",
                )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        previous_scope = None
        with self._transaction(check_scope=False) as conn:
            row = conn.execute(
                "SELECT * FROM namespaces WHERE namespace=?", (scope.namespace,)
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO namespaces VALUES (?,?,?,?)",
                    (
                        scope.namespace,
                        self.owner_digest,
                        canonical_json(scope),
                        scope.scope_digest,
                    ),
                )
            else:
                require(
                    row["owner_digest"] == self.owner_digest, "wrong_database_owner"
                )
                if row["scope_digest"] != scope.scope_digest:
                    require(recover and replace_stale, "stale_context")
                    previous_scope = RuntimeScope.from_json(row["scope"])
        try:
            if recover:
                import fcntl

                path = self.root / (
                    "owner-" + digest(scope.namespace).split(":")[1] + ".lock"
                )
                self._lease = os.open(
                    path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
                )
                try:
                    _file_check(path)
                    fcntl.flock(self._lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except (OSError, PersistenceError) as exc:
                    raise PersistenceError("runtime_already_owned") from exc
            if previous_scope is not None:
                # Only the namespace owner lease may replace an old context on
                # process restart. Fence the exact observed scope, never adopt it.
                with self._transaction(check_scope=False) as conn:
                    current = conn.execute(
                        "SELECT scope_digest FROM namespaces WHERE namespace=?",
                        (scope.namespace,),
                    ).fetchone()
                    require(
                        current["scope_digest"] == previous_scope.scope_digest,
                        "stale_context",
                    )
                    for table in ("artifacts", "jobs", "traces"):
                        conn.execute(
                            f"UPDATE {table} SET stale=1 WHERE namespace=?",
                            (scope.namespace,),
                        )
                    conn.execute(
                        "UPDATE jobs SET state='stale',revision=revision+1 WHERE namespace=? AND state NOT IN ('complete','cancelled','failed','stale','interrupted')",
                        (scope.namespace,),
                    )
                    conn.execute(
                        "UPDATE namespaces SET scope=?,scope_digest=? WHERE namespace=?",
                        (canonical_json(scope), scope.scope_digest, scope.namespace),
                    )
            if recover:
                with self._transaction() as conn:
                    conn.execute(
                        "UPDATE jobs SET state='interrupted',revision=revision+1,error=? WHERE namespace=? AND state NOT IN ('complete','cancelled','failed','stale','interrupted')",
                        (
                            canonical_json({"code": "runtime_restarted"}),
                            scope.namespace,
                        ),
                    )
            self.integrity_check()
        except BaseException:
            self.close()
            raise

    @property
    def scope(self):
        # Immutable binding. Invalidation fences this handle; reopening a new
        # context requires an explicit new Store rather than retagging old work.
        return self._scope

    @contextmanager
    def _operation_lock(self, timeout_ms=5000):
        require(
            type(timeout_ms) is int and 0 <= timeout_ms <= 5000, "invalid_busy_timeout"
        )
        require(self._lock.acquire(timeout=timeout_ms / 1000), "store_busy")
        try:
            yield
        finally:
            if self.closed:
                self._release_lease()
            self._lock.release()

    def _release_lease(self):
        if self._lease is not None:
            os.close(self._lease)
            self._lease = None

    def _check_files(self):
        require(not self.closed, "store_closed")
        _, identity = _directory(self.root)
        require(identity == self.identity, "replaced_store_directory")
        _file_check(self.marker)
        require(self.marker.read_bytes() == self.marker_bytes, "invalid_store_marker")
        # The primary database is mandatory; SQLite's WAL/SHM sidecars are not.
        _file_check(self.db)
        for path in (Path(str(self.db) + "-wal"), Path(str(self.db) + "-shm")):
            if path.exists() or path.is_symlink():
                try:
                    _file_check(path)
                except FileNotFoundError:
                    # SQLite removes transient sidecars when its last
                    # connection closes, possibly after the existence probe.
                    pass

    @contextmanager
    def _connect(self, busy_timeout_ms=5000):
        require(
            type(busy_timeout_ms) is int and 0 <= busy_timeout_ms <= 5000,
            "invalid_busy_timeout",
        )
        self._check_files()
        try:
            conn = sqlite3.connect(
                self.db, timeout=busy_timeout_ms / 1000, isolation_level=None
            )
            try:
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA foreign_keys=ON")
                conn.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=FULL")
                yield conn
            finally:
                conn.close()
        except sqlite3.DatabaseError as exc:
            raise PersistenceError("sqlite_failure") from exc

    def _check_scope(self, conn):
        row = conn.execute(
            "SELECT owner_digest,scope_digest FROM namespaces WHERE namespace=?",
            (self.scope.namespace,),
        ).fetchone()
        if row is None or row["owner_digest"] != self.owner_digest:
            raise PersistenceError("wrong_database_owner")
        require(row["scope_digest"] == self.scope.scope_digest, "stale_context")

    @contextmanager
    def _transaction(self, *, check_scope=True, busy_timeout_ms=5000):
        with (
            self._operation_lock(busy_timeout_ms),
            self._connect(busy_timeout_ms) as conn,
        ):
            conn.execute("BEGIN IMMEDIATE")
            try:
                if check_scope:
                    self._check_scope(conn)
                yield conn
                require(not self.closed, "store_closed")
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise

    def _blob(self, conn, value):
        key, length = self.blobs.put(value)
        conn.execute("INSERT OR IGNORE INTO blobs VALUES (?,?)", (key, length))
        require(
            conn.execute("SELECT length FROM blobs WHERE digest=?", (key,)).fetchone()[
                0
            ]
            == length,
            "blob_length_conflict",
        )
        return key

    def _row(self, conn, table, identifier):
        require(table in {"artifacts", "jobs", "traces"}, "invalid_table")
        row = conn.execute(
            f"SELECT * FROM {table} WHERE id=?", (identifier,)
        ).fetchone()
        require(row is not None, "not_found")
        require(row["namespace"] == self.scope.namespace, "wrong_database")
        require(
            not row["stale"] and row["scope_digest"] == self.scope.scope_digest,
            "stale_context",
        )
        return row

    def _request(self, conn, operation, key, request):
        require(type(key) is str and 0 < len(key) <= 256, "invalid_request_key")
        request_digest = digest(request)
        old = conn.execute(
            "SELECT * FROM requests WHERE namespace=? AND operation=? AND request_key=?",
            (self.scope.namespace, operation, key),
        ).fetchone()
        if old:
            require(old["request_digest"] == request_digest, "idempotency_conflict")
            return request_digest, self.blobs.read(old["response_blob"])
        return request_digest, None

    def _remember(self, conn, operation, key, request_digest, response):
        blob = self._blob(conn, response)
        conn.execute(
            "INSERT INTO requests VALUES (?,?,?,?,?)",
            (self.scope.namespace, operation, key, request_digest, blob),
        )
        return blob

    def _artifact_scope_matches(self, actual):
        # Database fingerprint and function semantic digest are distinct axes.
        # The row still binds the artifact to the current authoritative DB scope.
        return all(
            getattr(actual, key) == getattr(self.scope, key)
            for key in (
                "namespace",
                "binary_digest",
                "profile_digest",
                "rule_digest",
                "summary_digest",
                "policy_digest",
            )
        )

    @_scope_operation
    def put_artifact(self, kind, value):
        require(
            kind in {"snapshot", "graph", "analysis", "evidence"},
            "invalid_artifact_kind",
        )
        if kind == "snapshot":
            snapshot = value if type(value) is Snapshot else Snapshot.from_data(value)
            identity = snapshot.identity
            actual = RuntimeScope(
                identity.namespace,
                identity.semantic_digest,
                identity.binary_digest,
                identity.profile_digest,
                identity.rule_digest,
                identity.summary_digest,
                identity.policy_digest,
            )
            require(self._artifact_scope_matches(actual), "snapshot_scope_mismatch")
            value = snapshot.to_data()
        if kind == "graph":
            graph = value if type(value) is Graph else Graph.from_data(value)
            if not isinstance(graph.snapshot, Snapshot):
                raise PersistenceError("structured_graph_not_supported")
            identity = graph.snapshot.identity
            actual = RuntimeScope(
                identity.namespace,
                identity.semantic_digest,
                identity.binary_digest,
                identity.profile_digest,
                identity.rule_digest,
                identity.summary_digest,
                identity.policy_digest,
            )
            require(self._artifact_scope_matches(actual), "graph_scope_mismatch")
            value = graph.to_data()
        with self._transaction() as conn:
            blob = self._blob(conn, value)
            identifier = _token("artifact")
            conn.execute(
                "INSERT INTO artifacts(id,namespace,scope_digest,scope,kind,blob) VALUES (?,?,?,?,?,?)",
                (
                    identifier,
                    self.scope.namespace,
                    self.scope.scope_digest,
                    canonical_json(self.scope),
                    kind,
                    blob,
                ),
            )
            return identifier

    @_scope_operation
    def artifact(self, identifier):
        with self._transaction() as conn:
            row = self._row(conn, "artifacts", identifier)
            return self.blobs.read(row["blob"])

    @_scope_operation
    def evidence_page(self, identifier, offset=0, length=2048):
        require(
            type(offset) is int and offset >= 0 and type(length) is int and length > 0,
            "invalid_evidence_range",
        )
        with self._transaction() as conn:
            row = self._row(conn, "artifacts", identifier)
            require(row["kind"] == "evidence", "wrong_artifact_kind")
            text = self.blobs.read(row["blob"])
            require(type(text) is str and offset <= len(text), "invalid_evidence_range")
            result = {
                "artifact_id": identifier,
                "offset": offset,
                "next_offset": min(len(text), offset + length),
                "total_length": len(text),
                "text": text[offset : offset + length],
            }
            require(len(json.dumps(result)) <= PAGE_HARD_CHARS, "item_too_large")
            return result

    @_scope_operation
    def create_job(
        self, handler, input_value, request_key, *, budget=None, retry_of=None
    ):
        require(
            type(handler) is str
            and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", handler) is not None,
            "invalid_handler_name",
        )
        require(budget is None or type(budget) is dict, "invalid_job_budget")
        request = {
            "handler": handler,
            "input": input_value,
            "budget": budget or {},
            "retry_of": retry_of,
            "scope": self.scope.scope_digest,
        }
        with self._transaction() as conn:
            rd, replay = self._request(conn, "create_job", request_key, request)
            if replay is not None:
                return replay["job_id"]
            if retry_of:
                previous = self._row(conn, "jobs", retry_of)
                require(
                    previous["state"] in {"failed", "cancelled", "interrupted"},
                    "unsafe_retry_state",
                )
                require(
                    previous["handler"] == handler
                    and self.blobs.read(previous["input_blob"]) == input_value,
                    "retry_input_changed",
                )
            blob = self._blob(conn, input_value)
            identifier = _token("job")
            conn.execute(
                "INSERT INTO jobs(id,namespace,scope_digest,scope,handler,input_blob,state,progress,budget,retry_of) VALUES (?,?,?,?,?,?,'queued',?,?,?)",
                (
                    identifier,
                    self.scope.namespace,
                    self.scope.scope_digest,
                    canonical_json(self.scope),
                    handler,
                    blob,
                    "{}",
                    canonical_json(budget or {}),
                    retry_of,
                ),
            )
            self._remember(conn, "create_job", request_key, rd, {"job_id": identifier})
            return identifier

    @_scope_operation
    def job(self, identifier, *, _busy_timeout_ms=5000):
        with self._transaction(busy_timeout_ms=_busy_timeout_ms) as conn:
            row = dict(self._row(conn, "jobs", identifier))
            row["input"] = self.blobs.read(row["input_blob"])
            for key in ("scope", "progress", "budget", "error"):
                if row[key] is not None:
                    row[key] = json.loads(row[key])
            if row["last_commit"]:
                row["result"] = self.blobs.read(row["last_commit"])
            return row

    @_scope_operation
    def transition_job(
        self,
        identifier,
        expected,
        state,
        *,
        owner=None,
        deadline=None,
        progress=None,
        error=None,
        result=_MISSING,
        _busy_timeout_ms=5000,
    ):
        require(state in TRANSITIONS.get(expected, set()), "invalid_job_transition")
        if deadline is not None:
            require(
                type(deadline) in (int, float)
                and math.isfinite(deadline)
                and deadline > 0,
                "invalid_deadline",
            )
        with self._transaction(busy_timeout_ms=_busy_timeout_ms) as conn:
            row = self._row(conn, "jobs", identifier)
            require(row["state"] == expected, "job_conflict")
            require(owner is None or row["owner"] in (None, owner), "wrong_job_owner")
            last = row["last_commit"]
            require(
                state != "complete" or result is not _MISSING,
                "complete_requires_result",
            )
            if result is not _MISSING:
                require(state == "complete", "result_before_complete")
                last = self._blob(conn, result)
            conn.execute(
                "UPDATE jobs SET state=?,revision=revision+1,owner=?,deadline=?,progress=?,error=?,last_commit=? WHERE id=?",
                (
                    state,
                    owner or row["owner"],
                    deadline if deadline is not None else row["deadline"],
                    canonical_json(progress)
                    if progress is not None
                    else row["progress"],
                    canonical_json(error) if error is not None else row["error"],
                    last,
                    identifier,
                ),
            )
            return row["revision"] + 1

    @_scope_operation
    def checkpoint_job(self, identifier, owner, progress, checkpoint=None):
        require(type(progress) is dict, "invalid_job_progress")
        with self._transaction() as conn:
            row = self._row(conn, "jobs", identifier)
            require(
                row["state"] in {"extracting", "analyzing", "committing"},
                "job_conflict",
            )
            require(row["owner"] == owner, "wrong_job_owner")
            last = row["last_commit"]
            if checkpoint is not None:
                last = self._blob(conn, checkpoint)
            conn.execute(
                "UPDATE jobs SET progress=?,last_commit=?,revision=revision+1 WHERE id=?",
                (canonical_json(progress), last, identifier),
            )
            return row["revision"] + 1

    @_scope_operation
    def request_cancel(self, identifier, *, _busy_timeout_ms=5000):
        with self._transaction(busy_timeout_ms=_busy_timeout_ms) as conn:
            row = self._row(conn, "jobs", identifier)
            if row["state"] in TERMINAL or row["state"] == "cancel_requested":
                return row["state"]
            conn.execute(
                "UPDATE jobs SET state='cancel_requested',revision=revision+1 WHERE id=?",
                (identifier,),
            )
            return "cancel_requested"

    def _trace_graph(self, conn, spec):
        row = self._row(conn, "artifacts", spec.graph_artifact)
        require(row["kind"] == "graph", "trace_requires_graph")
        return Graph.from_data(self.blobs.read(row["blob"]))

    def _validate_trace_state(self, graph, state):
        node_ids = {n.node_id for n in graph.nodes}
        require(
            set(
                state.frontier
                + state.visited
                + state.emitted
                + state.pending
                + state.unresolved
            )
            <= node_ids,
            "dangling_trace_node",
        )

    @_scope_operation
    def create_trace(self, spec: TraceSpec, source, state: TraceState, request_key):
        require(
            type(spec) is TraceSpec and type(state) is TraceState,
            "invalid_trace_contract",
        )
        require(digest(source) == spec.source_digest, "source_digest_mismatch")
        request = {
            "spec": spec.to_data(),
            "source": source,
            "state": state.to_data(),
            "scope": self.scope.scope_digest,
        }
        with self._transaction() as conn:
            snapshot = self._row(conn, "artifacts", spec.snapshot_artifact)
            require(snapshot["kind"] == "snapshot", "trace_requires_snapshot")
            graph = self._trace_graph(conn, spec)
            stored_snapshot = Snapshot.from_data(self.blobs.read(snapshot["blob"]))
            require(graph.snapshot == stored_snapshot, "trace_snapshot_mismatch")
            require(
                type(source) is dict and source.get("kind") in {"value", "memory"},
                "invalid_trace_source",
            )
            selected = (
                ValueSource.from_data(source)
                if source["kind"] == "value"
                else MemorySource.from_data(source)
            )
            graph.validate_source(selected)
            self._validate_trace_state(graph, state)
            rd, replay = self._request(conn, "create_trace", request_key, request)
            if replay is not None:
                return replay["trace_id"]
            source_blob = self._blob(conn, source)
            state_blob = self._blob(conn, state)
            identifier = _token("trace")
            conn.execute(
                "INSERT INTO traces(id,namespace,scope_digest,scope,snapshot_artifact,spec,source_blob,state_blob) VALUES (?,?,?,?,?,?,?,?)",
                (
                    identifier,
                    self.scope.namespace,
                    self.scope.scope_digest,
                    canonical_json(self.scope),
                    spec.snapshot_artifact,
                    canonical_json(spec),
                    source_blob,
                    state_blob,
                ),
            )
            self._remember(
                conn, "create_trace", request_key, rd, {"trace_id": identifier}
            )
            return identifier

    @_scope_operation
    def trace(self, identifier):
        with self._transaction() as conn:
            row = dict(self._row(conn, "traces", identifier))
            row["state"] = TraceState.from_data(self.blobs.read(row["state_blob"]))
            row["source"] = self.blobs.read(row["source_blob"])
            row["spec"] = TraceSpec.from_json(row["spec"])
            return row

    @_scope_operation
    def commit_page(
        self,
        identifier,
        expected_revision,
        request_key,
        request,
        items,
        next_state: TraceState,
        *,
        operation="flow_continue_trace",
        _fault=None,
    ):
        require(
            type(expected_revision) is int and expected_revision >= 0,
            "invalid_revision",
        )
        require(
            type(next_state) is TraceState and type(items) is list,
            "invalid_page_contract",
        )
        require(
            operation
            in {
                "flow_trace_forward",
                "flow_trace_backward",
                "flow_continue_trace",
                "flow_cancel_trace",
            },
            "invalid_page_operation",
        )
        canonical_request = {
            "trace_id": identifier,
            "expected_revision": expected_revision,
            "request": request,
        }
        with self._transaction() as conn:
            row = self._row(conn, "traces", identifier)
            rd, replay = self._request(conn, operation, request_key, canonical_request)
            if replay is not None:
                return replay
            require(row["revision"] == expected_revision, "revision_conflict")
            old = TraceState.from_data(self.blobs.read(row["state_blob"]))
            graph = self._trace_graph(conn, TraceSpec.from_json(row["spec"]))
            self._validate_trace_state(graph, next_state)
            require(old.status in {"active", "budget_exceeded"}, "terminal_trace")
            require(
                set(old.visited) <= set(next_state.visited)
                and set(old.emitted) <= set(next_state.emitted),
                "trace_progress_regressed",
            )
            revision = expected_revision + 1
            response = {
                "trace_id": identifier,
                "revision": revision,
                "cursor": digest(
                    {"trace": identifier, "revision": revision, "version": 1}
                ),
                "schema_version": "flow-trace-page/1",
                "items": items,
                "status": next_state.status,
                "frontier_remaining": len(next_state.frontier),
                "pending_remaining": len(next_state.pending),
                "unresolved_count": len(next_state.unresolved),
            }
            serialized_chars = len(json.dumps(response))
            require(serialized_chars <= PAGE_HARD_CHARS, "item_too_large")
            require(
                len(items) <= 1 or serialized_chars <= PAGE_TARGET_CHARS,
                "page_target_exceeded",
            )
            state_blob = self._blob(conn, next_state)
            response_blob = self._remember(conn, operation, request_key, rd, response)
            conn.execute(
                "INSERT INTO pages VALUES (?,?,?,?)",
                (identifier, revision, response_blob, state_blob),
            )
            conn.execute(
                "UPDATE traces SET revision=?,state_blob=? WHERE id=?",
                (revision, state_blob, identifier),
            )
            if _fault:
                _fault("before_commit")
        if _fault:
            _fault("after_commit")
        return response

    @_scope_operation
    def invalidate_context(self, new_scope: RuntimeScope):
        require(
            type(new_scope) is RuntimeScope
            and new_scope.namespace == self.scope.namespace,
            "wrong_database",
        )
        with self._transaction() as conn:
            if new_scope == self.scope:
                return False
            for table in ("artifacts", "jobs", "traces"):
                conn.execute(
                    f"UPDATE {table} SET stale=1 WHERE namespace=?",
                    (self.scope.namespace,),
                )
            conn.execute(
                "UPDATE jobs SET state='stale',revision=revision+1 WHERE namespace=? AND state NOT IN ('complete','cancelled','failed','stale','interrupted')",
                (self.scope.namespace,),
            )
            conn.execute(
                "UPDATE namespaces SET scope=?,scope_digest=? WHERE namespace=?",
                (
                    canonical_json(new_scope),
                    new_scope.scope_digest,
                    self.scope.namespace,
                ),
            )
        return True

    def _references(self, conn):
        refs = set()
        for table, columns in (
            ("artifacts", ("blob",)),
            ("jobs", ("input_blob", "last_commit")),
            ("traces", ("source_blob", "state_blob")),
            ("requests", ("response_blob",)),
            ("pages", ("response_blob", "state_blob")),
        ):
            for column in columns:
                refs.update(
                    r[0]
                    for r in conn.execute(
                        f"SELECT {column} FROM {table} WHERE {column} IS NOT NULL"
                    )
                )
        return refs

    @_scope_operation
    def integrity_check(self):
        with self._transaction() as conn:
            require(
                conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok",
                "sqlite_integrity_failure",
            )
            require(
                not conn.execute("PRAGMA foreign_key_check").fetchall(),
                "sqlite_reference_failure",
            )
            # Orphan rows/files may be half-cleaned after a crash. Only live
            # references are authoritative; recover_blobs removes orphan rows.
            for key in self._references(conn):
                row = conn.execute(
                    "SELECT length FROM blobs WHERE digest=?", (key,)
                ).fetchone()
                require(row is not None, "missing_blob_metadata")
                value = self.blobs.read(key)
                require(
                    len(canonical_json(value).encode("utf-8")) == row["length"],
                    "blob_length_conflict",
                )
        return True

    @_scope_operation
    def recover_blobs(self):
        removed = []
        with self._transaction() as conn:
            refs = self._references(conn)
            # Verify all referenced data before any cleanup. All namespaces count.
            for key in refs:
                self.blobs.read(key)
            self.blobs._check()
            for path in self.blobs.path.iterdir():
                name = path.name
                if re.fullmatch(r"\.tmp-[0-9a-f]{32}\.json", name):
                    removable = True
                elif re.fullmatch(r"[0-9a-f]{64}\.json", name):
                    removable = "sha256-v1:" + name[:-5] not in refs
                else:
                    continue
                if removable:
                    _file_check(path)
                    path.unlink()
                    removed.append(name)
            for row in conn.execute("SELECT digest FROM blobs").fetchall():
                if row[0] not in refs:
                    conn.execute("DELETE FROM blobs WHERE digest=?", (row[0],))
        return tuple(sorted(removed))

    def close(self):
        # Signal before locking: shutdown must not wait on a blocked publisher.
        # An in-flight transaction sees closed before commit and rolls back; its
        # final lock release also releases the lease after it has stopped writing.
        self.closed = True
        if self._lock.acquire(blocking=False):
            try:
                self._release_lease()
            finally:
                self._lock.release()
