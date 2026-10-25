"""Immutable, digest-bound graph query index for durable trace continuation."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid

from .contracts import Edge, Graph, Node, ResultAxes
from .serialization import ContractError, canonical_json, digest


INDEX_VERSION = 1
_SCHEMA = """
CREATE TABLE metadata(
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  index_version INTEGER NOT NULL,
  namespace TEXT NOT NULL,
  scope_digest TEXT NOT NULL,
  owner_digest TEXT NOT NULL,
  graph_artifact TEXT NOT NULL,
  graph_digest TEXT NOT NULL,
  snapshot_id TEXT NOT NULL,
  axes_json TEXT NOT NULL,
  axes_sha256 TEXT NOT NULL,
  node_count INTEGER NOT NULL CHECK(node_count>=0),
  edge_count INTEGER NOT NULL CHECK(edge_count>=0)
);
CREATE TABLE nodes(
  node_id TEXT PRIMARY KEY,
  payload_json TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  memory_json TEXT
);
CREATE TABLE edges(
  edge_id TEXT PRIMARY KEY,
  source_node_id TEXT NOT NULL,
  target_node_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL
);
CREATE INDEX edges_by_source ON edges(source_node_id,kind,target_node_id,edge_id);
CREATE INDEX edges_by_target ON edges(target_node_id,kind,source_node_id,edge_id);
"""


class GraphIndexError(ContractError):
    pass


def _require(value: bool, code: str) -> None:
    if not value:
        raise GraphIndexError(code)


def _directory(path: Path, *, create: bool = False) -> tuple[Path, tuple[int, int]]:
    path = path.absolute()
    if create:
        try:
            path.mkdir(mode=0o700)
            _sync_directory(path.parent)
        except FileExistsError:
            pass
    info = path.lstat()
    _require(
        stat.S_ISDIR(info.st_mode)
        and not path.is_symlink()
        and info.st_uid == os.getuid()
        and not (info.st_mode & 0o077),
        "insecure_trace_index_directory",
    )
    return path, (info.st_dev, info.st_ino)


def _file(path: Path) -> os.stat_result:
    info = path.lstat()
    _require(
        stat.S_ISREG(info.st_mode)
        and not path.is_symlink()
        and info.st_nlink == 1
        and info.st_uid == os.getuid()
        and not (info.st_mode & 0o077),
        "insecure_trace_index",
    )
    return info


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _decode_payload(text: str, expected_digest: str, code: str) -> object:
    try:
        value = json.loads(text)
    except (TypeError, ValueError) as exc:
        raise GraphIndexError(code) from exc
    _require(digest(value) == expected_digest, code)
    return value


def _index_basename(graph_artifact: str) -> str:
    _require(
        type(graph_artifact) is str
        and graph_artifact.startswith("artifact_")
        and graph_artifact[9:].isalnum(),
        "invalid_graph_artifact",
    )
    return f"trace-{digest({'graph_artifact': graph_artifact, 'version': INDEX_VERSION}).split(':', 1)[1]}.sqlite"


def _connect(path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(
            f"{path.as_uri()}?mode=ro" if readonly else path,
            uri=readonly,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        if not readonly:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
        return connection
    except sqlite3.DatabaseError as exc:
        raise GraphIndexError("trace_index_sqlite_failure") from exc


class GraphQueryIndex:
    def __init__(
        self,
        path: Path,
        *,
        graph_artifact: str,
        namespace: str,
        owner_digest: str,
        scope_digest: str,
    ) -> None:
        self.path = path
        self.identity = _file(path)
        self.graph_artifact = graph_artifact
        self.namespace = namespace
        self.owner_digest = owner_digest
        self.scope_digest = scope_digest
        try:
            with self.connect() as connection:
                _require(
                    connection.execute("PRAGMA quick_check").fetchone()[0] == "ok",
                    "trace_index_integrity_failure",
                )
                row = connection.execute(
                    "SELECT * FROM metadata WHERE singleton=1"
                ).fetchone()
                _require(row is not None, "trace_index_metadata_missing")
                _require(
                    row["index_version"] == INDEX_VERSION,
                    "trace_index_version_unsupported",
                )
                _require(row["namespace"] == namespace, "trace_index_wrong_namespace")
                _require(row["scope_digest"] == scope_digest, "trace_index_stale_scope")
                _require(row["owner_digest"] == owner_digest, "trace_index_wrong_owner")
                _require(row["graph_artifact"] == graph_artifact, "trace_index_wrong_graph")
                axes_data = _decode_payload(
                    row["axes_json"], row["axes_sha256"], "trace_index_axes_changed"
                )
                self.axes = ResultAxes.from_data(axes_data)
                self.graph_digest = row["graph_digest"]
                self.snapshot_id = row["snapshot_id"]
                self.node_count = row["node_count"]
                self.edge_count = row["edge_count"]
                _require(
                    connection.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
                    == self.node_count,
                    "trace_index_node_count_changed",
                )
                _require(
                    connection.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
                    == self.edge_count,
                    "trace_index_edge_count_changed",
                )
        except sqlite3.DatabaseError as exc:
            raise GraphIndexError("trace_index_sqlite_failure") from exc

    def connect(self) -> sqlite3.Connection:
        current = _file(self.path)
        _require(
            (current.st_dev, current.st_ino) == (self.identity.st_dev, self.identity.st_ino),
            "trace_index_replaced",
        )
        return _connect(self.path, readonly=True)

    def contains_all(self, node_ids: set[str]) -> bool:
        if not node_ids:
            return True
        with self.connect() as connection:
            try:
                for values in _chunks(tuple(sorted(node_ids)), 400):
                    marks = ",".join("?" for _ in values)
                    count = connection.execute(
                        f"SELECT COUNT(*) FROM nodes WHERE node_id IN ({marks})", values
                    ).fetchone()[0]
                    if count != len(values):
                        return False
            except sqlite3.DatabaseError as exc:
                raise GraphIndexError("trace_index_sqlite_failure") from exc
        return True

    def reader(self) -> GraphIndexReader:
        return GraphIndexReader(self)

    def has_memory_reference(self, reference: object) -> bool:
        memory_json = canonical_json(reference)
        with self.connect() as connection:
            try:
                return (
                    connection.execute(
                        "SELECT 1 FROM nodes WHERE memory_json=? LIMIT 1", (memory_json,)
                    ).fetchone()
                    is not None
                )
            except sqlite3.DatabaseError as exc:
                raise GraphIndexError("trace_index_sqlite_failure") from exc

    def node(self, node_id: str) -> Node:
        with self.reader() as reader:
            return reader.node(node_id)

    def relations(
        self, node_id: str, direction: str, edge_kinds: tuple[str, ...]
    ) -> list[tuple[str, Edge]]:
        with self.reader() as reader:
            return reader.relations(node_id, direction, edge_kinds)


class GraphIndexReader:
    def __init__(self, index: GraphQueryIndex) -> None:
        self.index = index
        self.connection: sqlite3.Connection | None = None

    def __enter__(self) -> GraphIndexReader:
        _require(self.connection is None, "trace_index_reader_reused")
        self.connection = self.index.connect()
        return self

    def __exit__(self, _kind, _error, _traceback) -> None:
        connection, self.connection = self.connection, None
        if connection is not None:
            connection.close()

    def _connection(self) -> sqlite3.Connection:
        _require(self.connection is not None, "trace_index_reader_closed")
        return self.connection

    def node(self, node_id: str) -> Node:
        try:
            row = self._connection().execute(
                "SELECT payload_json,payload_sha256 FROM nodes WHERE node_id=?", (node_id,)
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise GraphIndexError("trace_index_sqlite_failure") from exc
        _require(row is not None, "trace_index_node_missing")
        data = _decode_payload(
            row["payload_json"], row["payload_sha256"], "trace_index_node_changed"
        )
        node = Node.from_data(data)
        _require(node.node_id == node_id, "trace_index_node_identity_changed")
        return node

    def relations(
        self, node_id: str, direction: str, edge_kinds: tuple[str, ...]
    ) -> list[tuple[str, Edge]]:
        _require(direction in {"forward", "backward"}, "invalid_trace_direction")
        _require(bool(edge_kinds), "invalid_trace_edge_filter")
        endpoint = "source_node_id" if direction == "forward" else "target_node_id"
        target = "target_node_id" if direction == "forward" else "source_node_id"
        marks = ",".join("?" for _ in edge_kinds)
        query = (
            f"SELECT edge_id,{target} AS next_node_id,payload_json,payload_sha256 "
            f"FROM edges WHERE {endpoint}=? AND kind IN ({marks}) "
            "ORDER BY next_node_id,edge_id"
        )
        try:
            rows = self._connection().execute(
                query, (node_id, *edge_kinds)
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise GraphIndexError("trace_index_sqlite_failure") from exc
        result: list[tuple[str, Edge]] = []
        for row in rows:
            data = _decode_payload(
                row["payload_json"], row["payload_sha256"], "trace_index_edge_changed"
            )
            edge = Edge.from_data(data)
            _require(edge.edge_id == row["edge_id"], "trace_index_edge_identity_changed")
            result.append((row["next_node_id"], edge))
        return result


def ensure_graph_query_index(
    root: Path,
    graph_artifact: str,
    graph: Graph,
    *,
    namespace: str,
    owner_digest: str,
    scope_digest: str,
) -> GraphQueryIndex:
    root, _ = _directory(root, create=True)
    final = root / _index_basename(graph_artifact)
    if final.exists() or final.is_symlink():
        index = GraphQueryIndex(
            final,
            graph_artifact=graph_artifact,
            namespace=namespace,
            owner_digest=owner_digest,
            scope_digest=scope_digest,
        )
        _require(index.graph_digest == graph.graph_digest, "trace_index_graph_changed")
        _require(index.snapshot_id == graph.snapshot.snapshot_id, "trace_index_snapshot_changed")
        return index

    temporary = root / f".{final.name}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(
        temporary, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    os.close(descriptor)
    try:
        connection = _connect(temporary)
        try:
            connection.execute("BEGIN IMMEDIATE")
            for statement in _SCHEMA.split(";"):
                if statement.strip():
                    connection.execute(statement)
            axes = graph.axes.to_data()
            connection.execute(
                "INSERT INTO metadata(singleton,index_version,namespace,scope_digest,owner_digest,"
                "graph_artifact,graph_digest,snapshot_id,axes_json,axes_sha256,node_count,edge_count) "
                "VALUES (1,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    INDEX_VERSION,
                    namespace,
                    scope_digest,
                    owner_digest,
                    graph_artifact,
                    graph.graph_digest,
                    graph.snapshot.snapshot_id,
                    canonical_json(axes),
                    digest(axes),
                    len(graph.nodes),
                    len(graph.edges),
                ),
            )
            connection.executemany(
                "INSERT INTO nodes VALUES (?,?,?,?)",
                (
                    (
                        node.node_id,
                        canonical_json(node),
                        digest(node),
                        None if node.memory is None else canonical_json(node.memory),
                    )
                    for node in graph.nodes
                ),
            )
            connection.executemany(
                "INSERT INTO edges VALUES (?,?,?,?,?,?)",
                (
                    (
                        edge.edge_id,
                        edge.source,
                        edge.target,
                        edge.kind,
                        canonical_json(edge),
                        digest(edge),
                    )
                    for edge in graph.edges
                ),
            )
            connection.execute(f"PRAGMA user_version={INDEX_VERSION}")
            connection.execute("COMMIT")
            _require(
                connection.execute("PRAGMA quick_check").fetchone()[0] == "ok",
                "trace_index_integrity_failure",
            )
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        _sync_file(temporary)
        try:
            os.link(temporary, final, follow_symlinks=False)
            _sync_directory(root)
        except FileExistsError:
            pass
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    index = GraphQueryIndex(
        final,
        graph_artifact=graph_artifact,
        namespace=namespace,
        owner_digest=owner_digest,
        scope_digest=scope_digest,
    )
    _require(index.graph_digest == graph.graph_digest, "trace_index_graph_changed")
    _require(index.snapshot_id == graph.snapshot.snapshot_id, "trace_index_snapshot_changed")
    return index


def open_graph_query_index(
    root: Path,
    graph_artifact: str,
    *,
    namespace: str,
    owner_digest: str,
    scope_digest: str,
) -> GraphQueryIndex:
    root, _ = _directory(root)
    final = root / _index_basename(graph_artifact)
    _require(final.exists() and not final.is_symlink(), "trace_index_missing")
    return GraphQueryIndex(
        final,
        graph_artifact=graph_artifact,
        namespace=namespace,
        owner_digest=owner_digest,
        scope_digest=scope_digest,
    )


def _chunks(values: tuple[str, ...], size: int):
    for offset in range(0, len(values), size):
        yield values[offset : offset + size]
