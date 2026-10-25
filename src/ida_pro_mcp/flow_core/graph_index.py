"""Immutable, digest-bound graph query index for paging and trace continuation."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid
from collections.abc import Callable, Iterable

from .contracts import Edge, Graph, Node, ResultAxes
from .serialization import (
    ContractError,
    canonical_json,
    canonical_json_v2,
    digest,
    to_wire_v2,
)


INDEX_VERSION = 2
INDEX_BUILD_BATCH_ROWS = 1000
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
  snapshot_json TEXT NOT NULL,
  snapshot_sha256 TEXT NOT NULL,
  axes_json TEXT NOT NULL,
  axes_sha256 TEXT NOT NULL,
  node_count INTEGER NOT NULL CHECK(node_count>=0),
  edge_count INTEGER NOT NULL CHECK(edge_count>=0),
  evidence_count INTEGER NOT NULL CHECK(evidence_count>=0),
  memory_dependency_count INTEGER NOT NULL CHECK(memory_dependency_count>=0),
  opaque_memory_dependency_count INTEGER NOT NULL CHECK(opaque_memory_dependency_count>=0)
);
CREATE TABLE nodes(
  node_id TEXT PRIMARY KEY,
  ordinal INTEGER NOT NULL UNIQUE CHECK(ordinal>=0),
  kind TEXT NOT NULL,
  operation TEXT,
  payload_json TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  memory_json TEXT,
  row_sha256 TEXT NOT NULL
);
CREATE INDEX nodes_by_kind_ordinal ON nodes(kind,ordinal);
CREATE INDEX nodes_by_operation_ordinal ON nodes(operation,ordinal);
CREATE TABLE node_source_eas(
  node_id TEXT NOT NULL,
  source_ea TEXT NOT NULL,
  row_sha256 TEXT NOT NULL,
  PRIMARY KEY(node_id,source_ea)
);
CREATE INDEX nodes_by_source_ea ON node_source_eas(source_ea,node_id);
CREATE TABLE edges(
  edge_id TEXT PRIMARY KEY,
  ordinal INTEGER NOT NULL UNIQUE CHECK(ordinal>=0),
  source_node_id TEXT NOT NULL,
  target_node_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  row_sha256 TEXT NOT NULL
);
CREATE INDEX edges_by_source ON edges(source_node_id,kind,target_node_id,edge_id);
CREATE INDEX edges_by_target ON edges(target_node_id,kind,source_node_id,edge_id);
CREATE INDEX edges_by_ordinal ON edges(ordinal);
CREATE TABLE evidence_items(
  evidence_id TEXT NOT NULL,
  chunk_index INTEGER NOT NULL CHECK(chunk_index>=0),
  ordinal INTEGER NOT NULL UNIQUE CHECK(ordinal>=0),
  payload_json TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  row_sha256 TEXT NOT NULL,
  PRIMARY KEY(evidence_id,chunk_index)
);
CREATE INDEX evidence_by_ordinal ON evidence_items(ordinal);
"""


class GraphIndexError(ContractError):
    pass


def evidence_chunks(items, *, wire_version="flow-wire/1"):
    """Large evidence remains reconstructible JSON, never a text preview."""
    chunks = []
    for item in items:
        v2 = wire_version == "flow-wire/2"
        body = canonical_json_v2(item) if v2 else canonical_json(item)
        size = len(json.dumps(to_wire_v2(item) if v2 else item))
        if size < 8000:
            chunks.append(item)
            continue
        for offset in range(0, len(body), 1000):
            chunks.append(
                {
                    "evidence_id": item["evidence_id"],
                    "encoding": (
                        "canonical-json-v2-text"
                        if v2
                        else "canonical-json-text"
                    ),
                    "offset": offset,
                    "length": len(body[offset : offset + 1000]),
                    "total_length": len(body),
                    "text": body[offset : offset + 1000],
                }
            )
    return chunks


def _indexed_evidence_items(graph: Graph):
    wire_version = (
        "flow-wire/2"
        if graph.snapshot.snapshot_id.startswith("snapshot-v2:")
        else "flow-wire/1"
    )
    ordinal = 0
    for evidence in sorted(graph.evidence, key=lambda item: item.evidence_id):
        item = {"evidence_id": evidence.evidence_id, **evidence.to_data()}
        for chunk_index, chunk in enumerate(
            evidence_chunks([item], wire_version=wire_version)
        ):
            payload_json = canonical_json(chunk)
            payload_sha256 = digest(chunk)
            yield (
                evidence.evidence_id,
                chunk_index,
                ordinal,
                payload_json,
                payload_sha256,
                digest(
                    {
                        "evidence_id": evidence.evidence_id,
                        "chunk_index": chunk_index,
                        "ordinal": ordinal,
                        "payload_sha256": payload_sha256,
                    }
                ),
            )
            ordinal += 1


def _indexed_nodes(graph: Graph):
    for ordinal, node in enumerate(graph.nodes):
        payload_json = canonical_json(node)
        payload_sha256 = digest(node)
        memory_json = None if node.memory is None else canonical_json(node.memory)
        yield (
            node.node_id,
            ordinal,
            node.kind,
            node.operation,
            payload_json,
            payload_sha256,
            memory_json,
            digest(
                {
                    "node_id": node.node_id,
                    "ordinal": ordinal,
                    "kind": node.kind,
                    "operation": node.operation,
                    "payload_sha256": payload_sha256,
                    "memory_json": memory_json,
                }
            ),
        )


def _indexed_edges(graph: Graph):
    for ordinal, edge in enumerate(graph.edges):
        payload_json = canonical_json(edge)
        payload_sha256 = digest(edge)
        yield (
            edge.edge_id,
            ordinal,
            edge.source,
            edge.target,
            edge.kind,
            payload_json,
            payload_sha256,
            digest(
                {
                    "edge_id": edge.edge_id,
                    "ordinal": ordinal,
                    "source_node_id": edge.source,
                    "target_node_id": edge.target,
                    "kind": edge.kind,
                    "payload_sha256": payload_sha256,
                }
            ),
        )


def _indexed_node_sources(graph: Graph, evidence_by_id):
    for node in graph.nodes:
        for source_ea in sorted(
            {
                source_ea
                for evidence_id in node.evidence_ids
                for source_ea in evidence_by_id[evidence_id].source_eas
            }
        ):
            source_text = str(source_ea)
            yield (
                node.node_id,
                source_text,
                digest({"node_id": node.node_id, "source_ea": source_text}),
            )


def _insert_rows(
    connection: sqlite3.Connection,
    statement: str,
    rows: Iterable[tuple],
    *,
    section: str,
    checkpoint: Callable[[], None] | None,
    progress: Callable[[dict], None] | None,
) -> None:
    batch = []
    processed = 0
    for row in rows:
        batch.append(row)
        if len(batch) < INDEX_BUILD_BATCH_ROWS:
            continue
        if checkpoint is not None:
            checkpoint()
        connection.executemany(statement, batch)
        processed += len(batch)
        batch.clear()
        if progress is not None:
            progress({"section": section, "processed": processed})
    if batch:
        if checkpoint is not None:
            checkpoint()
        connection.executemany(statement, batch)
        processed += len(batch)
        if progress is not None:
            progress({"section": section, "processed": processed})
    if checkpoint is not None:
        checkpoint()


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
                self.index_version = row["index_version"]
                _require(row["namespace"] == namespace, "trace_index_wrong_namespace")
                _require(row["scope_digest"] == scope_digest, "trace_index_stale_scope")
                _require(row["owner_digest"] == owner_digest, "trace_index_wrong_owner")
                _require(row["graph_artifact"] == graph_artifact, "trace_index_wrong_graph")
                axes_data = _decode_payload(
                    row["axes_json"], row["axes_sha256"], "trace_index_axes_changed"
                )
                self.snapshot = _decode_payload(
                    row["snapshot_json"],
                    row["snapshot_sha256"],
                    "trace_index_snapshot_changed",
                )
                self.axes = ResultAxes.from_data(axes_data)
                self.graph_digest = row["graph_digest"]
                self.snapshot_id = row["snapshot_id"]
                self.node_count = row["node_count"]
                self.edge_count = row["edge_count"]
                self.evidence_count = row["evidence_count"]
                self.memory_dependency_count = row["memory_dependency_count"]
                self.opaque_memory_dependency_count = row[
                    "opaque_memory_dependency_count"
                ]
                _require(
                    type(self.snapshot) is dict
                    and self.snapshot.get("snapshot_id") == self.snapshot_id,
                    "trace_index_snapshot_changed",
                )
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
                _require(
                    connection.execute(
                        "SELECT COUNT(DISTINCT evidence_id) FROM evidence_items"
                    ).fetchone()[0]
                    == self.evidence_count,
                    "trace_index_evidence_count_changed",
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

    def memory_nodes(self, reference: object) -> tuple[str, ...]:
        memory_json = canonical_json(reference)
        with self.connect() as connection:
            try:
                return tuple(
                    row["node_id"]
                    for row in connection.execute(
                        "SELECT node_id FROM nodes WHERE memory_json=? ORDER BY node_id",
                        (memory_json,),
                    )
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

    def page_items(
        self,
        *,
        after: tuple[str, int] | None,
        limit: int,
        item_type: str | None,
        node_id: str | None,
        node_kind: str | None,
        operation: str | None,
        source_ea: int | None,
        source_node_id: str | None,
        target_node_id: str | None,
        edge_kinds: tuple[str, ...],
    ) -> list[tuple[str, int, Node | Edge]]:
        with self.reader() as reader:
            if after is not None:
                _require(
                    reader.position_matches(
                        after,
                        item_type=item_type,
                        node_id=node_id,
                        node_kind=node_kind,
                        operation=operation,
                        source_ea=source_ea,
                        source_node_id=source_node_id,
                        target_node_id=target_node_id,
                        edge_kinds=edge_kinds,
                    ),
                    "invalid_cursor",
                )
            return reader.page_items(
                after=after,
                limit=limit,
                item_type=item_type,
                node_id=node_id,
                node_kind=node_kind,
                operation=operation,
                source_ea=source_ea,
                source_node_id=source_node_id,
                target_node_id=target_node_id,
                edge_kinds=edge_kinds,
            )

    def page_evidence_items(
        self, *, after_ordinal: int | None, limit: int
    ) -> list[tuple[int, dict]]:
        with self.reader() as reader:
            if after_ordinal is not None:
                _require(
                    reader.evidence_position_exists(after_ordinal),
                    "invalid_cursor",
                )
            return reader.page_evidence_items(
                after_ordinal=-1 if after_ordinal is None else after_ordinal,
                limit=limit,
            )

    def selected_evidence_items(self, evidence_ids: tuple[str, ...]) -> list[dict]:
        with self.reader() as reader:
            return reader.selected_evidence_items(evidence_ids)


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
                "SELECT node_id,ordinal,kind,operation,payload_json,payload_sha256,"
                "memory_json,row_sha256 FROM nodes WHERE node_id=?",
                (node_id,),
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise GraphIndexError("trace_index_sqlite_failure") from exc
        _require(row is not None, "trace_index_node_missing")
        _, _, node = self._decode_node_row(row)
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
            f"SELECT edge_id,ordinal,source_node_id,target_node_id,kind,"
            f"{target} AS next_node_id,payload_json,payload_sha256,row_sha256 "
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
            _, _, edge = self._decode_edge_row(row)
            result.append((row["next_node_id"], edge))
        return result

    @staticmethod
    def _node_predicates(
        *,
        node_id: str | None,
        node_kind: str | None,
        operation: str | None,
        source_ea: int | None,
    ) -> tuple[list[str], list[object]]:
        clauses: list[str] = []
        values: list[object] = []
        if node_id is not None:
            clauses.append("n.node_id=?")
            values.append(node_id)
        if node_kind is not None:
            clauses.append("n.kind=?")
            values.append(node_kind)
        if operation is not None:
            clauses.append("n.operation=?")
            values.append(operation)
        if source_ea is not None:
            clauses.append(
                "EXISTS(SELECT 1 FROM node_source_eas s "
                "WHERE s.node_id=n.node_id AND s.source_ea=?)"
            )
            values.append(str(source_ea))
        return clauses, values

    @staticmethod
    def _edge_predicates(
        *,
        source_node_id: str | None,
        target_node_id: str | None,
        edge_kinds: tuple[str, ...],
    ) -> tuple[list[str], list[object]]:
        clauses: list[str] = []
        values: list[object] = []
        if source_node_id is not None:
            clauses.append("e.source_node_id=?")
            values.append(source_node_id)
        if target_node_id is not None:
            clauses.append("e.target_node_id=?")
            values.append(target_node_id)
        if edge_kinds:
            clauses.append("e.kind IN (" + ",".join("?" for _ in edge_kinds) + ")")
            values.extend(edge_kinds)
        return clauses, values

    def _node_rows(
        self,
        *,
        after_ordinal: int,
        limit: int,
        node_id: str | None,
        node_kind: str | None,
        operation: str | None,
        source_ea: int | None,
    ) -> list[sqlite3.Row]:
        clauses, values = self._node_predicates(
            node_id=node_id,
            node_kind=node_kind,
            operation=operation,
            source_ea=source_ea,
        )
        clauses.insert(0, "n.ordinal>?")
        values.insert(0, after_ordinal)
        try:
            rows = self._connection().execute(
                "SELECT n.ordinal,n.node_id,n.kind,n.operation,n.payload_json,"
                "n.payload_sha256,n.memory_json,n.row_sha256 "
                "FROM nodes n WHERE "
                + " AND ".join(clauses)
                + " ORDER BY n.ordinal LIMIT ?",
                (*values, limit),
            ).fetchall()
            if source_ea is not None:
                source_text = str(source_ea)
                for row in rows:
                    source = self._connection().execute(
                        "SELECT node_id,source_ea,row_sha256 FROM node_source_eas "
                        "WHERE node_id=? AND source_ea=?",
                        (row["node_id"], source_text),
                    ).fetchone()
                    _require(
                        source is not None
                        and digest(
                            {
                                "node_id": source["node_id"],
                                "source_ea": source["source_ea"],
                            }
                        )
                        == source["row_sha256"],
                        "trace_index_node_source_changed",
                    )
            return rows
        except sqlite3.DatabaseError as exc:
            raise GraphIndexError("trace_index_sqlite_failure") from exc

    def _edge_rows(
        self,
        *,
        after_ordinal: int,
        limit: int,
        source_node_id: str | None,
        target_node_id: str | None,
        edge_kinds: tuple[str, ...],
    ) -> list[sqlite3.Row]:
        clauses, values = self._edge_predicates(
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            edge_kinds=edge_kinds,
        )
        clauses.insert(0, "e.ordinal>?")
        values.insert(0, after_ordinal)
        try:
            return self._connection().execute(
                "SELECT e.ordinal,e.edge_id,e.source_node_id,e.target_node_id,e.kind,"
                "e.payload_json,e.payload_sha256,e.row_sha256 "
                "FROM edges e WHERE "
                + " AND ".join(clauses)
                + " ORDER BY e.ordinal LIMIT ?",
                (*values, limit),
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise GraphIndexError("trace_index_sqlite_failure") from exc

    @staticmethod
    def _decode_node_row(row: sqlite3.Row) -> tuple[str, int, Node]:
        _require(
            digest(
                {
                    "node_id": row["node_id"],
                    "ordinal": row["ordinal"],
                    "kind": row["kind"],
                    "operation": row["operation"],
                    "payload_sha256": row["payload_sha256"],
                    "memory_json": row["memory_json"],
                }
            )
            == row["row_sha256"],
            "trace_index_node_row_changed",
        )
        data = _decode_payload(
            row["payload_json"], row["payload_sha256"], "trace_index_node_changed"
        )
        node = Node.from_data(data)
        _require(node.node_id == row["node_id"], "trace_index_node_identity_changed")
        _require(
            node.kind == row["kind"]
            and node.operation == row["operation"]
            and (None if node.memory is None else canonical_json(node.memory))
            == row["memory_json"],
            "trace_index_node_row_changed",
        )
        return "node", row["ordinal"], node

    @staticmethod
    def _decode_edge_row(row: sqlite3.Row) -> tuple[str, int, Edge]:
        _require(
            digest(
                {
                    "edge_id": row["edge_id"],
                    "ordinal": row["ordinal"],
                    "source_node_id": row["source_node_id"],
                    "target_node_id": row["target_node_id"],
                    "kind": row["kind"],
                    "payload_sha256": row["payload_sha256"],
                }
            )
            == row["row_sha256"],
            "trace_index_edge_row_changed",
        )
        data = _decode_payload(
            row["payload_json"], row["payload_sha256"], "trace_index_edge_changed"
        )
        edge = Edge.from_data(data)
        _require(edge.edge_id == row["edge_id"], "trace_index_edge_identity_changed")
        _require(
            edge.source == row["source_node_id"]
            and edge.target == row["target_node_id"]
            and edge.kind == row["kind"],
            "trace_index_edge_row_changed",
        )
        return "edge", row["ordinal"], edge

    def page_items(
        self,
        *,
        after: tuple[str, int] | None,
        limit: int,
        item_type: str | None,
        node_id: str | None,
        node_kind: str | None,
        operation: str | None,
        source_ea: int | None,
        source_node_id: str | None,
        target_node_id: str | None,
        edge_kinds: tuple[str, ...],
    ) -> list[tuple[str, int, Node | Edge]]:
        rows: list[tuple[str, int, Node | Edge]] = []
        after_kind, after_ordinal = after if after is not None else (None, -1)
        if item_type in {None, "node"} and after_kind != "edge":
            node_rows = self._node_rows(
                after_ordinal=after_ordinal if after_kind == "node" else -1,
                limit=limit,
                node_id=node_id,
                node_kind=node_kind,
                operation=operation,
                source_ea=source_ea,
            )
            rows.extend(self._decode_node_row(row) for row in node_rows)
        if item_type in {None, "edge"} and len(rows) < limit:
            edge_rows = self._edge_rows(
                after_ordinal=after_ordinal if after_kind == "edge" else -1,
                limit=limit - len(rows),
                source_node_id=source_node_id,
                target_node_id=target_node_id,
                edge_kinds=edge_kinds,
            )
            rows.extend(self._decode_edge_row(row) for row in edge_rows)
        return rows

    def position_matches(
        self,
        position: tuple[str, int],
        *,
        item_type: str | None,
        node_id: str | None,
        node_kind: str | None,
        operation: str | None,
        source_ea: int | None,
        source_node_id: str | None,
        target_node_id: str | None,
        edge_kinds: tuple[str, ...],
    ) -> bool:
        kind, ordinal = position
        if kind == "node" and item_type in {None, "node"}:
            clauses, values = self._node_predicates(
                node_id=node_id,
                node_kind=node_kind,
                operation=operation,
                source_ea=source_ea,
            )
            clauses.insert(0, "n.ordinal=?")
            values.insert(0, ordinal)
            query = "SELECT 1 FROM nodes n WHERE " + " AND ".join(clauses)
        elif kind == "edge" and item_type in {None, "edge"}:
            clauses, values = self._edge_predicates(
                source_node_id=source_node_id,
                target_node_id=target_node_id,
                edge_kinds=edge_kinds,
            )
            clauses.insert(0, "e.ordinal=?")
            values.insert(0, ordinal)
            query = "SELECT 1 FROM edges e WHERE " + " AND ".join(clauses)
        else:
            return False
        try:
            return self._connection().execute(query, values).fetchone() is not None
        except sqlite3.DatabaseError as exc:
            raise GraphIndexError("trace_index_sqlite_failure") from exc

    @staticmethod
    def _decode_evidence_row(row: sqlite3.Row) -> dict:
        _require(
            digest(
                {
                    "evidence_id": row["evidence_id"],
                    "chunk_index": row["chunk_index"],
                    "ordinal": row["ordinal"],
                    "payload_sha256": row["payload_sha256"],
                }
            )
            == row["row_sha256"],
            "trace_index_evidence_row_changed",
        )
        item = _decode_payload(
            row["payload_json"],
            row["payload_sha256"],
            "trace_index_evidence_changed",
        )
        _require(
            type(item) is dict and item.get("evidence_id") == row["evidence_id"],
            "trace_index_evidence_identity_changed",
        )
        return item

    def evidence_position_exists(self, ordinal: int) -> bool:
        try:
            return (
                self._connection()
                .execute(
                    "SELECT 1 FROM evidence_items WHERE ordinal=?", (ordinal,)
                )
                .fetchone()
                is not None
            )
        except sqlite3.DatabaseError as exc:
            raise GraphIndexError("trace_index_sqlite_failure") from exc

    def page_evidence_items(
        self, *, after_ordinal: int, limit: int
    ) -> list[tuple[int, dict]]:
        try:
            rows = self._connection().execute(
                "SELECT ordinal,evidence_id,chunk_index,payload_json,payload_sha256,"
                "row_sha256 "
                "FROM evidence_items WHERE ordinal>? ORDER BY ordinal LIMIT ?",
                (after_ordinal, limit),
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise GraphIndexError("trace_index_sqlite_failure") from exc
        return [(row["ordinal"], self._decode_evidence_row(row)) for row in rows]

    def selected_evidence_items(self, evidence_ids: tuple[str, ...]) -> list[dict]:
        result = []
        try:
            for evidence_id in evidence_ids:
                rows = self._connection().execute(
                    "SELECT evidence_id,chunk_index,ordinal,payload_json,"
                    "payload_sha256,row_sha256 "
                    "FROM evidence_items WHERE evidence_id=? ORDER BY chunk_index",
                    (evidence_id,),
                ).fetchall()
                if not rows:
                    result.append({"evidence_id": evidence_id, "missing": True})
                    continue
                result.extend(self._decode_evidence_row(row) for row in rows)
        except sqlite3.DatabaseError as exc:
            raise GraphIndexError("trace_index_sqlite_failure") from exc
        return result


def ensure_graph_query_index(
    root: Path,
    graph_artifact: str,
    graph: Graph,
    *,
    namespace: str,
    owner_digest: str,
    scope_digest: str,
    checkpoint: Callable[[], None] | None = None,
    progress: Callable[[dict], None] | None = None,
    graph_digest: str | None = None,
) -> GraphQueryIndex:
    expected_graph_digest = graph_digest or graph.graph_digest
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
        _require(
            index.graph_digest == expected_graph_digest,
            "trace_index_graph_changed",
        )
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
            snapshot = graph.snapshot.to_data()
            memory_dependency_count = sum(
                edge.kind == "memory_data_dependency" for edge in graph.edges
            )
            opaque_memory_dependency_count = sum(
                edge.kind == "memory_data_dependency"
                and edge.axes.precision == "opaque"
                for edge in graph.edges
            )
            connection.execute(
                "INSERT INTO metadata(singleton,index_version,namespace,scope_digest,owner_digest,"
                "graph_artifact,graph_digest,snapshot_id,snapshot_json,snapshot_sha256,"
                "axes_json,axes_sha256,node_count,edge_count,evidence_count,"
                "memory_dependency_count,opaque_memory_dependency_count) "
                "VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    INDEX_VERSION,
                    namespace,
                    scope_digest,
                    owner_digest,
                    graph_artifact,
                    expected_graph_digest,
                    graph.snapshot.snapshot_id,
                    canonical_json(snapshot),
                    digest(snapshot),
                    canonical_json(axes),
                    digest(axes),
                    len(graph.nodes),
                    len(graph.edges),
                    len(graph.evidence),
                    memory_dependency_count,
                    opaque_memory_dependency_count,
                ),
            )
            _insert_rows(
                connection,
                "INSERT INTO nodes VALUES (?,?,?,?,?,?,?,?)",
                _indexed_nodes(graph),
                section="nodes",
                checkpoint=checkpoint,
                progress=progress,
            )
            _insert_rows(
                connection,
                "INSERT INTO edges VALUES (?,?,?,?,?,?,?,?)",
                _indexed_edges(graph),
                section="edges",
                checkpoint=checkpoint,
                progress=progress,
            )
            evidence_by_id = {
                item.evidence_id: item for item in graph.evidence
            }
            _insert_rows(
                connection,
                "INSERT INTO node_source_eas VALUES (?,?,?)",
                _indexed_node_sources(graph, evidence_by_id),
                section="node_source_eas",
                checkpoint=checkpoint,
                progress=progress,
            )
            _insert_rows(
                connection,
                "INSERT INTO evidence_items VALUES (?,?,?,?,?,?)",
                _indexed_evidence_items(graph),
                section="evidence",
                checkpoint=checkpoint,
                progress=progress,
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
    _require(
        index.graph_digest == expected_graph_digest,
        "trace_index_graph_changed",
    )
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
