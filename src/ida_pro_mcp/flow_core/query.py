"""Bounded immutable artifact views and durable structural graph traversal.

Traversal is reachability, not seeded taint, path feasibility, or a safety verdict.
Cursors bind the immutable artifact/filter or the durable trace revision.
"""

from collections import deque
from dataclasses import replace
import json
import re
from typing import get_args

from .contracts import (
    EdgeKind,
    Graph,
    MemorySource,
    Node,
    NodeKind,
    Snapshot,
    ValueSource,
)
from .memory_graph import reassemble_graph, verify_window_slices
from .graph_index import evidence_chunks as _evidence_chunks
from .persistence import PAGE_HARD_CHARS, PAGE_TARGET_CHARS, PersistenceError, require
from .runtime_contracts import TraceSpec, TraceState
from .serialization import (
    JS_SAFE_INTEGER,
    digest,
    from_wire_v2,
    to_wire_v2,
    validate_ea,
)
from .states import check_id

DEFAULT_EDGES = ("memory_data_dependency", "phi_input", "value_dependency")
PAGE_LIMIT_MIN = 1
PAGE_LIMIT_MAX = 200
TRACE_BUDGET_MIN = 1
evidence_chunks = _evidence_chunks
NODE_KINDS = frozenset(get_args(NodeKind))
EDGE_KINDS = frozenset(get_args(EdgeKind))
GRAPH_PAGE_LIMITATIONS = (
    "This page is intra-function value and byte-range reachability; use the dedicated implicit, bounded-proof, and call-composition artifacts for those distinct semantics.",
    "Supported-anchor memory edges assume successful flat user-space accesses; TLS/MMIO and null/fault feasibility are unresolved.",
)


def wire_safe_node_item(item: dict) -> dict:
    """Render one node for a v1 page without losing wide constants.

    A 64-bit constant (2**53 and above) cannot travel as a v1 JSON number,
    so it is preserved as ``constant_hex`` with ``constant`` nulled. Narrow
    values pass through untouched; no other field is rewritten.
    """
    constant = item.get("constant")
    if type(constant) is int and abs(constant) > JS_SAFE_INTEGER:
        item = {**item, "constant": None, "constant_hex": hex(constant)}
    return item


def trace_cursor(trace_id, revision):
    return digest({"trace": trace_id, "revision": revision, "version": 1})


def bounded(response, *, v2=False):
    payload = to_wire_v2(response) if v2 else response
    require(len(json.dumps(payload)) <= PAGE_HARD_CHARS, "item_too_large")
    return response


def artifact_page(artifact_id, section, items, metadata, cursor=None, limit=50):
    """Stateless cursor includes offset AND immutable content/filter identity."""
    require(
        type(limit) is int and PAGE_LIMIT_MIN <= limit <= PAGE_LIMIT_MAX,
        "invalid_page_limit",
    )
    identity_data = {"artifact": artifact_id, "section": section, "items": items}
    v2 = type(metadata) is dict and (
        metadata.get("wire_version") == "flow-wire/2"
        or str(metadata.get("snapshot_id", "")).startswith("snapshot-v2:")
        or str(metadata.get("graph_digest", "")).startswith("sha256-v2:")
    )
    if v2:
        identity_data.update(
            {
                "wire_version": "flow-wire/2",
                "snapshot_id": metadata.get("snapshot_id"),
                "graph_digest": metadata.get("graph_digest"),
            }
        )
    identity = digest(identity_data)
    offset = 0
    if cursor is not None:
        require(type(cursor) is str, "invalid_cursor")
        try:
            index, token = cursor.split("/", 1)
            offset = int(index)
        except (ValueError, TypeError):
            raise PersistenceError("invalid_cursor") from None
        require(0 <= offset <= len(items), "invalid_cursor")
        require(
            token == digest({"identity": identity, "offset": offset}), "invalid_cursor"
        )
    response = {
        "schema_version": "flow-page/1",
        "artifact_id": artifact_id,
        "section": section,
        "metadata": metadata,
        "items": [],
        "next_cursor": None,
    }
    for item in items[offset : offset + limit]:
        candidate = {**response, "items": response["items"] + [item]}
        end = offset + len(candidate["items"])
        candidate["next_cursor"] = (
            f"{end}/" + digest({"identity": identity, "offset": end})
            if end < len(items)
            else None
        )
        sized_candidate = to_wire_v2(candidate) if v2 else candidate
        if response["items"] and len(json.dumps(sized_candidate)) > PAGE_TARGET_CHARS:
            break
        bounded(candidate, v2=v2)
        response = candidate
    return bounded(response, v2=v2)


def _graph_page_filter(
    *,
    item_type=None,
    node_id=None,
    node_kind=None,
    operation=None,
    source_ea=None,
    source_node_id=None,
    target_node_id=None,
    edge_kinds=None,
):
    require(item_type in {None, "node", "edge"}, "invalid_graph_filter")
    node_filter = any(
        value is not None for value in (node_id, node_kind, operation, source_ea)
    )
    edge_filter = any(
        value is not None
        for value in (source_node_id, target_node_id, edge_kinds)
    )
    require(not (node_filter and edge_filter), "invalid_graph_filter")
    require(not node_filter or item_type in {None, "node"}, "invalid_graph_filter")
    require(not edge_filter or item_type in {None, "edge"}, "invalid_graph_filter")
    if node_filter and item_type is None:
        item_type = "node"
    if edge_filter and item_type is None:
        item_type = "edge"
    for value in (node_id, source_node_id, target_node_id):
        require(value is None or type(value) is str, "invalid_graph_filter")
        if value is not None:
            check_id(value, "node")
    require(
        node_kind is None or node_kind in NODE_KINDS,
        "invalid_graph_filter",
    )
    require(
        operation is None or (type(operation) is str and bool(operation)),
        "invalid_graph_filter",
    )
    require(
        source_ea is None or type(source_ea) in {int, dict},
        "invalid_graph_filter",
    )
    require(
        edge_kinds is None
        or (
            type(edge_kinds) in {list, tuple}
            and bool(edge_kinds)
            and all(type(kind) is str and kind in EDGE_KINDS for kind in edge_kinds)
        ),
        "invalid_graph_filter",
    )
    return {
        "item_type": item_type,
        "node_id": node_id,
        "node_kind": node_kind,
        "operation": operation,
        "source_ea": source_ea,
        "source_node_id": source_node_id,
        "target_node_id": target_node_id,
        "edge_kinds": tuple(sorted(set(edge_kinds or ()))),
    }


def _graph_page_metadata(index):
    snapshot = Snapshot.from_data(index.snapshot)
    require(
        isinstance(snapshot, Snapshot),
        "public_runtime_requires_normal_snapshot",
    )
    metadata = {
        "snapshot_id": snapshot.snapshot_id,
        "graph_digest": index.graph_digest,
        "axes": index.axes.to_data(),
        "maturity": snapshot.identity.maturity,
        "profile_digest": snapshot.identity.profile_digest,
        "rule_digest": snapshot.identity.rule_digest,
        "summary_digest": snapshot.identity.summary_digest,
        "environment": snapshot.identity.environment.to_data(),
        "diagnostics": [item.to_data() for item in snapshot.function.diagnostics],
        "argument_bindings": [],
        "memory_dependency_count": index.memory_dependency_count,
        "opaque_memory_dependency_count": index.opaque_memory_dependency_count,
        "limitations": list(GRAPH_PAGE_LIMITATIONS),
    }
    if snapshot.snapshot_id.startswith("snapshot-v2:"):
        metadata["wire_version"] = "flow-wire/2"
    return metadata


def _graph_page_cursor(identity, position):
    kind, ordinal = position
    return f"{kind}:{ordinal}/" + digest(
        {"identity": identity, "kind": kind, "ordinal": ordinal}
    )


def _parse_graph_page_cursor(cursor, identity):
    if cursor is None:
        return None
    require(type(cursor) is str, "invalid_cursor")
    try:
        position, token = cursor.split("/", 1)
        kind, ordinal_text = position.split(":", 1)
        ordinal = int(ordinal_text)
    except (TypeError, ValueError):
        raise PersistenceError("invalid_cursor") from None
    require(
        kind in {"node", "edge"}
        and ordinal >= 0
        and cursor == _graph_page_cursor(identity, (kind, ordinal)),
        "invalid_cursor",
    )
    return kind, ordinal


def _evidence_page_cursor(identity, ordinal):
    return f"{ordinal}/" + digest({"identity": identity, "ordinal": ordinal})


def _parse_evidence_page_cursor(cursor, identity):
    if cursor is None:
        return None
    require(type(cursor) is str, "invalid_cursor")
    try:
        ordinal_text, token = cursor.split("/", 1)
        ordinal = int(ordinal_text)
    except (TypeError, ValueError):
        raise PersistenceError("invalid_cursor") from None
    require(
        ordinal >= 0 and cursor == _evidence_page_cursor(identity, ordinal),
        "invalid_cursor",
    )
    return ordinal


class Queries:
    def __init__(self, store):
        self.store = store

    def graph(self, artifact_id):
        return Graph.from_data(self.store.artifact(artifact_id))

    def page_graph(
        self,
        artifact_id,
        cursor=None,
        limit=50,
        *,
        item_type=None,
        node_id=None,
        node_kind=None,
        operation=None,
        source_ea=None,
        source_node_id=None,
        target_node_id=None,
        edge_kinds=None,
    ):
        require(
            type(limit) is int and PAGE_LIMIT_MIN <= limit <= PAGE_LIMIT_MAX,
            "invalid_page_limit",
        )
        selected = _graph_page_filter(
            item_type=item_type,
            node_id=node_id,
            node_kind=node_kind,
            operation=operation,
            source_ea=source_ea,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            edge_kinds=edge_kinds,
        )
        index = self._trace_index(artifact_id)
        if selected["source_ea"] is not None:
            tagged = type(selected["source_ea"]) is dict
            require(
                tagged == index.snapshot_id.startswith("snapshot-v2:"),
                "mixed_wire_versions",
            )
            source = (
                from_wire_v2(selected["source_ea"])
                if tagged
                else selected["source_ea"]
            )
            bitness = index.snapshot["identity"]["environment"]["bitness"]
            selected["source_ea"] = validate_ea(source, bitness)
        identity_filter = {
            **selected,
            "edge_kinds": list(selected["edge_kinds"]),
            **(
                {"source_ea": {"$int": str(selected["source_ea"])}}
                if selected["source_ea"] is not None
                else {}
            ),
        }
        identity = digest(
            {
                "artifact": artifact_id,
                "section": "graph",
                "graph_digest": index.graph_digest,
                "filter": identity_filter,
                "index_version": index.index_version,
            }
        )
        after = _parse_graph_page_cursor(cursor, identity)
        indexed = index.page_items(after=after, limit=limit + 1, **selected)
        has_more = len(indexed) > limit
        response = {
            "schema_version": "flow-page/1",
            "artifact_id": artifact_id,
            "section": "graph",
            "metadata": _graph_page_metadata(index),
            "items": [],
            "next_cursor": None,
        }
        last_position = None
        v2 = index.snapshot_id.startswith("snapshot-v2:")
        for kind, ordinal, value in indexed[:limit]:
            item = (
                {"type": "node", "node_id": value.node_id, **value.to_data()}
                if isinstance(value, Node)
                else {"type": "edge", "edge_id": value.edge_id, **value.to_data()}
            )
            if not v2 and isinstance(value, Node):
                item = wire_safe_node_item(item)
            candidate = {**response, "items": response["items"] + [item]}
            position = (kind, ordinal)
            candidate["next_cursor"] = (
                _graph_page_cursor(identity, position)
                if has_more or len(response["items"]) + 1 < len(indexed)
                else None
            )
            sized = to_wire_v2(candidate) if v2 else candidate
            if response["items"] and len(json.dumps(sized)) > PAGE_TARGET_CHARS:
                has_more = True
                break
            bounded(candidate, v2=v2)
            response = candidate
            last_position = position
        if has_more and last_position is not None:
            response["next_cursor"] = _graph_page_cursor(identity, last_position)
        return bounded(response, v2=v2)

    def page_evidence(
        self,
        artifact_id,
        cursor=None,
        limit=50,
        *,
        evidence_ids=None,
    ):
        require(
            type(limit) is int and PAGE_LIMIT_MIN <= limit <= PAGE_LIMIT_MAX,
            "invalid_page_limit",
        )
        require(
            evidence_ids is None
            or (
                type(evidence_ids) is list
                and len(evidence_ids) <= 100
                and all(type(item) is str for item in evidence_ids)
            ),
            "invalid_evidence_ids",
        )
        index = self._trace_index(artifact_id)
        identity_version = 2 if index.snapshot_id.startswith("snapshot-v2:") else 1
        require(
            evidence_ids is None
            or all(
                    re.fullmatch(
                        rf"evidence-v{identity_version}:[0-9a-f]{{64}}", item
                    )
                    is not None
                    for item in evidence_ids
            ),
            "invalid_evidence_ids",
        )
        metadata = _graph_page_metadata(index)
        if evidence_ids is not None:
            selected = tuple(sorted(set(evidence_ids)))
            return artifact_page(
                artifact_id,
                "evidence",
                index.selected_evidence_items(selected),
                metadata,
                cursor,
                limit,
            )
        identity = digest(
            {
                "artifact": artifact_id,
                "section": "evidence",
                "graph_digest": index.graph_digest,
                "index_version": index.index_version,
            }
        )
        after = _parse_evidence_page_cursor(cursor, identity)
        indexed = index.page_evidence_items(after_ordinal=after, limit=limit + 1)
        has_more = len(indexed) > limit
        response = {
            "schema_version": "flow-page/1",
            "artifact_id": artifact_id,
            "section": "evidence",
            "metadata": metadata,
            "items": [],
            "next_cursor": None,
        }
        last_ordinal = None
        v2 = identity_version == 2
        for ordinal, item in indexed[:limit]:
            candidate = {**response, "items": response["items"] + [item]}
            candidate["next_cursor"] = (
                _evidence_page_cursor(identity, ordinal)
                if has_more or len(response["items"]) + 1 < len(indexed)
                else None
            )
            sized = to_wire_v2(candidate) if v2 else candidate
            if response["items"] and len(json.dumps(sized)) > PAGE_TARGET_CHARS:
                has_more = True
                break
            bounded(candidate, v2=v2)
            response = candidate
            last_ordinal = ordinal
        if has_more and last_ordinal is not None:
            response["next_cursor"] = _evidence_page_cursor(identity, last_ordinal)
        return bounded(response, v2=v2)

    def graph_from_chain(self, chain_artifact):
        """Verify a window chain and reassemble its enriched graph.

        Slices are integrity-checked against the manifest digest before use,
        and the reassembled graph must reproduce the manifest graph digest,
        so neither a swapped base graph nor a tampered slice passes.
        """
        manifest = self.store.artifact(chain_artifact)
        require(type(manifest) is dict, "invalid_window_chain")
        require(
            manifest.get("schema_version") == "flow-window-chain/1",
            "invalid_window_chain",
        )
        for key in (
            "base_graph_artifact",
            "graph_digest",
            "head_digest",
        ):
            require(type(manifest.get(key)) is str, "invalid_window_chain")
        refs = manifest.get("slices")
        require(type(refs) is list and bool(refs), "invalid_window_chain")
        require(
            all(
                type(ref) is dict
                and type(ref.get("artifact_id")) is str
                and type(ref.get("slice_digest")) is str
                for ref in refs
            ),
            "invalid_window_chain",
        )
        base = self.graph(manifest["base_graph_artifact"])
        slices = [self.store.artifact(ref["artifact_id"]) for ref in refs]
        head = verify_window_slices(slices, manifest["graph_digest"])
        require(head == manifest["head_digest"], "Window chain head mismatch")
        for ref, body in zip(refs, slices):
            require(
                body.get("slice_digest") == ref["slice_digest"],
                "Window chain manifest mismatch",
            )
        reassembled = reassemble_graph(base, slices)
        require(
            reassembled.graph_digest == manifest["graph_digest"],
            "Window chain graph mismatch",
        )
        return reassembled

    def start(
        self,
        snapshot_artifact,
        graph_artifact,
        source,
        direction,
        request_key,
        *,
        edge_kinds=DEFAULT_EDGES,
        budget=None,
        limit=50,
        _index=None,
    ):
        require(
            budget is None or (type(budget) is int and budget >= TRACE_BUDGET_MIN),
            "invalid_trace_budget",
        )
        require(
            type(limit) is int and PAGE_LIMIT_MIN <= limit <= PAGE_LIMIT_MAX,
            "invalid_page_limit",
        )
        require(
            type(edge_kinds) in (list, tuple)
            and all(type(kind) is str for kind in edge_kinds),
            "invalid_trace_edge_filter",
        )
        require(type(source) is dict, "invalid_trace_source")
        require(
            set(source)
            == (
                {"kind", "node_id"}
                if source.get("kind") == "value"
                else {"kind", "reference"}
                if source.get("kind") == "memory"
                else set()
            ),
            "invalid_trace_source",
        )
        index = _index if _index is not None else self._trace_index(graph_artifact)
        source = {"snapshot_id": index.snapshot_id, **source}
        require(source.get("kind") in {"value", "memory"}, "invalid_trace_source")
        selected = (
            ValueSource if source["kind"] == "value" else MemorySource
        ).from_data(source)
        if isinstance(selected, ValueSource):
            require(index.contains_all({selected.node_id}), "Dangling source node")
            start = (selected.node_id,)
        else:
            # Memory content traversal requires a graph with concrete byte-memory
            # relations. Scalar-only graphs fail validation; do not infer addresses.
            start = index.memory_nodes(selected.reference)
            require(bool(start), "memory_source_has_no_graph_relation")
        spec = TraceSpec(
            snapshot_artifact,
            self.store.scope.policy_digest,
            digest(source),
            "function",
            direction,
            tuple(sorted(set(edge_kinds))),
            graph_artifact,
        )
        trace_key = digest(
            {"public_tool": "flow_trace_" + direction, "request_key": request_key}
        )
        identifier = self.store.create_trace(
            spec,
            source,
            TraceState(frontier=start, budget_remaining=budget),
            trace_key,
        )
        return self.continue_trace(
            identifier,
            0,
            trace_cursor(identifier, 0),
            digest(
                {
                    "public_tool": "flow_trace_" + direction,
                    "request_key": request_key,
                    "page": "first",
                }
            ),
            limit=limit,
            public_tool="flow_trace_" + direction,
            _index=index,
        )

    def continue_trace(
        self,
        identifier,
        revision,
        cursor,
        request_key,
        *,
        limit=50,
        cancel=False,
        additional_budget=None,
        public_tool=None,
        _index=None,
    ):
        require(
            type(limit) is int and PAGE_LIMIT_MIN <= limit <= PAGE_LIMIT_MAX,
            "invalid_page_limit",
        )
        require(cursor == trace_cursor(identifier, revision), "invalid_cursor")
        require(
            additional_budget is None
            or (type(additional_budget) is int and additional_budget >= TRACE_BUDGET_MIN),
            "invalid_trace_budget",
        )
        row = self.store.trace(identifier)
        state, spec = row["state"], row["spec"]
        request = {
            "limit": limit,
            "cursor": cursor,
            "cancel": cancel,
            **(
                {}
                if additional_budget is None
                else {"additional_budget": additional_budget}
            ),
        }
        public_tool = public_tool or (
            "flow_cancel_trace" if cancel else "flow_continue_trace"
        )
        require(
            public_tool
            in {
                "flow_trace_forward",
                "flow_trace_backward",
                "flow_continue_trace",
                "flow_cancel_trace",
            },
            "invalid_page_operation",
        )
        page_key = digest(
            {
                "public_tool": public_tool,
                "request_key": request_key,
            }
        )
        # Store checks replay before revision/terminal state. Do not advance from
        # the current frontier when an older committed request is retried.
        if row["revision"] != revision:
            return self.store.commit_page(
                identifier,
                revision,
                page_key,
                request,
                [],
                state,
                operation=public_tool,
            )
        if cancel:
            return self.store.commit_page(
                identifier,
                revision,
                page_key,
                request,
                [],
                replace(state, status="cancelled"),
                operation=public_tool,
            )
        if state.status == "budget_exceeded":
            require(
                additional_budget is not None,
                "trace_budget_extension_required",
            )
        else:
            require(additional_budget is None, "trace_budget_extension_not_required")
        index = _index if _index is not None else self._trace_index(spec.graph_artifact)
        queue, seen, emitted = (
            deque(state.frontier),
            set(state.visited),
            set(state.emitted),
        )
        queued = set(queue)
        unresolved = set(state.unresolved)
        remaining = (
            additional_budget
            if state.status == "budget_exceeded"
            else state.budget_remaining
        )
        items = []
        with index.reader() as reader:
            while (
                queue
                and (remaining is None or remaining > 0)
                and len(items) < limit
            ):
                nid = queue[0]
                if nid in seen:
                    queue.popleft()
                    queued.discard(nid)
                    continue
                node = reader.node(nid)
                relations = reader.relations(nid, spec.direction, spec.edge_kinds)
                item = {
                    "node_id": nid,
                    "kind": node.kind,
                    "edges": [
                        {"edge_id": edge.edge_id, **edge.to_data()}
                        for _, edge in relations
                    ],
                    "evidence_ids": list(node.evidence_ids),
                    "analysis": index.axes.analysis,
                }
                # Reserve envelope/cursor overhead before committing anything.
                size = len(json.dumps(items + [item])) + 1500
                if items and size > PAGE_TARGET_CHARS:
                    break
                if size > PAGE_HARD_CHARS:
                    # An indivisible high-degree node must not silently lose edges.
                    # The immutable graph can be paged separately to reconstruct
                    # the exact selected adjacency while traversal still visits all
                    # relations below.
                    item.pop("edges")
                    item["edges_externalized"] = {
                        "graph_artifact": spec.graph_artifact,
                        "graph_digest": index.graph_digest,
                        "node_id": nid,
                        "direction": spec.direction,
                        "edge_kinds": list(spec.edge_kinds),
                        "edge_count": len(relations),
                        "edge_ids_digest": digest(
                            sorted(edge.edge_id for _, edge in relations)
                        ),
                        "retrieval_tool": "flow_get_graph",
                    }
                    size = len(json.dumps(items + [item])) + 1500
                require(size <= PAGE_HARD_CHARS, "item_too_large")
                queue.popleft()
                queued.discard(nid)
                seen.add(nid)
                emitted.add(nid)
                if remaining is not None:
                    remaining -= 1
                items.append(item)
                if node.kind in {"UnknownValue", "OpaqueEffect", "Call"} or any(
                    edge.kind == "memory_data_dependency"
                    and edge.axes.precision == "opaque"
                    for _, edge in relations
                ):
                    unresolved.add(nid)
                for target, _ in relations:
                    if target not in seen and target not in queued:
                        queue.append(target)
                        queued.add(target)
        status = (
            "frontier_exhausted"
            if not queue
            else "budget_exceeded"
            if remaining == 0
            else "active"
        )
        next_state = TraceState._from_validated_progress(
            frontier=tuple(queue),
            visited=tuple(sorted(seen)),
            emitted=tuple(sorted(emitted)),
            pending=(),
            unresolved=tuple(sorted(unresolved)),
            budget_remaining=remaining,
            status=status,
        )
        return self.store.commit_page(
            identifier,
            revision,
            page_key,
            request,
            items,
            next_state,
            operation=public_tool,
        )

    def _trace_index(self, graph_artifact):
        try:
            return self.store.trace_index(graph_artifact)
        except PersistenceError as exc:
            if str(exc) != "trace_index_missing":
                raise
        graph = self.graph(graph_artifact)
        return self.store.ensure_trace_index(graph_artifact, graph)
