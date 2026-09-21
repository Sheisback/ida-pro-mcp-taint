"""Bounded immutable artifact views and durable structural graph traversal.

Traversal is reachability, not seeded taint, path feasibility, or a safety verdict.
Cursors bind the immutable artifact/filter or the durable trace revision.
"""

from dataclasses import replace
import json

from .contracts import Graph, MemorySource, ValueSource
from .persistence import PAGE_HARD_CHARS, PAGE_TARGET_CHARS, require
from .runtime_contracts import TraceSpec, TraceState
from .serialization import digest, canonical_json

DEFAULT_EDGES = ("memory_data_dependency", "phi_input", "value_dependency")


def trace_cursor(trace_id, revision):
    return digest({"trace": trace_id, "revision": revision, "version": 1})


def bounded(response):
    require(len(json.dumps(response)) <= PAGE_HARD_CHARS, "item_too_large")
    return response


def artifact_page(artifact_id, section, items, metadata, cursor=None, limit=50):
    """Stateless cursor includes offset AND immutable content/filter identity."""
    require(type(limit) is int and 1 <= limit <= 200, "invalid_page_limit")
    identity = digest({"artifact": artifact_id, "section": section, "items": items})
    offset = 0
    if cursor is not None:
        require(type(cursor) is str, "invalid_cursor")
        try:
            index, token = cursor.split("/", 1)
            offset = int(index)
        except (ValueError, TypeError):
            require(False, "invalid_cursor")
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
        if response["items"] and len(json.dumps(candidate)) > PAGE_TARGET_CHARS:
            break
        bounded(candidate)
        response = candidate
    return bounded(response)


class Queries:
    def __init__(self, store):
        self.store = store

    def graph(self, artifact_id):
        return Graph.from_data(self.store.artifact(artifact_id))

    def start(
        self,
        snapshot_artifact,
        graph_artifact,
        source,
        direction,
        request_key,
        *,
        edge_kinds=DEFAULT_EDGES,
        budget=10000,
        limit=50,
    ):
        require(type(budget) is int and 1 <= budget <= 100000, "invalid_trace_budget")
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
        graph = self.graph(graph_artifact)
        source = {"snapshot_id": graph.snapshot.snapshot_id, **source}
        require(source.get("kind") in {"value", "memory"}, "invalid_trace_source")
        selected = (
            ValueSource if source["kind"] == "value" else MemorySource
        ).from_data(source)
        graph.validate_source(selected)
        if isinstance(selected, ValueSource):
            start = (selected.node_id,)
        else:
            # Memory content traversal requires a graph with concrete byte-memory
            # relations. Scalar-only graphs fail validation; do not infer addresses.
            start = tuple(
                sorted(n.node_id for n in graph.nodes if n.memory == selected.reference)
            )
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
        public_tool=None,
    ):
        require(type(limit) is int and 1 <= limit <= 200, "invalid_page_limit")
        require(cursor == trace_cursor(identifier, revision), "invalid_cursor")
        row = self.store.trace(identifier)
        state, spec = row["state"], row["spec"]
        request = {"limit": limit, "cursor": cursor, "cancel": cancel}
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
        graph = self.graph(spec.graph_artifact)
        nodes = {node.node_id: node for node in graph.nodes}
        adjacency = {nid: [] for nid in nodes}
        for edge in graph.edges:
            if edge.kind in spec.edge_kinds:
                a, b = (
                    (edge.source, edge.target)
                    if spec.direction == "forward"
                    else (edge.target, edge.source)
                )
                adjacency[a].append((b, edge))
        queue, seen, emitted = (
            list(state.frontier),
            set(state.visited),
            set(state.emitted),
        )
        unresolved, remaining, items = set(state.unresolved), state.budget_remaining, []
        while queue and remaining and len(items) < limit:
            nid = queue[0]
            if nid in seen:
                queue.pop(0)
                continue
            node = nodes[nid]
            relations = sorted(
                adjacency[nid], key=lambda pair: (pair[0], pair[1].edge_id)
            )
            item = {
                "node_id": nid,
                "kind": node.kind,
                "edges": [
                    {"edge_id": edge.edge_id, **edge.to_data()} for _, edge in relations
                ],
                "evidence_ids": list(node.evidence_ids),
                "analysis": graph.axes.analysis,
            }
            # Reserve envelope/cursor overhead before committing anything.
            size = len(json.dumps(items + [item])) + 1500
            if items and size > PAGE_TARGET_CHARS:
                break
            require(size <= PAGE_HARD_CHARS, "item_too_large")
            queue.pop(0)
            seen.add(nid)
            emitted.add(nid)
            remaining -= 1
            items.append(item)
            if node.kind in {"UnknownValue", "OpaqueEffect", "Call"} or any(
                edge.kind == "memory_data_dependency"
                and edge.axes.precision == "opaque"
                for _, edge in relations
            ):
                unresolved.add(nid)
            for target, _ in relations:
                if target not in seen and target not in queue:
                    queue.append(target)
        status = (
            "frontier_exhausted"
            if not queue
            else "budget_exceeded"
            if remaining == 0
            else "active"
        )
        next_state = TraceState(
            tuple(queue),
            tuple(sorted(seen)),
            tuple(sorted(emitted)),
            (),
            tuple(sorted(unresolved)),
            remaining,
            status,
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


def evidence_chunks(items):
    """Large evidence remains reconstructible JSON, never a text preview."""
    chunks = []
    for item in items:
        text = canonical_json(item)
        if len(json.dumps(item)) < 8000:
            chunks.append(item)
            continue
        for offset in range(0, len(text), 1000):
            chunks.append(
                {
                    "evidence_id": item["evidence_id"],
                    "encoding": "canonical-json-text",
                    "offset": offset,
                    "length": len(text[offset : offset + 1000]),
                    "total_length": len(text),
                    "text": text[offset : offset + 1000],
                }
            )
    return chunks
