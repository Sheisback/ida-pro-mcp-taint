"""Whole-graph byte contract, including the completed database publication gate."""

import base64
import hashlib
import json
import shutil
import subprocess
import types
from dataclasses import replace

import pytest

from ida_pro_mcp.flow_core.contracts import Snapshot
from ida_pro_mcp.flow_core.persistence import Store
from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
from ida_pro_mcp.flow_core.runtime_contracts import RuntimeScope
from ida_pro_mcp.flow_core.serialization import (
    ContractError,
    canonical_json,
    digest,
    from_wire_v2,
    graph_digest_bytes_v2,
)
from ida_pro_mcp.flow_core.ssa import build_ssa
from test_flow_capabilities import ROOT, flow as flow_fixture  # noqa: F401


@pytest.fixture
def export_graph(flow_fixture, monkeypatch, tmp_path):  # noqa: F811
    module, _ = flow_fixture
    snapshot = Snapshot.from_data(
        json.loads(
            (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
        )["snapshot"]
    )
    graph = build_ssa(snapshot).graph
    identity = snapshot.identity
    scope = RuntimeScope(
        identity.namespace,
        identity.semantic_digest,
        identity.binary_digest,
        identity.profile_digest,
        identity.rule_digest,
        identity.summary_digest,
        identity.policy_digest,
    )
    store = Store(
        tmp_path / "graph-store", scope, "graph-export-owner-secret-0001-long"
    )
    monkeypatch.setattr(
        module._service(), "get_runtime", lambda: types.SimpleNamespace(store=store)
    )
    artifact = store.put_artifact("graph", graph)
    job = store.create_job("snapshot_ssa_v1", {}, "graph-export")
    store.transition_job(job, "queued", "extracting")
    store.transition_job(job, "extracting", "analyzing")
    store.transition_job(job, "analyzing", "committing")
    yield module, store, graph, artifact, job
    store.close()


def publish(store, job, artifact):
    store.transition_job(
        job, "committing", "complete", result={"graph_artifact": artifact}
    )


def collect(module, artifact):
    pages = []
    cursor = None
    while True:
        page = module.flow_get_graph_digest_bytes(artifact, cursor)
        assert page["schema_version"] == "flow-graph-bytes/1", page
        pages.append(page)
        cursor = page["next_cursor"]
        if cursor is None:
            return pages


def verify(pages):
    """Consumer validation must reject incomplete, reordered or mixed exports."""
    binding_keys = (
        "artifact_id",
        "snapshot_id",
        "graph_digest",
        "identity_version",
        "build_id",
        "total_bytes",
    )
    binding = {key: pages[0][key] for key in binding_keys}
    payload = b""
    for index, page in enumerate(pages):
        assert {key: page[key] for key in binding_keys} == binding
        assert page["offset"] == len(payload)
        chunk = base64.urlsafe_b64decode(page["chunk_base64url"] + "===")
        assert len(chunk) == page["byte_count"]
        assert (page["next_cursor"] is None) == (index == len(pages) - 1)
        payload += chunk
    assert len(payload) == binding["total_bytes"]
    assert "sha256-v1:" + hashlib.sha256(payload).hexdigest() == binding["graph_digest"]
    return payload


def test_v2_graph_export_has_lossless_large_ea_and_matching_digest(
    export_graph, monkeypatch
):
    module, store, original, _, _ = export_graph
    large_ea = (1 << 53) + 1
    function = original.snapshot.function
    block = function.blocks[1]
    instruction = block.instructions[0]
    instruction = replace(
        instruction,
        source_eas=tuple(sorted(set(instruction.source_eas) | {large_ea})),
    )
    block = replace(block, instructions=(instruction,) + block.instructions[1:])
    function = replace(
        function, blocks=(function.blocks[0], block) + function.blocks[2:]
    )
    identity = replace(
        original.snapshot.identity,
        input_digest=digest(function),
        wire_version="flow-wire/2",
    )
    snapshot = Snapshot(identity, function, identity.snapshot_id)
    graph = build_ssa(snapshot).graph
    artifact = store.put_artifact("graph", graph)
    job = store.create_job("snapshot_ssa_v1", {}, "v2-graph-export")
    store.transition_job(job, "queued", "extracting")
    store.transition_job(job, "extracting", "analyzing")
    store.transition_job(job, "analyzing", "committing")
    publish(store, job, artifact)

    pages = collect(module, artifact)
    payload = b"".join(
        base64.urlsafe_b64decode(page["chunk_base64url"] + "===") for page in pages
    )
    assert payload == graph_digest_bytes_v2(graph)
    assert pages[0]["identity_version"] == 2
    assert pages[0]["graph_digest"] == graph.graph_digest
    assert graph.graph_digest == "sha256-v2:" + hashlib.sha256(payload).hexdigest()
    wrapper = json.loads(payload)
    assert wrapper["value"]["snapshot"]["function"]["blocks"][1]["instructions"][0][
        "source_eas"
    ][-1] == {"$int": str(large_ea)}
    assert from_wire_v2(wrapper["value"]) == graph.to_data()

    page = module.flow_get_graph(artifact, limit=1)
    assert page["metadata"]["wire_version"] == "flow-wire/2"
    assert page["metadata"]["environment"]["bitness"] == {"$int": "64"}
    assert page["next_cursor"] is not None
    assert module.flow_get_graph(artifact, page["next_cursor"], 1)["items"]
    ssa_artifact = store.put_artifact("analysis", build_ssa(snapshot).to_data())
    assert (
        module.flow_get_function_ssa(ssa_artifact, limit=1)["metadata"]["wire_version"]
        == "flow-wire/2"
    )
    evidence = module.flow_get_evidence(artifact)
    assert evidence["metadata"]["wire_version"] == "flow-wire/2"
    assert any(
        {"$int": str(large_ea)} in item.get("source_eas", [])
        for item in evidence["items"]
    )
    memory = build_memory_graph(snapshot)
    memory_artifact = store.put_artifact("analysis", memory.result.to_data())
    assert (
        module.flow_get_memory_analysis(memory_artifact, limit=1)["metadata"][
            "wire_version"
        ]
        == "flow-wire/2"
    )
    snapshot_artifact = store.put_artifact("snapshot", snapshot)
    trace_edge = graph.edges[0]
    trace = module.flow_trace_backward(
        snapshot_artifact,
        artifact,
        {"kind": "value", "node_id": trace_edge.target},
        "v2-trace",
        edge_kinds=[trace_edge.kind],
        limit=1,
    )
    assert trace["wire_version"] == "flow-wire/2", trace
    assert trace["revision"] == {"$int": "1"}
    assert trace["snapshot_id"] == snapshot.snapshot_id
    next_trace = module.flow_continue_trace(
        trace["trace_id"], trace["revision"], trace["cursor"], "v2-trace-next", 1
    )
    assert "revision" in next_trace, next_trace
    assert next_trace["revision"] == {"$int": "2"}, next_trace
    result_job = store.create_job("snapshot_ssa_v1", {}, "v2-status")
    store.transition_job(result_job, "queued", "extracting")
    store.transition_job(result_job, "extracting", "analyzing")
    store.transition_job(result_job, "analyzing", "committing")
    store.transition_job(
        result_job,
        "committing",
        "complete",
        result={"snapshot_id": snapshot.snapshot_id, "ea": large_ea},
    )
    monkeypatch.setattr(
        module._service(),
        "get_runtime",
        lambda: types.SimpleNamespace(store=store, status=store.job),
    )
    job_view = module.flow_get_job(result_job)
    assert "revision" in job_view, job_view
    assert job_view["revision"] == {"$int": "4"}
    assert job_view["result"]["ea"] == {"$int": str(large_ea)}
    legacy_identity = replace(identity, wire_version="flow-wire/1")
    legacy_snapshot = Snapshot(legacy_identity, function, legacy_identity.snapshot_id)
    legacy_graph = build_ssa(legacy_snapshot).graph
    legacy_artifact = store.put_artifact("graph", legacy_graph)
    assert (
        module.flow_get_graph(legacy_artifact, page["next_cursor"], 1)["error"]["code"]
        == "invalid_cursor"
    )
    assert module.flow_get_evidence(legacy_artifact)["error"]["code"] == (
        "unsafe_integer_for_wire_v1"
    )
    if pages[0]["next_cursor"] is not None:
        assert (
            module.flow_get_graph_digest_bytes(artifact, pages[0]["next_cursor"])[
                "offset"
            ]
            > 0
        )


def test_graph_bytes_reassembly_and_consumer_tamper_detection(
    export_graph, monkeypatch
):
    module, store, graph, artifact, job = export_graph
    publish(store, job, artifact)
    # Small chunks exercise page boundaries even for a compact graph.
    monkeypatch.setattr(module._service(), "GRAPH_EXPORT_CHUNK_BYTES", 256)
    pages = collect(module, artifact)
    assert len(pages) > 2
    payload = verify(pages)
    assert payload == canonical_json(graph).encode("utf-8")
    assert json.loads(payload)["snapshot"]["snapshot_id"] == graph.snapshot.snapshot_id
    for broken in (pages[:-1], pages[1:], [pages[0], *pages], list(reversed(pages))):
        with pytest.raises(AssertionError):
            verify(broken)
    changed = [dict(page) for page in pages]
    chunk = base64.urlsafe_b64decode(changed[0]["chunk_base64url"] + "===")
    changed[0]["chunk_base64url"] = base64.urlsafe_b64encode(
        bytes([chunk[0] ^ 1]) + chunk[1:]
    ).decode()
    with pytest.raises(AssertionError):
        verify(changed)
    other = [dict(page) for page in pages]
    other[1]["artifact_id"] = "other-graph"
    with pytest.raises(AssertionError):
        verify(other)


def test_graph_bytes_publication_and_database_gate(export_graph, tmp_path):
    module, store, graph, artifact, job = export_graph
    assert (
        module.flow_get_graph_digest_bytes(artifact)["error"]["code"]
        == "graph_artifact_not_complete"
    )
    wrong_kind = store.put_artifact("analysis", graph.to_data())
    assert (
        module.flow_get_graph_digest_bytes(wrong_kind)["error"]["code"]
        == "wrong_artifact_kind"
    )
    assert (
        module.flow_get_graph_digest_bytes("artifact_missing")["error"]["code"]
        == "wrong_database_or_unknown_id"
    )
    publish(store, job, artifact)
    assert (
        module.flow_get_graph_digest_bytes(artifact)["schema_version"]
        == "flow-graph-bytes/1"
    )
    foreign = Store(
        tmp_path / "foreign-store",
        replace(store.scope, namespace="foreign-database"),
        "foreign-graph-owner-secret-0001-long",
    )
    try:
        with pytest.raises(ContractError, match="wrong_database_or_unknown_id"):
            foreign.completed_graph_artifact(artifact)
    finally:
        foreign.close()


def test_graph_bytes_cursor_and_size_limits(export_graph, monkeypatch):
    module, store, graph, artifact, job = export_graph
    publish(store, job, artifact)
    service = module._service()
    length = len(canonical_json(graph).encode("utf-8"))
    monkeypatch.setattr(service, "GRAPH_EXPORT_CHUNK_BYTES", 256)
    first = service.graph_digest_bytes(artifact)
    assert first["byte_count"] == 256
    cursor = first["next_cursor"]
    assert service.graph_digest_bytes(artifact, cursor)["offset"] == 256
    for malformed in (
        "bad",
        cursor.replace("256/", "257/"),
        "0/" + cursor.split("/")[1],
        True,
    ):
        with pytest.raises(ContractError, match="invalid_cursor"):
            service.graph_digest_bytes(artifact, malformed)
    other = store.put_artifact("graph", graph)
    other_job = store.create_job("snapshot_ssa_v1", {}, "other")
    for before, after in (
        ("queued", "extracting"),
        ("extracting", "analyzing"),
        ("analyzing", "committing"),
    ):
        store.transition_job(other_job, before, after)
    publish(store, other_job, other)
    with pytest.raises(ContractError, match="invalid_cursor"):
        service.graph_digest_bytes(other, cursor)
    monkeypatch.setattr(service, "GRAPH_EXPORT_MAX_BYTES", length)
    assert verify(collect(module, artifact)) == canonical_json(graph).encode("utf-8")
    monkeypatch.setattr(service, "GRAPH_EXPORT_MAX_BYTES", length - 1)
    assert (
        module.flow_get_graph_digest_bytes(artifact)["error"]["code"]
        == "graph_export_too_large"
    )
    monkeypatch.setattr(service, "GRAPH_EXPORT_MAX_BYTES", length)
    monkeypatch.setattr(service, "GRAPH_EXPORT_MAX_PAGES", 1)
    assert (
        module.flow_get_graph_digest_bytes(artifact)["error"]["code"]
        == "graph_export_too_large"
    )
    monkeypatch.setattr(service, "GRAPH_EXPORT_MAX_PAGES", 1024)
    monkeypatch.setattr(service, "GRAPH_EXPORT_RESPONSE_BYTES", 1)
    assert (
        module.flow_get_graph_digest_bytes(artifact)["error"]["code"]
        == "graph_export_too_large"
    )


def test_graph_bytes_javascript_digest(export_graph):
    module, store, graph, artifact, job = export_graph
    publish(store, job, artifact)
    pages = collect(module, artifact)
    payload = verify(pages)
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js required for independent consumer digest")
    script = "const fs=require('fs'),crypto=require('crypto');const p=JSON.parse(fs.readFileSync(0,'utf8'));const b=Buffer.concat(p.map(x=>Buffer.from(x.chunk_base64url,'base64url')));process.stdout.write(crypto.createHash('sha256').update(b).digest('hex'));"
    result = subprocess.run(
        [node, "-e", script],
        input=json.dumps(pages),
        text=True,
        capture_output=True,
        check=True,
    )
    assert result.stdout == hashlib.sha256(payload).hexdigest()
