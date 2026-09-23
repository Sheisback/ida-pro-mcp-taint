"""Public memory graph bridge: independent store/load/range query expectations."""

from dataclasses import replace
import json
from pathlib import Path

import pytest

from ida_pro_mcp.flow_core import ContractError
from ida_pro_mcp.flow_core.contracts import Instruction, Snapshot
from ida_pro_mcp.flow_core.memory_graph import (
    MemoryGraphAnalysis,
    build_memory_graph,
)
from ida_pro_mcp.flow_core.persistence import PersistenceError, Store
from ida_pro_mcp.flow_core.query import Queries
from ida_pro_mcp.flow_core.serialization import canonical_json
from ida_pro_mcp.flow_core.states import ByteRange
from test_memory import const, load, plan, reg, ret, store
from test_persistence import OWNER, scope_of

ROOT = Path(__file__).resolve().parents[2]


def extracted(arch, function):
    raw = json.loads(
        (
            ROOT / f"tests/flow_fixtures/manifests/memory/{arch}_{function}.json"
        ).read_text()
    )
    return build_memory_graph(Snapshot.from_data(raw["snapshot"]))


def memory_edges(bundle):
    return [
        edge
        for edge in bundle.graph.edges
        if edge.kind == "memory_data_dependency" and edge.interval is not None
    ]


def operations(bundle, kind):
    definitions = {
        definition.node_id: definition for definition in bundle.program.definitions
    }
    return sorted(
        (node for node in bundle.graph.nodes if node.kind == kind),
        key=lambda node: (
            definitions[node.node_id].block,
            definitions[node.node_id].order,
        ),
    )


@pytest.mark.parametrize("arch", ("x86_64", "arm64"))
def test_two_anchor_before_store_after_and_alias_dependencies(arch):
    before_after = extracted(arch, "memory_before_after")
    nodes = {node.node_id: node for node in before_after.graph.nodes}
    argument = {
        obj.object_id for obj in before_after.result.objects if obj.kind == "argument"
    }
    loads = [
        access
        for access in before_after.result.accesses
        if nodes[access.node_id].kind == "Load"
        and {candidate.object_id for candidate in access.candidates} <= argument
    ]
    definitions = {
        definition.node_id: definition
        for definition in before_after.program.definitions
    }
    loads.sort(key=lambda access: definitions[access.node_id].order)
    assert len(loads) == 2
    reaching = [
        edge for edge in memory_edges(before_after) if edge.target == loads[1].node_id
    ]
    assert any(
        edge.interval == ByteRange(0, 1)
        and edge.axes.precision == "exact"
        and edge.source != loads[0].node_id
        for edge in reaching
    )
    assert all(edge.target != loads[0].node_id for edge in memory_edges(before_after))

    alias = extracted(arch, "memory_alias")
    nodes = {node.node_id: node for node in alias.graph.nodes}
    relation = next(
        edge
        for edge in memory_edges(alias)
        if nodes[edge.source].kind == "Store"
        and nodes[edge.target].kind == "Load"
        and edge.interval == ByteRange(0, 1)
        and edge.axes.precision == "exact"
    )
    assert relation.source != relation.target
    assert relation.memory_object_id is not None
    assert relation.memory_rule_id == "byte-reaching-store-v1"
    derivation = next(
        evidence
        for evidence in alias.graph.evidence
        if evidence.rule_id == relation.memory_rule_id
        and set(evidence.origins) == {relation.source, relation.target}
    )
    assert derivation.evidence_id in relation.evidence_ids
    assert any("flat user-space" in item for item in derivation.assumptions)


def test_partial_byte_and_pointer_copy_edges_are_public_and_precise():
    partial_snapshot = plan(
        (store(0, const(0x12)), load(1, bits=16), ret(2, bits=16))
    ).program.graph.snapshot
    partial = build_memory_graph(partial_snapshot)
    store_node = operations(partial, "Store")[0]
    load_node = operations(partial, "Load")[0]
    relation = next(
        edge
        for edge in memory_edges(partial)
        if edge.source == store_node.node_id and edge.target == load_node.node_id
    )
    assert relation.interval == ByteRange(0, 1) and relation.width_bits == 8
    assert relation.interval != ByteRange(1, 2)

    alias_snapshot = plan(
        (
            Instruction(0, "m_mov", (reg(), reg(64, 64, "destination"))),
            store(1, reg(192, 8), reg(64, 64, "destination")),
            load(2),
            ret(3),
        )
    ).program.graph.snapshot
    alias = build_memory_graph(alias_snapshot)
    store_node = operations(alias, "Store")[0]
    load_node = operations(alias, "Load")[0]
    assert any(
        edge.source == store_node.node_id
        and edge.target == load_node.node_id
        and edge.axes.precision == "exact"
        for edge in memory_edges(alias)
    )


def test_unknown_cross_object_relation_is_may_alias_not_exact():
    for arch in ("x86_64", "arm64"):
        bundle = extracted(arch, "memory_global_roundtrip")
        assert any(edge.axes.precision == "may_alias" for edge in memory_edges(bundle))
        # Completion of the modeled computation does not promote an uncertain
        # relation to must-alias; edge precision carries that uncertainty.
        assert bundle.result.status == "complete_in_scope"
        assert "partial_scalar_input" not in bundle.result.diagnostics


@pytest.mark.parametrize("extension", ("m_xdu", "m_xds"))
def test_width_changing_pointer_cast_never_preserves_exact_alias(extension):
    snapshot = plan(
        (
            store(0, const(7)),
            Instruction(1, "m_low", (reg(), reg(64, 32, "destination"))),
            Instruction(2, extension, (reg(64, 32), reg(96, 64, "destination"))),
            store(3, const(0), reg(96, 64, "destination")),
            load(4),
            ret(5),
        )
    ).program.graph.snapshot
    bundle = build_memory_graph(snapshot)
    stores = operations(bundle, "Store")
    loaded = operations(bundle, "Load")[-1]
    incoming = [
        edge
        for edge in memory_edges(bundle)
        if edge.target == loaded.node_id
        and edge.source in {node.node_id for node in stores}
    ]
    assert {edge.source for edge in incoming} == {node.node_id for node in stores}
    assert any(edge.axes.precision != "exact" for edge in incoming)
    fact = next(fact for fact in bundle.result.facts if fact.node_id == loaded.node_id)
    assert fact.value.value is None and bundle.result.status == "partial"


def test_loaded_pointer_dereference_remains_partial_instead_of_being_seeded():
    snapshot = plan(
        (
            load(0, out=64, bits=64),
            load(1, address=reg(64, 64, "right")),
            ret(2),
        )
    ).program.graph.snapshot
    bundle = build_memory_graph(snapshot)
    second = operations(bundle, "Load")[-1]
    access = next(
        access for access in bundle.result.accesses if access.node_id == second.node_id
    )
    assert access.unresolved
    assert bundle.result.status == "partial"
    assert "unknown_address" in bundle.result.diagnostics


def test_memory_source_query_traverses_reaching_store_and_roundtrips(tmp_path):
    bundle = extracted("x86_64", "memory_alias")
    assert MemoryGraphAnalysis.from_json(canonical_json(bundle)) == bundle
    store = Store(tmp_path / "memory-graph", scope_of(bundle.graph.snapshot), OWNER)
    try:
        sid = store.put_artifact("snapshot", bundle.graph.snapshot)
        gid = store.put_artifact("graph", bundle.graph)
        nodes = {node.node_id: node for node in bundle.graph.nodes}
        relation = next(
            edge
            for edge in memory_edges(bundle)
            if nodes[edge.source].kind == "Store"
            and nodes[edge.target].kind == "Load"
            and edge.axes.precision == "exact"
        )
        load_node = nodes[relation.target]
        store_node = nodes[relation.source]
        step = next(
            step for step in bundle.plan.steps if step.node_id == store_node.node_id
        )
        assert store_node.memory.version_id == step.after
        assert store_node.memory.version_id != step.before
        page = Queries(store).start(
            sid,
            gid,
            {"kind": "memory", "reference": load_node.memory.to_data()},
            "backward",
            "memory-backward",
            limit=200,
        )
        assert store_node.node_id in {item["node_id"] for item in page["items"]}
        assert any(
            edge["kind"] == "memory_data_dependency"
            and edge["interval"] == {"start": 0, "end": 1}
            for item in page["items"]
            for edge in item["edges"]
        )
        pre_store = replace(store_node.memory, version_id=step.before)
        with pytest.raises(
            PersistenceError, match="memory_source_has_no_graph_relation"
        ):
            Queries(store).start(
                sid,
                gid,
                {"kind": "memory", "reference": pre_store.to_data()},
                "forward",
                "pre-store-version",
            )
    finally:
        store.close()


def test_memory_edge_derivation_evidence_is_tamper_evident():
    bundle = extracted("x86_64", "memory_alias")
    nodes = {node.node_id: node for node in bundle.graph.nodes}
    relation = next(
        edge
        for edge in memory_edges(bundle)
        if nodes[edge.source].kind == "Store"
        and nodes[edge.target].kind == "Load"
        and edge.memory_object_id is not None
    )

    def forged(edge, evidence=bundle.graph.evidence):
        edges = [
            item for item in bundle.graph.edges if item.edge_id != relation.edge_id
        ]
        edges.append(edge)
        return replace(
            bundle.graph,
            edges=tuple(sorted(edges, key=lambda item: item.edge_id)),
            evidence=evidence,
        )

    with pytest.raises(ContractError, match="Missing memory derivation evidence"):
        forged(replace(relation, memory_rule_id="forged-memory-rule"))
    other = next(
        obj.object_id
        for obj in bundle.graph.objects
        if obj.object_id != relation.memory_object_id
    )
    with pytest.raises(ContractError, match="Missing memory derivation evidence"):
        forged(replace(relation, memory_object_id=other))
    derivation_ids = {
        evidence.evidence_id
        for evidence in bundle.graph.evidence
        if evidence.rule_id == relation.memory_rule_id
        and evidence.memory_object_id == relation.memory_object_id
        and evidence.origins == tuple(sorted((relation.source, relation.target)))
    }
    with pytest.raises(ContractError, match="Dangling edge evidence"):
        forged(
            relation,
            tuple(
                evidence
                for evidence in bundle.graph.evidence
                if evidence.evidence_id not in derivation_ids
            ),
        )
    with pytest.raises(ContractError, match="Memory edge width/range mismatch"):
        forged(replace(relation, width_bits=relation.width_bits + 8))
