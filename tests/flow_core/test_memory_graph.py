"""Public memory graph bridge: independent store/load/range query expectations."""

from dataclasses import replace
import json
from pathlib import Path

import pytest

from ida_pro_mcp.flow_core import ContractError
import ida_pro_mcp.flow_core.memory_graph as memory_graph
from ida_pro_mcp.flow_core.contracts import Block, Instruction, Operand, Snapshot
from ida_pro_mcp.flow_core.memory import MemoryPolicy, build_memory_plan
from ida_pro_mcp.flow_core.memory_graph import (
    MemoryGraphAnalysis,
    build_memory_graph,
    replay_memory_graph,
)
from ida_pro_mcp.flow_core.persistence import PersistenceError, Store
from ida_pro_mcp.flow_core.query import Queries
from ida_pro_mcp.flow_core.serialization import canonical_json
from ida_pro_mcp.flow_core.ssa import build_ssa
from ida_pro_mcp.flow_core.states import ByteRange, StorageLocation
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


def test_stack_address_root_survives_bounded_symbolic_offset():
    source = plan(
        (
            Instruction(
                0,
                "m_mov",
                (Operand("stack_address", 64, address=8), reg(0, 64, "destination")),
            ),
            Instruction(
                1,
                "m_and",
                (reg(256, 32), const(1, 32, "right"), reg(320, 32, "destination")),
            ),
            Instruction(2, "m_xdu", (reg(320, 32), reg(384, 64, "destination"))),
            Instruction(
                3,
                "m_mul",
                (reg(384, 64), const(4, 64, "right"), reg(448, 64, "destination")),
            ),
            Instruction(
                4,
                "m_add",
                (reg(0, 64), reg(448, 64, "right"), reg(64, 64, "destination")),
            ),
            load(5, address=reg(64, 64, "right")),
            ret(6),
        )
    )
    bundle = build_memory_graph(source.program.graph.snapshot)
    target = operations(bundle, "Load")[0]
    access = next(a for a in bundle.result.accesses if a.node_id == target.node_id)
    objects = {o.object_id: o for o in bundle.result.objects}
    assert {
        (objects[c.object_id].kind, c.interval.start, c.interval.end)
        for c in access.candidates
    } == {("stack", 8, 9), ("stack", 12, 13)}
    assert access.precision == "may_alias" and not access.unresolved


def test_type_backed_entry_pointer_does_not_alias_current_private_frame():
    entry = StorageLocation("microregister", "bank", 0, 64)
    local = StorageLocation("stack", "stack", 0, 8)
    source = plan(
        (
            Instruction(
                0,
                "m_arg",
                (
                    Operand("constant", 32, constant=0, role="left"),
                    Operand(
                        "storage",
                        64,
                        storage=entry,
                        role="argument",
                        native_kind="typed_pointer_argument_argloc",
                        synthetic=True,
                    ),
                ),
                synthetic=True,
            ),
            Instruction(
                1,
                "m_mov",
                (const(7), Operand("storage", 8, storage=local, role="destination")),
            ),
            load(2),
            ret(3),
        )
    )
    bundle = build_memory_graph(source.program.graph.snapshot)
    objects = {obj.kind: obj for obj in bundle.result.objects}
    assert "typed_entry" in objects and "stack" in objects
    assert objects["typed_entry"].disjoint is False
    assert objects["stack"].disjoint is True
    loaded = operations(bundle, "Load")[-1]
    assert not any(
        edge.source in {node.node_id for node in operations(bundle, "Store")}
        and edge.target == loaded.node_id
        and edge.kind == "memory_data_dependency"
        for edge in bundle.graph.edges
    )


def test_integer_typed_argloc_cast_to_address_does_not_gain_pointer_noalias():
    entry = StorageLocation("microregister", "bank", 0, 64)
    local = StorageLocation("stack", "stack", 0, 8)
    source = plan(
        (
            Instruction(
                0,
                "m_arg",
                (
                    Operand("constant", 32, constant=0, role="left"),
                    Operand(
                        "storage",
                        64,
                        storage=entry,
                        role="argument",
                        native_kind="typed_argument_argloc",
                        synthetic=True,
                    ),
                ),
                synthetic=True,
            ),
            Instruction(
                1,
                "m_mov",
                (const(7), Operand("storage", 8, storage=local, role="destination")),
            ),
            load(2),
            ret(3),
        )
    )
    bundle = build_memory_graph(source.program.graph.snapshot)
    objects = {obj.kind for obj in bundle.result.objects}
    assert "argument" in objects and "stack" in objects
    assert "typed_entry" not in objects
    loaded = operations(bundle, "Load")[-1]
    assert any(
        edge.source in {node.node_id for node in operations(bundle, "Store")}
        and edge.target == loaded.node_id
        and edge.kind == "memory_data_dependency"
        and edge.axes.precision == "may_alias"
        for edge in bundle.graph.edges
    )


def _full_width_entry_pointer_spill_snapshot():
    spill = StorageLocation("stack", "stack", 0, 64)
    return plan(
        (
            Instruction(
                0,
                "m_mov",
                (
                    reg(0, 64),
                    Operand("storage", 64, storage=spill, role="destination"),
                ),
            ),
            Instruction(
                1,
                "m_mov",
                (Operand("storage", 64, storage=spill), reg(64, 64, "destination")),
            ),
            load(2, out=128, bits=32, address=reg(64, 64, "right")),
            ret(3, offset=128, bits=32),
        )
    ).program.graph.snapshot


def test_exact_full_width_entry_pointer_spill_recovers_pointee_abstract_object():
    bundle = build_memory_graph(_full_width_entry_pointer_spill_snapshot())
    dereference = operations(bundle, "Load")[-1]
    access = next(a for a in bundle.result.accesses if a.node_id == dereference.node_id)
    objects = {obj.object_id: obj for obj in bundle.result.objects}
    assert len(access.candidates) == 1
    assert objects[access.candidates[0].object_id].kind == "argument"
    assert not access.unresolved
    assert replay_memory_graph(bundle.program).result.dependencies == bundle.result.dependencies


def _split_entry_pointer_spill(*, typed, separate_arguments=False):
    spill = StorageLocation("stack", "stack", 0, 64)
    instructions = []
    if typed:
        markers = ((0, 0, 32), (1, 32, 32)) if separate_arguments else ((0, 0, 64),)
        for ordinal, offset, bits in markers:
            instructions.append(
                Instruction(
                    len(instructions),
                    "m_arg",
                    (
                        Operand("constant", 32, constant=ordinal, role="left"),
                        Operand(
                            "storage",
                            bits,
                            storage=StorageLocation(
                                "microregister", "bank", offset, bits
                            ),
                            role="argument",
                            native_kind=(
                                "typed_argument_argloc"
                                if separate_arguments
                                else "typed_pointer_argument_argloc"
                            ),
                            synthetic=True,
                        ),
                    ),
                    synthetic=True,
                )
            )
    instructions.extend(
        (
            Instruction(
                len(instructions),
                "m_mov",
                (reg(32, 32), reg(288, 32, "destination")),
            ),
            Instruction(
                len(instructions) + 1,
                "m_mov",
                (
                    reg(0, 64),
                    Operand("storage", 64, storage=spill, role="destination"),
                ),
            ),
            Instruction(
                len(instructions) + 2,
                "m_mov",
                (Operand("storage", 64, storage=spill), reg(64, 64, "destination")),
            ),
            load(len(instructions) + 3, out=128, bits=32, address=reg(64, 64, "right")),
            ret(len(instructions) + 4, offset=128, bits=32),
        )
    )
    return plan(tuple(instructions)).program.graph.snapshot


def test_typed_contiguous_entry_fragments_recover_exact_spilled_pointer():
    bundle = build_memory_graph(_split_entry_pointer_spill(typed=True))
    dereference = operations(bundle, "Load")[-1]
    access = next(a for a in bundle.result.accesses if a.node_id == dereference.node_id)
    objects = {obj.object_id: obj for obj in bundle.result.objects}
    assert len(access.candidates) == 1
    assert objects[access.candidates[0].object_id].kind == "typed_entry"
    assert not access.unresolved


def test_untyped_fragments_do_not_gain_private_frame_noalias_by_adjacency():
    bundle = build_memory_graph(_split_entry_pointer_spill(typed=False))
    dereference = operations(bundle, "Load")[-1]
    access = next(a for a in bundle.result.accesses if a.node_id == dereference.node_id)
    assert access.unresolved
    assert "unknown_address" in bundle.result.diagnostics


def test_two_typed_scalar_arguments_are_not_one_spilled_pointer():
    bundle = build_memory_graph(
        _split_entry_pointer_spill(typed=True, separate_arguments=True)
    )
    dereference = operations(bundle, "Load")[-1]
    access = next(a for a in bundle.result.accesses if a.node_id == dereference.node_id)
    assert access.unresolved
    assert "unknown_address" in bundle.result.diagnostics


def test_partial_spill_overwrite_does_not_recover_entry_pointer_identity():
    spill = StorageLocation("stack", "stack", 0, 64)
    upper = StorageLocation("stack", "stack", 32, 32)
    snapshot = plan(
        (
            Instruction(
                0,
                "m_mov",
                (
                    reg(0, 64),
                    Operand("storage", 64, storage=spill, role="destination"),
                ),
            ),
            Instruction(
                1,
                "m_mov",
                (
                    const(0, 32),
                    Operand("storage", 32, storage=upper, role="destination"),
                ),
            ),
            Instruction(
                2,
                "m_mov",
                (Operand("storage", 64, storage=spill), reg(64, 64, "destination")),
            ),
            load(3, out=128, bits=32, address=reg(64, 64, "right")),
            ret(4, offset=128, bits=32),
        )
    ).program.graph.snapshot
    bundle = build_memory_graph(snapshot)
    dereference = operations(bundle, "Load")[-1]
    access = next(a for a in bundle.result.accesses if a.node_id == dereference.node_id)
    assert access.unresolved
    assert not any(obj.kind == "argument" for obj in bundle.result.objects)


def test_may_alias_writer_blocks_entry_pointer_spill_recovery():
    spill = StorageLocation("stack", "stack", 0, 64)
    snapshot = plan(
        (
            Instruction(
                0,
                "m_mov",
                (
                    reg(0, 64),
                    Operand("storage", 64, storage=spill, role="destination"),
                ),
            ),
            store(1, data=const(7, 32), address=reg(192, 64, "destination")),
            Instruction(
                2,
                "m_mov",
                (Operand("storage", 64, storage=spill), reg(64, 64, "destination")),
            ),
            load(3, out=128, bits=32, address=reg(64, 64, "right")),
            ret(4, offset=128, bits=32),
        )
    ).program.graph.snapshot
    bundle = build_memory_graph(snapshot)
    dereference = operations(bundle, "Load")[-1]
    access = next(a for a in bundle.result.accesses if a.node_id == dereference.node_id)
    root = next(
        entry.node_id
        for entry in bundle.program.entry_storage
        if entry.storage.bit_offset == 0
    )
    root_fact = next(fact for fact in bundle.result.facts if fact.node_id == root)
    assert root_fact.pointer is None
    assert access.unresolved


def test_nondominating_spill_store_cannot_prove_loaded_entry_pointer():
    spill = StorageLocation("stack", "stack", 0, 64)
    write = Instruction(
        0,
        "m_mov",
        (reg(0, 64), Operand("storage", 64, storage=spill, role="destination")),
    )
    reload = Instruction(
        0,
        "m_mov",
        (Operand("storage", 64, storage=spill), reg(64, 64, "destination")),
    )
    blocks = (
        Block(0, (), ()),
        Block(1, (0,), (write,)),
        Block(2, (0,), ()),
        Block(
            3,
            (1, 2),
            (
                reload,
                load(1, out=128, bits=32, address=reg(64, 64, "right")),
                ret(2, offset=128, bits=32),
            ),
        ),
    )
    snapshot = plan((), blocks=blocks).program.graph.snapshot
    bundle = build_memory_graph(snapshot)
    root = next(
        entry.node_id
        for entry in bundle.program.entry_storage
        if entry.storage.bit_offset == 0
    )
    root_fact = next(fact for fact in bundle.result.facts if fact.node_id == root)
    assert root_fact.pointer is None


def test_recovered_pointer_is_discarded_if_final_alias_graph_breaks_proof(monkeypatch):
    spill = StorageLocation("stack", "stack", 0, 64)
    snapshot = plan(
        (
            Instruction(
                0,
                "m_mov",
                (
                    reg(0, 64),
                    Operand("storage", 64, storage=spill, role="destination"),
                ),
            ),
            Instruction(
                1,
                "m_mov",
                (Operand("storage", 64, storage=spill), reg(64, 64, "destination")),
            ),
            load(2, out=128, bits=32, address=reg(64, 64, "right")),
            ret(3, offset=128, bits=32),
        )
    ).program.graph.snapshot
    memory_plan = build_memory_plan(build_ssa(snapshot, storage_model="memory"))
    genuine = memory_graph.analyze_memory
    calls = []

    def changed_after_recovery(*args, **kwargs):
        result = genuine(*args, **kwargs)
        calls.append(result)
        return replace(result, dependencies=()) if len(calls) == 2 else result

    monkeypatch.setattr(memory_graph, "analyze_memory", changed_after_recovery)
    objects, pointers, result = memory_graph._analyze_plan(
        memory_plan, MemoryPolicy(flat_segment_assumption="test flat memory")
    )
    assert len(calls) == 2
    assert result == calls[0]
    assert not any(obj.kind == "argument" for obj in objects)
    root = next(
        entry.node_id
        for entry in memory_plan.program.entry_storage
        if entry.storage.bit_offset == 0
    )
    assert root not in {seed.node_id for seed in pointers}


def test_recovered_object_cannot_confirm_its_own_spill_proof(monkeypatch):
    memory_plan = build_memory_plan(
        build_ssa(_full_width_entry_pointer_spill_snapshot(), storage_model="memory")
    )
    genuine = memory_graph.analyze_memory
    calls = []

    def candidate_from_recovered_object(*args, **kwargs):
        result = genuine(*args, **kwargs)
        calls.append(result)
        if len(calls) != 2:
            return result
        original_ids = {obj.object_id for obj in calls[0].objects}
        recovered_id = next(
            obj.object_id for obj in result.objects if obj.object_id not in original_ids
        )
        nodes = {node.node_id: node for node in memory_plan.program.graph.nodes}
        dereference = next(
            node
            for node in nodes.values()
            if node.memory_operands is not None
            and memory_graph._whole_width_origin(
                nodes, node.memory_operands.address
            ).kind == "Load"
        )
        spill_id = memory_graph._whole_width_origin(
            nodes, dereference.memory_operands.address
        ).node_id
        accesses = tuple(
            replace(
                access,
                candidates=(replace(access.candidates[0], object_id=recovered_id),),
            )
            if access.node_id == spill_id
            else access
            for access in result.accesses
        )
        return replace(result, accesses=accesses)

    monkeypatch.setattr(memory_graph, "analyze_memory", candidate_from_recovered_object)
    objects, pointers, result = memory_graph._analyze_plan(
        memory_plan, MemoryPolicy(flat_segment_assumption="test flat memory")
    )
    assert len(calls) == 2
    assert result == calls[0]
    assert objects == calls[0].objects
    root = next(
        entry.node_id
        for entry in memory_plan.program.entry_storage
        if entry.storage.bit_offset == 0
    )
    assert root not in {seed.node_id for seed in pointers}


def test_stored_memory_graph_replays_bound_relations_not_generic_ssa_edges():
    bundle = extracted("x86_64", "memory_before_after")
    replay = replay_memory_graph(bundle.program)
    assert replay.graph == bundle.graph
    assert replay.result.dependencies == bundle.result.dependencies
    assert replay.result.objects == bundle.result.objects
    bound = next(
        edge
        for edge in bundle.graph.edges
        if edge.kind == "memory_data_dependency" and edge.memory_object_id is not None
    )
    changed = replace(
        bundle.graph, edges=tuple(edge for edge in bundle.graph.edges if edge != bound)
    )
    with pytest.raises(ContractError, match="Stored memory dependency replay mismatch"):
        replay_memory_graph(replace(bundle.program, graph=changed))


@pytest.mark.parametrize("arch", ("x86_64", "arm64"))
def test_two_anchor_before_store_after_and_alias_dependencies(arch):
    before_after = extracted(arch, "memory_before_after")
    nodes = {node.node_id: node for node in before_after.graph.nodes}
    typed_entry = {
        obj.object_id for obj in before_after.result.objects if obj.kind == "typed_entry"
    }
    assert len(typed_entry) == 1  # Refreshed IDA 9.3 IDB argloc evidence.
    loads = [
        access
        for access in before_after.result.accesses
        if nodes[access.node_id].kind == "Load"
        and bool(access.candidates)
        and {candidate.object_id for candidate in access.candidates} <= typed_entry
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
    evidence = {item.evidence_id: item for item in before_after.graph.evidence}
    assert any(
        "current IDB type register argloc is an analyst assumption"
        in evidence[evidence_id].assumptions
        for edge in reaching
        for evidence_id in edge.evidence_ids
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
