"""Regression coverage for reviewed wire and cross-artifact boundaries."""

from dataclasses import replace
import json

import pytest

from ida_pro_mcp.flow_core.contracts import Snapshot
from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
from ida_pro_mcp.flow_core.path_conditions import PathSelector, path_bindings
from ida_pro_mcp.flow_core.refine import (
    RefinementSpec,
    refine_memory_proof,
    run_memory_refinement,
)
from ida_pro_mcp.flow_core.serialization import (
    ContractError,
    canonical_json,
    digest,
    ensure_wire_v1_safe,
    from_wire_v2,
)
from test_flow_capabilities import flow as flow_fixture  # noqa: F401
from test_flow_pointee_store import harness, memory_fixture  # noqa: F401


def changed_memory(memory, value):
    snapshot = memory.graph.snapshot
    block = snapshot.function.blocks[0]
    instruction = block.instructions[0]
    operand = replace(instruction.operands[0], constant=value)
    instruction = replace(
        instruction, operands=(operand,) + instruction.operands[1:]
    )
    block = replace(block, instructions=(instruction,) + block.instructions[1:])
    function = replace(snapshot.function, blocks=(block,))
    identity = replace(snapshot.identity, input_digest=digest(function))
    return build_memory_graph(Snapshot(identity, function, identity.snapshot_id))


def access_ids(memory):
    nodes = memory.graph.nodes
    return (
        next(node.node_id for node in nodes if node.kind == "Load"),
        next(node.node_id for node in nodes if node.kind == "Store"),
    )


@pytest.mark.parametrize("tool", ["flow_get_graph", "flow_get_function_ssa"])
def test_v2_wide_constant_retains_tagged_integer(harness, tool):  # noqa: F811
    module, _, store, _, _ = harness
    memory, _ = memory_fixture(v2=True)
    # The stored value is 32 bits in this fixture; widen it and the Store.
    snapshot = memory.graph.snapshot
    block = snapshot.function.blocks[0]
    instruction = block.instructions[0]
    wide = (1 << 64) - 2
    operand = replace(instruction.operands[0], width_bits=64, constant=wide)
    instruction = replace(
        instruction, operands=(operand,) + instruction.operands[1:]
    )
    function = replace(
        snapshot.function,
        blocks=(replace(block, instructions=(instruction,) + block.instructions[1:]),),
    )
    identity = replace(snapshot.identity, input_digest=digest(function))
    memory = build_memory_graph(Snapshot(identity, function, identity.snapshot_id))
    artifact = (
        store.put_artifact("graph", memory.graph)
        if tool == "flow_get_graph"
        else store.put_artifact("analysis", memory.program.to_data())
    )
    page = getattr(module, tool)(artifact, limit=100)
    constants = [item for item in page["items"] if item.get("kind") == "Constant"]
    node = next(item for item in constants if item["width_bits"] == {"$int": "64"})
    assert node["constant"] == {"$int": str(wide)}
    assert "constant_hex" not in node
    assert from_wire_v2(node)["constant"] == wide


@pytest.mark.parametrize("padding", [0, 7700, 8000])
def test_v1_wide_analysis_item_is_lossless_independent_of_size(harness, padding):  # noqa: F811
    _, service, _, _, _ = harness
    item = {
        "type": "call_binding",
        "spoiled_locations": {"memory": [{"start": 0, "end": (1 << 64) - 1}]},
        "description": "x" * padding,
    }
    chunks = service._chunk_large_items("interprocedural", [item])
    ensure_wire_v1_safe(chunks)
    assert all(chunk["type"] == "canonical_json_chunk" for chunk in chunks)
    text = "".join(chunk["text"] for chunk in chunks)
    assert text.encode("utf-8") == canonical_json(item).encode("utf-8")
    assert json.loads(text) == item


def test_safe_analysis_item_remains_unchunked(harness):  # noqa: F811
    _, service, _, _, _ = harness
    item = {"type": "call_binding", "value": 42}
    assert service._chunk_large_items("interprocedural", [item]) == [item]


def test_memory_refinement_accepts_genuine_enriched_program():
    memory, _ = memory_fixture()
    assert memory.program != memory.plan.program
    load_id, store_id = access_ids(memory)
    artifact = refine_memory_proof(
        memory.plan, memory.graph, memory.result,
        PathSelector(path_bindings(memory.graph), (0,)),
        load_id, store_id, RefinementSpec(),
    )
    assert artifact["baseline"]["result_digest"] == digest(memory.result)


@pytest.mark.parametrize("tamper", ["foreign", "graph", "missing_access"])
def test_memory_refinement_rejects_unbound_evidence(tamper):
    memory, _ = memory_fixture()
    load_id, store_id = access_ids(memory)
    graph, plan, result = memory.graph, memory.plan, memory.result
    if tamper == "foreign":
        other = changed_memory(memory, 1)
        plan, result = other.plan, other.result
    elif tamper == "graph":
        precision = "exact" if graph.axes.precision != "exact" else "opaque"
        graph = replace(graph, axes=replace(graph.axes, precision=precision))
        assert graph != memory.graph
    else:
        result = replace(result, accesses=tuple(
            access for access in result.accesses if access.node_id != load_id
        ))
    with pytest.raises(ContractError):
        refine_memory_proof(
            plan, graph, result, PathSelector(path_bindings(graph), (0,)),
            load_id, store_id, RefinementSpec(),
        )


def test_public_memory_refinement_refuses_foreign_plan_before_submission(harness):  # noqa: F811
    module, _, store, submitted, _ = harness
    memory, _ = memory_fixture()
    other = changed_memory(memory, 1)
    load_id, store_id = access_ids(memory)
    response = module.flow_refine_memory_proof(
        ssa_artifact=store.put_artifact("analysis", memory.program.to_data()),
        memory_plan_artifact=store.put_artifact("analysis", other.plan.to_data()),
        memory_result_artifact=store.put_artifact("analysis", other.result.to_data()),
        path=PathSelector(path_bindings(memory.graph), (0,)).to_data(),
        load_id=load_id, store_id=store_id,
        refinement=RefinementSpec().to_data(), request_key="foreign-memory",
    )
    assert response["schema_version"] == "flow-error/1"
    assert not submitted


@pytest.mark.parametrize("foreign", ["plan", "graph"])
def test_memory_job_runner_rechecks_program_ownership(harness, foreign):  # noqa: F811
    _, _, store, _, _ = harness
    memory, _ = memory_fixture()
    other = changed_memory(memory, 1)
    load_id, store_id = access_ids(memory)
    selected = other if foreign == "plan" else memory
    request = {
        "ssa_artifact": store.put_artifact("analysis", memory.program.to_data()),
        "memory_plan_artifact": store.put_artifact("analysis", selected.plan.to_data()),
        "memory_result_artifact": store.put_artifact("analysis", selected.result.to_data()),
        "path": PathSelector(path_bindings(memory.graph), (0,)).to_data(),
        "load_id": load_id, "store_id": store_id,
        "refinement": RefinementSpec().to_data(),
    }
    if foreign == "graph":
        request["graph_artifact"] = store.put_artifact("graph", other.graph)
    with pytest.raises(ContractError):
        run_memory_refinement(store, request)


def test_public_memory_refinement_accepts_and_replays_enriched_artifacts(harness):  # noqa: F811
    module, _, store, submitted, _ = harness
    memory, _ = memory_fixture()
    load_id, store_id = access_ids(memory)
    response = module.flow_refine_memory_proof(
        ssa_artifact=store.put_artifact("analysis", memory.program.to_data()),
        memory_plan_artifact=store.put_artifact("analysis", memory.plan.to_data()),
        memory_result_artifact=store.put_artifact("analysis", memory.result.to_data()),
        path=PathSelector(path_bindings(memory.graph), (0,)).to_data(),
        load_id=load_id, store_id=store_id,
        refinement=RefinementSpec().to_data(), request_key="bound-memory",
    )
    assert response["schema_version"] == "flow-job/1"
    result = run_memory_refinement(store, submitted[0][1])
    artifact = store.artifact(result["refined_memory_proof_artifact"])
    assert artifact["baseline"]["result_digest"] == digest(memory.result)
