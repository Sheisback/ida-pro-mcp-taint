"""A08: default refinement equals v1; angr tier is explicit opt-in only."""

import sys
from dataclasses import replace

import pytest

from ida_pro_mcp.flow_core.angr_client import (
    AngrContext,
    AngrSidecar,
    build_prefix_query,
)
from ida_pro_mcp.flow_core.contracts import Block, Instruction, Operand
from ida_pro_mcp.flow_core.path_conditions import (
    PathSelector,
    path_bindings,
    prove_path,
)
from ida_pro_mcp.flow_core.proof import validate_proof_result
from ida_pro_mcp.flow_core.refine import (
    RefinementSpec,
    check_refined_memory_artifact,
    check_refined_path_artifact,
    refine_memory_proof,
    refine_path_proof,
    refinement_agreement,
)
from ida_pro_mcp.flow_core.serialization import (
    ContractError,
    digest,
    ensure_wire_v1_safe,
)
from ida_pro_mcp.flow_core.ssa import build_ssa
from test_memory import load as mem_load
from test_memory import obj, plan as mem_plan, ptrseed, run, store as mem_store
from test_ssa import const, ins, reg, snapshot

DIGEST = "sha256-v1:" + "ab" * 32

FEASIBLE_ANGR = "feasible_angr_v1"
INFEASIBLE_ANGR = "infeasible_angr_v1"


def branch_graph(left=None, *, bits=8, opcode="m_jz"):
    left = left if left is not None else const(3, bits=bits)
    return build_ssa(
        snapshot(
            (
                Block(
                    0,
                    (),
                    (
                        ins(
                            0,
                            opcode,
                            left,
                            const(3, bits=bits, role="right"),
                            Operand("block", None, block_index=1, role="destination"),
                        ),
                    ),
                ),
                Block(1, (0,), ()),
                Block(2, (0,), ()),
            )
        )
    ).graph


def vanishing_graph():
    # (x ^ x) == 1 never holds; v1 cannot see through the xor.
    return build_ssa(
        snapshot(
            (
                Block(
                    0,
                    (),
                    (
                        ins(0, "m_xor", reg(bits=32), reg(bits=32, role="right"),
                            reg(64, 32, "destination")),
                        ins(
                            1,
                            "m_jz",
                            reg(64, 32),
                            const(1, bits=32, role="right"),
                            Operand("block", None, block_index=1, role="destination"),
                        ),
                    ),
                ),
                Block(1, (0,), ()),
                Block(2, (0,), ()),
            )
        )
    ).graph


def addressed(blocks, base=0x401000):
    """Attach ascending synthetic EAs so a prefix query is buildable."""
    out = []
    ea = base
    for block in blocks:
        instructions = block.instructions or (Instruction(0, "m_nop", ()),)
        patched = []
        for instruction in instructions:
            patched.append(replace(instruction, source_eas=(ea,)))
            ea += 1
        out.append(Block(block.index, block.predecessors, tuple(patched)))
    return snapshot(tuple(out))


def angr_branch_graph():
    """(x ^ x) == 1 never holds, but v1 cannot see through the xor."""
    return build_ssa(
        addressed(
            (
                Block(
                    0,
                    (),
                    (
                        ins(0, "m_xor", reg(bits=32), reg(bits=32, role="right"),
                            reg(64, 32, "destination")),
                        ins(
                            1,
                            "m_jz",
                            reg(64, 32),
                            const(1, bits=32, role="right"),
                            Operand("block", None, block_index=1, role="destination"),
                        ),
                    ),
                ),
                Block(1, (0,), ()),
                Block(2, (0,), ()),
            )
        )
    ).graph


def access_ids(memory_plan, graph):
    nodes = {n.node_id: n for n in graph.nodes}
    stores = [s.node_id for s in memory_plan.steps if nodes[s.node_id].kind == "Store"]
    loads = [s.node_id for s in memory_plan.steps if nodes[s.node_id].kind == "Load"]
    return stores, loads


def write_runner(tmp_path, status, witness=(), unresolved=()):
    target = tmp_path / f"fake_runner_{status}.py"
    target.write_text(
        "import json, sys\n"
        f"request = json.loads(open(sys.argv[1]).read())\n"
        "assert request['schema_version'] == 1, request\n"
        "assert request['find_eas'], request\n"
        f"json.dump({{'status': {status!r}, 'witness': list({witness!r}), "
        "'engine': {'name': 'angr-sidecar', "
        "'runner_version': 'flow-angr-runner/1', "
        "'angr_version': '9.2.213', 'z3_version': '4.13.0', "
        "'simprocedures': [], 'loop_bound': 8, 'exploration_steps': 3}, "
        f"'unresolved': list({unresolved!r}), 'target_executed': False}}, "
        "open(sys.argv[2], 'w'))\n"
    )
    return AngrSidecar(interpreter=sys.executable, runner=str(target))


def angr_context(sidecar):
    return AngrContext(sidecar, "/fake/probe.elf", DIGEST, 0x0)


def test_default_refinement_equals_v1_feasible():
    graph = branch_graph()
    selector = PathSelector(path_bindings(graph), (0, 1))
    expected_query, expected = prove_path(graph, selector)
    validate_proof_result(expected_query, expected)
    artifact = refine_path_proof(graph, selector, RefinementSpec())
    check_refined_path_artifact(artifact)
    assert artifact["original"] is None
    assert artifact["baseline"]["status"] == expected.status == "feasible"
    assert artifact["baseline"]["result_digest"] == digest(expected.to_data())
    assert artifact["baseline"]["query_digest"] == expected_query.query_digest
    assert artifact["baseline"]["unresolved"] == list(expected.unresolved)
    assert artifact["refined"] == {
        "attempted": False,
        "status": "unknown",
        "reason": "solver_not_invoked",
    }
    assert artifact["agreement"] == "consistent"
    assert artifact["target_executed"] is False
    assert artifact["no_auto_vulnerability_verdict"] is True


def test_default_refinement_equals_v1_unknown():
    graph = vanishing_graph()
    selector = PathSelector(path_bindings(graph), (0, 1))
    _query, expected = prove_path(graph, selector)
    assert expected.status == "unknown"
    artifact = refine_path_proof(graph, selector, RefinementSpec())
    assert artifact["baseline"]["status"] == "unknown"
    assert artifact["baseline"]["result_digest"] == digest(expected.to_data())
    assert artifact["refined"]["attempted"] is False


def test_default_spec_ignores_angr_context(tmp_path):
    """An all-off spec never touches the engine, even when configured."""
    graph = branch_graph()
    selector = PathSelector(path_bindings(graph), (0, 1))
    context = angr_context(write_runner(tmp_path, "feasible"))
    artifact = refine_path_proof(graph, selector, RefinementSpec(), angr=context)
    assert artifact["refined"] == {
        "attempted": False,
        "status": "unknown",
        "reason": "solver_not_invoked",
    }
    assert artifact["agreement"] == "consistent"


def test_original_link_cross_checked():
    graph = branch_graph()
    selector = PathSelector(path_bindings(graph), (0, 1))
    query, result = prove_path(graph, selector)
    original = {
        "artifact_id": "artifact-original",
        "query": query.to_data(),
        "proof": result.to_data(),
    }
    artifact = refine_path_proof(
        graph, selector, RefinementSpec(), original=original
    )
    link = artifact["original"]
    assert link["artifact_id"] == "artifact-original"
    assert link["query_digest"] == query.query_digest
    assert link["result_digest"] == digest(result.to_data())
    assert link["status"] == result.status
    # A tampered original must refuse, not silently rebaseline.
    tampered_proof = dict(result.to_data())
    tampered_proof["assignments_checked"] = tampered_proof["assignments_checked"] + 1
    tampered = {
        "artifact_id": "artifact-original",
        "query": query.to_data(),
        "proof": tampered_proof,
    }
    with pytest.raises(Exception, match="refine_baseline_mismatch"):
        refine_path_proof(graph, selector, RefinementSpec(), original=tampered)


def test_refinement_agreement_matrix():
    assert refinement_agreement("feasible", FEASIBLE_ANGR) == "consistent"
    assert refinement_agreement("infeasible", INFEASIBLE_ANGR) == "consistent"
    assert refinement_agreement("unknown", "unknown") == "consistent"
    assert refinement_agreement("unknown", FEASIBLE_ANGR) == "refined"
    assert refinement_agreement("unknown", INFEASIBLE_ANGR) == "refined"
    assert refinement_agreement("feasible", "unknown") == "consistent"
    assert refinement_agreement("feasible", INFEASIBLE_ANGR) == "contradiction"
    assert refinement_agreement("infeasible", FEASIBLE_ANGR) == "contradiction"


def test_angr_tier_can_settle_v1_unknown(tmp_path):
    graph = angr_branch_graph()
    selector = PathSelector(path_bindings(graph), (0, 1))
    _query, baseline = prove_path(graph, selector)
    assert baseline.status == "unknown"
    witness = ({"name": "rdi", "width_bits": 8, "value_hex": "0x3"},)
    context = angr_context(write_runner(tmp_path, "feasible", witness=witness))
    artifact = refine_path_proof(
        graph, selector, RefinementSpec(symbolic_angr=True), angr=context
    )
    check_refined_path_artifact(artifact)
    assert artifact["baseline"]["status"] == "unknown"
    assert artifact["refined"]["attempted"] is True
    assert artifact["refined"]["status"] == FEASIBLE_ANGR
    assert artifact["refined"]["witness"] == list(witness)
    assert artifact["refined"]["solver_stamp"]
    assert artifact["refined"]["engine"]["name"] == "angr-sidecar"
    assert artifact["agreement"] == "refined"
    ensure_wire_v1_safe(artifact)


def test_angr_tier_agreement_when_consistent(tmp_path):
    graph = build_ssa(
        addressed(
            (
                Block(
                    0,
                    (),
                    (
                        ins(
                            0,
                            "m_jz",
                            const(3),
                            const(3, role="right"),
                            Operand("block", None, block_index=1, role="destination"),
                        ),
                    ),
                ),
                Block(1, (0,), ()),
                Block(2, (0,), ()),
            )
        )
    ).graph
    selector = PathSelector(path_bindings(graph), (0, 1))
    context = angr_context(write_runner(tmp_path, "feasible"))
    artifact = refine_path_proof(
        graph, selector, RefinementSpec(symbolic_angr=True), angr=context
    )
    assert artifact["baseline"]["status"] == "feasible"
    assert artifact["refined"]["status"] == FEASIBLE_ANGR
    assert artifact["agreement"] == "consistent"


def test_contradiction_flagged_not_silenced(tmp_path):
    """v1 infeasible + angr feasible: both verdicts stay visible."""
    graph = build_ssa(
        addressed(
            (
                Block(
                    0,
                    (),
                    (
                        ins(
                            0,
                            "m_jz",
                            const(3),
                            const(3, role="right"),
                            Operand("block", None, block_index=1, role="destination"),
                        ),
                    ),
                ),
                Block(1, (0,), ()),
                Block(2, (0,), ()),
            )
        )
    ).graph
    selector = PathSelector(path_bindings(graph), (0, 2))
    _query, baseline = prove_path(graph, selector)
    assert baseline.status == "infeasible"
    context = angr_context(write_runner(tmp_path, "feasible"))
    artifact = refine_path_proof(
        graph, selector, RefinementSpec(symbolic_angr=True), angr=context
    )
    assert artifact["baseline"]["status"] == "infeasible"
    assert artifact["refined"]["status"] == FEASIBLE_ANGR
    assert artifact["agreement"] == "contradiction"


def test_angr_requested_but_unconfigured_keeps_baseline():
    graph = angr_branch_graph()
    selector = PathSelector(path_bindings(graph), (0, 1))
    artifact = refine_path_proof(
        graph, selector, RefinementSpec(symbolic_angr=True), angr=None
    )
    assert artifact["refined"] == {
        "attempted": False,
        "status": "unknown",
        "reason": "angr_not_configured",
    }
    assert artifact["agreement"] == "consistent"


def test_unaddressed_graph_query_unbuildable(tmp_path):
    graph = branch_graph(reg(bits=8))
    selector = PathSelector(path_bindings(graph), (0, 1))
    context = angr_context(write_runner(tmp_path, "feasible"))
    artifact = refine_path_proof(
        graph, selector, RefinementSpec(symbolic_angr=True), angr=context
    )
    assert artifact["refined"]["attempted"] is False
    assert artifact["refined"]["reason"].startswith("angr_query_unbuildable:")
    assert artifact["agreement"] == "consistent"


def test_prefix_query_needs_entry_rooted_x64(tmp_path):
    graph = angr_branch_graph()
    context = angr_context(write_runner(tmp_path, "feasible"))
    selector = PathSelector(path_bindings(graph), (0, 1))
    built = build_prefix_query(
        graph, selector, context, timeout_ms=5000, loop_bound=8
    )
    assert built.find_eas and built.entry_ea > 0
    assert built.avoid_eas
    with pytest.raises(ContractError, match="angr prefix must be entry-rooted"):
        build_prefix_query(
            graph,
            PathSelector(path_bindings(graph), (1,)),
            context,
            timeout_ms=5000,
        )


def test_wide_witness_hex_stays_wire_safe(tmp_path):
    huge = 2**64 - 1
    graph = angr_branch_graph()
    selector = PathSelector(path_bindings(graph), (0, 1))
    witness = ({"name": "rdi", "width_bits": 64, "value_hex": hex(huge)},)
    context = angr_context(write_runner(tmp_path, "feasible", witness=witness))
    artifact = refine_path_proof(
        graph, selector, RefinementSpec(symbolic_angr=True), angr=context
    )
    (binding,) = artifact["refined"]["witness"]
    assert binding["width_bits"] == 64
    assert int(binding["value_hex"], 16) == huge
    assert huge > 2**53 - 1
    ensure_wire_v1_safe(artifact)


def _mem_fixture():
    memory_plan = mem_plan((
        mem_store(0, reg(8, 8), reg(0, 64, "destination")),
        mem_load(1, bits=8, address=reg(0, 64, "right")),
    ))
    graph = memory_plan.program.graph
    stores, loads = access_ids(memory_plan, graph)
    first, second = obj(memory_plan, key="A"), obj(memory_plan, key="B")
    facts = run(memory_plan, (first, second),
                (ptrseed(memory_plan, first, register=0),))
    assert facts.dependencies, "v1 fixture must yield candidate objects"
    return memory_plan, graph, facts, loads[0], stores[0]


def test_default_memory_refinement_quotes_v1_verbatim():
    memory_plan, graph, facts, load_id, store_id = _mem_fixture()
    selector = PathSelector(path_bindings(graph), (0,))
    artifact = refine_memory_proof(
        memory_plan,
        graph,
        facts,
        selector,
        load_id,
        store_id,
        RefinementSpec(),
    )
    check_refined_memory_artifact(artifact)
    assert artifact["load_id"] == load_id
    assert artifact["store_id"] == store_id
    baseline = artifact["baseline"]
    assert baseline["result_digest"] == digest(facts.to_data())
    assert baseline["plan_digest"] == facts.plan_digest == memory_plan.plan_digest
    pair = {load_id, store_id}
    assert baseline["facts"] == [
        item.to_data() for item in facts.facts if item.node_id in pair
    ]
    assert baseline["dependencies"] == [
        item.to_data()
        for item in facts.dependencies
        if item.source in pair or item.target in pair
    ]
    # No alias-narrowing tier by design: narrowing is the analyst's call.
    assert artifact["refined"] == {
        "attempted": False,
        "status": "unknown",
        "reason": "evidence_only",
    }


def test_memory_refinement_rejects_plan_drift():
    memory_plan, graph, facts, load_id, store_id = _mem_fixture()
    other_plan = mem_plan((
        mem_store(0, reg(8, 8), reg(16, 64, "destination")),
        mem_load(1, bits=8, address=reg(16, 64, "right")),
    ))
    selector = PathSelector(path_bindings(graph), (0,))
    with pytest.raises(Exception, match="refine_plan_mismatch"):
        refine_memory_proof(
            other_plan,
            graph,
            facts,
            selector,
            load_id,
            store_id,
            RefinementSpec(),
        )


def test_refinement_spec_rejects_bad_budgets():
    with pytest.raises(Exception, match="invalid_refinement_timeout"):
        RefinementSpec(solver_timeout_ms=0)
    with pytest.raises(Exception, match="invalid_refinement_timeout"):
        RefinementSpec(solver_timeout_ms=120001)
    with pytest.raises(Exception, match="invalid_refinement_loop_bound"):
        RefinementSpec(loop_bound=0)
    with pytest.raises(ContractError):
        RefinementSpec(symbolic_angr="yes")
    with pytest.raises(ContractError):
        RefinementSpec.from_data(
            {"symbolic_angr": 1, "solver_timeout_ms": 5000, "schema_version": 1}
        )
