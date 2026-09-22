"""Program correspondence is independent of solver correctness."""

from dataclasses import replace

import pytest

from ida_pro_mcp.flow_core import ContractError, digest
from ida_pro_mcp.flow_core.contracts import Block, Operand
from ida_pro_mcp.flow_core.path_conditions import (
    PathSelector,
    derive_path_query,
    path_bindings,
    prove_path,
)
from ida_pro_mcp.flow_core.ssa import build_ssa
from test_ssa import snapshot, ins, const, reg


def branch_graph(left=None):
    return build_ssa(
        snapshot(
            (
                Block(
                    0,
                    (),
                    (
                        ins(
                            0,
                            "m_jz",
                            left or const(3),
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


@pytest.mark.parametrize("target,status", [(1, "feasible"), (2, "infeasible")])
def test_program_branch_derivation(target, status):
    graph = branch_graph()
    query, proof = prove_path(graph, PathSelector(path_bindings(graph), (0, target)))
    assert proof.status == status
    assert query.constraints[0].origin_id in {n.node_id for n in graph.nodes}
    assert query.bounds.loop_bound == query.bounds.call_bound == 0
    assert proof.witness is None or proof.witness.valid


def test_program_owned_input_domain_and_independent_witness():
    graph = branch_graph(reg())
    query, proof = prove_path(graph, PathSelector(path_bindings(graph), (0, 1)))
    assert proof.status == "feasible"
    assert query.variables[0].name in {n.node_id for n in graph.nodes}
    assert query.variables[0].domain == tuple(range(256))
    assert proof.witness.valid


def test_unsupported_wide_input_is_unknown_not_false():
    graph = branch_graph(reg(bits=64))
    _, proof = prove_path(graph, PathSelector(path_bindings(graph), (0, 1)))
    assert proof.status == "unknown"
    assert proof.model_kind == "incomplete"


def test_selector_rejects_equations_and_foreign_transitions():
    graph = branch_graph()
    selector = PathSelector(path_bindings(graph), (0, 1))
    for extra in (
        "variables",
        "constraints",
        "origins",
        "predicate",
        "assumptions",
        "bounds",
    ):
        with pytest.raises(ContractError):
            PathSelector.from_data({**selector.to_data(), extra: []})
    with pytest.raises(ContractError, match="path_foreign_transition"):
        derive_path_query(graph, replace(selector, blocks=(0, 1, 2)))
    for field in (
        "snapshot_id",
        "graph_digest",
        "profile_digest",
        "ruleset_digest",
        "summary_digests",
    ):
        value = (digest("stale"),) if field == "summary_digests" else digest("stale")
        if field == "snapshot_id":
            value = "snapshot-v1:" + "0" * 64
        with pytest.raises(ContractError, match="path_query_artifact_mismatch"):
            derive_path_query(
                graph,
                replace(
                    selector, bindings=replace(selector.bindings, **{field: value})
                ),
            )


def test_path_proof_cancellation_remains_unknown():
    graph = branch_graph(reg())
    _, proof = prove_path(
        graph, PathSelector(path_bindings(graph), (0, 1)), cancelled=lambda: True
    )
    assert proof.status == "unknown"
    assert "cancelled" in str(proof.unresolved)


def test_empty_prefix_does_not_claim_program_feasibility():
    graph = branch_graph()
    _, proof = prove_path(graph, PathSelector(path_bindings(graph), (0,)))
    assert proof.status == "unknown"
    assert proof.model_kind == "incomplete"


@pytest.mark.parametrize(
    "opcode,left,right,taken",
    [
        ("m_jz", 3, 3, True),
        ("m_jnz", 3, 3, False),
        ("m_jz", 2, 3, False),
        ("m_jnz", 2, 3, True),
        ("m_jb", 255, 1, False),
        ("m_jl", 255, 1, True),
        ("m_ja", 255, 1, True),
        ("m_jg", 255, 1, False),
        ("m_jbe", 3, 3, True),
        ("m_jle", 3, 3, True),
        ("m_jae", 3, 3, True),
        ("m_jge", 3, 3, True),
    ],
)
def test_branch_polarity_matches_structured_opcode(opcode, left, right, taken):
    graph = build_ssa(
        snapshot(
            (
                Block(
                    0,
                    (),
                    (
                        ins(
                            0,
                            opcode,
                            const(left),
                            const(right, role="right"),
                            Operand("block", None, block_index=1, role="destination"),
                        ),
                    ),
                ),
                Block(1, (0,), ()),
                Block(2, (0,), ()),
            )
        )
    ).graph
    for target in (1, 2):
        _, proof = prove_path(graph, PathSelector(path_bindings(graph), (0, target)))
        assert proof.status == ("feasible" if (target == 1) == taken else "infeasible")


def test_contradictory_correlated_program_guards_are_infeasible():
    def branch(opcode, target):
        return ins(
            0,
            opcode,
            reg(),
            const(3, role="right"),
            Operand("block", None, block_index=target, role="destination"),
        )

    graph = build_ssa(
        snapshot(
            (
                Block(0, (), (branch("m_jz", 1),)),
                Block(1, (0,), (branch("m_jnz", 3),)),
                Block(2, (0, 1), ()),
                Block(3, (1,), ()),
            )
        )
    ).graph
    query, proof = prove_path(graph, PathSelector(path_bindings(graph), (0, 1, 3)))
    assert len(query.variables) == 1
    assert proof.status == "infeasible"
    assert proof.scope == "within_bounds"


def test_graph_predicate_cannot_override_structured_branch():
    graph = branch_graph()
    graph = replace(
        graph,
        nodes=tuple(
            replace(n, operation="ne") if n.kind == "Compare" else n
            for n in graph.nodes
        ),
    )
    _, proof = prove_path(graph, PathSelector(path_bindings(graph), (0, 1)))
    assert proof.status == "unknown"
    assert "unsupported_predicate_correspondence" in proof.unresolved


def test_selector_requires_explicit_wire_schema_version():
    graph = branch_graph()
    selector = PathSelector(path_bindings(graph), (0, 1))
    data = selector.to_data()
    assert data["schema_version"] == 1
    assert PathSelector.from_data(data) == selector
    del data["schema_version"]
    with pytest.raises(ContractError, match="Wrong fields for PathSelector"):
        PathSelector.from_data(data)
    with pytest.raises(ContractError, match="invalid_path_selector_version"):
        PathSelector.from_data({**data, "schema_version": 2})


def graph_with_prefix(prefix, *, final_instructions=()):
    guard = ins(
        len(prefix),
        "m_jz",
        const(3),
        const(3, role="right"),
        Operand("block", None, block_index=1, role="destination"),
    )
    return build_ssa(
        snapshot(
            (
                Block(0, (), tuple(prefix) + (guard,)),
                Block(1, (0,), tuple(final_instructions)),
                Block(2, (0,), ()),
            )
        )
    ).graph


@pytest.mark.parametrize(
    "opcode,kind",
    [
        ("m_call", "Call"),
        ("m_nop", "OpaqueEffect"),
        ("m_unknown_path_test", "UnknownValue"),
    ],
)
def test_unsupported_executed_path_effects_are_incomplete(opcode, kind):
    graph = graph_with_prefix(
        (ins(0, opcode, None if opcode == "m_nop" else const(0)),)
    )
    assert any(n.kind == kind for n in graph.nodes)
    _, proof = prove_path(graph, PathSelector(path_bindings(graph), (0, 1)))
    assert proof.status == "unknown"
    assert proof.model_kind == "incomplete"


def test_selected_final_block_is_reached_before_its_call_executes():
    graph = graph_with_prefix((), final_instructions=(ins(0, "m_call", const(0)),))
    assert any(n.kind == "Call" for n in graph.nodes)
    _, proof = prove_path(graph, PathSelector(path_bindings(graph), (0, 1)))
    assert proof.status == "feasible"
    assert proof.witness.valid


def test_select_in_executed_prefix_is_unknown():
    from ida_pro_mcp.flow_core.contracts import Instruction

    select = Instruction(
        0,
        "m_select",
        (
            reg(16),
            reg(0, role="right"),
            reg(8, role="argument"),
            reg(24, role="destination"),
        ),
    )
    graph = graph_with_prefix((select,))
    assert any(n.kind == "Select" for n in graph.nodes)
    _, proof = prove_path(graph, PathSelector(path_bindings(graph), (0, 1)))
    assert proof.status == "unknown" and proof.model_kind == "incomplete"


def test_phi_dependency_is_unknown_even_with_a_selected_predecessor():
    def branch(index, target, left):
        return ins(
            index,
            "m_jz",
            left,
            const(3, role="right"),
            Operand("block", None, block_index=target, role="destination"),
        )

    graph = build_ssa(
        snapshot(
            (
                Block(0, (), (branch(0, 1, reg(16)),)),
                Block(
                    1, (0,), (ins(0, "m_mov", const(3), dest=reg(role="destination")),)
                ),
                Block(
                    2, (0,), (ins(0, "m_mov", const(4), dest=reg(role="destination")),)
                ),
                Block(3, (1, 2), (branch(0, 4, reg()),)),
                Block(4, (3,), ()),
                Block(5, (3,), ()),
            )
        )
    ).graph
    assert any(n.kind == "Phi" for n in graph.nodes)
    _, proof = prove_path(graph, PathSelector(path_bindings(graph), (0, 1, 3, 4)))
    assert proof.status == "unknown" and proof.model_kind == "incomplete"


def test_repeated_block_loop_is_incomplete():
    graph = build_ssa(
        snapshot(
            (
                Block(0, (), ()),
                Block(
                    1,
                    (0, 1),
                    (
                        ins(
                            0,
                            "m_jnz",
                            reg(),
                            const(0, role="right"),
                            Operand("block", None, block_index=1, role="destination"),
                        ),
                    ),
                ),
                Block(2, (1,), ()),
            )
        )
    ).graph
    _, proof = prove_path(graph, PathSelector(path_bindings(graph), (0, 1, 1, 2)))
    assert proof.status == "unknown" and proof.model_kind == "incomplete"
    assert "loop_unrolling_unsupported" in proof.unresolved


def test_modular_addition_feeds_guard_with_independent_byte_expectation():
    graph = build_ssa(
        snapshot(
            (
                Block(
                    0,
                    (),
                    (
                        ins(
                            0,
                            "m_add",
                            const(255),
                            const(2, role="right"),
                            reg(role="destination"),
                        ),
                        ins(
                            1,
                            "m_jz",
                            reg(),
                            const(1, role="right"),
                            Operand("block", None, block_index=1, role="destination"),
                        ),
                    ),
                ),
                Block(1, (0,), ()),
                Block(2, (0,), ()),
            )
        )
    ).graph
    assert (255 + 2) & 255 == 1
    for target, expected in ((1, "feasible"), (2, "infeasible")):
        query, proof = prove_path(
            graph, PathSelector(path_bindings(graph), (0, target))
        )
        assert proof.status == expected
        assert "add" in query.coverage.operators
        assert proof.witness is None or proof.witness.valid


@pytest.mark.parametrize("kind", ["Load", "Store"])
def test_memory_access_in_executed_prefix_is_incomplete(kind):
    from test_memory import load, store

    operation = load(0) if kind == "Load" else store(0)
    graph = graph_with_prefix((operation,))
    assert any(n.kind == kind for n in graph.nodes)
    _, proof = prove_path(graph, PathSelector(path_bindings(graph), (0, 1)))
    assert proof.status == "unknown" and proof.model_kind == "incomplete"


@pytest.mark.parametrize("opcode,expected", [("m_and", 1), ("m_or", 15), ("m_xor", 14)])
def test_native_bitwise_operation_names_map_to_constraint_semantics(opcode, expected):
    graph = build_ssa(
        snapshot(
            (
                Block(
                    0,
                    (),
                    (
                        ins(
                            0,
                            opcode,
                            const(5),
                            const(11, role="right"),
                            reg(role="destination"),
                        ),
                        ins(
                            1,
                            "m_jz",
                            reg(),
                            const(expected, role="right"),
                            Operand("block", None, block_index=1, role="destination"),
                        ),
                    ),
                ),
                Block(1, (0,), ()),
                Block(2, (0,), ()),
            )
        )
    ).graph
    _, proof = prove_path(graph, PathSelector(path_bindings(graph), (0, 1)))
    assert proof.status == "feasible" and proof.witness.valid


@pytest.mark.parametrize(
    "mask,opcode,status",
    [(1, "m_jz", "feasible"), (256, "m_jz", "unknown"), (1, "m_jl", "unknown")],
)
def test_exact_mask_projection_never_assumes_upper_input_bits_zero(
    mask, opcode, status
):
    graph = build_ssa(
        snapshot(
            (
                Block(
                    0,
                    (),
                    (
                        ins(
                            0,
                            "m_and",
                            reg(bits=32),
                            const(mask, 32, role="right"),
                            reg(64, 32, "destination"),
                        ),
                        ins(
                            1,
                            opcode,
                            reg(64, 32),
                            const(0, 32, role="right"),
                            Operand("block", None, block_index=1, role="destination"),
                        ),
                    ),
                ),
                Block(
                    1,
                    (0,),
                    (ins(0, "m_mov", reg(bits=8), dest=reg(128, 8, "destination")),),
                ),
                Block(2, (0,), ()),
            )
        )
    ).graph
    assert any(n.operation == "concat_low" for n in graph.nodes)
    query, proof = prove_path(graph, PathSelector(path_bindings(graph), (0, 1)))
    assert proof.status == status
    if status == "feasible":
        assert query.constraints[0].rule_id == "program-path-byte-mask-projection-v1"
        assert query.variables[0].width_bits == 8
        assert query.variables[0].domain == tuple(range(256))
        low = proof.witness.assignments[0].value
        for high in (0, 1, 255, 65535, 0xFFFFFF):
            assert (((high << 8) | low) & mask) == 0
    else:
        assert proof.model_kind == "incomplete"


@pytest.mark.parametrize(
    "severity,status", [("information", "feasible"), ("unsupported", "unknown")]
)
def test_diagnostics_do_not_conflate_information_with_missing_semantics(
    severity, status
):
    from ida_pro_mcp.flow_core import digest
    from ida_pro_mcp.flow_core.contracts import Diagnostic, Snapshot

    graph = branch_graph()
    function = replace(
        graph.snapshot.function,
        diagnostics=(Diagnostic("test_diagnostic", "test", severity),),
    )
    identity = replace(graph.snapshot.identity, input_digest=digest(function))
    graph = build_ssa(Snapshot(identity, function, identity.snapshot_id)).graph
    _, proof = prove_path(graph, PathSelector(path_bindings(graph), (0, 1)))
    assert proof.status == status
