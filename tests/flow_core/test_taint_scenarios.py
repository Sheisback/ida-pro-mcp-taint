"""Benign C-like taint probes; synthetic IR only, never execute a binary.

Expectations use source-level data dependence, not engine-produced goldens.
A failure can identify conservative overtaint, not necessarily unsoundness.
"""

import pytest

from ida_pro_mcp.flow_core.analysis import Seed, analyze, seeds_for_entry
from ida_pro_mcp.flow_core.contracts import Block, Instruction, Operand
from ida_pro_mcp.flow_core.implicit_analysis import ImplicitPolicy
from ida_pro_mcp.flow_core.memory_graph import analyze_seeded_memory, build_memory_graph
from ida_pro_mcp.flow_core.ssa import build_ssa
from ida_pro_mcp.flow_core.states import Labels, StorageLocation
from test_implicit_analysis import result as implicit_result
from test_implicit_analysis import returned as implicit_returned
from test_implicit_analysis import definitions as implicit_definitions
from test_implicit_analysis import facts as implicit_facts
from test_memory import const as mc
from test_memory import fact, load, memseed, nodes, obj, plan, ptrseed
from test_memory import reg as mr
from test_memory import ret, run, store
from test_ssa import const, ins, linear, reg, returned, seed_storage, snapshot


@pytest.mark.parametrize("opcode", ("m_add", "m_xor", "m_or"))
def test_data_preserving_zero_operations_keep_source(opcode):
    """uint8_t f(uint8_t x) { return x OP 0; }"""
    p = build_ssa(
        linear(
            (
                ins(
                    0, opcode, reg(), const(0, role="right"), reg(8, role="destination")
                ),
                ins(1, "m_ret", reg(8)),
            )
        )
    )
    r = analyze(p.graph, (seed_storage(p),))
    assert returned(p, r).labels.explicit == ("X",)
    assert r.status == "complete_in_scope"


@pytest.mark.parametrize(
    "opcode,rhs",
    (
        ("m_and", "zero"),
        ("m_mul", "zero"),
        ("m_xor", "self"),
        ("m_sub", "self"),
    ),
)
def test_source_independent_annihilation_does_not_taint_return(opcode, rhs):
    """For every uint8_t x, these four expressions equal zero."""
    operand = const(0, role="right") if rhs == "zero" else reg(role="right")
    p = build_ssa(
        linear(
            (
                ins(0, opcode, reg(), operand, reg(8, role="destination")),
                ins(1, "m_ret", reg(8)),
            )
        )
    )
    r = analyze(p.graph, (seed_storage(p),))
    assert returned(p, r).labels.explicit == (), (
        f"{opcode} with {rhs} is source-independent; observed conservative overtaint"
    )
    assert returned(p, r).value.value == 0


@pytest.mark.parametrize("opcode", ("m_xor", "m_sub"))
def test_different_ssa_values_do_not_get_self_annihilation(opcode):
    p = build_ssa(
        linear(
            (
                ins(
                    0, opcode, reg(), reg(8, role="right"), reg(16, role="destination")
                ),
                ins(1, "m_ret", reg(16)),
            )
        )
    )
    seeds = tuple(
        sorted((seed_storage(p), seed_storage(p, 8, "Y")), key=lambda s: s.node_id)
    )
    result = analyze(p.graph, seeds)
    assert returned(p, result).labels.explicit == ("X", "Y")
    assert returned(p, result).value.value is None


def test_direct_result_seed_survives_zero_annihilation():
    p = build_ssa(
        linear(
            (
                ins(
                    0,
                    "m_and",
                    reg(),
                    const(0, role="right"),
                    reg(8, role="destination"),
                ),
                ins(1, "m_ret", reg(8)),
            )
        )
    )
    result_node = next(node for node in p.graph.nodes if node.kind == "Binary")
    seeds = tuple(
        sorted(
            (seed_storage(p), Seed(result_node.node_id, Labels(("DIRECT",)))),
            key=lambda s: s.node_id,
        )
    )
    result = analyze(p.graph, seeds)
    assert returned(p, result).labels.explicit == ("DIRECT",)
    assert returned(p, result).value.value == 0


@pytest.mark.parametrize("opcode,selected", (("m_low", "LOW"), ("m_high", "HIGH")))
def test_opt_in_scalar_register_half_source_selection_is_exact(opcode, selected):
    """Opt-in scalar IR can select a half without changing memory SSA."""
    source = plan(
        (
            Instruction(0, opcode, (mr(0, 64), mr(128, 32, "destination"))),
            ret(1, 128, 32),
        )
    ).program.graph.snapshot
    p = build_ssa(source, split_microregisters=True)
    atoms = [e.storage for e in p.entry_storage if e.storage.bit_offset in (0, 32)]
    assert [(a.bit_offset, a.width_bits) for a in atoms] == [(0, 32), (32, 32)]
    seeds = tuple(
        sorted(
            (
                *seeds_for_entry(
                    p, StorageLocation("microregister", "bank", 0, 32), Labels(("LOW",))
                ),
                *seeds_for_entry(
                    p,
                    StorageLocation("microregister", "bank", 32, 32),
                    Labels(("HIGH",)),
                ),
            ),
            key=lambda seed: seed.node_id,
        )
    )
    result = analyze(p.graph, seeds)
    assert returned(p, result).labels.explicit == (selected,)


def test_direct_concat_seed_reaches_high_half_without_low_half_bleed():
    source = plan(
        (
            Instruction(0, "m_high", (mr(0, 64), mr(128, 32, "destination"))),
            ret(1, 128, 32),
        )
    ).program.graph.snapshot
    p = build_ssa(source, split_microregisters=True)
    concat = next(node for node in p.graph.nodes if node.operation == "concat_low")
    low = seeds_for_entry(
        p, StorageLocation("microregister", "bank", 0, 32), Labels(("LOW",))
    )
    seeds = tuple(
        sorted(
            (*low, Seed(concat.node_id, Labels(("DIRECT",)))),
            key=lambda seed: seed.node_id,
        )
    )
    assert returned(p, analyze(p.graph, seeds)).labels.explicit == ("DIRECT",)


def test_zero_extension_high_bits_do_not_inherit_low_source_label():
    source = plan(
        (
            Instruction(0, "m_xdu", (mr(0, 32), mr(64, 64, "destination"))),
            Instruction(1, "m_high", (mr(64, 64), mr(128, 32, "destination"))),
            ret(2, 128, 32),
        )
    ).program.graph.snapshot
    p = build_ssa(source, split_microregisters=True)
    low = seeds_for_entry(
        p, StorageLocation("microregister", "bank", 0, 32), Labels(("LOW",))
    )
    assert returned(p, analyze(p.graph, low)).labels.explicit == ()


def test_typed_entry_partition_projects_seeded_memory_labels_by_half():
    marker = Instruction(
        0,
        "m_arg",
        (
            mc(0, 32),
            mr(0, 32, "argument"),
        ),
        synthetic=True,
    )
    source = plan(
        (
            marker,
            Instruction(1, "m_high", (mr(0, 64), mr(128, 32, "destination"))),
            ret(2, 128, 32),
        )
    ).program.graph.snapshot
    bundle = build_memory_graph(source)
    program = bundle.program
    low = seeds_for_entry(
        program, StorageLocation("microregister", "bank", 0, 32), Labels(("LOW",))
    )
    high = seeds_for_entry(
        program, StorageLocation("microregister", "bank", 32, 32), Labels(("HIGH",))
    )
    seeds = tuple(sorted((*low, *high), key=lambda seed: seed.node_id))
    result = analyze_seeded_memory(bundle, seeds)
    return_id = next(n.node_id for n in program.graph.nodes if n.kind == "Return")
    assert next(f for f in result.facts if f.node_id == return_id).labels.explicit == (
        "HIGH",
    )

    concat = next(n for n in program.graph.nodes if n.operation == "concat_low")
    direct = tuple(
        sorted(
            (*low, Seed(concat.node_id, Labels(("DIRECT",)))),
            key=lambda seed: seed.node_id,
        )
    )
    result = analyze_seeded_memory(bundle, direct)
    assert next(f for f in result.facts if f.node_id == return_id).labels.explicit == (
        "DIRECT",
    )


def test_unmodeled_call_effect_survives_zero_result_dependency():
    p = build_ssa(
        linear(
            (
                Instruction(
                    0,
                    "m_call",
                    (const(4096, 64), reg(role="argument"), reg(8, role="destination")),
                ),
                ins(
                    1,
                    "m_and",
                    reg(8),
                    const(0, role="right"),
                    reg(16, role="destination"),
                ),
                ins(2, "m_ret", reg(16)),
            )
        )
    )
    result = analyze(p.graph, (seed_storage(p),))
    assert returned(p, result).value.value == 0
    assert returned(p, result).labels.explicit == ()
    assert result.status == "partial"
    assert "unresolved_boundary" in result.diagnostics


def test_overwriting_original_does_not_erase_earlier_copy():
    """y=x; x=0; return y; must retain the original source."""
    p = build_ssa(
        linear(
            (
                ins(0, "m_mov", reg(), dest=reg(8, role="destination")),
                ins(1, "m_mov", const(0), dest=reg(role="destination")),
                ins(2, "m_ret", reg(8)),
            )
        )
    )
    assert returned(p, analyze(p.graph, (seed_storage(p),))).labels.explicit == ("X",)


def test_unrelated_computation_does_not_contaminate_return():
    """tmp=x+1; return y; has no explicit x-to-return flow."""
    p = build_ssa(
        linear(
            (
                ins(
                    0,
                    "m_add",
                    reg(),
                    const(1, role="right"),
                    reg(16, role="destination"),
                ),
                ins(1, "m_ret", reg(8)),
            )
        )
    )
    assert returned(p, analyze(p.graph, (seed_storage(p),))).labels == Labels()


@pytest.mark.parametrize("condition", (0, 1))
def test_constant_select_excludes_dead_source_arm(condition):
    """return true ? 7 : x (or false ? x : 7) is independent of x."""
    arms = (
        (const(7, role="right"), reg(role="argument"))
        if condition
        else (
            reg(role="right"),
            const(7, role="argument"),
        )
    )
    p = build_ssa(
        linear(
            (
                Instruction(
                    0, "m_select", (const(condition), *arms, reg(8, role="destination"))
                ),
                ins(1, "m_ret", reg(8)),
            )
        )
    )
    out = returned(p, analyze(p.graph, (seed_storage(p),)))
    assert out.value.value == 7
    assert out.labels.explicit == (), (
        "Unselected constant-condition arm overtaints result"
    )


def test_copied_constant_select_only_taints_selected_arm():
    p = build_ssa(
        linear(
            (
                ins(0, "m_mov", const(1), dest=reg(16, role="destination")),
                Instruction(
                    1,
                    "m_select",
                    (
                        reg(16),
                        reg(0, role="right"),
                        reg(8, role="argument"),
                        reg(24, role="destination"),
                    ),
                ),
                ins(2, "m_ret", reg(24)),
            )
        )
    )
    seeds = tuple(
        sorted((seed_storage(p), seed_storage(p, 8, "Y")), key=lambda s: s.node_id)
    )
    assert returned(p, analyze(p.graph, seeds)).labels.explicit == ("X",)


@pytest.mark.parametrize(
    "kind,address,operation",
    (("stack_address", 8, "stack_address"), ("address", 0x100002008, "global_address")),
)
def test_address_of_is_an_address_value_not_a_content_load(kind, address, operation):
    p = build_ssa(
        linear(
            (
                ins(
                    0,
                    "m_mov",
                    Operand(kind, 64, address=address),
                    dest=reg(0, 64, "destination"),
                ),
                ins(1, "m_ret", reg(0, 64)),
            )
        ),
        storage_model="memory",
    )
    result = analyze(p.graph)
    assert returned(p, result).value.value == address
    assert not any(n.kind == "Load" for n in p.graph.nodes)
    assert any(n.kind == "Constant" and n.operation == operation for n in p.graph.nodes)


@pytest.mark.parametrize("reload_offset,expected", ((0, ()), (1, ("X",))))
def test_byte_clear_only_removes_taint_from_addressed_byte(reload_offset, expected):
    """a[0]=0; return a[i]; only byte zero is sanitized."""
    p = plan((store(0, mc(0)), load(1, address=mr(64, role="right")), ret(2)))
    a = obj(p, size=2)
    r = run(
        p, (a,), (ptrseed(p, a), ptrseed(p, a, 64, reload_offset)), (memseed(a, 0, 2),)
    )
    assert fact(r, nodes(p, "Return")[0].node_id).labels.explicit == expected


@pytest.mark.parametrize("tainted_last", (False, True))
def test_last_exact_store_controls_returned_content(tainted_last):
    """*p=x; *p=0 and *p=0; *p=x have opposite taint outcomes."""
    values = (mc(0), mr(192, 8)) if tainted_last else (mr(192, 8), mc(0))
    p = plan((store(0, values[0]), store(1, values[1]), load(2), ret(3)))
    a = obj(p)
    entry = next(e for e in p.program.entry_storage if e.storage.bit_offset == 192)
    r = run(p, (a,), (ptrseed(p, a),), values=(Seed(entry.node_id, Labels(("X",))),))
    assert fact(r, nodes(p, "Return")[0].node_id).labels.explicit == (
        ("X",) if tainted_last else ()
    )


def test_pointer_taint_stays_separate_from_clean_loaded_content():
    p = plan((load(0), ret(1)))
    a = obj(p)
    pointer = ptrseed(p, a)
    r = run(
        p,
        (a,),
        (pointer,),
        (memseed(a, label="", value=42),),
        (Seed(pointer.node_id, Labels(("ADDRESS",))),),
    )
    loaded = fact(r, nodes(p, "Load")[0].node_id)
    assert loaded.labels == Labels()
    assert loaded.address_labels.explicit == ("ADDRESS",)
    returned_value = fact(r, nodes(p, "Return")[0].node_id).value
    assert returned_value is not None
    assert returned_value.value == 42


def test_branch_selected_constants_are_control_not_explicit_flow():
    """if (x) y=1; else y=2; return y; depends on x via control."""
    p = build_ssa(
        snapshot(
            (
                Block(0, (), (ins(0, "m_jcnd", reg()),)),
                Block(
                    1,
                    (0,),
                    (ins(0, "m_mov", const(1), dest=reg(8, role="destination")),),
                ),
                Block(
                    2,
                    (0,),
                    (ins(0, "m_mov", const(2), dest=reg(8, role="destination")),),
                ),
                Block(3, (1, 2), (ins(0, "m_ret", reg(8)),)),
            )
        )
    )
    seeds = (seed_storage(p),)
    assert returned(p, analyze(p.graph, seeds)).labels.explicit == ()
    labels = implicit_returned(p, implicit_result(p, seeds))
    assert labels.explicit == ()
    assert labels.control == ("X",)


def test_loop_carried_copy_reaches_return():
    """Loop-carried y=y+x must preserve source x at the exit."""
    p = build_ssa(
        snapshot(
            (
                Block(
                    0, (), (ins(0, "m_mov", const(0), dest=reg(8, role="destination")),)
                ),
                Block(
                    1,
                    (0, 1),
                    (
                        ins(
                            0,
                            "m_add",
                            reg(8),
                            reg(role="right"),
                            reg(8, role="destination"),
                        ),
                    ),
                ),
                Block(2, (1,), (ins(0, "m_ret", reg(8)),)),
            )
        )
    )
    r = analyze(p.graph, (seed_storage(p),))
    assert returned(p, r).labels.explicit == ("X",)
    assert r.status == "complete_in_scope"


def test_unmodeled_call_return_is_not_reported_clean():
    """Without a summary, opaque(x) must remain unknown, not proven safe."""
    p = build_ssa(
        linear(
            (
                Instruction(
                    0,
                    "m_call",
                    (
                        const(4096, 64),
                        reg(role="argument"),
                        reg(8, role="destination"),
                    ),
                ),
                ins(1, "m_ret", reg(8)),
            )
        )
    )
    r = analyze(p.graph, (seed_storage(p),))
    out = returned(p, r)
    assert out.labels.unknown_provenance
    assert r.status == "partial"


def test_loop_header_feedback_is_modeled_without_unknown_frontier():
    """while (x) { x=x-1; } requires analyzing the loop-header predicate."""
    p = build_ssa(
        snapshot(
            (
                Block(0, (), ()),
                Block(1, (0, 2), (ins(0, "m_jcnd", reg()),)),
                Block(
                    2,
                    (1,),
                    (
                        ins(
                            0,
                            "m_sub",
                            reg(),
                            const(1, role="right"),
                            reg(role="destination"),
                        ),
                    ),
                ),
                Block(3, (1,), (ins(0, "m_ret", reg()),)),
            )
        )
    )
    r = implicit_result(p, (seed_storage(p),))
    assert implicit_returned(p, r).explicit == ("X",)
    assert implicit_returned(p, r).control == ("X",)
    assert not implicit_returned(p, r).unknown_provenance
    assert r.status == "complete_in_scope"
    assert not r.diagnostics and not r.frontier
    body = implicit_definitions(p, 2, "Binary")[0]
    assert implicit_facts(r)[body].control == ("X",)
    feedback = [rel for rel in r.relations if rel.origin == "loop_feedback"]
    assert len(feedback) == 1
    assert feedback[0].predicate_node_id == feedback[0].target_node_id
    assert feedback[0].branch_node_id and feedback[0].evidence_ids
    assert all(
        rel.predicate_node_id != rel.target_node_id
        for rel in r.relations
        if rel.origin != "loop_feedback"
    )
    bounded = implicit_result(p, (seed_storage(p),), ImplicitPolicy(1))
    assert bounded.status == "partial"
    assert "implicit_evaluation_budget" in bounded.diagnostics
    assert bounded.frontier
    unknown_seed = Seed(
        seed_storage(p).node_id,
        Labels(("X",), unknown_provenance=True),
    )
    unknown = implicit_result(p, (unknown_seed,))
    assert implicit_returned(p, unknown).unknown_provenance


def test_do_while_predicate_controls_next_body_without_crashing():
    """The backedge controls a later body execution, not a clean value verdict."""
    p = build_ssa(
        snapshot(
            (
                Block(0, (), ()),
                Block(
                    1,
                    (0, 2),
                    (ins(0, "m_mov", const(7), dest=reg(8, role="destination")),),
                ),
                Block(2, (1,), (ins(0, "m_jcnd", reg()),)),
                Block(3, (2,), (ins(0, "m_ret", reg(8)),)),
            )
        )
    )
    result = implicit_result(p, (seed_storage(p),))
    body_constant = implicit_definitions(p, 1, "Constant")[0]
    assert implicit_facts(result)[body_constant].control == ("X",)
    assert all(
        rel.predicate_node_id != rel.target_node_id or rel.origin == "loop_feedback"
        for rel in result.relations
    )


def test_nested_loop_predicates_keep_both_control_sources():
    """Both independent loop conditions can govern the innermost assignment."""
    p = build_ssa(
        snapshot(
            (
                Block(0, (), ()),
                Block(1, (0, 5), (ins(0, "m_jcnd", reg()),)),
                Block(2, (1, 4), (ins(0, "m_jcnd", reg(16)),)),
                Block(
                    3,
                    (2,),
                    (ins(0, "m_mov", const(7), dest=reg(8, role="destination")),),
                ),
                Block(4, (3,), (ins(0, "m_goto", reg(16)),)),
                Block(5, (2,), (ins(0, "m_goto", reg()),)),
                Block(6, (1,), (ins(0, "m_ret", reg(8)),)),
            )
        )
    )
    seeds = tuple(
        sorted((seed_storage(p), seed_storage(p, 16, "Y")), key=lambda s: s.node_id)
    )
    result = implicit_result(p, seeds)
    body_constant = implicit_definitions(p, 3, "Constant")[0]
    assert set(implicit_facts(result)[body_constant].control) == {"X", "Y"}
    assert all(
        rel.predicate_node_id != rel.target_node_id or rel.origin == "loop_feedback"
        for rel in result.relations
    )
