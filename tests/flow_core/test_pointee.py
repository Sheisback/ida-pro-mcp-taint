"""Pointee source contracts and byte semantics; fixtures are never executed."""

from dataclasses import replace

import pytest

from ida_pro_mcp.flow_core import ContractError
from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
from ida_pro_mcp.flow_core.pointee import PointeeSeed, bind_pointee_sources
from ida_pro_mcp.flow_core.states import ByteRange, Labels
from test_memory import FLAT, const, load, plan, reg, ret, store


def fixture(instructions):
    base = build_memory_graph(plan(instructions).program.graph.snapshot)
    memory = min(
        (n for n in base.graph.nodes if n.kind in {"Load", "Store"}),
        key=lambda n: next(
            d.order for d in base.program.definitions if d.node_id == n.node_id
        ),
    )
    pointer = next(
        n for n in base.graph.nodes if n.node_id == memory.memory_operands.address
    )
    return base, pointer.node_id


def source(pointer, start=0, end=8, label="user"):
    return PointeeSeed(
        pointer, ByteRange(start, end), Labels((label,)), "analyst_assumed_exact"
    )


def test_partial_overwrite_preserves_only_tail():
    base, pointer = fixture([store(0, const(0, 32)), load(1, bits=64), ret(2, bits=64)])
    bound, seeds = bind_pointee_sources(base, (source(pointer),))
    from ida_pro_mcp.flow_core.memory_analysis import analyze_memory

    result = analyze_memory(
        bound.plan, bound.result.objects, value_seeds=seeds, policy=FLAT
    )
    fact = next(
        f
        for f in result.facts
        if f.node_id == next(n.node_id for n in bound.graph.nodes if n.kind == "Load")
    )
    assert fact.labels.explicit == ("user",)
    assert [
        (r.label, r.bit_offset, r.width_bits) for r in fact.explicit_bit_ranges
    ] == [("user", 32, 32)]
    # A second load reads only the cleared prefix.
    base, pointer = fixture([store(0, const(0, 32)), load(1, bits=32), ret(2, bits=32)])
    bound, seeds = bind_pointee_sources(base, (source(pointer),))
    result = analyze_memory(
        bound.plan, bound.result.objects, value_seeds=seeds, policy=FLAT
    )
    assert (
        next(
            f
            for f in result.facts
            if f.node_id
            == next(n.node_id for n in bound.graph.nodes if n.kind == "Load")
        ).labels.explicit
        == ()
    )


def test_identity_independent_of_labels_and_replayable():
    base, pointer = fixture([load(0), ret(1)])
    a, sa = bind_pointee_sources(base, (source(pointer),))
    b, sb = bind_pointee_sources(base, (source(pointer, label="other"),))
    assert a == b
    assert sa[0].node_id == sb[0].node_id
    assert sa != sb
    assert bind_pointee_sources(base, (source(pointer),)) == (a, sa)
    obj = next(
        o
        for o in a.graph.objects
        if o.object_id
        == a.plan.program.pointee_bindings[0].pointer.candidates[0].object_id
    )
    assert not obj.disjoint and obj.size_bytes is None
    node = next(n for n in a.graph.nodes if n.operation == "pointee_source")
    assert not node.inputs
    assert any(
        e.source == pointer
        and e.target == node.node_id
        and e.kind == "address_dependency"
        for e in a.graph.edges
    )


def test_reject_overlap_budget_and_nonexplicit_labels():
    base, pointer = fixture([load(0), ret(1)])
    with pytest.raises(ContractError):
        bind_pointee_sources(base, (source(pointer), source(pointer, 4, 12)))
    with pytest.raises(ContractError):
        source(pointer, end=513)
    with pytest.raises(ContractError):
        replace(source(pointer), labels=Labels(control=("control",)))
    with pytest.raises(ContractError):
        bind_pointee_sources(base, tuple(source(pointer, i, i + 1) for i in range(17)))


def test_derived_binding_rejects_unresolved_input():
    base, _ = fixture([load(0, bits=64), ret(1, bits=64)])
    pointer = next(n.node_id for n in base.graph.nodes if n.kind == "Load")
    with pytest.raises(ContractError):
        bind_pointee_sources(
            base,
            (replace(source(pointer), binding_mode="require_program_derived_exact"),),
        )


def test_loaded_pointer_source_is_after_load():
    base, _ = fixture(
        [
            load(0, out=128, bits=64),
            load(1, out=256, address=reg(128, role="right")),
            ret(2, offset=256),
        ]
    )
    pointer = next(
        n.node_id for n in base.graph.nodes if n.kind == "Load" and n.width_bits == 64
    )
    bound, seeds = bind_pointee_sources(base, (source(pointer),))
    definitions = {d.node_id: d for d in bound.plan.program.definitions}
    assert definitions[seeds[0].node_id].order == definitions[pointer].order + 1


def test_sources_never_taint_pointer_values():
    base, pointer = fixture([load(0), ret(1)])
    bound, seeds = bind_pointee_sources(base, (source(pointer),))
    from ida_pro_mcp.flow_core.memory_analysis import analyze_memory

    result = analyze_memory(
        bound.plan, bound.result.objects, value_seeds=seeds, policy=FLAT
    )
    facts = {f.node_id: f for f in result.facts}
    assert facts[pointer].labels.explicit == ()
    loaded = next(n.node_id for n in bound.graph.nodes if n.kind == "Load")
    assert facts[loaded].labels.explicit == ("user",)


def test_loaded_pointer_does_not_retroactively_taint_its_load():
    base, _ = fixture(
        [
            load(0, out=128, bits=64),
            load(1, out=256, address=reg(128, role="right")),
            ret(2, offset=256),
        ]
    )
    pointer = next(
        n.node_id for n in base.graph.nodes if n.kind == "Load" and n.width_bits == 64
    )
    bound, seeds = bind_pointee_sources(base, (source(pointer),))
    from ida_pro_mcp.flow_core.memory_analysis import analyze_memory

    result = analyze_memory(
        bound.plan, bound.result.objects, value_seeds=seeds, policy=FLAT
    )
    facts = {f.node_id: f for f in result.facts}
    assert facts[pointer].labels.explicit == ()
    loaded = next(
        n.node_id for n in bound.graph.nodes if n.kind == "Load" and n.width_bits == 8
    )
    assert facts[loaded].labels.explicit == ("user",)


def test_reject_source_load_in_cycle():
    from ida_pro_mcp.flow_core.contracts import Block

    snapshot = plan(
        [],
        blocks=(
            Block(0, (), ()),
            Block(1, (0, 1), (load(0, bits=64), ret(1, bits=64))),
        ),
    ).program.graph.snapshot
    base = build_memory_graph(snapshot)
    pointer = next(n.node_id for n in base.graph.nodes if n.kind == "Load")
    with pytest.raises(ContractError, match="cycle"):
        bind_pointee_sources(base, (source(pointer),))


def test_copy_and_phi_keep_content_labels():
    from ida_pro_mcp.flow_core.contracts import Block, Instruction

    blocks = (
        Block(0, (), (load(0, out=128),)),
        Block(
            1,
            (0,),
            (Instruction(0, "m_mov", (reg(128, 8), reg(256, 8, "destination"))),),
        ),
        Block(
            2, (0,), (Instruction(0, "m_mov", (const(0), reg(256, 8, "destination"))),)
        ),
        Block(3, (1, 2), (ret(0, offset=256),)),
    )
    base = build_memory_graph(plan([], blocks=blocks).program.graph.snapshot)
    pointer = next(
        n.node_id
        for n in base.graph.nodes
        if n.kind == "InputValue" and n.width_bits == 64
    )
    bound, seeds = bind_pointee_sources(base, (source(pointer),))
    from ida_pro_mcp.flow_core.memory_analysis import analyze_memory

    result = analyze_memory(
        bound.plan, bound.result.objects, value_seeds=seeds, policy=FLAT
    )
    facts = {f.node_id: f for f in result.facts}
    merged = next(n for n in bound.graph.nodes if n.kind == "Phi")
    assert facts[merged.node_id].labels.explicit == ("user",)


def test_strict_wire_contract_and_checkpoint():
    base, pointer = fixture([load(0), ret(1)])
    seed = source(pointer)
    assert PointeeSeed.from_data(seed.to_data()) == seed
    for key, value in (
        ("schema_version", 2),
        ("point", "function_entry"),
        ("kind", "value"),
        ("binding_mode", "guess"),
    ):
        with pytest.raises(ContractError):
            PointeeSeed.from_data({**seed.to_data(), key: value})
    calls = []
    bind_pointee_sources(base, (seed,), checkpoint=lambda: calls.append(True))
    assert calls


def test_public_seeded_replay_and_implicit_report_byte_tail():
    from ida_pro_mcp.flow_core.memory_graph import analyze_seeded_memory
    from ida_pro_mcp.flow_core.implicit_analysis import analyze_implicit

    base, pointer = fixture([store(0, const(0, 32)), load(1, bits=64), ret(2, bits=64)])
    bound, seeds = bind_pointee_sources(base, (source(pointer),))
    loaded = next(n.node_id for n in bound.graph.nodes if n.kind == "Load")
    for result in (
        analyze_seeded_memory(bound, seeds),
        analyze_implicit(bound.program, seeds, memory_model=bound),
    ):
        fact = next(f for f in result.facts if f.node_id == loaded)
        assert [
            (r.label, r.bit_offset, r.width_bits) for r in fact.explicit_bit_ranges
        ] == [("user", 32, 32)]


def test_program_derived_entry_binding_reuses_object():
    base, pointer = fixture([load(0), ret(1)])
    known = next(f.pointer for f in base.result.facts if f.node_id == pointer)
    bound, seeds = bind_pointee_sources(
        base, (replace(source(pointer), binding_mode="require_program_derived_exact"),)
    )
    binding = bound.plan.program.pointee_bindings[0]
    assert binding.pointer == known
    node = next(n for n in bound.graph.nodes if n.node_id == seeds[0].node_id)
    evidence = next(
        e for e in bound.graph.evidence if e.evidence_id == node.evidence_ids[0]
    )
    assert evidence.rule_id == "derived-pointee-range-v1"
    assert evidence.assumptions == (
        "analyst designates these bytes as explicit taint at the source point",
    )


def test_distinct_pointer_views_do_not_claim_noalias():
    from ida_pro_mcp.flow_core.memory_graph import analyze_seeded_memory

    base, _ = fixture(
        [
            load(0, out=128, bits=64),
            load(1, out=256, bits=64, address=reg(512, role="right")),
            store(2, const(0, 32), address=reg(256, role="destination")),
            load(3, out=320, bits=32, address=reg(128, role="right")),
            ret(4, offset=320, bits=32),
        ]
    )
    pointers = sorted(
        n.node_id for n in base.graph.nodes if n.kind == "Load" and n.width_bits == 64
    )
    bound, seeds = bind_pointee_sources(base, tuple(source(p) for p in pointers))
    result = analyze_seeded_memory(bound, seeds)
    loaded = next(
        n.node_id for n in bound.graph.nodes if n.kind == "Load" and n.width_bits == 32
    )
    fact = next(f for f in result.facts if f.node_id == loaded)
    assert fact.labels.explicit == ("user",)
    assert all(
        not o.disjoint for o in bound.graph.objects if o.key.startswith("pointee:")
    )
    assert any(d.precision == "may_alias" for d in result.dependencies)


def test_multiple_disjoint_ranges_share_one_pointer_object():
    from ida_pro_mcp.flow_core.memory_graph import analyze_seeded_memory

    base, pointer = fixture([load(0, bits=64), ret(1, bits=64)])
    sources = (source(pointer, 0, 4, "first"), source(pointer, 4, 8, "second"))
    bound, seeds = bind_pointee_sources(base, sources)
    assert (
        len({b.pointer.candidates[0].object_id for b in bound.program.pointee_bindings})
        == 1
    )
    result = analyze_seeded_memory(bound, seeds)
    loaded = next(n.node_id for n in bound.graph.nodes if n.kind == "Load")
    fact = next(f for f in result.facts if f.node_id == loaded)
    assert [
        (r.label, r.bit_offset, r.width_bits) for r in fact.explicit_bit_ranges
    ] == [("first", 0, 32), ("second", 32, 32)]


def test_known_null_loaded_pointer_cannot_be_assumed_nonnull():
    base, _ = fixture([store(0, const(0, 64)), load(1, bits=64), ret(2, bits=64)])
    pointer = next(n.node_id for n in base.graph.nodes if n.kind == "Load")
    with pytest.raises(ContractError, match="Null"):
        bind_pointee_sources(base, (source(pointer),))


def test_source_requests_are_order_independent():
    base, pointer = fixture([load(0, bits=64), ret(1, bits=64)])
    sources = (source(pointer, 0, 4, "a"), source(pointer, 4, 8, "b"))
    assert bind_pointee_sources(base, sources) == bind_pointee_sources(
        base, sources[::-1]
    )


@pytest.mark.parametrize("endian,remaining_bit", [("little", 32), ("big", 0)])
def test_source_partial_clear_maps_memory_bytes_to_value_endianness(
    endian, remaining_bit
):
    from ida_pro_mcp.flow_core.memory_graph import analyze_seeded_memory

    snapshot = plan(
        [store(0, const(0, 32)), load(1, bits=64), ret(2, bits=64)], endian
    ).program.graph.snapshot
    base = build_memory_graph(snapshot)
    loaded = next(n for n in base.graph.nodes if n.kind == "Load")
    bound, seeds = bind_pointee_sources(base, (source(loaded.memory_operands.address),))
    result = analyze_seeded_memory(bound, seeds)
    fact = next(f for f in result.facts if f.node_id == loaded.node_id)
    assert [
        (span.label, span.bit_offset, span.width_bits)
        for span in fact.explicit_bit_ranges
    ] == [("user", remaining_bit, 32)]


def test_memory_phi_keeps_source_on_branch_that_did_not_overwrite():
    from ida_pro_mcp.flow_core.contracts import Block
    from ida_pro_mcp.flow_core.memory_graph import analyze_seeded_memory

    blocks = (
        Block(0, (), ()),
        Block(1, (0,), (store(0, const(0, 32)), load(1, out=128, bits=32))),
        Block(2, (0,), (load(0, out=192, bits=32),)),
        Block(3, (1, 2), (load(0, out=256, bits=64), ret(1, 256, 64))),
    )
    base = build_memory_graph(plan([], blocks=blocks).program.graph.snapshot)
    pointer = next(
        n.memory_operands.address for n in base.graph.nodes if n.kind == "Store"
    )
    bound, seeds = bind_pointee_sources(base, (source(pointer),))
    result = analyze_seeded_memory(bound, seeds)
    facts = {f.node_id: f for f in result.facts}
    positions = {d.node_id: d.block for d in bound.program.definitions}
    loads = {
        positions[n.node_id]: facts[n.node_id]
        for n in bound.graph.nodes
        if n.kind == "Load"
    }
    assert loads[1].labels.explicit == ()
    assert loads[2].labels.explicit == ("user",)
    assert [(r.bit_offset, r.width_bits) for r in loads[3].explicit_bit_ranges] == [
        (0, 64)
    ]
    assert any(phi.block == 3 for phi in bound.plan.phis)


def test_unknown_effect_after_source_is_not_reported_clean():
    from ida_pro_mcp.flow_core.contracts import Instruction
    from ida_pro_mcp.flow_core.memory_graph import analyze_seeded_memory

    base, pointer = fixture(
        [
            load(0, bits=64),
            Instruction(1, "m_ext", ()),
            load(2, out=256, bits=64),
            ret(3, 256, 64),
        ]
    )
    bound, seeds = bind_pointee_sources(base, (source(pointer),))
    result = analyze_seeded_memory(bound, seeds)
    target = next(n.node_id for n in bound.graph.nodes if n.kind == "Return")
    fact = next(f for f in result.facts if f.node_id == target)
    assert result.status == "partial" and fact.labels.unknown_provenance
    assert "user" in fact.labels.explicit or fact.labels.any_explicit_source
    assert "unknown_call_or_write" in result.diagnostics
