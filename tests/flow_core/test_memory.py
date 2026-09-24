"""Independent byte/alias expectations. Never executes fixture binaries."""

from dataclasses import replace
import json
from pathlib import Path

import pytest

from ida_pro_mcp.flow_core import ContractError, canonical_json, digest
from ida_pro_mcp.flow_core.analysis import Seed
from ida_pro_mcp.flow_core.contracts import (
    Block,
    Diagnostic,
    FunctionInput,
    Instruction,
    MemoryObject,
    Operand,
    Snapshot,
)
from ida_pro_mcp.flow_core.memory import (
    MemoryPlan,
    MemoryPolicy,
    MemoryResult,
    MemorySeed,
    PointerSeed,
    alias_relation,
    build_memory_plan,
)
from ida_pro_mcp.flow_core.memory_analysis import analyze_memory
from ida_pro_mcp.flow_core.ssa import build_ssa
from ida_pro_mcp.flow_core.states import (
    BitValue,
    ByteRange,
    Labels,
    PointerCandidate,
    PointerValue,
    StorageLocation,
)

ROOT = Path(__file__).resolve().parents[2]
FLAT = MemoryPolicy(flat_segment_assumption="hand-authored flat ram fixture")


def reg(offset=0, bits=64, role="left"):
    return Operand(
        "storage",
        bits,
        storage=StorageLocation("microregister", "bank", offset, bits),
        role=role,
    )


def const(value, bits=8, role="left"):
    return Operand("constant", bits, constant=value, role=role)


def load(index, out=128, bits=8, address=None):
    return Instruction(
        index,
        "m_ldx",
        (const(0, 16), address or reg(role="right"), reg(out, bits, "destination")),
    )


def store(index, data=None, address=None):
    return Instruction(
        index,
        "m_stx",
        (data or const(0), const(0, 16, "right"), address or reg(role="destination")),
    )


def ret(index, offset=128, bits=8):
    return Instruction(index, "m_ret", (reg(offset, bits),))


def plan(instructions, endian="little", blocks=None):
    original = Snapshot.from_data(
        json.loads(
            (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
        )["snapshot"]
    )
    blocks = blocks or (Block(0, (), tuple(instructions)),)
    blocks = tuple(
        replace(
            b, successors=tuple(c.index for c in blocks if b.index in c.predecessors)
        )
        for b in blocks
    )
    function = FunctionInput("memory-fixture", 0, blocks)
    identity = replace(
        original.identity,
        function_id=function.function_id,
        input_digest=digest(function),
        environment=replace(original.identity.environment, data_endian=endian),
    )
    return build_memory_plan(
        build_ssa(Snapshot(identity, function, identity.snapshot_id))
    )


def obj(p, key="A", size=8, singleton=True, disjoint=True, kind="argument"):
    return MemoryObject(
        p.program.graph.snapshot.snapshot_id,
        key,
        "ram",
        size,
        kind,
        singleton,
        "hand singleton assumption" if singleton else None,
        disjoint,
        "hand disjoint identities" if disjoint else None,
    )


def ptrseed(p, o, register=0, offset=0):
    entry = next(e for e in p.program.entry_storage if e.storage.bit_offset == register)
    return PointerSeed(
        entry.node_id,
        PointerValue(
            "ram", entry.storage.width_bits, (PointerCandidate(o.object_id, offset),)
        ),
    )


def memseed(o, start=0, end=1, label="X", value=None):
    return MemorySeed(
        o.object_id,
        ByteRange(start, end),
        BitValue(8 * (end - start), value),
        Labels((label,) if label else ()),
    )


def run(p, objects, pointers, memory=(), values=(), policy=FLAT):
    return analyze_memory(
        p,
        tuple(sorted(objects, key=lambda o: o.object_id)),
        tuple(sorted(pointers, key=lambda s: s.node_id)),
        tuple(
            sorted(
                memory, key=lambda s: (s.object_id, s.interval.start, s.interval.end)
            )
        ),
        tuple(sorted(values, key=lambda s: s.node_id)),
        policy,
    )


def fact(result, nid):
    return next(f for f in result.facts if f.node_id == nid)


def nodes(p, kind):
    definitions = {d.node_id: d for d in p.program.definitions}
    return sorted(
        (n for n in p.program.graph.nodes if n.kind == kind),
        key=lambda n: (definitions[n.node_id].block, definitions[n.node_id].order),
    )


def test_m01_m02_before_store_after_no_backwards_taint():
    p = plan((load(0), store(1), load(2, 136), ret(3, 136)))
    a = obj(p)
    pointer = ptrseed(p, a)
    r = run(
        p,
        (a,),
        (pointer,),
        (memseed(a),),
        (Seed(pointer.node_id, Labels(("ADDRESS",))),),
    )
    before, after = nodes(p, "Load")
    assert fact(r, before.node_id).labels.explicit == ("X",)
    assert fact(r, after.node_id).labels == Labels()
    assert fact(r, after.node_id).value.value == 0
    assert fact(r, after.node_id).address_labels.explicit == ("ADDRESS",)
    assert "ADDRESS" not in fact(r, before.node_id).labels.explicit
    assert r.status == "complete_in_scope"
    assert all(d.target != before.node_id for d in r.dependencies)
    assert any(d.target == after.node_id for d in r.dependencies)
    assert MemoryPlan.from_json(canonical_json(p)) == p
    assert MemoryResult.from_json(canonical_json(r)) == r


@pytest.mark.parametrize("endian,expected", [("little", 0xAB12), ("big", 0x12CD)])
def test_m03_m07_partial_store_and_endian_width(endian, expected):
    p = plan((store(0, const(0x12)), load(1, bits=16), ret(2, bits=16)), endian)
    a = obj(p)
    r = run(p, (a,), (ptrseed(p, a),), (memseed(a, 0, 2, value=0xABCD),))
    out = fact(r, nodes(p, "Return")[0].node_id)
    assert out.value.value == expected
    assert out.labels.explicit == ("X",)
    assert not out.labels.unknown_provenance


def test_m04_pointer_copy_alias_and_memory_not_pointer_label():
    p = plan(
        (
            Instruction(0, "m_mov", (reg(), reg(64, 64, "destination"))),
            store(1, reg(192, 8), reg(64, 64, "destination")),
            load(2),
            ret(3),
        )
    )
    a = obj(p)
    data = next(e for e in p.program.entry_storage if e.storage.bit_offset == 192)
    seed = ptrseed(p, a)
    r = run(p, (a,), (seed,), (), (Seed(data.node_id, Labels(("DATA",))),))
    assert fact(r, nodes(p, "Return")[0].node_id).labels.explicit == ("DATA",)
    assert not fact(r, seed.node_id).labels.explicit
    assert next(
        access
        for access in r.accesses
        if access.node_id == nodes(p, "Store")[0].node_id
    ).strong_update


def test_m05_two_argument_objects_may_alias_without_disjoint_proof():
    p = plan((store(0, const(9)), load(1, address=reg(64, 64, "right")), ret(2)))
    a, b = obj(p, "A", disjoint=False), obj(p, "B", disjoint=False)
    assert alias_relation(a, ByteRange(0, 1), b, ByteRange(0, 1)) == "may_alias"
    r = run(p, (a, b), (ptrseed(p, a), ptrseed(p, b, 64)), (memseed(b),))
    out = fact(r, nodes(p, "Return")[0].node_id)
    assert out.labels.explicit == ("X",)
    assert out.labels.unknown_provenance


def test_m06_multiple_pointer_candidates_force_weak_update():
    p = plan((store(0), load(1), ret(2)))
    a, b = obj(p, "A"), obj(p, "B")
    seed = ptrseed(p, a)
    pointer = PointerValue(
        "ram",
        64,
        tuple(
            sorted(
                (PointerCandidate(a.object_id, 0), PointerCandidate(b.object_id, 0)),
                key=lambda c: c.object_id,
            )
        ),
    )
    r = run(
        p,
        (a, b),
        (replace(seed, pointer=pointer),),
        (memseed(a, label="A"), memseed(b, label="B")),
    )
    assert fact(r, nodes(p, "Return")[0].node_id).labels.explicit == ("A", "B")
    assert not any(access.strong_update for access in r.accesses)


def test_m10_summary_object_never_strong_updates():
    p = plan((store(0), load(1), ret(2)))
    a = obj(p, singleton=False)
    r = run(p, (a,), (ptrseed(p, a),), (memseed(a),))
    assert fact(r, nodes(p, "Return")[0].node_id).labels.explicit == ("X",)
    assert not any(access.strong_update for access in r.accesses)


def test_d05_unknown_offset_write_keeps_disjoint_object_clean():
    p = plan(
        (
            store(0, reg(192, 8)),
            load(1, address=reg(64, 64, "right")),
            load(2, 136, address=reg(256, 64, "right")),
            ret(3, 136),
        )
    )
    a, b = obj(p, "A"), obj(p, "B")
    unknown = ptrseed(p, a, offset=None)
    data = next(e for e in p.program.entry_storage if e.storage.bit_offset == 192)
    r = run(
        p,
        (a, b),
        (unknown, ptrseed(p, a, 64), ptrseed(p, b, 256)),
        (memseed(a, value=1), memseed(b, label="", value=7)),
        (Seed(data.node_id, Labels(("WRITE",))),),
    )
    first, second = nodes(p, "Load")
    assert fact(r, first.node_id).labels.unknown_provenance
    assert "WRITE" in fact(r, first.node_id).labels.explicit
    assert fact(r, second.node_id).labels == Labels()
    assert fact(r, second.node_id).value.value == 7
    assert r.status == "partial"


def test_m08_pointer_store_reload_then_dereference():
    p = plan(
        (
            store(0, reg(64, 64)),
            load(1, out=128, bits=64),
            load(2, out=192, address=reg(128, 64, "right")),
            ret(3, 192),
        )
    )
    slot, target = obj(p, "slot"), obj(p, "target")
    r = run(
        p,
        (slot, target),
        (ptrseed(p, slot), ptrseed(p, target, 64)),
        (memseed(target, value=42),),
    )
    first, second = nodes(p, "Load")
    assert fact(r, first.node_id).pointer == PointerValue(
        "ram", 64, (PointerCandidate(target.object_id, 0),)
    )
    assert fact(r, second.node_id).value.value == 42
    assert fact(r, second.node_id).labels.explicit == ("X",)
    assert not fact(r, first.node_id).labels.explicit


def test_d07_iteration_budget_and_sources_are_not_reused():
    p = plan((load(0), ret(1)))
    a = obj(p)
    first = run(
        p, (a,), (ptrseed(p, a),), (memseed(a),), policy=replace(FLAT, max_iterations=1)
    )
    assert first.status == "partial" and first.frontier
    assert fact(first, nodes(p, "Return")[0].node_id).labels.any_explicit_source
    x = run(p, (a,), (ptrseed(p, a),), (memseed(a, label="X"),))
    y = run(p, (a,), (ptrseed(p, a),), (memseed(a, label="Y"),))
    assert x.plan_digest == y.plan_digest and x.cache_key != y.cache_key
    assert fact(x, nodes(p, "Return")[0].node_id).labels.explicit == ("X",)
    assert fact(y, nodes(p, "Return")[0].node_id).labels.explicit == ("Y",)


def test_store_roles_reject_ambiguous_and_keep_data_address_edges_separate():
    p = plan((store(0, reg(128, 8)),))
    node = nodes(p, "Store")[0]
    edges = [e for e in p.program.graph.edges if e.target == node.node_id]
    assert {e.kind for e in edges if e.source == node.memory_operands.data} == {
        "memory_data_dependency"
    }
    assert {e.kind for e in edges if e.source == node.memory_operands.address} == {
        "address_dependency"
    }
    with pytest.raises(ContractError, match="role"):
        replace(node, inputs=tuple(reversed(node.inputs)))
    with pytest.raises(ContractError, match="roles"):
        plan(
            (
                Instruction(
                    0,
                    "m_stx",
                    (const(0), const(0, 16, "argument"), reg(role="destination")),
                ),
            )
        )


def test_seeded_argument_memory_reaches_other_may_alias_argument_before_writes():
    p = plan((load(0, address=reg(64, 64, "right")), ret(1)))
    a, b = obj(p, "A", disjoint=False), obj(p, "B", disjoint=False)
    r = run(p, (a, b), (ptrseed(p, b, 64),), (memseed(a),))
    assert "X" in fact(r, nodes(p, "Return")[0].node_id).labels.explicit


def test_memory_phi_branch_join_and_branch_local_observations():
    blocks = (
        Block(0, (), ()),
        Block(1, (0,), (store(0, reg(192, 8)), load(1))),
        Block(2, (0,), (store(0, const(9)), load(1, 136))),
        Block(3, (1, 2), (load(0, 144), ret(1, 144))),
    )
    p = plan((), blocks=blocks)
    a = obj(p)
    data = next(e for e in p.program.entry_storage if e.storage.bit_offset == 192)
    r = run(p, (a,), (ptrseed(p, a),), (), (Seed(data.node_id, Labels(("X",))),))
    true, false, merged = nodes(p, "Load")
    assert fact(r, true.node_id).labels.explicit == ("X",)
    assert fact(r, false.node_id).labels.explicit == ()
    assert fact(r, false.node_id).value.value == 9
    assert fact(r, merged.node_id).labels.explicit == ("X",)
    phi = next(phi for phi in p.phis if phi.block == 3)
    exits = {b.block: b.exit for b in p.blocks}
    assert tuple((i.predecessor, i.version_id) for i in phi.inputs) == (
        (1, exits[1]),
        (2, exits[2]),
    )
    assert len({v.version_id for v in p.versions}) == len(p.versions)
    assert MemoryPlan.from_json(canonical_json(p)) == p
    with pytest.raises(ContractError, match="mapping"):
        bad = replace(
            phi,
            inputs=(
                replace(phi.inputs[0], version_id=phi.inputs[1].version_id),
                phi.inputs[1],
            ),
        )
        replace(p, phis=tuple(bad if old.block == 3 else old for old in p.phis))


def test_loop_memory_versions_remain_static_and_fixed_point_finishes():
    blocks = (
        Block(0, (), ()),
        Block(1, (0, 1), (load(0), store(1, const(0)))),
        Block(2, (1,), (load(0, 136), ret(1, 136))),
    )
    p = plan((), blocks=blocks)
    a = obj(p)
    r = run(p, (a,), (ptrseed(p, a),), (memseed(a),))
    header, after = nodes(p, "Load")
    assert fact(r, header.node_id).labels.explicit == ("X",)
    assert (
        fact(r, after.node_id).value.value == 0
        and not fact(r, after.node_id).labels.explicit
    )
    assert not r.frontier and r.iterations < FLAT.max_iterations
    assert len(p.versions) == 4  # initial, two block phis, one static store
    assert run(p, (a,), (ptrseed(p, a),), (memseed(a),)) == r


def test_pointer_phi_ab_store_is_weak_and_both_candidates_survive():
    blocks = (
        Block(0, (), ()),
        Block(
            1, (0,), (Instruction(0, "m_mov", (reg(), reg(256, 64, "destination"))),)
        ),
        Block(
            2, (0,), (Instruction(0, "m_mov", (reg(64), reg(256, 64, "destination"))),)
        ),
        Block(
            3,
            (1, 2),
            (
                store(0, address=reg(256, 64, "destination")),
                load(1, address=reg(256, 64, "right")),
                ret(2),
            ),
        ),
    )
    p = plan((), blocks=blocks)
    a, b = obj(p, "A"), obj(p, "B")
    r = run(
        p,
        (a, b),
        (ptrseed(p, a), ptrseed(p, b, 64)),
        (memseed(a, label="A"), memseed(b, label="B")),
    )
    assert fact(r, nodes(p, "Return")[0].node_id).labels.explicit == ("A", "B")
    store_access = next(
        x for x in r.accesses if x.node_id == nodes(p, "Store")[0].node_id
    )
    assert len(store_access.candidates) == 2 and not store_access.strong_update


def test_unknown_write_havoc_reaches_later_return():
    p = plan((Instruction(0, "m_unmodeled_write", ()), load(1), ret(2)))
    a = obj(p)
    r = run(p, (a,), (ptrseed(p, a),), (memseed(a),))
    out = fact(r, nodes(p, "Return")[0].node_id)
    assert out.labels.unknown_provenance and out.labels.explicit == ("X",)
    assert r.status == "partial"


def test_partial_pointer_overwrite_never_reconstructs_exact_target():
    p = plan(
        (
            store(0, reg(64, 64)),
            store(1, const(0)),
            load(2, out=128, bits=64),
            ret(3, bits=64),
        )
    )
    slot, target = obj(p, "slot"), obj(p, "target")
    r = run(p, (slot, target), (ptrseed(p, slot), ptrseed(p, target, 64)))
    out = fact(r, nodes(p, "Return")[0].node_id)
    assert out.pointer.any_compatible_location and out.pointer.may_be_null
    assert out.labels.unknown_provenance and r.status == "partial"


def test_pointer_constant_offset_and_symbolic_offset_widening():
    p = plan(
        (
            Instruction(
                0, "m_add", (reg(), const(1, 64, "right"), reg(64, 64, "destination"))
            ),
            load(1, address=reg(64, 64, "right")),
            ret(2),
        )
    )
    a = obj(p)
    r = run(p, (a,), (ptrseed(p, a),), (memseed(a, 1, 2, value=17),))
    assert fact(r, nodes(p, "Return")[0].node_id).value.value == 17
    assert r.accesses[0].candidates[0].interval == ByteRange(1, 2)
    p = plan(
        (
            Instruction(
                0, "m_add", (reg(), reg(256, 64, "right"), reg(64, 64, "destination"))
            ),
            load(1, address=reg(64, 64, "right")),
            ret(2),
        )
    )
    a = obj(p)
    r = run(p, (a,), (ptrseed(p, a),), (memseed(a),))
    assert r.status == "partial" and r.accesses[0].unresolved
    assert fact(r, nodes(p, "Return")[0].node_id).labels.unknown_provenance


@pytest.mark.parametrize("mask", (1, 63))
def test_masked_bounded_array_index_keeps_possible_source_or_unknown(mask):
    """a[n & 1] may read either byte; a wide mask exceeds candidate budget."""
    instructions = (
        Instruction(
            0,
            "m_and",
            (reg(256, 32), const(mask, 32, "right"), reg(320, 32, "destination")),
        ),
        Instruction(1, "m_xdu", (reg(320, 32), reg(384, 64, "destination"))),
        Instruction(
            2,
            "m_mul",
            (reg(384, 64), const(4, 64, "right"), reg(448, 64, "destination")),
        ),
        Instruction(
            3, "m_add", (reg(0, 64), reg(448, 64, "right"), reg(64, 64, "destination"))
        ),
        load(4, address=reg(64, 64, "right")),
        ret(5),
    )
    p = plan(instructions)
    a = obj(p, size=8)
    b = obj(p, key="unrelated", size=8)
    r = run(
        p,
        (a, b),
        (ptrseed(p, a),),
        (
            memseed(a, 0, 1, value=7),
            memseed(a, 4, 5, label="", value=9),
            memseed(b, 0, 1, label="Y", value=3),
        ),
    )
    access = next(
        item for item in r.accesses if item.node_id == nodes(p, "Load")[0].node_id
    )
    out = fact(r, nodes(p, "Return")[0].node_id)
    if mask == 1:
        assert {(c.interval.start, c.interval.end) for c in access.candidates} == {
            (0, 1),
            (4, 5),
        }
        assert access.precision == "may_alias" and not access.unresolved
        assert {c.object_id for c in access.candidates} == {a.object_id}
        assert out.labels.explicit == ("X",)
        assert "Y" not in out.labels.explicit
        assert not out.labels.unknown_provenance
        assert r.status == "complete_in_scope"
    else:
        assert access.unresolved and r.status == "partial"
        assert out.labels.unknown_provenance


def test_private_stack_is_not_aliased_by_fixed_global_or_typed_entry():
    p = plan((load(0),))
    stack = obj(p, "current_frame", kind="stack", disjoint=True)
    typed = obj(p, "typed_input", kind="typed_entry", disjoint=False)
    other_typed = obj(p, "other_typed", kind="typed_entry", disjoint=False)
    global_object = obj(p, "fixed_global", kind="global", disjoint=False)
    uncertain = obj(p, "uncertain_input", kind="argument", disjoint=False)
    interval = ByteRange(0, 1)
    assert alias_relation(stack, interval, typed, interval) == "no_alias"
    assert alias_relation(typed, interval, stack, interval) == "no_alias"
    assert alias_relation(stack, interval, global_object, interval) == "no_alias"
    assert alias_relation(typed, interval, other_typed, interval) == "may_alias"
    assert alias_relation(stack, interval, uncertain, interval) == "may_alias"


def test_untyped_input_may_read_a_current_frame_spill_in_flat_binary_model():
    """A numeric input address can name a future stack slot without provenance proof."""
    p = plan(
        (
            store(0, data=reg(128, 8), address=reg(64, 64, "destination")),
            load(1, out=256, address=reg(0, 64, "right")),
            ret(2, offset=256),
        )
    )
    stack = obj(p, "current_frame", kind="stack", disjoint=True)
    incoming = obj(p, "untyped_incoming", kind="argument", disjoint=False)
    data = next(e for e in p.program.entry_storage if e.storage.bit_offset == 128)
    result = run(
        p,
        (stack, incoming),
        (ptrseed(p, incoming), ptrseed(p, stack, 64)),
        values=(Seed(data.node_id, Labels(("X",))),),
    )

    assert alias_relation(stack, ByteRange(0, 1), incoming, ByteRange(0, 1)) == "may_alias"
    assert any(
        dep.source == nodes(p, "Store")[0].node_id
        and dep.target == nodes(p, "Load")[0].node_id
        and dep.object_id == incoming.object_id
        and dep.precision == "may_alias"
        for dep in result.dependencies
    )
    observed = fact(result, nodes(p, "Return")[0].node_id).labels
    assert "X" in observed.explicit
    assert observed.unknown_provenance


def test_bounded_symbolic_store_weakly_updates_both_candidates():
    p = plan(
        (
            Instruction(
                0,
                "m_and",
                (reg(256, 32), const(1, 32, "right"), reg(320, 32, "destination")),
            ),
            Instruction(1, "m_xdu", (reg(320, 32), reg(384, 64, "destination"))),
            Instruction(
                2,
                "m_mul",
                (reg(384, 64), const(4, 64, "right"), reg(448, 64, "destination")),
            ),
            Instruction(
                3,
                "m_add",
                (reg(0, 64), reg(448, 64, "right"), reg(64, 64, "destination")),
            ),
            store(4, data=reg(640, 8), address=reg(64, 64, "destination")),
            load(5, out=128, address=reg(0, 64, "right")),
            load(6, out=136, address=reg(512, 64, "right")),
            ret(7),
        )
    )
    a = obj(p, size=8)
    data = next(e for e in p.program.entry_storage if e.storage.bit_offset == 640)
    result = run(
        p,
        (a,),
        (ptrseed(p, a), ptrseed(p, a, 512, 4)),
        (memseed(a, 0, 1, label="", value=7), memseed(a, 4, 5, label="", value=9)),
        values=(Seed(data.node_id, Labels(("WRITE",))),),
    )
    symbolic = next(
        a for a in result.accesses if a.node_id == nodes(p, "Store")[0].node_id
    )
    assert {c.interval.start for c in symbolic.candidates} == {0, 4}
    assert symbolic.precision == "may_alias" and not symbolic.strong_update
    loaded = nodes(p, "Load")
    assert all("WRITE" in fact(result, item.node_id).labels.explicit for item in loaded)
    assert result.status == "complete_in_scope"


def test_null_pointer_is_unresolved_not_clean_no_flow():
    p = plan((load(0), ret(1)))
    a = obj(p)
    seed = replace(ptrseed(p, a), pointer=PointerValue("ram", 64, may_be_null=True))
    r = run(p, (a,), (seed,))
    assert r.status == "partial"
    assert fact(r, nodes(p, "Return")[0].node_id).labels.unknown_provenance
    assert not any(access.strong_update for access in r.accesses)


def test_label_byte_candidate_budgets_preserve_unknown():
    p = plan((load(0), ret(1)))
    a, b = obj(p, "A"), obj(p, "B")
    seed = ptrseed(p, a)
    wide = replace(memseed(a), labels=Labels(("A", "B")))
    r = run(p, (a,), (seed,), (wide,), policy=replace(FLAT, max_labels=1))
    out = fact(r, nodes(p, "Return")[0].node_id)
    assert (
        out.labels.any_explicit_source
        and out.labels.unknown_provenance
        and r.status == "partial"
    )
    r = run(p, (a,), (seed,), (memseed(a, 0, 8),), policy=replace(FLAT, max_bytes=1))
    out = fact(r, nodes(p, "Return")[0].node_id)
    assert (
        out.labels.explicit == ("X",)
        and out.labels.unknown_provenance
        and r.status == "partial"
    )
    candidates = tuple(
        sorted(
            (PointerCandidate(a.object_id, 0), PointerCandidate(b.object_id, 0)),
            key=lambda c: c.object_id,
        )
    )
    seed = replace(seed, pointer=PointerValue("ram", 64, candidates))
    r = run(
        p,
        (a, b),
        (seed,),
        (memseed(a, label="A"), memseed(b, label="B")),
        policy=replace(FLAT, max_candidates=1),
    )
    assert set(fact(r, nodes(p, "Return")[0].node_id).labels.explicit) == {"A", "B"}
    assert r.status == "partial"


def test_memory_contract_failures_and_seed_validation():
    p = plan((load(0),))
    a = obj(p)
    with pytest.raises(ContractError, match="proof"):
        replace(a, singleton_evidence=None)
    with pytest.raises(ContractError, match="proof"):
        replace(a, disjoint_evidence=None)
    with pytest.raises(ContractError, match="extent"):
        run(p, (a,), (ptrseed(p, a),), (memseed(a, 0, 9),))
    with pytest.raises(ContractError, match="width"):
        run(
            p,
            (a,),
            (
                replace(
                    ptrseed(p, a),
                    pointer=PointerValue(
                        "ram", 32, (PointerCandidate(a.object_id, 0),)
                    ),
                ),
            ),
        )
    with pytest.raises(ContractError, match="Overlapping"):
        run(p, (a,), (ptrseed(p, a),), (memseed(a, 0, 2), memseed(a, 1, 3)))
    with pytest.raises(ContractError, match="Dangling"):
        replace(
            p,
            steps=(
                replace(
                    p.steps[0],
                    before="memory-v1:" + "0" * 64,
                    after="memory-v1:" + "0" * 64,
                ),
            ),
        )


def test_g003_memory_oracle_expectations_are_not_treated_as_engine_goldens():
    corpus = json.loads((ROOT / "tests/flow_fixtures/oracles/s0.json").read_text())
    cases = {c["oracle_id"]: c for c in corpus["cases"]}
    assert {"S0-PARTIAL", "S0-ALIAS", "S0-MERGE", "S0-OUTPUT", "S0-UNKNOWN"} <= set(
        cases
    )
    assert all(
        "hand-authored" in cases[k]["oracle_origin"]
        for k in ("S0-PARTIAL", "S0-ALIAS", "S0-MERGE")
    )
    assert (
        "p pointer value becomes X merely because its contents are X"
        in cases["S0-ALIAS"]["forbidden_relations"]
    )


def test_unknown_width_store_is_a_memory_havoc_boundary():
    p = plan(
        (store(0, Operand("global", None, address=4096, role="left")), load(1), ret(2))
    )
    a = obj(p)
    r = run(p, (a,), (ptrseed(p, a),), (memseed(a, value=7),))
    out = fact(r, nodes(p, "Return")[0].node_id)
    assert out.value.value is None and out.labels.unknown_provenance
    assert out.labels.explicit == ("X",) and r.status == "partial"
    assert any(s.effect == "havoc" for s in p.steps)


def test_pointer_cells_roundtrip_and_mixed_address_spaces_widen():
    from ida_pro_mcp.flow_core.states import MemoryCell, MemoryReference
    from ida_pro_mcp.flow_core import stable_id

    p = plan((load(0, bits=64),))
    a = obj(p)
    pointer = PointerValue("ram", 64, (PointerCandidate(a.object_id, 0),))
    cell = MemoryCell(
        MemoryReference(
            a.object_id, stable_id("memory", "test"), "ram", ByteRange(0, 8), "little"
        ),
        pointer,
        Labels(("POINTER",)),
    )
    assert MemoryCell.from_json(canonical_json(cell)) == cell
    other = replace(a, key="other-space", address_space="io")
    assert alias_relation(a, ByteRange(0, 1), other, ByteRange(0, 1)) == "no_alias"
    r = run(
        p,
        (a, other),
        (
            replace(
                ptrseed(p, a),
                pointer=PointerValue(
                    "*", 64, any_compatible_location=True, may_be_null=True
                ),
            ),
        ),
        (memseed(a), memseed(other, label="IO")),
    )
    assert {c.object_id for c in r.accesses[0].candidates} == {
        a.object_id,
        other.object_id,
    }
    assert set(fact(r, nodes(p, "Load")[0].node_id).labels.explicit) == {"X", "IO"}
    assert r.status == "partial"


def test_loaded_pointer_seed_is_rejected_instead_of_ignored():
    p = plan((load(0, bits=64),))
    a = obj(p)
    with pytest.raises(ContractError, match="memory seed"):
        run(p, (a,), (replace(ptrseed(p, a), node_id=nodes(p, "Load")[0].node_id),))


@pytest.mark.parametrize("arch", ("x86_64", "arm64"))
@pytest.mark.parametrize(
    "function",
    (
        "memory_before_after",
        "memory_alias",
        "memory_global_roundtrip",
        "memory_stack_roundtrip",
    ),
)
def test_actual_memory_receipts_independent_observations_and_fresh_hashes(
    arch, function
):
    import hashlib
    import runpy

    make = runpy.run_path(str(ROOT / "tests/flow_core/record_memory_receipts.py"))[
        "receipt"
    ]
    base = ROOT / "tests/flow_fixtures/manifests/memory"
    raw = json.loads((base / f"{arch}_{function}.json").read_text())
    expected = json.loads((base / f"{arch}_{function}_analysis.json").read_text())
    assert expected == make(arch, function)
    assert (
        raw["extractor_sha256"]
        == hashlib.sha256(
            (ROOT / "src/ida_pro_mcp/ida_mcp/flow/extractor.py").read_bytes()
        ).hexdigest()
    )
    assert (
        raw["script_sha256"]
        == hashlib.sha256(
            (ROOT / "scripts/flow_memory_extract.py").read_bytes()
        ).hexdigest()
    )
    assert raw["snapshot"]["identity"]["maturity"] == "MMAT_CALLS"
    assert raw["repeat_equal"] and raw["roundtrip_equal"] and not raw["target_executed"]
    assert (
        expected["repeat_equal"]
        and expected["roundtrip_equal"]
        and not expected["target_executed"]
    )
    observed = expected["load_observations"]
    if function == "memory_before_after":
        assert len(observed) == 2
        assert observed[0]["fact"]["labels"]["explicit"] == ["X"]
        assert observed[1]["fact"]["labels"]["explicit"] == []
        assert observed[1]["fact"]["value"]["value"] == 0
    else:
        assert len(observed) == 1
        assert (
            observed[0]["fact"]["value"]["value"]
            == {
                "memory_alias": 37,
                "memory_global_roundtrip": 41,
                "memory_stack_roundtrip": 43,
            }[function]
        )
        assert observed[0]["fact"]["labels"]["explicit"] == []
    assert all(
        store["strong_update"] and store["alias"] == "must_alias"
        for store in expected["target_stores"]
    )
    if function == "memory_global_roundtrip":
        assert any(
            o["kind"] == "global" and o["key"] == raw["global_symbol"]["name"]
            for o in expected["objects"]
        )
    if function == "memory_stack_roundtrip":
        assert {o["kind"] for o in expected["objects"]} == {"stack"}


def test_actual_memory_builds_source_and_debug_companions_are_pinned():
    import hashlib

    builds = json.loads(
        (ROOT / "tests/flow_fixtures/manifests/memory/build.json").read_text()
    )
    assert {b["arch"] for b in builds} == {"x86_64", "arm64"}
    for build in builds:
        assert (
            build["source_sha256"]
            == hashlib.sha256((ROOT / build["source"]).read_bytes()).hexdigest()
        )
        assert (
            build["builder_sha256"]
            == hashlib.sha256(
                (ROOT / "scripts/build_flow_memory_anchors.py").read_bytes()
            ).hexdigest()
        )
        assert build["reproducibility"] == {
            "fresh_builds": 2,
            "binary_sha256_equal": True,
            "dwarf_sha256_equal": True,
        }
        assert build["companion_artifacts"][0]["required"]
        assert build["environment"] == {"SOURCE_DATE_EPOCH": "0"}
        assert build["object_mtime"] == 0 and not build["target_executed"]
        assert (
            build["compile_command"][0] == "clang"
            and build["link_command"][0] == "clang"
        )
        assert build["dsym_command"][0] == "dsymutil"
        for function in build["functions"]:
            receipt = json.loads(
                (
                    ROOT
                    / f"tests/flow_fixtures/manifests/memory/{build['arch']}_{function}.json"
                ).read_text()
            )
            assert (
                receipt["snapshot"]["identity"]["binary_digest"]
                == "sha256-v1:" + build["binary_sha256"]
            )
            assert (
                receipt["profile"]["abi_provenance"]["source_sha256"]
                == build["source_sha256"]
            )


def test_widened_load_has_opaque_data_evidence_not_just_memory_order():
    p = plan((store(0, reg(192, 8)), load(1, address=reg(64, 64, "right")), ret(2)))
    a = obj(p)
    data = next(e for e in p.program.entry_storage if e.storage.bit_offset == 192)
    r = run(
        p,
        (a,),
        (ptrseed(p, a), ptrseed(p, a, 64, offset=None)),
        (),
        (Seed(data.node_id, Labels(("X",))),),
    )
    assert fact(r, nodes(p, "Return")[0].node_id).labels.explicit == ("X",)
    assert any(
        d.interval is None and d.precision == "opaque" and d.evidence_ids
        for d in r.dependencies
    )
    assert all(d.kind == "memory_data_dependency" for d in r.dependencies)
    assert all(step.rule_id == "logical-memory-step-v1" for step in p.steps)


def test_oversized_store_does_not_advertise_strong_update():
    p = plan((store(0, const(0, 64)), load(1), ret(2)))
    a = obj(p)
    r = run(p, (a,), (ptrseed(p, a),), (memseed(a),), policy=replace(FLAT, max_bytes=1))
    access = next(a for a in r.accesses if a.node_id == nodes(p, "Store")[0].node_id)
    assert not access.strong_update and access.precision == "range_widened"
    assert access.unresolved and r.status == "partial"
    assert fact(r, nodes(p, "Return")[0].node_id).labels.explicit == ("X",)


def test_conflicting_same_key_object_metadata_is_not_disjoint_identity():
    p = plan((load(0),))
    a = obj(p)
    with pytest.raises(ContractError, match="Conflicting"):
        run(p, (a, replace(a, size_bytes=16)), (ptrseed(p, a),))


@pytest.mark.parametrize("offset", (-1, 8))
def test_out_of_object_address_cannot_borrow_disjoint_object_proof(offset):
    p = plan((store(0, reg(192, 8)), load(1, address=reg(64, 64, "right")), ret(2)))
    a, b = obj(p, "A"), obj(p, "B")
    data = next(e for e in p.program.entry_storage if e.storage.bit_offset == 192)
    r = run(
        p,
        (a, b),
        (ptrseed(p, a, offset=offset), ptrseed(p, b, 64)),
        (memseed(b, label="", value=7),),
        (Seed(data.node_id, Labels(("WRITE",))),),
    )
    out = fact(r, nodes(p, "Return")[0].node_id)
    assert out.labels.unknown_provenance and "WRITE" in out.labels.explicit
    assert out.value.value is None and r.status == "partial"


def test_direct_call_target_is_not_data_but_indirect_global_target_is():
    for opcode, expected_loads in (("m_call", 0), ("m_icall", 1)):
        initial = plan(
            (
                Instruction(
                    0, opcode, (Operand("global", 64, address=4096, role="left"),)
                ),
            )
        )
        p = build_memory_plan(
            build_ssa(initial.program.graph.snapshot, storage_model="memory")
        )
        assert len(nodes(p, "Load")) == expected_loads
        assert len(
            [n for n in p.program.graph.nodes if n.operation == "call_target_address"]
        ) == (1 if opcode == "m_call" else 0)


@pytest.mark.parametrize("opcode", ("m_add", "m_sub"))
@pytest.mark.parametrize("nullable_candidate", (False, True))
@pytest.mark.parametrize("encoded_delta", (1, (1 << 64) - 1))
def test_null_nonzero_arithmetic_widens_and_store_effect_reaches_real_object(
    opcode, nullable_candidate, encoded_delta
):
    p = plan(
        (
            Instruction(
                0,
                opcode,
                (reg(), const(encoded_delta, 64, "right"), reg(64, 64, "destination")),
            ),
            store(1, reg(192, 8), reg(64, 64, "destination")),
            load(2, address=reg(256, 64, "right")),
            ret(3),
        )
    )
    a = obj(p)
    initial = ptrseed(p, a)
    pointer = PointerValue(
        "ram",
        64,
        (PointerCandidate(a.object_id, 0),) if nullable_candidate else (),
        may_be_null=True,
    )
    data = next(e for e in p.program.entry_storage if e.storage.bit_offset == 192)
    r = run(
        p,
        (a,),
        (replace(initial, pointer=pointer), ptrseed(p, a, 256)),
        (memseed(a, label="", value=7),),
        (Seed(data.node_id, Labels(("WRITE",))),),
    )
    arithmetic = next(n for n in p.program.graph.nodes if n.kind == "Binary")
    out = fact(r, arithmetic.node_id)
    assert out.pointer.any_compatible_location and out.pointer.may_be_null
    assert out.labels.unknown_provenance
    loaded = fact(r, nodes(p, "Return")[0].node_id)
    assert loaded.value.value is None and loaded.labels.unknown_provenance
    assert "WRITE" in loaded.labels.explicit and r.status == "partial"
    assert any(
        d.source == nodes(p, "Store")[0].node_id and d.evidence_ids
        for d in r.dependencies
    )


@pytest.mark.parametrize("opcode", ("m_add", "m_sub"))
@pytest.mark.parametrize("nullable_candidate", (False, True))
def test_null_arithmetic_zero_preserves_pointer_domain(opcode, nullable_candidate):
    p = plan(
        (
            Instruction(
                0, opcode, (reg(), const(0, 64, "right"), reg(64, 64, "destination"))
            ),
            ret(1, 64, 64),
        )
    )
    a = obj(p)
    initial = ptrseed(p, a)
    pointer = PointerValue(
        "ram",
        64,
        (PointerCandidate(a.object_id, 0),) if nullable_candidate else (),
        may_be_null=True,
    )
    r = run(p, (a,), (replace(initial, pointer=pointer),))
    assert fact(r, nodes(p, "Return")[0].node_id).pointer == pointer
    assert "pointer_relation_widened" not in r.diagnostics


@pytest.mark.parametrize("opcode,expected_offset", (("m_add", 5), ("m_sub", 3)))
def test_nonnull_candidate_constant_displacement_remains_precise(
    opcode, expected_offset
):
    p = plan(
        (
            Instruction(
                0, opcode, (reg(), const(1, 64, "right"), reg(64, 64, "destination"))
            ),
            ret(1, 64, 64),
        )
    )
    a = obj(p)
    r = run(p, (a,), (ptrseed(p, a, offset=4),))
    pointer = fact(r, nodes(p, "Return")[0].node_id).pointer
    assert pointer.candidates == (PointerCandidate(a.object_id, expected_offset),)
    assert not pointer.any_compatible_location and not pointer.may_be_null


def test_no_candidate_unresolved_store_havocs_compatible_objects():
    p = plan((store(0, reg(192, 8)), load(1, address=reg(64, 64, "right")), ret(2)))
    a = obj(p)
    null = replace(ptrseed(p, a), pointer=PointerValue("ram", 64, may_be_null=True))
    data = next(e for e in p.program.entry_storage if e.storage.bit_offset == 192)
    r = run(
        p,
        (a,),
        (null, ptrseed(p, a, 64)),
        (memseed(a, label="", value=7),),
        (Seed(data.node_id, Labels(("WRITE",))),),
    )
    store_access = next(
        x for x in r.accesses if x.node_id == nodes(p, "Store")[0].node_id
    )
    assert store_access.unresolved and not store_access.candidates
    loaded = fact(r, nodes(p, "Return")[0].node_id)
    assert loaded.value.value is None and loaded.labels.unknown_provenance
    assert loaded.labels.explicit == ("WRITE",)
    assert any(
        d.source == store_access.node_id and d.target == nodes(p, "Load")[0].node_id
        for d in r.dependencies
    )


@pytest.mark.parametrize("effect", ("Store", "Branch", "OpaqueEffect", "Return"))
def test_effect_value_seed_is_rejected_never_silently_discarded(effect):
    instruction = {
        "Store": store(0),
        "Branch": Instruction(0, "m_goto", ()),
        "OpaqueEffect": Instruction(0, "m_nop", ()),
        "Return": Instruction(0, "m_ret", ()),
    }[effect]
    p = plan((instruction,))
    a = obj(p)
    target = nodes(p, effect)[0]
    with pytest.raises(ContractError, match="MemorySeed.*Store data input"):
        run(p, (a,), (), values=(Seed(target.node_id, Labels(("SEED",))),))


def test_load_value_seed_retained_and_source_digest_changes():
    p = plan((load(0), ret(1)))
    a = obj(p)
    target = nodes(p, "Load")[0]
    original = run(p, (a,), (ptrseed(p, a),), (memseed(a, label="", value=7),))
    seeded = run(
        p,
        (a,),
        (ptrseed(p, a),),
        (memseed(a, label="", value=7),),
        (Seed(target.node_id, Labels(("LOAD",))),),
    )
    assert fact(seeded, nodes(p, "Return")[0].node_id).labels.explicit == ("LOAD",)
    assert (
        original.plan_digest == seeded.plan_digest
        and original.source_digest != seeded.source_digest
    )
    assert original.cache_key != seeded.cache_key
    assert FLAT.ruleset == "range-memory-v7"
    old = FLAT.to_data() | {"ruleset": "range-memory-v5"}
    assert digest(FLAT) != digest(old)
    with pytest.raises(ContractError):
        MemoryPolicy.from_data(old)


@pytest.mark.parametrize("opcode,expected_offset", (("m_add", 3), ("m_sub", 5)))
def test_nonnull_full_width_negative_displacement(opcode, expected_offset):
    p = plan(
        (
            Instruction(
                0,
                opcode,
                (reg(), const((1 << 64) - 1, 64, "right"), reg(64, 64, "destination")),
            ),
            ret(1, 64, 64),
        )
    )
    a = obj(p)
    r = run(p, (a,), (ptrseed(p, a, offset=4),))
    assert fact(r, nodes(p, "Return")[0].node_id).pointer.candidates == (
        PointerCandidate(a.object_id, expected_offset),
    )


@pytest.mark.parametrize(
    "severity,expected_status,expected_diagnostics",
    [
        ("information", "complete_in_scope", ()),
        ("unsupported", "partial", ("partial_scalar_input",)),
    ],
)
def test_information_diagnostic_does_not_make_memory_input_partial(
    severity, expected_status, expected_diagnostics
):
    original = plan(
        (
            Instruction(0, "m_mov", (const(7, 8), reg(128, 8, "destination"))),
            ret(1, 128, 8),
        )
    ).program.graph.snapshot
    function = replace(
        original.function,
        diagnostics=(Diagnostic("note", "diagnostic only", severity),),
    )
    identity = replace(original.identity, input_digest=digest(function))
    source = Snapshot(identity, function, identity.snapshot_id)
    result = run(build_memory_plan(build_ssa(source)), (), ())
    assert result.status == expected_status
    assert result.diagnostics == expected_diagnostics
