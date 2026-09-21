"""Independent scalar/CFG expectations; no engine-output golden oracle."""

from dataclasses import replace
import json
from pathlib import Path

import pytest

from ida_pro_mcp.flow_core import ContractError, canonical_json, digest
from ida_pro_mcp.flow_core.analysis import AnalysisResult, ScalarPolicy, Seed, analyze
from ida_pro_mcp.flow_core.cfg import dominance
from ida_pro_mcp.flow_core.contracts import (
    Block,
    FunctionInput,
    Instruction,
    Operand,
    Snapshot,
    StorageLocation,
)
from ida_pro_mcp.flow_core.ssa import SSAProgram, build_ssa
from ida_pro_mcp.flow_core.states import Labels

ROOT = Path(__file__).resolve().parents[2]


def reg(offset=0, bits=8, role="left"):
    return Operand(
        "storage",
        bits,
        storage=StorageLocation("scalar", "bank", offset, bits),
        role=role,
    )


def const(value, bits=8, role="left"):
    return Operand("constant", bits, constant=value, role=role)


def ins(index, opcode, left, right=None, dest=None):
    return Instruction(
        index, opcode, tuple(o for o in (left, right, dest) if o is not None)
    )


def snapshot(blocks):
    base = Snapshot.from_data(
        json.loads(
            (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
        )["snapshot"]
    )
    blocks = tuple(
        replace(
            b, successors=tuple(c.index for c in blocks if b.index in c.predecessors)
        )
        for b in blocks
    )
    function = FunctionInput("scalar-test", 0, blocks)
    identity = replace(
        base.identity, function_id=function.function_id, input_digest=digest(function)
    )
    return Snapshot(identity, function, identity.snapshot_id)


def linear(instructions):
    return snapshot((Block(0, (), tuple(instructions)),))


def facts(result):
    return {f.node_id: f for f in result.facts}


def returned(program, result):
    return facts(result)[
        next(n.node_id for n in program.graph.nodes if n.kind == "Return")
    ]


def seed_storage(program, offset=0, label="X"):
    entry = next(e for e in program.entry_storage if e.storage.bit_offset == offset)
    return Seed(entry.node_id, Labels((label,)))


def test_v01_scalar_copy_and_overwrite_oracle():
    source = linear(
        (
            ins(0, "m_add", reg(), const(7, role="right"), reg(8, role="destination")),
            ins(1, "m_ret", reg(8)),
        )
    )
    p = build_ssa(source)
    result = analyze(p.graph, (seed_storage(p),))
    assert returned(p, result).labels.explicit == ("X",)
    for node in p.graph.nodes:
        if node.kind == "Constant":
            assert not facts(result)[node.node_id].labels.explicit
    overwrite = linear(
        (
            ins(0, "m_mov", reg(), dest=reg(8, role="destination")),
            ins(1, "m_mov", const(5), dest=reg(8, role="destination")),
            ins(2, "m_ret", reg(8)),
        )
    )
    p = build_ssa(overwrite)
    result = analyze(p.graph, (seed_storage(p),))
    assert returned(p, result).value.value == 5
    assert returned(p, result).labels == Labels()
    assert result.status == "complete_in_scope"


@pytest.mark.parametrize(
    "opcode,expected",
    [
        ("m_add", 2),
        ("m_sub", 12),
        ("m_mul", 13),
        ("m_and", 3),
        ("m_or", 15),
        ("m_xor", 12),
    ],
)
def test_modular_arithmetic_independent_truth(opcode, expected):
    p = build_ssa(
        linear(
            (
                ins(
                    0,
                    opcode,
                    const(15, 4),
                    const(3, 4, "right"),
                    reg(0, 4, "destination"),
                ),
                ins(1, "m_ret", reg(0, 4)),
            )
        )
    )
    assert returned(p, analyze(p.graph)).value.value == expected


def diamond():
    return snapshot(
        (
            Block(0, (), (ins(0, "m_jcnd", reg(16)),)),
            Block(
                1, (0,), (ins(0, "m_mov", reg(0), dest=reg(24, role="destination")),)
            ),
            Block(
                2, (0,), (ins(0, "m_mov", reg(8), dest=reg(24, role="destination")),)
            ),
            Block(3, (1, 2), (ins(0, "m_ret", reg(24)),)),
        )
    )


def test_v03_diamond_phi_has_predecessor_origins_not_condition_label():
    p = build_ssa(diamond())
    seeds = tuple(
        sorted(
            (
                seed_storage(p, 0, "X"),
                seed_storage(p, 8, "Y"),
                seed_storage(p, 16, "C"),
            ),
            key=lambda s: s.node_id,
        )
    )
    result = analyze(p.graph, seeds)
    assert returned(p, result).labels.explicit == ("X", "Y")
    assert "C" not in returned(p, result).labels.explicit
    phi = next(n for n in p.graph.nodes if n.kind == "Phi")
    assert {x.predecessor for x in phi.phi_inputs} == {1, 2}
    defs = {d.node_id: d for d in p.definitions}
    assert all(defs[x.node_id].block == x.predecessor for x in phi.phi_inputs)
    assert len([e for e in p.graph.edges if e.kind == "phi_input"]) == 2
    assert SSAProgram.from_json(canonical_json(p)) == p


def test_select_and_branch_phi_observables_agree():
    p = build_ssa(
        linear(
            (
                Instruction(
                    0,
                    "m_select",
                    (
                        reg(16),
                        reg(0, role="right"),
                        reg(8, role="argument"),
                        reg(24, role="destination"),
                    ),
                ),
                ins(1, "m_ret", reg(24)),
            )
        )
    )
    seeds = tuple(
        sorted(
            (
                seed_storage(p, 0, "X"),
                seed_storage(p, 8, "Y"),
                seed_storage(p, 16, "C"),
            ),
            key=lambda s: s.node_id,
        )
    )
    assert returned(p, analyze(p.graph, seeds)).labels.explicit == ("X", "Y")
    assert not any(n.kind == "Phi" for n in p.graph.nodes)


def test_v04_loop_fixedpoint_and_budget_dont_fake_no_flow():
    s = snapshot(
        (
            Block(0, (), ()),
            Block(
                1,
                (0, 1),
                (
                    ins(
                        0,
                        "m_add",
                        reg(),
                        const(1, role="right"),
                        reg(role="destination"),
                    ),
                ),
            ),
            Block(2, (1,), (ins(0, "m_ret", reg()),)),
        )
    )
    p = build_ssa(s)
    seeds = (seed_storage(p),)
    r = analyze(p.graph, seeds)
    assert returned(p, r).labels.explicit == ("X",)
    assert r.status == "complete_in_scope" and not r.frontier
    limited = analyze(p.graph, seeds, ScalarPolicy(1))
    assert limited.status == "partial" and limited.frontier
    assert returned(p, limited).labels.unknown_provenance
    assert returned(p, limited).labels.any_explicit_source
    assert limited.cache_key != r.cache_key
    with pytest.raises(ContractError, match="budget"):
        build_ssa(s, max_nodes=1)


def test_v05_partial_storage_write_preserves_other_bits():
    p = build_ssa(
        linear(
            (
                ins(0, "m_mov", const(0xABCD, 16), dest=reg(0, 16, "destination")),
                ins(1, "m_mov", const(0x12), dest=reg(0, 8, "destination")),
                ins(2, "m_ret", reg(0, 16)),
            )
        )
    )
    assert returned(p, analyze(p.graph)).value.value == 0xAB12
    p = build_ssa(
        linear(
            (
                ins(0, "m_mov", const(0x12), dest=reg(0, 8, "destination")),
                ins(1, "m_ret", reg(0, 16)),
            )
        )
    )
    high_seed = seed_storage(p, 8, "HIGH")
    result = analyze(p.graph, (high_seed,))
    assert returned(p, result).labels.explicit == ("HIGH",)
    low_seed = seed_storage(p, 0, "LOW")
    assert returned(p, analyze(p.graph, (low_seed,))).labels.explicit == ()


def test_v06_unknown_opcode_retains_inputs_and_propagates_unknown():
    p = build_ssa(
        linear(
            (
                ins(0, "m_unreviewed", reg(), dest=reg(8, role="destination")),
                ins(1, "m_ret", reg(8)),
            )
        )
    )
    r = analyze(p.graph, (seed_storage(p),))
    assert returned(p, r).labels.explicit == ("X",)
    assert returned(p, r).labels.unknown_provenance
    assert r.status == "partial"


def test_dominance_diamond_unreachable_and_irreducible():
    d = dominance(diamond().function)
    assert d.reachable == (0, 1, 2, 3)
    assert d.blocks[1].frontier == (3,)
    assert d.blocks[2].frontier == (3,)
    assert d.blocks[3].dominators == (0, 3)
    s = snapshot(
        (Block(0, (), ()), Block(1, (0, 2), ()), Block(2, (0, 1), ()), Block(3, (), ()))
    )
    d = dominance(s.function)
    assert d.unreachable == (3,)
    assert d.blocks[1].dominators == (0, 1)
    assert d.blocks[2].dominators == (0, 2)
    assert build_ssa(s).graph.axes.analysis == "partial"


def test_invalid_definition_and_false_dominance_certificate_rejected():
    p = build_ssa(diamond())
    definition = next(d for d in p.definitions if d.order >= 0 and d.block == 1)
    invalid = tuple(
        replace(d, block=2) if d == definition else d for d in p.definitions
    )
    with pytest.raises(ContractError, match="dominate"):
        replace(p, definitions=invalid)
    with pytest.raises(ContractError, match="certificate"):
        replace(
            p,
            dominance=replace(
                p.dominance,
                blocks=tuple(
                    replace(b, immediate=None) if b.block == 1 else b
                    for b in p.dominance.blocks
                ),
            ),
        )


@pytest.mark.parametrize(
    "opcode,input_value,input_bits,output_bits,expected",
    [
        ("m_xdu", 255, 8, 16, 255),
        ("m_xds", 255, 8, 16, 65535),
        ("m_low", 0xABCD, 16, 8, 0xCD),
        ("m_high", 0xABCD, 16, 8, 0xAB),
    ],
)
def test_a10_extension_once(opcode, input_value, input_bits, output_bits, expected):
    p = build_ssa(
        linear(
            (
                ins(
                    0,
                    opcode,
                    const(input_value, input_bits),
                    dest=reg(0, output_bits, "destination"),
                ),
                ins(1, "m_ret", reg(0, output_bits)),
            )
        )
    )
    assert returned(p, analyze(p.graph)).value.value == expected
    assert (
        len(
            [
                n
                for n in p.graph.nodes
                if n.operation in ("zext", "sext", "trunc", "high")
            ]
        )
        == 1
    )


def test_graph_is_seed_independent_and_cache_sources_separate():
    s = linear((ins(0, "m_ret", reg()),))
    p = build_ssa(s)
    empty = analyze(p.graph)
    seeded = analyze(p.graph, (seed_storage(p),))
    assert empty.graph_digest == seeded.graph_digest == build_ssa(s).graph.graph_digest
    assert (
        empty.source_digest != seeded.source_digest
        and empty.cache_key != seeded.cache_key
    )
    assert AnalysisResult.from_json(canonical_json(seeded)) == seeded


@pytest.mark.parametrize("anchor", ["x64", "a64"])
def test_actual_g005_snapshots_common_scalar_core(anchor):
    receipt = json.loads(
        (ROOT / f"tests/flow_fixtures/manifests/extraction_{anchor}.json").read_text()
    )
    s = Snapshot.from_data(receipt["snapshot"])
    assert digest(s) == receipt["canonical_digest"]
    p = build_ssa(s)
    assert build_ssa(s) == p
    assert SSAProgram.from_json(canonical_json(p)) == p
    assert p.graph.axes.analysis == "partial"
    assert any(n.kind == "Phi" for n in p.graph.nodes)
    assert len([n for n in p.graph.nodes if n.operation == "zext"]) == 1
    assert any(n.kind == "Load" for n in p.graph.nodes)
    assert any(n.kind == "Store" for n in p.graph.nodes)
    for entry in p.entry_storage:
        r = analyze(p.graph, (Seed(entry.node_id, Labels(("ANCHOR",))),))
        assert r.status == "partial"
        assert facts(r)[entry.node_id].labels.explicit == ("ANCHOR",)
    source = Path(
        __import__("ida_pro_mcp.flow_core.ssa", fromlist=["__file__"]).__file__
    ).read_text()
    assert (
        ".processor" not in source and "x86" not in source and "aarch64" not in source
    )


def test_g003_scalar_oracles_are_independent_inputs_not_receipt_proof():
    cases = json.loads((ROOT / "tests/flow_fixtures/oracles/s0.json").read_text())[
        "cases"
    ]
    selected = {
        c["oracle_id"]: c
        for c in cases
        if c["oracle_id"] in {"S0-SCALAR", "S0-PHI", "S0-OVERWRITE"}
    }
    assert len(selected) == 3
    assert all("hand-authored" in c["oracle_origin"] for c in selected.values())
    assert selected["S0-OVERWRITE"]["expected_relations"] == [
        "return is constant 5 with no explicit X"
    ]


def test_s0_exact_uint32_scalar_and_overwrite_contract():
    p = build_ssa(
        linear(
            (
                ins(
                    0,
                    "m_add",
                    const(0xFFFFFFFF, 32),
                    const(7, 32, "right"),
                    reg(0, 32, "destination"),
                ),
                ins(1, "m_ret", reg(0, 32)),
            )
        )
    )
    assert returned(p, analyze(p.graph)).value.value == 6
    p = build_ssa(
        linear(
            (
                ins(0, "m_mov", reg(0, 32), dest=reg(32, 32, "destination")),
                ins(1, "m_mov", const(5, 32), dest=reg(32, 32, "destination")),
                ins(2, "m_ret", reg(32, 32)),
            )
        )
    )
    result = analyze(p.graph, (seed_storage(p),))
    assert returned(p, result).value.width_bits == 32
    assert returned(p, result).value.value == 5
    assert not returned(p, result).labels.explicit


@pytest.mark.parametrize(
    "opcode,reference",
    [
        ("m_add", lambda a, b: (a + b) % 4),
        ("m_sub", lambda a, b: (a - b) % 4),
        ("m_mul", lambda a, b: (a * b) % 4),
        ("m_setb", lambda a, b: int(a < b)),
    ],
)
def test_all_two_bit_operand_pairs_against_independent_reference(opcode, reference):
    for a in range(4):
        for b in range(4):
            p = build_ssa(
                linear(
                    (
                        ins(
                            0,
                            opcode,
                            const(a, 2),
                            const(b, 2, "right"),
                            reg(0, 2, "destination"),
                        ),
                        ins(1, "m_ret", reg(0, 2)),
                    )
                )
            )
            assert returned(p, analyze(p.graph)).value.value == reference(a, b)


def test_unsupported_value_profile_top_inputs_and_shift_failure():
    p = build_ssa(
        linear(
            (
                ins(
                    0, "m_add", reg(), reg(8, role="right"), reg(16, role="destination")
                ),
                ins(1, "m_ret", reg(16)),
            )
        )
    )
    altered = tuple(
        replace(n, operation="unreviewed") if n.kind == "Binary" else n
        for n in p.graph.nodes
    )
    r = analyze(replace(p.graph, nodes=altered), (seed_storage(p),))
    assert r.status == "partial"
    assert returned(p, r).labels.explicit == ("X",)
    assert returned(p, r).labels.unknown_provenance
    p = build_ssa(
        linear(
            (
                ins(
                    0,
                    "m_shl",
                    const(1),
                    const(8, role="right"),
                    reg(role="destination"),
                ),
                ins(1, "m_ret", reg()),
            )
        )
    )
    r = analyze(p.graph)
    assert r.status == "partial" and returned(p, r).value.value is None


def test_unmodeled_no_destination_effect_havocs_later_uses():
    p = build_ssa(
        linear(
            (
                ins(0, "m_mov", const(5), dest=reg(role="destination")),
                Instruction(1, "unmodeled-effect", ()),
                ins(2, "m_ret", reg()),
            )
        )
    )
    r = analyze(p.graph)
    assert returned(p, r).value.value is None
    assert returned(p, r).labels.unknown_provenance
    assert r.status == "partial"


def test_control_edge_is_separate_from_explicit_payload():
    p = build_ssa(
        linear(
            (
                Instruction(
                    0,
                    "m_select",
                    (
                        reg(16),
                        reg(0, role="right"),
                        reg(8, role="argument"),
                        reg(24, role="destination"),
                    ),
                ),
                ins(1, "m_ret", reg(24)),
            )
        )
    )
    select = next(n for n in p.graph.nodes if n.kind == "Select")
    assert {
        e.kind
        for e in p.graph.edges
        if e.source == select.inputs[0] and e.target == select.node_id
    } == {"control_dependency"}
    assert {
        e.kind
        for e in p.graph.edges
        if e.source == select.inputs[1] and e.target == select.node_id
    } == {"value_dependency"}


def test_self_loop_phi_values_reach_top_and_keep_seed():
    s = snapshot(
        (
            Block(0, (), (ins(0, "m_mov", const(0), dest=reg(role="destination")),)),
            Block(
                1,
                (0, 1),
                (
                    ins(
                        0,
                        "m_add",
                        reg(),
                        const(1, role="right"),
                        reg(role="destination"),
                    ),
                ),
            ),
            Block(2, (1,), (ins(0, "m_ret", reg()),)),
        )
    )
    p = build_ssa(s)
    r = analyze(p.graph)
    assert returned(p, r).value.value is None
    assert r.status == "complete_in_scope"


def test_irreducible_phi_placement_converges():
    s = snapshot(
        (
            Block(0, (), ()),
            Block(1, (0, 2), (ins(0, "m_mov", reg(8), dest=reg(role="destination")),)),
            Block(2, (0, 1), (ins(0, "m_mov", reg(16), dest=reg(role="destination")),)),
            Block(3, (1, 2), (ins(0, "m_ret", reg()),)),
        )
    )
    p = build_ssa(s)
    seeds = tuple(
        sorted(
            (seed_storage(p, 8, "A"), seed_storage(p, 16, "B")), key=lambda s: s.node_id
        )
    )
    r = analyze(p.graph, seeds)
    assert returned(p, r).labels.explicit == ("A", "B")
    assert not r.frontier


def test_d03_unknown_copy_phi_return_chain():
    s = snapshot(
        (
            Block(
                0, (), (ins(0, "m_unreviewed", reg(), dest=reg(8, role="destination")),)
            ),
            Block(
                1, (0,), (ins(0, "m_mov", reg(8), dest=reg(16, role="destination")),)
            ),
            Block(
                2, (0,), (ins(0, "m_mov", const(5), dest=reg(16, role="destination")),)
            ),
            Block(3, (1, 2), (ins(0, "m_ret", reg(16)),)),
        )
    )
    p = build_ssa(s)
    r = analyze(p.graph, (seed_storage(p),))
    assert returned(p, r).labels.explicit == ("X",)
    assert returned(p, r).labels.unknown_provenance
    assert any(n.kind == "Phi" for n in p.graph.nodes)


@pytest.mark.parametrize(
    "opcode,reference",
    [
        ("m_and", lambda a, b: a & b),
        ("m_or", lambda a, b: a | b),
        ("m_xor", lambda a, b: a ^ b),
        ("m_shl", lambda a, b: (a << b) % 4 if b < 2 else None),
        ("m_shr", lambda a, b: a >> b if b < 2 else None),
        ("m_sar", lambda a, b: ((a if a < 2 else a - 4) >> b) % 4 if b < 2 else None),
        ("m_setz", lambda a, b: int(a == b)),
        ("m_setnz", lambda a, b: int(a != b)),
        ("m_seta", lambda a, b: int(a > b)),
        ("m_setae", lambda a, b: int(a >= b)),
        ("m_setbe", lambda a, b: int(a <= b)),
        ("m_setl", lambda a, b: int((a if a < 2 else a - 4) < (b if b < 2 else b - 4))),
        (
            "m_setle",
            lambda a, b: int((a if a < 2 else a - 4) <= (b if b < 2 else b - 4)),
        ),
        ("m_setg", lambda a, b: int((a if a < 2 else a - 4) > (b if b < 2 else b - 4))),
        (
            "m_setge",
            lambda a, b: int((a if a < 2 else a - 4) >= (b if b < 2 else b - 4)),
        ),
    ],
)
def test_d02_remaining_binary_profile_all_two_bit_inputs(opcode, reference):
    for a in range(4):
        for b in range(4):
            p = build_ssa(
                linear(
                    (
                        ins(
                            0,
                            opcode,
                            const(a, 2),
                            const(b, 2, "right"),
                            reg(0, 2, "destination"),
                        ),
                        ins(1, "m_ret", reg(0, 2)),
                    )
                )
            )
            result = analyze(p.graph)
            assert returned(p, result).value.value == reference(a, b)
            if reference(a, b) is None:
                assert returned(p, result).labels.unknown_provenance


@pytest.mark.parametrize(
    "opcode,outbits,reference",
    [
        ("m_neg", 2, lambda a: (-a) % 4),
        ("m_bnot", 2, lambda a: 3 - a),
        ("m_lnot", 2, lambda a: int(a == 0)),
        ("m_xdu", 4, lambda a: a),
        ("m_xds", 4, lambda a: a if a < 2 else a + 12),
        ("m_low", 1, lambda a: a % 2),
        ("m_high", 1, lambda a: a // 2),
    ],
)
def test_d02_unary_profile_all_two_bit_inputs(opcode, outbits, reference):
    for a in range(4):
        p = build_ssa(
            linear(
                (
                    ins(0, opcode, const(a, 2), dest=reg(0, outbits, "destination")),
                    ins(1, "m_ret", reg(0, outbits)),
                )
            )
        )
        assert returned(p, analyze(p.graph)).value.value == reference(a)


def test_d01_joins_idempotent_commutative_associative():
    from itertools import product
    from ida_pro_mcp.flow_core.states import BitValue

    domain = [BitValue(2, x) for x in range(4)] + [BitValue(2)]
    labels = [
        Labels(),
        Labels(("X",)),
        Labels(control=("C",)),
        Labels(unknown_provenance=True),
    ]
    for values in (domain, labels):
        for a, b, c in product(values, repeat=3):
            assert a.join(a) == a
            assert a.join(b) == b.join(a)
            assert a.join(b).join(c) == a.join(b.join(c))


def test_anchor_receipts_fresh_and_common_observations():
    import runpy

    make = runpy.run_path(str(ROOT / "tests/flow_core/record_scalar_receipts.py"))[
        "receipt"
    ]
    for anchor in ("x64", "a64"):
        stored = json.loads(
            (ROOT / f"tests/flow_fixtures/manifests/ssa_{anchor}.json").read_text()
        )
        assert stored == make(anchor)
        assert stored["analysis_status"] == "partial"
        assert stored["observable"]["width_bits"] == 64
        assert stored["observable"]["fact"]["labels"]["explicit"] == ["ANCHOR_ENTRY"]
        assert stored["observable"]["fact"]["labels"]["unknown_provenance"]
        assert stored["microcode_operation_counts"]["m_xdu"] == 1
        assert stored["repeat_equal"] and stored["roundtrip_equal"]
        assert not stored["target_executed"] and not stored["new_ida_extraction"]


def test_unknown_global_width_is_not_fabricated_one_bit_data():
    p = build_ssa(linear((ins(0, "m_ret", Operand("global", None, address=4096)),)))
    unknown = next(n for n in p.graph.nodes if n.kind == "UnknownValue")
    assert unknown.width_bits is None
    r = analyze(p.graph)
    assert returned(p, r).value is None
    assert returned(p, r).labels.unknown_provenance and r.status == "partial"


def test_entry_source_range_resolution_is_exact_not_abi_inference():
    from ida_pro_mcp.flow_core.analysis import seeds_for_entry

    p = build_ssa(
        linear(
            (
                ins(0, "m_mov", const(1), dest=reg(0, 8, "destination")),
                ins(1, "m_ret", reg(0, 16)),
            )
        )
    )
    seeds = seeds_for_entry(
        p, StorageLocation("scalar", "bank", 0, 16), Labels(("RANGE",))
    )
    assert len(seeds) == 2
    assert {s.node_id for s in seeds} == {e.node_id for e in p.entry_storage}
    for storage in (
        StorageLocation("scalar", "bank", 0, 4),
        StorageLocation("other", "bank", 0, 16),
        StorageLocation("scalar", "bank", 0, 32),
    ):
        with pytest.raises(ContractError, match="complete scalar atoms"):
            seeds_for_entry(p, storage, Labels(("X",)))


@pytest.mark.parametrize("opcode", ("m_shl", "m_shr", "m_sar"))
@pytest.mark.parametrize(
    "bits,count,unsupported",
    [
        (8, 0, False),
        (8, 7, False),
        (8, 8, True),
        (8, 9, True),
        (1, 0, False),
        (1, 1, True),
    ],
)
def test_symbolic_shift_payload_count_profile(opcode, bits, count, unsupported):
    p = build_ssa(
        linear(
            (
                ins(
                    0,
                    opcode,
                    reg(0, bits),
                    const(count, 8, "right"),
                    reg(16, bits, "destination"),
                ),
                ins(1, "m_ret", reg(16, bits)),
            )
        )
    )
    result = analyze(p.graph, (seed_storage(p),))
    fact = returned(p, result)
    assert fact.value.value is None and fact.value.width_bits == bits
    assert fact.labels.explicit == ("X",)
    assert fact.labels.unknown_provenance is unsupported
    assert result.status == ("partial" if unsupported else "complete_in_scope")


@pytest.mark.parametrize("opcode", ("m_shl", "m_shr", "m_sar"))
@pytest.mark.parametrize("bits", (1, 8))
@pytest.mark.parametrize("symbolic_payload", (False, True))
def test_symbolic_shift_count_cannot_prove_supported_range(
    opcode, bits, symbolic_payload
):
    left = reg(0, bits) if symbolic_payload else const(1, bits)
    p = build_ssa(
        linear(
            (
                ins(0, opcode, left, reg(8, 8, "right"), reg(16, bits, "destination")),
                ins(1, "m_ret", reg(16, bits)),
            )
        )
    )
    seeds = [seed_storage(p, 8, "COUNT")]
    if symbolic_payload:
        seeds.append(seed_storage(p, 0, "PAYLOAD"))
    result = analyze(p.graph, tuple(sorted(seeds, key=lambda seed: seed.node_id)))
    fact = returned(p, result)
    assert fact.value.value is None and fact.value.width_bits == bits
    assert fact.labels.explicit == (
        ("COUNT", "PAYLOAD") if symbolic_payload else ("COUNT",)
    )
    assert fact.labels.unknown_provenance and result.status == "partial"


@pytest.mark.parametrize("opcode", ("m_shl", "m_shr", "m_sar"))
@pytest.mark.parametrize("count", (0, 1))
def test_one_bit_concrete_shift_profile(opcode, count):
    p = build_ssa(
        linear(
            (
                ins(
                    0,
                    opcode,
                    const(1, 1),
                    const(count, 8, "right"),
                    reg(0, 1, "destination"),
                ),
                ins(1, "m_ret", reg(0, 1)),
            )
        )
    )
    result = analyze(p.graph)
    fact = returned(p, result)
    assert fact.value.width_bits == 1
    assert fact.value.value == (1 if count == 0 else None)
    assert fact.labels.unknown_provenance is (count != 0)
    assert result.status == ("complete_in_scope" if count == 0 else "partial")


def test_shift_support_revision_invalidates_old_policy_cache_identity():
    policy = ScalarPolicy()
    previous = policy.to_data() | {"ruleset": "scalar-transfer-v1"}
    assert policy.ruleset == "scalar-transfer-v2"
    assert digest(policy) != digest(previous)
    with pytest.raises(ContractError):
        ScalarPolicy.from_data(previous)
