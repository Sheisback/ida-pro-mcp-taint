"""Numeric Store-site proofs never classify types or claim final slot state."""

from dataclasses import replace

import pytest

from ida_pro_mcp.flow_core.contracts import Block, Instruction
from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
from ida_pro_mcp.flow_core.store_proof import prove_store, validate_store_proof
from test_memory import const, load, plan, reg, store


TARGET = 0x12345678


def fixture(value=TARGET, offset=112, bits=64, prefix=()):
    source = plan(
        (
            *prefix,
            Instruction(
                len(prefix),
                "m_add",
                (reg(), const(offset, 64, "right"), reg(64, 64, "destination")),
            ),
            store(len(prefix) + 1, const(value, bits), reg(64, 64, "destination")),
        )
    )
    memory = build_memory_graph(source.program.graph.snapshot)
    base = next(
        e.node_id for e in memory.program.entry_storage if e.storage.bit_offset == 0
    )
    target = next(n.node_id for n in memory.graph.nodes if n.kind == "Store")
    return memory, target, base


def test_callback_like_store_proves_only_numeric_site_and_replays():
    memory, target, base = fixture()
    proof = prove_store(memory, target, base, 112, TARGET)
    assert proof.status == "proven_in_scope"
    assert proof.observed_base_node_id == base
    assert proof.observed_byte_offset == 112
    assert proof.observed_target_ea == TARGET
    assert proof.width_bits == 64
    assert proof.steps and proof.evidence_ids and proof.assumptions
    assert validate_store_proof(memory, proof)
    assert not validate_store_proof(
        memory, replace(proof, target_ea=TARGET + 1, observed_target_ea=TARGET + 1)
    )
    assert not validate_store_proof(
        memory, replace(proof, assumptions=("altered_scope",))
    )


@pytest.mark.parametrize("value,offset", [(TARGET + 1, 112), (TARGET, 120)])
def test_changed_value_or_wrong_offset_is_mismatch(value, offset):
    memory, target, base = fixture(value, offset)
    assert prove_store(memory, target, base, 112, TARGET).status == "mismatch"


def test_short_store_is_unknown_not_registration():
    memory, target, base = fixture(bits=32)
    assert prove_store(memory, target, base, 112, TARGET).status == "unknown"


def test_budget_missing_source_and_different_snapshot_fail_closed():
    memory, target, base = fixture()
    assert (
        prove_store(memory, target, base, 112, TARGET, max_nodes=1).status == "unknown"
    )
    assert prove_store(memory, base, target, 112, TARGET).status == "unknown"
    proof = prove_store(memory, target, base, 112, TARGET)
    changed, _, _ = fixture(TARGET + 1)
    assert not validate_store_proof(changed, proof)


def test_unresolved_load_not_promoted_by_numeric_taint_facts():
    source = plan(
        (load(0, out=128, bits=64), store(1, reg(128, 64), reg(role="destination")))
    )
    memory = build_memory_graph(source.program.graph.snapshot)
    base = next(
        e.node_id for e in memory.program.entry_storage if e.storage.bit_offset == 0
    )
    target = next(n.node_id for n in memory.graph.nodes if n.kind == "Store")
    assert prove_store(memory, target, base, 0, TARGET).status == "unknown"


@pytest.mark.parametrize(
    "right,expected", [(TARGET, "proven_in_scope"), (TARGET + 1, "unknown")]
)
def test_phi_requires_identical_full_width_values(right, expected):
    blocks = (
        Block(0, (), ()),
        Block(
            1,
            (0,),
            (
                Instruction(
                    0, "m_mov", (const(TARGET, 64), reg(128, 64, "destination"))
                ),
            ),
        ),
        Block(
            2,
            (0,),
            (Instruction(0, "m_mov", (const(right, 64), reg(128, 64, "destination"))),),
        ),
        Block(3, (1, 2), (store(0, reg(128, 64), reg(role="destination")),)),
    )
    memory = build_memory_graph(plan((), blocks=blocks).program.graph.snapshot)
    base = next(
        e.node_id for e in memory.program.entry_storage if e.storage.bit_offset == 0
    )
    target = next(n.node_id for n in memory.graph.nodes if n.kind == "Store")
    assert prove_store(memory, target, base, 0, TARGET).status == expected


@pytest.mark.parametrize(
    "truncate,expected", [(False, "proven_in_scope"), (True, "unknown")]
)
def test_copy_and_truncate_then_extend(truncate, expected):
    instructions = [
        Instruction(0, "m_mov", (const(TARGET, 64), reg(128, 64, "destination")))
    ]
    if truncate:
        instructions.extend(
            (
                Instruction(1, "m_low", (reg(128, 64), reg(256, 32, "destination"))),
                Instruction(2, "m_xdu", (reg(256, 32), reg(320, 64, "destination"))),
            )
        )
    instructions.append(
        store(
            len(instructions),
            reg(320 if truncate else 128, 64),
            reg(role="destination"),
        )
    )
    memory = build_memory_graph(plan(instructions).program.graph.snapshot)
    base = next(
        e.node_id for e in memory.program.entry_storage if e.storage.bit_offset == 0
    )
    target = next(n.node_id for n in memory.graph.nodes if n.kind == "Store")
    assert prove_store(memory, target, base, 0, TARGET).status == expected


def test_stack_address_is_not_an_absolute_function_address():
    from ida_pro_mcp.flow_core.contracts import Operand

    memory = build_memory_graph(
        plan(
            (store(0, Operand("stack_address", 64, address=TARGET, role="left")),)
        ).program.graph.snapshot
    )
    base = next(
        e.node_id for e in memory.program.entry_storage if e.storage.bit_offset == 0
    )
    target = next(n.node_id for n in memory.graph.nodes if n.kind == "Store")
    assert prove_store(memory, target, base, 0, TARGET).status == "unknown"


def test_v2_high_function_address_keeps_exact_integer_and_digest():
    from ida_pro_mcp.flow_core.contracts import Operand, Snapshot
    from ida_pro_mcp.flow_core.serialization import from_wire_v2, to_wire_v2
    from ida_pro_mcp.flow_core.store_proof import StoreProof

    ea = 0xFFFFF80012345678
    source = plan(
        (store(0, Operand("address", 64, address=ea, role="left")),)
    ).program.graph.snapshot
    identity = replace(source.identity, wire_version="flow-wire/2")
    memory = build_memory_graph(
        Snapshot(identity, source.function, identity.snapshot_id)
    )
    base = next(
        e.node_id for e in memory.program.entry_storage if e.storage.bit_offset == 0
    )
    target = next(n.node_id for n in memory.graph.nodes if n.kind == "Store")
    proof = prove_store(memory, target, base, 0, ea)
    assert proof.status == "proven_in_scope"
    assert proof.observed_target_ea == ea
    restored = StoreProof.from_data(from_wire_v2(to_wire_v2(proof.to_data())))
    assert validate_store_proof(memory, restored)
    assert (
        proof.proof_digest != prove_store(memory, target, base, 0, ea + 1).proof_digest
    )


@pytest.mark.parametrize(
    "right,expected", [(TARGET, "proven_in_scope"), (TARGET + 1, "unknown")]
)
def test_select_requires_identical_arms_without_condition_claim(right, expected):
    source = plan(
        (
            Instruction(
                0,
                "m_select",
                (
                    reg(256, 8),
                    const(TARGET, 64, "right"),
                    const(right, 64, "argument"),
                    reg(128, 64, "destination"),
                ),
            ),
            store(1, reg(128, 64), reg(role="destination")),
        )
    )
    memory = build_memory_graph(source.program.graph.snapshot)
    base = next(
        e.node_id for e in memory.program.entry_storage if e.storage.bit_offset == 0
    )
    target = next(n.node_id for n in memory.graph.nodes if n.kind == "Store")
    assert prove_store(memory, target, base, 0, TARGET).status == expected


def test_reject_invalid_certificate_fields_before_replay():
    from ida_pro_mcp.flow_core.serialization import ContractError

    memory, target, base = fixture()
    proof = prove_store(memory, target, base, 112, TARGET)
    for fields in (
        {"target_ea": -1},
        {"max_nodes": 0},
        {"graph_digest": "bad"},
        {"reasons": ("contradiction",)},
        {"evidence_ids": ()},
    ):
        with pytest.raises(ContractError):
            replace(proof, **fields)


def segmented_fixture(segment):
    memory = build_memory_graph(
        plan(
            (
                Instruction(
                    0, "m_stx", (const(TARGET, 64), segment, reg(role="destination"))
                ),
            )
        ).program.graph.snapshot
    )
    base = next(
        e.node_id for e in memory.program.entry_storage if e.storage.bit_offset == 0
    )
    target = next(n.node_id for n in memory.graph.nodes if n.kind == "Store")
    return memory, target, base


def test_bound_flat_policy_allows_native_segment_and_records_exact_assumption():
    from ida_pro_mcp.flow_core.memory_graph import FLAT_USERSPACE_ASSUMPTION

    memory, target, base = segmented_fixture(reg(512, 16, "right"))
    proof = prove_store(memory, target, base, 0, TARGET)
    assert proof.status == "proven_in_scope"
    assert FLAT_USERSPACE_ASSUMPTION in proof.assumptions
    assert "flat_address_space_zero_segment" not in proof.assumptions
    assert validate_store_proof(memory, proof)


def test_segment_without_bound_flat_policy_is_unknown():
    from ida_pro_mcp.flow_core.memory import MemoryPolicy
    from ida_pro_mcp.flow_core.memory_analysis import analyze_memory

    memory, target, base = segmented_fixture(reg(512, 16, "right"))
    no_flat = analyze_memory(memory.plan, (), policy=MemoryPolicy())
    unbound = replace(memory, result=no_flat)
    assert prove_store(unbound, target, base, 0, TARGET).status == "unknown"


def test_tls_like_wide_segment_expression_not_promoted_by_flat_policy():
    memory, target, base = segmented_fixture(reg(512, 64, "right"))
    assert prove_store(memory, target, base, 0, TARGET).status == "unknown"
