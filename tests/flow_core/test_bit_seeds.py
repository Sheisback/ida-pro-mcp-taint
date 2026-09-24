"""Exact entry bit windows; byte-memory use remains conservative and partial."""

from dataclasses import replace

import pytest

from ida_pro_mcp.flow_core import ContractError
from ida_pro_mcp.flow_core.analysis import BitSeed, Seed
from ida_pro_mcp.flow_core.contracts import (
    Block,
    CallInfo,
    Instruction,
    LocationSet,
    Operand,
    Snapshot,
)
from ida_pro_mcp.flow_core.implicit_analysis import analyze_implicit
from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
from ida_pro_mcp.flow_core.states import Labels, StorageLocation
from test_ssa import snapshot


def reg(offset, width, role="left"):
    return Operand(
        "storage",
        width,
        storage=StorageLocation("microregister", "microregister", offset, width),
        role=role,
    )


def stack(offset, width, role="left"):
    return Operand(
        "storage",
        width,
        storage=StorageLocation("stack", "stack", offset, width),
        role=role,
    )


def program(*instructions, endian="little"):
    source = snapshot((Block(0, (), tuple(instructions)),))
    if endian != source.identity.environment.data_endian:
        identity = replace(
            source.identity,
            environment=replace(source.identity.environment, data_endian=endian),
        )
        source = Snapshot(identity, source.function, identity.snapshot_id)
    return build_memory_graph(source)


def entry(bundle, width=64):
    matches = [
        item
        for item in bundle.program.entry_storage
        if item.storage.address_space == "microregister"
        and item.storage.bit_offset == 0
    ]
    assert len(matches) == 1 and matches[0].storage.width_bits == width
    return matches[0].node_id


def labels(result, node):
    return next(fact.labels for fact in result.facts if fact.node_id == node.node_id)


def slice_program():
    return program(
        Instruction(0, "m_mov", (reg(0, 64), reg(64, 64, "destination"))),
        Instruction(1, "m_low", (reg(64, 64), reg(128, 32, "destination"))),
        Instruction(2, "m_high", (reg(64, 64), reg(160, 32, "destination"))),
        Instruction(3, "m_ret", (reg(128, 32),)),
    )


@pytest.mark.parametrize("bit_offset,selected", ((0, "trunc"), (32, "high")))
def test_bit_range_seed_projects_only_selected_half(bit_offset, selected):
    bundle = slice_program()
    source = entry(bundle)
    seed = BitSeed(source, Labels(("X",)), bit_offset, 32)
    result = analyze_implicit(bundle.program, (seed,), memory_model=bundle)
    projections = {
        node.operation: node
        for node in bundle.graph.nodes
        if node.kind == "Unary" and node.operation in {"trunc", "high"}
    }
    assert labels(result, projections[selected]).explicit == ("X",)
    other = "high" if selected == "trunc" else "trunc"
    assert labels(result, projections[other]).explicit == ()
    assert not labels(result, projections[other]).unknown_provenance
    returned = next(node for node in bundle.graph.nodes if node.kind == "Return")
    assert labels(result, returned).explicit == (("X",) if bit_offset == 0 else ())
    assert result.status == "complete_in_scope"


def test_bit_range_source_requires_owned_exact_input_window_and_memory_replay():
    bundle = slice_program()
    source = entry(bundle)
    valid = BitSeed(source, Labels(("X",)), 0, 32)
    assert BitSeed.from_data(valid.to_data()) == valid
    with pytest.raises(ContractError, match="whole-byte"):
        BitSeed(source, Labels(("X",)), 1, 32)
    with pytest.raises(ContractError, match="named explicit"):
        BitSeed(source, Labels(control=("C",)), 0, 32)
    with pytest.raises(ContractError, match="fit an InputValue"):
        analyze_implicit(
            bundle.program,
            (replace(valid, bit_offset=64),),
            memory_model=bundle,
        )
    with pytest.raises(ContractError, match="memory replay"):
        analyze_implicit(bundle.program, (valid,))
    whole = Seed(source, Labels(("X",)))
    with pytest.raises(ContractError, match="must not overlap"):
        analyze_implicit(bundle.program, (whole, valid), memory_model=bundle)
    too_many = BitSeed(
        source, Labels(tuple(f"L{index:02}" for index in range(17))), 0, 32
    )
    with pytest.raises(ContractError, match="label budget"):
        analyze_implicit(bundle.program, (too_many,), memory_model=bundle)


def test_distinct_low_and_high_sources_on_same_input_do_not_mix():
    bundle = slice_program()
    source = entry(bundle)
    result = analyze_implicit(
        bundle.program,
        (
            BitSeed(source, Labels(("LOW",)), 0, 32),
            BitSeed(source, Labels(("HIGH",)), 32, 32),
        ),
        memory_model=bundle,
    )
    projections = {
        node.operation: node
        for node in bundle.graph.nodes
        if node.kind == "Unary" and node.operation in {"trunc", "high"}
    }
    assert labels(result, projections["trunc"]).explicit == ("LOW",)
    assert labels(result, projections["high"]).explicit == ("HIGH",)
    returned = next(node for node in bundle.graph.nodes if node.kind == "Return")
    assert labels(result, returned).explicit == ("LOW",)


def test_whole_value_control_seed_and_bit_source_on_same_input_both_survive():
    bundle = slice_program()
    source = entry(bundle)
    result = analyze_implicit(
        bundle.program,
        (
            Seed(source, Labels(control=("C",))),
            BitSeed(source, Labels(("X",)), 0, 32),
        ),
        memory_model=bundle,
    )
    returned = next(node for node in bundle.graph.nodes if node.kind == "Return")
    assert labels(result, returned).explicit == ("X",)
    assert labels(result, returned).control == ("C",)


def test_bit_source_annihilator_stays_clean_but_unknown_operation_stays_partial():
    zero = Operand("constant", 64, constant=0, role="right")
    cleared = program(
        Instruction(
            0,
            "m_and",
            (reg(0, 64), zero, reg(64, 64, "destination")),
        ),
        Instruction(1, "m_ret", (reg(64, 64),)),
    )
    selected = BitSeed(entry(cleared), Labels(("X",)), 0, 32)
    clean = analyze_implicit(cleared.program, (selected,), memory_model=cleared)
    returned = next(node for node in cleared.graph.nodes if node.kind == "Return")
    assert labels(clean, returned).explicit == ()
    assert not labels(clean, returned).unknown_provenance

    unknown = program(
        Instruction(0, "m_unmodeled", (reg(0, 64), reg(64, 64, "destination"))),
        Instruction(1, "m_ret", (reg(64, 64),)),
    )
    selected = BitSeed(entry(unknown), Labels(("X",)), 0, 32)
    result = analyze_implicit(unknown.program, (selected,), memory_model=unknown)
    returned = next(node for node in unknown.graph.nodes if node.kind == "Return")
    assert labels(result, returned).explicit == ("X",)
    assert labels(result, returned).unknown_provenance
    assert result.status == "partial"


def test_bit_source_through_widthless_callinfo_keeps_named_possible_source():
    call = CallInfo(
        None,
        1,
        (reg(0, 64, "argument"),),
        (),
        64,
        LocationSet(tuple(range(8, 16))),
        LocationSet(),
        1,
        False,
    )
    bundle = program(
        Instruction(
            0,
            "m_icall",
            (
                reg(64, 64),
                Operand("void", None, role="right"),
                Operand("callinfo", None, call=call, role="destination"),
            ),
        ),
        Instruction(1, "m_ret", (reg(128, 64),)),
    )
    result = analyze_implicit(
        bundle.program,
        (BitSeed(entry(bundle), Labels(("X",)), 0, 32),),
        memory_model=bundle,
    )
    returned = next(node for node in bundle.graph.nodes if node.kind == "Return")
    assert labels(result, returned).explicit == ("X",)
    assert labels(result, returned).unknown_provenance
    assert result.status == "partial"


@pytest.mark.parametrize(
    "endian,offset,expected",
    (
        ("little", 0, ("X",)),
        ("little", 32, ()),
        ("big", 0, ()),
        ("big", 32, ("X",)),
    ),
)
def test_exact_byte_store_reload_preserves_only_selected_input_half(
    endian, offset, expected
):
    bundle = program(
        Instruction(0, "m_mov", (reg(0, 64), stack(0, 64, "destination"))),
        Instruction(1, "m_mov", (stack(offset, 32), reg(128, 32, "destination"))),
        Instruction(2, "m_ret", (reg(128, 32),)),
        endian=endian,
    )
    seed = BitSeed(entry(bundle), Labels(("X",)), 0, 32)
    result = analyze_implicit(bundle.program, (seed,), memory_model=bundle)
    returned = next(node for node in bundle.graph.nodes if node.kind == "Return")
    assert labels(result, returned).explicit == expected
    assert not labels(result, returned).unknown_provenance
    assert result.status == "complete_in_scope"
    assert "bit_seed_byte_store_widened" not in result.diagnostics


def test_may_alias_store_keeps_bit_source_and_partial_boundary():
    bundle = program(
        Instruction(
            0,
            "m_select",
            (
                reg(256, 1),
                Operand("stack_address", 64, address=0, role="right"),
                Operand("stack_address", 64, address=8, role="left"),
                reg(384, 64, "destination"),
            ),
        ),
        Instruction(
            1,
            "m_stx",
            (
                reg(0, 64),
                Operand("constant", 16, constant=0, role="right"),
                reg(384, 64, "destination"),
            ),
        ),
        Instruction(
            2,
            "m_ldx",
            (
                Operand("constant", 16, constant=0, role="left"),
                reg(384, 64, "right"),
                reg(448, 64, "destination"),
            ),
        ),
        Instruction(3, "m_ret", (reg(448, 64),)),
    )
    seed = BitSeed(entry(bundle), Labels(("X",)), 0, 32)
    result = analyze_implicit(bundle.program, (seed,), memory_model=bundle)
    returned = next(node for node in bundle.graph.nodes if node.kind == "Return")
    assert "X" in labels(result, returned).explicit
    assert result.status == "partial"
    assert "bit_seed_byte_store_widened" in result.diagnostics


def test_store_reload_keeps_subbyte_projection_without_tainting_other_bits():
    bundle = program(
        Instruction(0, "m_low", (reg(0, 8), reg(64, 1, "destination"))),
        Instruction(1, "m_xdu", (reg(64, 1), reg(72, 8, "destination"))),
        Instruction(2, "m_mov", (reg(72, 8), stack(0, 8, "destination"))),
        Instruction(3, "m_mov", (stack(0, 8), reg(88, 8, "destination"))),
        Instruction(4, "m_high", (reg(88, 8), reg(104, 1, "destination"))),
        Instruction(5, "m_ret", (reg(104, 1),)),
    )
    seed = BitSeed(entry(bundle, 8), Labels(("X",)), 0, 8)
    result = analyze_implicit(bundle.program, (seed,), memory_model=bundle)
    returned = next(node for node in bundle.graph.nodes if node.kind == "Return")
    assert labels(result, returned).explicit == ()
    assert not labels(result, returned).unknown_provenance
    assert result.status == "complete_in_scope"


@pytest.mark.parametrize(
    "opcode,count,expected,partial",
    (
        ("m_shr", 32, (), False),
        ("m_shl", 32, (), False),
        ("m_sar", 32, (), False),
        ("m_shr", 64, ("X",), True),
    ),
)
def test_constant_shift_projects_bit_window_or_fails_closed(
    opcode, count, expected, partial
):
    bundle = program(
        Instruction(
            0,
            opcode,
            (
                reg(0, 64),
                Operand("constant", 8, constant=count, role="right"),
                reg(64, 64, "destination"),
            ),
        ),
        Instruction(1, "m_low", (reg(64, 64), reg(128, 32, "destination"))),
        Instruction(2, "m_ret", (reg(128, 32),)),
    )
    seed = BitSeed(entry(bundle), Labels(("X",)), 0, 32)
    result = analyze_implicit(bundle.program, (seed,), memory_model=bundle)
    returned = next(node for node in bundle.graph.nodes if node.kind == "Return")
    assert labels(result, returned).explicit == expected
    assert (result.status == "partial") is partial
    if partial:
        assert labels(result, returned).unknown_provenance


def test_whole_low_entry_atom_does_not_taint_shifted_high_half():
    bundle = program(
        Instruction(0, "m_mov", (reg(0, 32), reg(320, 32, "destination"))),
        Instruction(
            1,
            "m_shr",
            (
                reg(0, 64),
                Operand("constant", 8, constant=32, role="right"),
                reg(128, 64, "destination"),
            ),
        ),
        Instruction(2, "m_low", (reg(128, 64), reg(192, 32, "destination"))),
        Instruction(3, "m_ret", (reg(192, 32),)),
    )
    seed = Seed(entry(bundle, 32), Labels(("X",)))
    result = analyze_implicit(bundle.program, (seed,), memory_model=bundle)
    returned = next(node for node in bundle.graph.nodes if node.kind == "Return")
    assert labels(result, returned).explicit == ()
    assert not labels(result, returned).unknown_provenance
    assert result.status == "complete_in_scope"


def test_whole_low_entry_atom_is_byte_precise_after_concat_store_reload():
    bundle = program(
        Instruction(0, "m_mov", (reg(0, 32), reg(320, 32, "destination"))),
        Instruction(1, "m_mov", (reg(0, 64), stack(0, 64, "destination"))),
        Instruction(2, "m_mov", (stack(32, 32), reg(128, 32, "destination"))),
        Instruction(3, "m_ret", (reg(128, 32),)),
    )
    seed = Seed(entry(bundle, 32), Labels(("X",)))
    result = analyze_implicit(bundle.program, (seed,), memory_model=bundle)
    returned = next(node for node in bundle.graph.nodes if node.kind == "Return")
    assert labels(result, returned).explicit == ()
    assert not labels(result, returned).unknown_provenance
    assert result.status == "complete_in_scope"


def test_direct_result_seed_survives_whole_entry_bit_annihilator():
    bundle = program(
        Instruction(
            0,
            "m_and",
            (
                reg(0, 64),
                Operand("constant", 64, constant=0, role="right"),
                reg(128, 64, "destination"),
            ),
        ),
        Instruction(1, "m_ret", (reg(128, 64),)),
    )
    binary = next(node for node in bundle.graph.nodes if node.kind == "Binary")
    seeds = tuple(
        sorted(
            (
                Seed(entry(bundle), Labels(("X",))),
                Seed(binary.node_id, Labels(("X",))),
            ),
            key=lambda seed: seed.node_id,
        )
    )
    result = analyze_implicit(bundle.program, seeds, memory_model=bundle)
    returned = next(node for node in bundle.graph.nodes if node.kind == "Return")
    assert labels(result, returned).explicit == ("X",)
    assert result.status == "complete_in_scope"


def test_unrelated_oversized_value_does_not_consume_bit_projection_budget():
    bundle = program(
        Instruction(
            0,
            "m_mov",
            (reg(512, 8192), reg(9000, 8192, "destination")),
        ),
        Instruction(1, "m_ret", (reg(0, 32),)),
    )
    seed = BitSeed(entry(bundle, 32), Labels(("X",)), 0, 32)
    result = analyze_implicit(bundle.program, (seed,), memory_model=bundle)
    returned = next(node for node in bundle.graph.nodes if node.kind == "Return")
    assert labels(result, returned).explicit == ("X",)
    assert result.status == "complete_in_scope"
    assert "bit_seed_projection_budget" not in result.diagnostics


def test_relevant_oversized_value_keeps_named_source_and_partial_budget():
    bundle = program(
        Instruction(0, "m_xdu", (reg(0, 64), reg(512, 8192, "destination"))),
        Instruction(1, "m_ret", (reg(512, 8192),)),
    )
    seed = BitSeed(entry(bundle), Labels(("X",)), 0, 32)
    result = analyze_implicit(bundle.program, (seed,), memory_model=bundle)
    returned = next(node for node in bundle.graph.nodes if node.kind == "Return")
    assert labels(result, returned).explicit == ("X",)
    assert labels(result, returned).unknown_provenance
    assert result.status == "partial"
    assert "bit_seed_projection_budget" in result.diagnostics
