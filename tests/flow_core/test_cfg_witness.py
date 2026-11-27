"""Production CFG-witness export over the exact immutable SSA snapshot."""

from dataclasses import replace

from ida_pro_mcp.flow_core.cfg_witness import build_cfg_witness
from ida_pro_mcp.flow_core.ssa import build_ssa
from test_ssa import Block, ins, reg, snapshot


def sourced(instruction, ea):
    return replace(instruction, source_eas=(ea,))


def program(*, duplicate_ea=False):
    return build_ssa(
        snapshot(
            (
                Block(0, (), (sourced(ins(0, "m_jcnd", reg(0)), 0x1010),)),
                Block(1, (0,), (sourced(ins(0, "m_mov", reg(8), dest=reg(16,
                    role="destination")), 0x1020),)),
                Block(2, (0,), (sourced(ins(0, "m_mov", reg(24), dest=reg(16,
                    role="destination")), 0x1030),)),
                Block(3, (1, 2), (sourced(ins(0, "m_ret", reg(16)), 0x1040),)),
                Block(4, (), (sourced(ins(0, "m_ret", reg(32)),
                    0x1010 if duplicate_ea else 0x1200),)),
            ),
            function_id="function-entry:4096",
        )
    )


def test_cfg_witness_exports_all_blocks_and_exact_native_rvas():
    witness = build_cfg_witness(program(), image_base=0x1000,
        exception_flow_complete=True, alternate_entry_blocks=())
    assert witness["schema_version"] == "flow-cfg-witness/1"
    assert witness["entry_block_id"].endswith(":0")
    assert witness["cfg_overapproximation_complete"] is True
    assert witness["exception_flow_complete"] is True
    assert witness["block_count"] == 5
    assert witness["alternate_entry_block_ids"] == []
    assert len(witness["blocks"]) == 5
    assert witness["blocks"][0]["successors"] == [
        {"target_block_id": witness["blocks"][1]["block_id"], "kind": "normal"},
        {"target_block_id": witness["blocks"][2]["block_id"], "kind": "normal"},
    ]
    assert witness["blocks"][4]["block_index"] == 4
    assert witness["blocks"][4]["instructions"] == [{
        "rva": "0x200", "instruction_identity": "instruction-rva:200",
        "supported": True,
    }]


def test_cfg_witness_fails_closed_for_exception_or_alternate_entry_gaps():
    with_exception_gap = build_cfg_witness(program(), image_base=0x1000,
        exception_flow_complete=False, alternate_entry_blocks=())
    assert with_exception_gap["cfg_overapproximation_complete"] is True
    assert with_exception_gap["exception_flow_complete"] is False
    alternate = build_cfg_witness(program(), image_base=0x1000,
        exception_flow_complete=True, alternate_entry_blocks=(4,))
    assert alternate["alternate_entry_block_ids"] == [alternate["blocks"][4]["block_id"]]


def test_cfg_witness_marks_ambiguous_native_instruction_ownership_incomplete():
    witness = build_cfg_witness(program(duplicate_ea=True), image_base=0x1000,
        exception_flow_complete=True, alternate_entry_blocks=())
    assert witness["cfg_overapproximation_complete"] is False
    assert any(block["has_unknown_successor"] for block in witness["blocks"])
