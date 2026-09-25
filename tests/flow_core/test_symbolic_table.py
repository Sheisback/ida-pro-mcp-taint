"""Op-table coverage, translator behavior, and the no-z3-import contract."""

import sys
from types import SimpleNamespace as NS

import pytest

from ida_pro_mcp.flow_core import ssa as ssa_mod
from ida_pro_mcp.flow_core.symbolic import (
    OP_TABLE,
    SymbolicBudgetError,
    evaluate_sym,
    support_matrix,
    translate_node,
)


def node(kind, width, operation=None, inputs=(), constant=None):
    return NS(kind=kind, width_bits=width, operation=operation,
             inputs=tuple(inputs), constant=constant)


def test_table_covers_all_ssa_scalar_opcodes():
    for opcode, operation in ssa_mod.UNARY.items():
        assert ("Unary", operation) in OP_TABLE, opcode
    for opcode, operation in ssa_mod.BINARY.items():
        assert ("Binary", operation) in OP_TABLE, opcode
    for opcode, operation in ssa_mod.COMPARE.items():
        assert ("Compare", operation) in OP_TABLE, opcode
    assert ("Binary", "concat_low") in OP_TABLE
    for key, (support, rationale) in OP_TABLE.items():
        assert support in {"exact_bv", "divergence_unknown", "unsupported"}
        assert rationale


def test_matrix_shape_and_shift_policy():
    rows = support_matrix()
    assert len(rows) == len(OP_TABLE)
    by_op = {(kind, op): support for kind, op, support, _ in rows}
    assert by_op[("Binary", "shl")] == "divergence_unknown"
    assert by_op[("Binary", "lshr")] == "divergence_unknown"
    assert by_op[("Binary", "ashr")] == "divergence_unknown"
    assert by_op[("Binary", "add")] == "exact_bv"
    assert by_op[("Phi", "-")] == "unsupported"
    assert by_op[("Load", "-")] == "unsupported"
    assert by_op[("CallResult", "-")] == "unsupported"


def test_translate_add_chain_and_copy():
    nodes = {
        "x": node("InputValue", 32),
        "k": node("Constant", 32, constant=1),
        "a": node("Binary", 32, "add", ("x", "k")),
        "c": node("Copy", 32, None, ("a",)),
    }
    result = translate_node(nodes, "c")
    assert result.unknowns == ()
    assert evaluate_sym(result.roots[0], {"x": 41}) == 42


def test_translate_width_mismatch_is_unknown():
    nodes = {
        "x": node("InputValue", 16),
        "k": node("Constant", 16, constant=1),
        "a": node("Binary", 32, "add", ("x", "k")),
    }
    result = translate_node(nodes, "a")
    assert result.roots[0].kind == "unknown"
    assert any("operand_width" in item for item in result.unknowns)


def test_shift_constant_in_range_exact_symbolic_unknown():
    nodes = {
        "x": node("InputValue", 8),
        "n": node("Constant", 8, constant=3),
        "s": node("Binary", 8, "shl", ("x", "n")),
    }
    exact = translate_node(nodes, "s")
    assert exact.unknowns == ()
    assert evaluate_sym(exact.roots[0], {"x": 1}) == 8
    nodes["c"] = node("InputValue", 8)
    nodes["t"] = node("Binary", 8, "shl", ("x", "c"))
    vague = translate_node(nodes, "t")
    assert vague.roots[0].kind == "unknown"
    assert any("shift_count_unbounded" in item for item in vague.unknowns)
    nodes["o"] = node("Constant", 8, constant=8)
    nodes["u"] = node("Binary", 8, "shl", ("x", "o"))
    over = translate_node(nodes, "u")
    assert over.roots[0].kind == "unknown"


def test_phi_load_call_are_unknown_with_reasons():
    nodes = {
        "p": node("Phi", 32),
        "l": node("Load", 32, "memory_load_boundary"),
        "r": node("CallResult", 32),
    }
    for root in ("p", "l", "r"):
        result = translate_node(nodes, root)
        assert result.roots[0].kind == "unknown"
        assert result.unknowns


def test_extract_pattern_supported_and_guarded():
    nodes = {
        "x": node("InputValue", 64),
        "e": node("Unary", 16, "extract:32", ("x",)),
    }
    result = translate_node(nodes, "e")
    assert result.unknowns == ()
    assert evaluate_sym(result.roots[0], {"x": 0xAAAA_BBBB_CCCC_DDDD}) == 0xBBBB
    bad = {
        "x": node("InputValue", 16),
        "e": node("Unary", 16, "extract:8", ("x",)),
    }
    over = translate_node(bad, "e")
    assert over.roots[0].kind == "unknown"
    assert any("malformed_extract" in item for item in over.unknowns)
    assert ("Unary", "extract:<offset>") in OP_TABLE


def test_budgets_and_dangling():
    nodes = {"x": node("InputValue", 8)}
    with pytest.raises(SymbolicBudgetError):
        translate_node(nodes, "missing")
    deep = {"n0": node("InputValue", 8)}
    for index in range(1, 10):
        deep[f"n{index}"] = node("Unary", 8, "not", (f"n{index - 1}",))
    with pytest.raises(SymbolicBudgetError):
        translate_node(deep, "n9", max_depth=4)
    with pytest.raises(SymbolicBudgetError):
        translate_node(deep, "n9", max_nodes=3)


def test_pure_path_never_imports_z3():
    before = "z3" in sys.modules
    nodes = {
        "x": node("InputValue", 8),
        "k": node("Constant", 8, constant=7),
        "a": node("Binary", 8, "xor", ("x", "k")),
    }
    result = translate_node(nodes, "a")
    assert evaluate_sym(result.roots[0], {"x": 0xFF}) == 0xF8
    assert ("z3" in sys.modules) == before
