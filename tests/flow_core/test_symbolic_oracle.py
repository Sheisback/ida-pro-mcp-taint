"""Big-int oracle self-tests: full-width meaning independent of Z3."""

import pytest

from ida_pro_mcp.flow_core.symbolic import (
    SymExpr,
    SymbolicBudgetError,
    UnsupportedSymbolicError,
    evaluate_sym,
)


def const(value, width):
    return SymExpr("const", width, value=value)


def var(name, width):
    return SymExpr("var", width, name=name)


def op(name, width, *children):
    return SymExpr("op", width, op=name, children=children)


def test_wraparound_32():
    add = op("add", 32, const(0xFFFFFFFF, 32), const(1, 32))
    assert evaluate_sym(add, {}) == 0
    sub = op("sub", 32, const(0, 32), const(1, 32))
    assert evaluate_sym(sub, {}) == 0xFFFFFFFF
    mul = op("mul", 32, const(0x10000, 32), const(0x10000, 32))
    assert evaluate_sym(mul, {}) == 0


def test_wraparound_64():
    add = op("add", 64, const(2**64 - 1, 64), const(2, 64))
    assert evaluate_sym(add, {}) == 1
    neg = op("neg", 64, const(1, 64))
    assert evaluate_sym(neg, {}) == 2**64 - 1
    sub = op("sub", 64, const(0, 64), const(2**63, 64))
    assert evaluate_sym(sub, {}) == 2**63


def test_signed_unsigned_compares_32():
    neg_one = const(0xFFFFFFFF, 32)
    one = const(1, 32)
    assert evaluate_sym(op("slt", 1, neg_one, one), {}) == 1
    assert evaluate_sym(op("ult", 1, neg_one, one), {}) == 0
    assert evaluate_sym(op("sgt", 1, one, neg_one), {}) == 1
    assert evaluate_sym(op("uge", 1, neg_one, one), {}) == 1
    assert evaluate_sym(op("sle", 1, neg_one, neg_one), {}) == 1
    assert evaluate_sym(op("eq", 8, neg_one, one), {}) == 0
    assert evaluate_sym(op("ne", 8, neg_one, one), {}) == 1


def test_shift_corners():
    assert evaluate_sym(op("shl", 8, const(1, 8), const(7, 8)), {}) == 0x80
    with pytest.raises(UnsupportedSymbolicError):
        evaluate_sym(op("shl", 8, const(1, 8), const(8, 8)), {})
    with pytest.raises(UnsupportedSymbolicError):
        evaluate_sym(op("lshr", 32, const(1, 32), const(33, 8)), {})
    assert evaluate_sym(op("lshr", 8, const(0x80, 8), const(7, 8)), {}) == 1
    assert evaluate_sym(op("ashr", 8, const(0x80, 8), const(7, 8)), {}) == 0xFF
    assert evaluate_sym(op("ashr", 8, const(0x7F, 8), const(7, 8)), {}) == 0


def test_extensions_and_narrowing():
    assert evaluate_sym(op("zext", 16, const(0xFF, 8)), {}) == 0xFF
    assert evaluate_sym(op("sext", 16, const(0xFF, 8)), {}) == 0xFFFF
    assert evaluate_sym(op("sext", 16, const(0x7F, 8)), {}) == 0x7F
    assert evaluate_sym(op("trunc", 8, const(0x1FF, 16)), {}) == 0xFF
    assert evaluate_sym(op("high", 8, const(0x1FF, 16)), {}) == 0x01
    assert evaluate_sym(op("high", 16, const(0xDEADBEEF, 32)), {}) == 0xDEAD


def test_bitwise_and_select_concat():
    assert evaluate_sym(op("and", 8, const(0xF0, 8), const(0xCC, 8)), {}) == 0xC0
    assert evaluate_sym(op("or", 8, const(0xF0, 8), const(0xCC, 8)), {}) == 0xFC
    assert evaluate_sym(op("xor", 8, const(0xFF, 8), const(0xFF, 8)), {}) == 0
    assert evaluate_sym(op("not", 8, const(0x00, 8)), {}) == 0xFF
    assert evaluate_sym(op("logical_not", 1, const(0, 32)), {}) == 1
    assert evaluate_sym(op("logical_not", 1, const(5, 32)), {}) == 0
    sel = op("select", 8, const(1, 1), const(0xA, 8), const(0xB, 8))
    assert evaluate_sym(sel, {}) == 0xA
    sel0 = op("select", 8, const(0, 8), const(0xA, 8), const(0xB, 8))
    assert evaluate_sym(sel0, {}) == 0xB
    cat = op("concat_low", 16, const(0xCD, 8), const(0xAB, 8))
    assert evaluate_sym(cat, {}) == 0xABCD


def test_extract_vectors_and_malformed():
    assert evaluate_sym(op("extract:0", 8, const(0xABCD, 16)), {}) == 0xCD
    assert evaluate_sym(op("extract:8", 8, const(0xABCD, 16)), {}) == 0xAB
    assert evaluate_sym(op("extract:16", 16, const(0xDEADBEEF, 32)), {}) == 0xDEAD
    with pytest.raises(UnsupportedSymbolicError):
        evaluate_sym(op("extract:9", 8, const(0xABCD, 16)), {})
    with pytest.raises(UnsupportedSymbolicError):
        evaluate_sym(op("extract:nope", 8, const(0xAB, 8)), {})


def test_unknown_unbound_and_budget():
    unk = SymExpr("unknown", 8, reason="probe")
    with pytest.raises(UnsupportedSymbolicError):
        evaluate_sym(op("add", 8, unk, const(1, 8)), {})
    with pytest.raises(UnsupportedSymbolicError):
        evaluate_sym(var("x", 8), {})
    assert evaluate_sym(var("x", 8), {"x": 0x1FF}) == 0xFF
    with pytest.raises(SymbolicBudgetError):
        evaluate_sym(op("add", 8, const(1, 8), const(2, 8)), {}, max_evaluations=1)
    with pytest.raises(UnsupportedSymbolicError):
        evaluate_sym(SymExpr("op", 8, op="nope", children=(const(1, 8),)), {})
