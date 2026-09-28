"""IOCTL discovery over dispatcher functions (read-only).

Mirrors the reference ``ioctl_decoder`` stage: per-dispatcher collection from
the decompiler, IDA switch tables, and a gated immediate scan, merged through
one validation funnel. Outbound codes the driver merely sends downstream are
excluded so they never pollute the driver's own dispatch surface.

Every candidate keeps its collection method and confidence so callers can
weigh ctree/switch evidence above raw immediates.
"""

from __future__ import annotations

import idaapi
import idc

from ida_pro_mcp.flow_core import driver_triage as core

from .context import (
    DriverContext,
    call_target,
    expired,
    func_name,
    func_range,
    hexrays_ready,
    iter_func_items,
    try_decompile,
)
from .dispatch import references_iocontrolcode

#: Mnemonics whose immediate operands are worth testing as IOCTLs.
_IMMEDIATE_MNEMS = frozenset({"cmp", "test", "sub", "mov", "and", "add"})


def ntstatus_values_from_db() -> tuple[set[int], str]:
    """Read NTSTATUS values from the IDA type database, with fallback note."""
    values: set[int] = set()
    for enum_name in ("NTSTATUS", "_NTSTATUS"):
        try:
            import ida_enum

            get_enum = getattr(ida_enum, "get_enum", None)
            if get_enum is None:
                continue
            enum_id = get_enum(enum_name)
            if enum_id is None or enum_id == idaapi.BADADDR:
                continue
            first = getattr(ida_enum, "get_first_enum_member", None)
            nxt = getattr(ida_enum, "get_next_enum_member", None)
            if first is None or nxt is None:
                continue
            member = first(enum_id)
            while member is not None and member != idaapi.BADADDR:
                values.add(int(member) & 0xFFFFFFFF)
                member = nxt(enum_id, member)
            if values:
                return values, f"IDA enum {enum_name}"
        except Exception:
            continue
    return values, "hardcoded fallback set"


def _collect_immediates(func_ea: int) -> list[tuple[int, int]]:
    """Collect (item_ea, imm32) from comparison/move instructions."""
    found: list[tuple[int, int]] = []
    for item_ea in iter_func_items(func_ea):
        try:
            if idc.print_insn_mnem(item_ea) not in _IMMEDIATE_MNEMS:
                continue
        except Exception:
            continue
        insn = idaapi.insn_t()
        if idaapi.decode_insn(insn, item_ea) <= 0:
            continue
        for op in insn.ops:
            if op.type == idaapi.o_imm:
                found.append((item_ea, int(op.value) & 0xFFFFFFFF))
    return found


def _switch_api():
    """Resolve switch-table helpers across IDA versions (may be None)."""
    try:
        import ida_nalt

        get_si = getattr(ida_nalt, "get_switch_info", None)
    except Exception:
        get_si = None
    if get_si is None:
        get_si = getattr(idaapi, "get_switch_info", None)
    calc = getattr(idaapi, "calc_switch_cases", None)
    if calc is None:
        try:
            import ida_nalt

            calc = getattr(ida_nalt, "calc_switch_cases", None)
        except Exception:
            calc = None
    return get_si, calc


def _normalize_switch_cases(result, defjump) -> list[int]:
    """Best-effort extraction of case values from calc_switch_cases output."""
    values: list[int] = []

    def _take(candidate) -> None:
        try:
            number = int(candidate)
        except Exception:
            return
        if 0 <= number <= 0xFFFFFFFF:
            values.append(number & 0xFFFFFFFF)

    try:
        items = result.items() if isinstance(result, dict) else result
    except Exception:
        return values
    try:
        for entry in items:
            target = None
            payload = entry
            if isinstance(entry, (tuple, list)) and len(entry) == 2:
                payload, target = entry
            elif not isinstance(entry, (tuple, list)):
                payload, target = entry, getattr(entry, "ea", None)
                if hasattr(entry, "values"):
                    payload = entry.values
            if defjump is not None and target == defjump:
                continue
            if isinstance(payload, (tuple, list, set)):
                for candidate in payload:
                    _take(candidate)
            else:
                _take(payload)
    except Exception:
        pass
    return values


def _collect_switch_cases(func_ea: int) -> tuple[list[tuple[int, int]], str]:
    """Collect (item_ea, value) from IDA switch tables in a function."""
    get_si, calc = _switch_api()
    if get_si is None or calc is None:
        return [], "switch API unavailable"
    found: list[tuple[int, int]] = []
    for item_ea in iter_func_items(func_ea):
        try:
            info = get_si(item_ea)
        except Exception:
            continue
        if info is None:
            continue
        try:
            defjump = getattr(info, "defjump", None)
            result = calc(item_ea, info)
        except Exception:
            continue
        for value in _normalize_switch_cases(result, defjump):
            found.append((item_ea, value))
    return found, "ida switch tables"


def _collect_ctree_consts(func_ea: int) -> tuple[list[tuple[int, int, str]], str]:
    """Collect constants from the decompiled control flow of a function.

    Returns (value, insn_ea, kind) triples where kind is "case" (switch-case
    label, high confidence) or "cmp" (equality comparison, medium).
    """
    cfunc = try_decompile(func_ea)
    if cfunc is None:
        return [], "decompiler unavailable"
    try:
        import ida_hexrays

        _base = getattr(ida_hexrays, "ctree_visitor_t", None) or getattr(
            ida_hexrays, "cfunc_visitor_t", None
        )
        if _base is None:
            return [], "ctree visitor API unavailable"

        class _Visitor(_base):  # type: ignore[misc, valid-type]
            def __init__(self):
                _base.__init__(self, ida_hexrays.CV_FAST)
                self.case_values: list[tuple[int, int]] = []
                self.cmp_values: list[tuple[int, int]] = []

            def visit_insn(self, ins):
                try:
                    if ins.op == ida_hexrays.cit_switch:
                        for case in ins.cswitch.cases:
                            for raw in case.values:
                                self.case_values.append((int(raw) & 0xFFFFFFFF, int(ins.ea)))
                except Exception:
                    pass
                return 0

            def visit_expr(self, expr):
                try:
                    if expr.op in (ida_hexrays.cot_eq, ida_hexrays.cot_ne):
                        for side in (expr.x, expr.y):
                            if side.op == ida_hexrays.cot_num:
                                number = getattr(getattr(side, "n", None), "_value", None)
                                if number is not None:
                                    self.cmp_values.append(
                                        (int(number) & 0xFFFFFFFF, int(expr.ea))
                                    )
                except Exception:
                    pass
                return 0

        visitor = _Visitor()
        visitor.apply_to(cfunc.body, None)
    except Exception:
        return [], "ctree walk failed"
    triples = [(v, ea, "case") for v, ea in visitor.case_values]
    triples += [(v, ea, "cmp") for v, ea in visitor.cmp_values]
    return triples, "hexrays ctree"


def _precedes_outbound_builder(item_ea: int, func_end: int, window: int = 6) -> str | None:
    """Return the outbound-builder name when a call site follows the address."""
    cursor = item_ea
    for _ in range(window):
        try:
            cursor = idc.next_head(cursor, func_end)
        except Exception:
            break
        if cursor == idaapi.BADADDR or cursor >= func_end or expired():
            break
        try:
            if idc.print_insn_mnem(cursor) != "call":
                continue
        except Exception:
            continue
        name, _target = call_target(cursor)
        if name in core.OUTBOUND_IOCTL_BUILDERS:
            return name
    return None


def scan_dispatchers(
    ctx: DriverContext,
    dispatch_eas: list[int],
    *,
    include_decompiler: bool = True,
    max_funcs: int = 32,
) -> tuple[list[dict], dict]:
    """Discover IOCTL candidates across dispatcher functions.

    Collection order per dispatcher is ctree, then switch tables, then the
    gated immediate fallback. Candidates merge through one validation funnel
    keyed by code value; the strongest method wins each code.
    """
    ntstatus_extra, ntstatus_source = ntstatus_values_from_db()
    merged: dict[int, dict] = {}
    stats = {
        "dispatchers_scanned": 0,
        "by_method": {},
        "excluded_outbound": 0,
        "rejected": 0,
        "ntstatus_source": ntstatus_source,
        "hexrays_ready": hexrays_ready(),
        "ctree_consts_found": False,
    }
    for func_ea in dispatch_eas[:max_funcs]:
        if expired():
            ctx.limitations.append("IOCTL scan hit the tool deadline (partial)")
            break
        bounds = func_range(func_ea)
        if bounds is None:
            continue
        _start, end = bounds
        stats["dispatchers_scanned"] += 1
        name = func_name(func_ea) or hex(func_ea)
        structured = False
        if include_decompiler:
            triples, _source = _collect_ctree_consts(func_ea)
            if triples:
                stats["ctree_consts_found"] = True
            for value, item_ea, kind in triples:
                method = "ctree_case" if kind == "case" else "ctree_cmp"
                if _emit(
                    ctx, merged, stats, value, method, name, func_ea, item_ea, end,
                    ntstatus_extra, "high" if kind == "case" else "medium",
                ):
                    structured = True
        switch_found, _source = _collect_switch_cases(func_ea)
        for item_ea, value in switch_found:
            if _emit(
                ctx, merged, stats, value, "switch_table", name, func_ea, item_ea, end,
                ntstatus_extra, "high",
            ):
                structured = True
        if structured:
            continue
        corroborated, _why = references_iocontrolcode(func_ea, ctx.is_64bit)
        if not corroborated:
            ctx.limitations.append(
                f"immediate fallback skipped for {name}: no IoControlCode reference"
            )
            continue
        for item_ea, value in _collect_immediates(func_ea):
            _emit(
                ctx, merged, stats, value, "immediate", name, func_ea, item_ea, end,
                ntstatus_extra, "low",
            )
    candidates = sorted(merged.values(), key=lambda c: c["code_int"])
    return candidates, stats


def _emit(
    ctx: DriverContext,
    merged: dict[int, dict],
    stats: dict,
    value: int,
    method: str,
    func_name_text: str,
    func_ea: int,
    item_ea: int,
    func_end: int,
    ntstatus_extra: set[int],
    confidence: str,
) -> bool:
    """Validate one raw candidate and merge it. Returns True when kept."""
    ok, reason = core.is_plausible_ioctl(value, ntstatus_extra)
    if not ok:
        stats["rejected"] += 1
        return False
    outbound = _precedes_outbound_builder(item_ea, func_end)
    if outbound is not None:
        stats["excluded_outbound"] += 1
        return False
    decoded = core.decode_ioctl(value)
    record = {
        "code": decoded["code"],
        "code_int": decoded["code_int"],
        "device_name": decoded["device_name"],
        "function_code": decoded["function"],
        "method": decoded["method_name"],
        "access": decoded["access_name"],
        "method_detail": method,
        "confidence": confidence,
        "function": func_name_text,
        "function_addr": hex(func_ea),
        "addr": hex(item_ea),
    }
    prior = merged.get(value)
    if prior is None or _method_rank(method) > _method_rank(prior["method_detail"]):
        merged[value] = record
    stats["by_method"][method] = stats["by_method"].get(method, 0) + 1
    return True


def _method_rank(method: str) -> int:
    return {"ctree_case": 4, "switch_table": 3, "ctree_cmp": 2, "immediate": 1}.get(method, 0)


def scan_iocontrolcode_fallback(
    ctx: DriverContext,
    exclude_codes: set[int],
    *,
    max_funcs: int = 16,
) -> tuple[list[dict], dict]:
    """Bounded fallback scan over IoControlCode-referencing functions.

    Runs only when dispatcher discovery recovered nothing, mirroring the
    reference fallback role. Whole-binary text matching is deliberately
    avoided: every scanned function must structurally reference the IRP's
    control-code field first.
    """
    import idautils

    ntstatus_extra, ntstatus_source = ntstatus_values_from_db()
    merged: dict[int, dict] = {}
    stats = {
        "functions_scanned": 0,
        "by_method": {},
        "excluded_outbound": 0,
        "rejected": 0,
        "ntstatus_source": ntstatus_source,
    }
    scanned = 0
    try:
        functions = list(idautils.Functions())
    except Exception:
        return [], stats
    for func_ea in functions:
        if scanned >= max_funcs or expired():
            break
        corroborated, _why = references_iocontrolcode(func_ea, ctx.is_64bit)
        if not corroborated:
            continue
        bounds = func_range(func_ea)
        if bounds is None:
            continue
        _start, end = bounds
        scanned += 1
        stats["functions_scanned"] += 1
        name = func_name(func_ea) or hex(func_ea)
        for item_ea, value in _collect_immediates(func_ea):
            if value in exclude_codes:
                continue
            _emit(
                ctx, merged, stats, value, "immediate", name, func_ea, item_ea, end,
                ntstatus_extra, "low",
            )
    return sorted(merged.values(), key=lambda c: c["code_int"]), stats
