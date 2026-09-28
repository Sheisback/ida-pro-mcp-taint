"""Heuristic review leads over dispatcher-reachable code (read-only).

Mirrors the reference ``heuristics`` stage: eleven narrowly-scoped checks run
over dispatcher functions and their transitive callees. Every output is a
triage lead that requires manual review; nothing here is a vulnerability
verdict, and checks that cannot run (no decompiler, non-x64 widths, missing
scope) report as unavailable instead of silent.
"""

from __future__ import annotations

import idaapi
import idautils
import idc

from ida_pro_mcp.flow_core import driver_triage as core

from ..api_core import _get_strings_cache
from . import opcodes as opcode_stage
from .callchain import transitive_callees
from .context import (
    DriverContext,
    call_target,
    calls_in_func,
    expired,
    func_name,
    func_range,
    iter_func_items,
    try_decompile,
)
from .dispatch import references_iocontrolcode

#: Check names accepted by run(checks=[...]).
CHECKS = (
    "unvalidated_copy",
    "pool_alloc_unguarded",
    "stack_alloc",
    "privileged_insn",
    "physical_memory_ref",
    "unsafe_mdl",
    "irql_cooccurrence",
    "missing_priv_gate",
    "arbitrary_write_shape",
    "double_fetch",
    "use_after_free",
)

_COPY_LOOKBACK = 20
_COPY_LOOKAHEAD = 6
_UAF_FORWARD = 40
_MAX_LEADS = 300


def _items(func_ea: int, limit: int = 20000) -> list[int]:
    return list(iter_func_items(func_ea, limit))


def _call_names_in_window(items: list[int], center: int, before: int, after: int) -> set[str]:
    names: set[str] = set()
    lo = max(0, center - before)
    hi = min(len(items), center + after + 1)
    for item_ea in items[lo:hi]:
        try:
            if idc.print_insn_mnem(item_ea) != "call":
                continue
        except Exception:
            continue
        name, _target = call_target(item_ea)
        if name:
            names.add(name)
    return names


def _check_unvalidated_copy(ctx, scope, dispatchers, leads) -> None:
    for func_ea in scope:
        if expired():
            break
        items = _items(func_ea)
        name = func_name(func_ea) or hex(func_ea)
        in_dispatcher = func_ea in dispatchers
        for index, item_ea in enumerate(items):
            try:
                if idc.print_insn_mnem(item_ea) != "call":
                    continue
            except Exception:
                continue
            call_name, _t = call_target(item_ea)
            if call_name not in core.RISKY_COPY_SINKS:
                continue
            nearby = _call_names_in_window(items, index, _COPY_LOOKBACK, _COPY_LOOKAHEAD)
            if nearby & set(core.COPY_GUARDS):
                continue
            leads.append(
                core.ReviewLead(
                    check="unvalidated_copy",
                    severity=core.SEV_HIGH if in_dispatcher else core.SEV_MEDIUM,
                    title=f"{call_name} without nearby probe/guard",
                    detail=(
                        f"{call_name} at {hex(item_ea)} has no ProbeFor*/checked "
                        f"routine within -{_COPY_LOOKBACK}/+{_COPY_LOOKAHEAD} "
                        "instructions; verify length and source validation."
                    ),
                    function=name,
                    addr=hex(item_ea),
                    evidence={"sink": call_name},
                    method="windowed call scan around copy sinks",
                ).as_dict()
            )


def _check_pool_alloc(ctx, scope, leads) -> None:
    for func_ea in scope:
        if expired():
            break
        items = _items(func_ea)
        name = func_name(func_ea) or hex(func_ea)
        for index, item_ea in enumerate(items):
            try:
                if idc.print_insn_mnem(item_ea) != "call":
                    continue
            except Exception:
                continue
            call_name, _t = call_target(item_ea)
            if call_name not in core.POOL_ALLOCATORS:
                continue
            nearby = _call_names_in_window(items, index, _COPY_LOOKBACK, _COPY_LOOKAHEAD)
            if nearby & set(core.COPY_GUARDS):
                continue
            leads.append(
                core.ReviewLead(
                    check="pool_alloc_unguarded",
                    severity=core.SEV_HIGH,
                    title=f"{call_name} without nearby size guard",
                    detail=(
                        f"{call_name} at {hex(item_ea)} has no checked-arithmetic "
                        "guard nearby; verify the size cannot overflow."
                    ),
                    function=name,
                    addr=hex(item_ea),
                    evidence={"sink": call_name},
                    method="windowed call scan around pool allocators",
                ).as_dict()
            )


def _check_stack_alloc(ctx, scope, leads) -> None:
    for func_ea in scope:
        if expired():
            break
        name = func_name(func_ea) or hex(func_ea)
        for call_ea, call_name, _t in calls_in_func(func_ea):
            if call_name not in core.STACK_ALLOCATORS:
                continue
            leads.append(
                core.ReviewLead(
                    check="stack_alloc",
                    severity=core.SEV_LOW,
                    title=f"Dynamic stack allocation via {call_name}",
                    detail="Large or dynamic stack allocation; verify bounded size.",
                    function=name,
                    addr=hex(call_ea),
                    evidence={"sink": call_name},
                    method="allocator call enumeration",
                ).as_dict()
            )


def _check_privileged(ctx, scope, leads, cached_hits) -> None:
    hits = cached_hits
    if hits is None:
        hits, _stats = opcode_stage.collect(ctx, scope)
    for hit in hits:
        leads.append(
            core.ReviewLead(
                check="privileged_insn",
                severity=hit["severity_rank"],
                title=f"Privileged instruction: {hit['detail']}",
                detail="Privileged CPU operation in handler-reachable code; verify intent.",
                function=hit["function"],
                addr=hit["addr"],
                evidence={"mnemonic": hit["mnemonic"]},
                method="scoped privileged-instruction scan",
            ).as_dict()
        )


def _check_physical_memory(ctx, scope, scope_ranges, leads) -> None:
    try:
        strings = _get_strings_cache()
    except Exception:
        return
    for ea, text in strings:
        if expired():
            break
        if not any(marker in text for marker in core.PHYSICAL_MEMORY_MARKERS):
            continue
        try:
            refs = [ref.frm for ref in idautils.XrefsTo(ea, 0)]
        except Exception:
            refs = []
        in_scope = any(
            any(start <= ref < end for start, end in scope_ranges) for ref in refs
        )
        leads.append(
            core.ReviewLead(
                check="physical_memory_ref",
                severity=core.SEV_HIGH if in_scope else core.SEV_MEDIUM,
                title="Reference to the physical-memory device object",
                detail=(
                    f"String at {hex(ea)} with {len(refs)} reference(s); classic "
                    "BYOVD pattern when opened from a handler."
                ),
                addr=hex(ea),
                evidence={"string": text, "xref_count": len(refs)},
                method="string table plus xref walk",
            ).as_dict()
        )


def _check_mdl(ctx, scope, leads) -> None:
    for func_ea in scope:
        if expired():
            break
        name = func_name(func_ea) or hex(func_ea)
        has_usermode = False
        for item_ea in iter_func_items(func_ea, 5000):
            try:
                if "UserMode" in (idc.GetDisasm(item_ea) or ""):
                    has_usermode = True
                    break
            except Exception:
                continue
        for call_ea, call_name, _t in calls_in_func(func_ea):
            if call_name not in core.MDL_FUNCS:
                continue
            leads.append(
                core.ReviewLead(
                    check="unsafe_mdl",
                    severity=core.SEV_HIGH if has_usermode else core.SEV_MEDIUM,
                    title=f"MDL mapping via {call_name}",
                    detail=(
                        f"{call_name} at {hex(call_ea)}"
                        + (" with a UserMode reference in the function" if has_usermode else "")
                        + "; verify the mapping mode and probe/lock pairing."
                    ),
                    function=name,
                    addr=hex(call_ea),
                    evidence={"sink": call_name, "usermode_text": has_usermode},
                    method="MDL call enumeration plus mode-text scan",
                ).as_dict()
            )


def _check_irql(ctx, scope, leads) -> None:
    for func_ea in scope:
        if expired():
            break
        names = {name for _, name, _ in calls_in_func(func_ea) if name}
        raisers = sorted(names & set(core.IRQL_RAISERS))
        if not raisers:
            continue
        blockable = sorted(
            n for n in names if n.startswith("Zw") or n.startswith("MmMap")
        )
        if not blockable:
            continue
        leads.append(
            core.ReviewLead(
                check="irql_cooccurrence",
                severity=core.SEV_MEDIUM,
                title="IRQL-raising and blockable calls share a function",
                detail=(
                    f"{raisers[0]} with {blockable[0]} in "
                    f"{func_name(func_ea) or hex(func_ea)}; verify IRQL discipline."
                ),
                function=func_name(func_ea) or hex(func_ea),
                addr=hex(func_ea),
                evidence={"raisers": raisers[:5], "blockable": blockable[:5]},
                method="same-function call co-occurrence",
            ).as_dict()
        )


def _check_missing_priv_gate(ctx, scope, leads, cap: int = 100) -> None:
    for func_ea in scope:
        if expired() or len(leads) >= cap:
            break
        closure, _info = transitive_callees([func_ea], max_depth=2, max_nodes=500)
        names: set[str] = set()
        for member in closure:
            for _, call_name, _t in calls_in_func(member):
                if call_name:
                    names.add(call_name)
        sensitive = sorted(
            n for n in names
            if core.SENSITIVE_SINKS.get(n, core.SEV_INFO) >= core.SEV_HIGH
        )
        if not sensitive or (names & set(core.PRIVILEGE_GATES)):
            continue
        leads.append(
            core.ReviewLead(
                check="missing_priv_gate",
                severity=core.SEV_HIGH,
                title=f"Sensitive sink without privilege gate: {sensitive[0]}",
                detail=(
                    f"{func_name(func_ea) or hex(func_ea)} reaches {sensitive[0]} "
                    "with no SeAccessCheck/token check in its 2-deep closure."
                ),
                function=func_name(func_ea) or hex(func_ea),
                addr=hex(func_ea),
                evidence={"sinks": sensitive[:5]},
                method="bounded closure scan for gates vs sensitive sinks",
            ).as_dict()
        )


def _ctree_write_shapes(func_ea: int) -> tuple[list[dict], bool]:
    """Find double-deref store shapes via the decompiler (HIGH/MEDIUM)."""
    cfunc = try_decompile(func_ea)
    if cfunc is None:
        return [], False
    shapes: list[dict] = []
    try:
        import ida_hexrays

        _base = getattr(ida_hexrays, "ctree_visitor_t", None) or getattr(
            ida_hexrays, "cfunc_visitor_t", None
        )
        if _base is None:
            return [], False

        class _Visitor(_base):  # type: ignore[misc, valid-type]
            def __init__(self):
                _base.__init__(self, ida_hexrays.CV_FAST)

            def visit_expr(self, expr):
                try:
                    if expr.op != ida_hexrays.cot_asg:
                        return 0
                    left, right = expr.x, expr.y
                    if (
                        left.op == ida_hexrays.cot_ptr
                        and left.x.op == ida_hexrays.cot_ptr
                    ):
                        shapes.append({"kind": "double_deref_store", "ea": int(expr.ea)})
                    elif (
                        left.op == ida_hexrays.cot_ptr
                        and right.op == ida_hexrays.cot_ptr
                    ):
                        shapes.append({"kind": "controlled_copy", "ea": int(expr.ea)})
                except Exception:
                    pass
                return 0

        visitor = _Visitor()
        visitor.apply_to(cfunc.body, None)
    except Exception:
        return [], True
    return shapes, True


def _check_arbitrary_write(ctx, scope, leads, unavailable) -> None:
    saw_decompiler = False
    for func_ea in scope:
        if expired():
            break
        shapes, ran = _ctree_write_shapes(func_ea)
        saw_decompiler = saw_decompiler or ran
        for shape in shapes[:3]:
            high = shape["kind"] == "double_deref_store"
            leads.append(
                core.ReviewLead(
                    check="arbitrary_write_shape",
                    severity=core.SEV_HIGH if high else core.SEV_MEDIUM,
                    title=(
                        "Possible write-what-where shape"
                        if high
                        else "Controlled-copy shape worth review"
                    ),
                    detail=(
                        f"Decompiler shows {'*(*p) = value' if high else '*p = *q'} "
                        f"at {hex(shape['ea'])}; verify pointer provenance."
                    ),
                    function=func_name(func_ea) or hex(func_ea),
                    addr=hex(shape["ea"]),
                    evidence={"shape": shape["kind"]},
                    method="decompiler ctree assignment walk",
                ).as_dict()
            )
    if not saw_decompiler:
        unavailable.append("arbitrary_write_shape needs the Hex-Rays decompiler")


def _mem_reads(func_ea: int) -> list[tuple[int, int, int, bool]]:
    """Collect (item_ea, base_reg, disp, is_call) for memory reads and calls."""
    rows: list[tuple[int, int, int, bool]] = []
    for item_ea in iter_func_items(func_ea):
        try:
            mnem = idc.print_insn_mnem(item_ea)
        except Exception:
            continue
        if mnem == "call":
            rows.append((item_ea, -1, 0, True))
            continue
        insn = idaapi.insn_t()
        if idaapi.decode_insn(insn, item_ea) <= 0:
            continue
        for position, op in enumerate(insn.ops):
            if position == 0:
                continue
            if op.type == idaapi.o_displ and op.reg != 0xFF:
                rows.append((item_ea, int(op.reg), int(op.addr), False))
    return rows


def _check_double_fetch(ctx, scope, leads) -> None:
    if not ctx.is_64bit:
        ctx.limitations.append("double_fetch runs on x64 only (register model)")
        return
    for func_ea in scope:
        if expired():
            break
        corroborated, _why = references_iocontrolcode(func_ea, True)
        if corroborated is False and func_name(func_ea) not in (
            ctx.driver_entry_name or "",
        ):
            # Still allow dispatchers; skip unrelated helpers to cut noise.
            pass
        names = {name for _, name, _ in calls_in_func(func_ea) if name}
        if "ProbeForRead" in names:
            continue
        rows = _mem_reads(func_ea)
        seen: dict[tuple[int, int], int] = {}
        calls_since: dict[tuple[int, int], int] = {}
        for item_ea, reg, disp, is_call in rows:
            if is_call:
                for key in list(seen):
                    calls_since[key] = calls_since.get(key, 0) + 1
                continue
            key = (reg, disp)
            if key in seen and calls_since.get(key, 0) >= 1:
                leads.append(
                    core.ReviewLead(
                        check="double_fetch",
                        severity=core.SEV_MEDIUM,
                        title="User-pointer field re-read across a call",
                        detail=(
                            f"[r{reg}+{hex(disp)}] read at {hex(seen[key])} and "
                            f"{hex(item_ea)} with a call between; verify TOCTOU handling."
                        ),
                        function=func_name(func_ea) or hex(func_ea),
                        addr=hex(item_ea),
                        evidence={"first_read": hex(seen[key])},
                        method="repeated displacement-read scan with call window",
                    ).as_dict()
                )
                break
            seen.setdefault(key, item_ea)


def _check_uaf_intra(ctx, scope, leads) -> None:
    if not ctx.is_64bit:
        ctx.limitations.append("intra-function UAF runs on x64 only (fastcall model)")
        return
    for func_ea in scope:
        if expired():
            break
        items = _items(func_ea)
        index_of = {ea: index for index, ea in enumerate(items)}
        for call_ea, call_name, _t in calls_in_func(func_ea):
            if call_name not in core.POOL_FREES:
                continue
            start = index_of.get(call_ea)
            if start is None:
                continue
            # First argument arrives in rcx; track it forward.
            freed_reg = 1  # ida x86/x64 rcx register number
            for probe_ea in items[start + 1 : start + 1 + _UAF_FORWARD]:
                try:
                    mnem = idc.print_insn_mnem(probe_ea)
                except Exception:
                    continue
                if mnem == "call":
                    break  # volatile regs do not survive calls
                insn = idaapi.insn_t()
                if idaapi.decode_insn(insn, probe_ea) <= 0 or not insn.ops:
                    continue
                dst = insn.ops[0]
                if dst.type == idaapi.o_reg and int(dst.reg) == freed_reg:
                    break  # redefined: no dangling use on this path
                for position, op in enumerate(insn.ops):
                    if position == 0:
                        continue
                    if op.type == idaapi.o_displ and int(op.reg) == freed_reg:
                        leads.append(
                            core.ReviewLead(
                                check="use_after_free",
                                severity=core.SEV_HIGH,
                                title="Possible use after ExFreePool",
                                detail=(
                                    f"Freed pointer register re-read at {hex(probe_ea)} "
                                    f"after {call_name} at {hex(call_ea)}; verify lifetime."
                                ),
                                function=func_name(func_ea) or hex(func_ea),
                                addr=hex(probe_ea),
                                evidence={"free_site": hex(call_ea), "sink": call_name},
                                method="forward register walk after pool free",
                            ).as_dict()
                        )
                        break
                else:
                    continue
                break


def _check_uaf_global(ctx, scope, leads, cap: int = 25) -> None:
    found = 0
    for func_ea in scope:
        if expired() or found >= cap:
            break
        bounds = func_range(func_ea)
        if bounds is None:
            continue
        _start, end = bounds
        for call_ea, call_name, _t in calls_in_func(func_ea):
            if call_name not in core.POOL_FREES or found >= cap:
                continue
            # Freed global arrives via lea reg, [global] shortly before the call.
            cursor, global_ea, global_name = call_ea, None, None
            for _ in range(8):
                try:
                    cursor = idc.prev_head(cursor, bounds[0])
                except Exception:
                    break
                if cursor == idaapi.BADADDR or cursor <= bounds[0]:
                    break
                try:
                    if idc.print_insn_mnem(cursor) != "lea":
                        continue
                    candidate = int(idc.get_operand_value(cursor, 1))
                except Exception:
                    continue
                if candidate in (0, idaapi.BADADDR):
                    continue
                try:
                    candidate_name = idc.get_name(candidate) or ""
                    is_func = idaapi.get_func(candidate) is not None
                except Exception:
                    continue
                if candidate_name and not is_func:
                    global_ea, global_name = candidate, candidate_name
                    break
            if global_ea is None:
                continue
            nulled = False
            probe = call_ea
            for _ in range(64):
                try:
                    probe = idc.next_head(probe, end)
                except Exception:
                    break
                if probe == idaapi.BADADDR or probe >= end:
                    break
                try:
                    if idc.print_insn_mnem(probe) != "mov":
                        continue
                    if int(idc.get_operand_value(probe, 0)) != global_ea:
                        continue
                    if int(idc.get_operand_value(probe, 1)) == 0:
                        nulled = True
                        break
                except Exception:
                    continue
            if nulled:
                continue
            try:
                other_refs = [
                    ref.frm
                    for ref in idautils.XrefsTo(global_ea, 0)
                    if ref.iscode and not (bounds[0] <= ref.frm < end)
                ]
            except Exception:
                other_refs = []
            if not other_refs:
                continue
            found += 1
            leads.append(
                core.ReviewLead(
                    check="use_after_free",
                    severity=core.SEV_HIGH,
                    title=f"Global freed without nulling: {global_name}",
                    detail=(
                        f"{global_name} freed at {hex(call_ea)} without a NULL store "
                        f"and referenced from {len(other_refs)} other site(s)."
                    ),
                    function=func_name(func_ea) or hex(func_ea),
                    addr=hex(call_ea),
                    evidence={
                        "global": global_name,
                        "global_addr": hex(global_ea),
                        "other_refs": [hex(r) for r in other_refs[:5]],
                    },
                    method="freed-global plus cross-function reference walk",
                ).as_dict()
            )


def run(
    ctx: DriverContext,
    scope_funcs: list[int],
    *,
    dispatchers: set[int] | None = None,
    checks: list[str] | None = None,
    opcode_hits: list[dict] | None = None,
) -> tuple[list[dict], dict]:
    """Run selected heuristic checks over handler-reachable functions."""
    wanted = [c for c in (checks or list(CHECKS)) if c in CHECKS]
    unknown = [c for c in (checks or []) if c not in CHECKS]
    leads: list[dict] = []
    unavailable: list[str] = []
    scope = [f for f in scope_funcs if func_range(f) is not None]
    dispatcher_set = set(dispatchers or [])
    scope_ranges = [r for r in (func_range(f) for f in scope) if r is not None]
    if "unvalidated_copy" in wanted:
        _check_unvalidated_copy(ctx, scope, dispatcher_set, leads)
    if "pool_alloc_unguarded" in wanted:
        _check_pool_alloc(ctx, scope, leads)
    if "stack_alloc" in wanted:
        _check_stack_alloc(ctx, scope, leads)
    if "privileged_insn" in wanted:
        _check_privileged(ctx, scope, leads, opcode_hits)
    if "physical_memory_ref" in wanted:
        _check_physical_memory(ctx, scope, scope_ranges, leads)
    if "unsafe_mdl" in wanted:
        _check_mdl(ctx, scope, leads)
    if "irql_cooccurrence" in wanted:
        _check_irql(ctx, scope, leads)
    if "missing_priv_gate" in wanted:
        _check_missing_priv_gate(ctx, scope, leads)
    if "arbitrary_write_shape" in wanted:
        _check_arbitrary_write(ctx, scope, leads, unavailable)
    if "double_fetch" in wanted:
        _check_double_fetch(ctx, scope, leads)
    if "use_after_free" in wanted:
        _check_uaf_intra(ctx, scope, leads)
        _check_uaf_global(ctx, scope, leads)
    truncated = len(leads) > _MAX_LEADS
    stats = {
        "scope_functions": len(scope),
        "checks_run": wanted,
        "checks_unavailable": unavailable,
        "unknown_checks": unknown,
        "leads": len(leads),
        "truncated": truncated,
    }
    if truncated:
        leads = leads[:_MAX_LEADS]
    leads.sort(key=lambda lead: (-lead["severity_rank"], lead["check"], lead["addr"] or ""))
    return leads, stats
