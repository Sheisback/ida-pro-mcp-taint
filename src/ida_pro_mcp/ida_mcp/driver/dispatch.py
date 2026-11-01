"""Driver framework classification and dispatcher discovery (read-only).

Mirrors the discovery role of the reference ``get_driver_id`` / ``wdm`` /
``wdf`` stages: classify the framework from imports, locate DriverEntry, and
find the IRP_MJ_DEVICE_CONTROL dispatchers. Unlike the reference plugin this
stage never renames functions and never applies structures or enums; it only
records addresses with evidence so MCP clients can navigate to them.

Slot offsets are derived from the public DRIVER_OBJECT layout for the active
pointer width instead of being matched as disassembly text.
"""

from __future__ import annotations

import idaapi
import idautils
import idc

from ida_pro_mcp.flow_core import driver_triage as core

from .context import (
    DriverContext,
    call_target,
    collect_function_names,
    collect_imports,
    expired,
    func_name,
    iter_func_items,
    strip_import_name,
    try_decompile,
)
from .selector_structure import (
    collect_driver_entry_registrations,
    finalize_registration_scan,
    expression_nodes,
    lvar_definition_hazard,
    registration_slot_write_form,
    call_is_proven_pre_registration,
    unmodeled_lvar_derived_write,
)

#: x64 IRP.Tail.Overlay.CurrentStackLocation offset (public WDK layout).
_X64_IOSTACK_OFFSET = 0xB8
#: x64 IO_STACK_LOCATION.Parameters.DeviceIoControl.IoControlCode offset.
_X64_IOCTLCODE_OFFSET = 0x10


def populate(ctx: DriverContext) -> DriverContext:
    """Fill context with PE/entry/import facts. Returns the same context."""
    try:
        file_type = idaapi.get_file_type_name() or ""
    except Exception:
        file_type = ""
    ctx.is_pe = "portable executable" in file_type.lower()
    try:
        ctx.is_64bit = idaapi.getseg(idaapi.get_imagebase()) is None or _inf_is_64()
    except Exception:
        ctx.is_64bit = True
    ctx.imports_map, _rows = collect_imports()
    ctx.functions_map = collect_function_names()
    _find_driver_entry(ctx)
    _classify_framework(ctx)
    _unwrap_entry_stub(ctx)
    ctx.dispatchers = discover_dispatchers(ctx)
    return ctx


def collect_trigger_registration_producer(ctx: DriverContext) -> dict:
    """Collect only direct typed DriverEntry registration proof authority."""
    base = {
        "contract_id": "ida.driver-trigger-registration-producer.v1",
        "version": 1,
        "driver_entry_ea": hex(ctx.driver_entry_ea or 0),
        "registrations": [],
    }
    if ctx.driver_entry_ea is None:
        return {**base, "status": "partial", "reason_code": "driver_entry_unavailable"}
    cfunc = try_decompile(ctx.driver_entry_ea)
    if cfunc is None:
        return {**base, "status": "partial",
            "reason_code": "driver_entry_decompile_unavailable"}
    try:
        import ida_hexrays
        import ida_typeinf

        def exact_function_entry(ea: int):
            found = idaapi.get_func(ea)
            return ea if found is not None and int(found.start_ea) == ea else None

        def documented_external_call(ea: int):
            return strip_import_name(func_name(ea)) in ctx.imports_map

        initial = collect_driver_entry_registrations(
            cfunc,
            ctx.driver_entry_ea,
            ida_hexrays,
            ida_typeinf,
            exact_function_entry,
            device_control_index=core.IRP_MJ_DEVICE_CONTROL,
            expected_pointer_width=8 if ctx.is_64bit else 4,
            documented_external_call=documented_external_call,
        )
        accepted_eas = {int(item["assignment_ea"], 16)
            for item in initial["registrations"]}
        argument_indices = [int(value) for value in cfunc.argidx]
        first_lvar_index = argument_indices[0] if argument_indices else -1
        unsupported_forms = []
        direct_top_level = []
        top_level = [cfunc.body.cblock[index]
            for index in range(len(cfunc.body.cblock))]
        for index, statement in enumerate(top_level):
            if statement.op != ida_hexrays.cit_expr:
                continue
            if registration_slot_write_form(statement.cexpr, first_lvar_index,
                    ida_hexrays, ida_typeinf, exact_function_entry,
                    device_control_index=core.IRP_MJ_DEVICE_CONTROL) == "direct":
                direct_top_level.append((index, statement.cexpr))
        allowed_pre_calls = []
        if len(direct_top_level) == 1:
            for statement in top_level[:direct_top_level[0][0]]:
                if statement.op != ida_hexrays.cit_expr:
                    continue
                allowed_pre_calls.extend(item for item in expression_nodes(statement.cexpr)
                    if item.op == ida_hexrays.cot_call)
        base_visitor = getattr(ida_hexrays, "ctree_visitor_t", None) or getattr(
            ida_hexrays, "cfunc_visitor_t", None)
        if base_visitor is not None and first_lvar_index >= 0:
            class RegistrationFormVisitor(base_visitor):  # type: ignore[misc,valid-type]
                def __init__(self):
                    base_visitor.__init__(self, ida_hexrays.CV_FAST)

                def visit_expr(self, expression):
                    form = registration_slot_write_form(expression, first_lvar_index,
                        ida_hexrays, ida_typeinf, exact_function_entry,
                        device_control_index=core.IRP_MJ_DEVICE_CONTROL)
                    if form == "cast":
                        unsupported_forms.append("cast_registration_form_unsupported")
                    elif form == "dynamic":
                        unsupported_forms.append("ambiguous_registration_form_unsupported")
                    elif form == "unknown":
                        unsupported_forms.append(
                            "typed_major_function_registration_form_unsupported")
                    elif form == "direct" and int(expression.ea) not in accepted_eas:
                        unsupported_forms.append("conditional_registration_form_unsupported")
                    elif form is None and unmodeled_lvar_derived_write(
                            expression, first_lvar_index, ida_hexrays, ida_typeinf):
                        unsupported_forms.append(
                            "ambiguous_registration_form_unsupported")
                    hazard = lvar_definition_hazard(expression, first_lvar_index,
                        ida_hexrays, documented_external_call,
                        after_registration=bool(direct_top_level)
                          and expression.op == ida_hexrays.cot_call
                          and not call_is_proven_pre_registration(
                              expression, allowed_pre_calls))
                    if hazard is not None:
                        unsupported_forms.append(hazard)
                    return 0

            visitor = RegistrationFormVisitor()
            visitor.apply_to(cfunc.body, None)
        result = collect_driver_entry_registrations(
            cfunc, ctx.driver_entry_ea, ida_hexrays, ida_typeinf,
            exact_function_entry, device_control_index=core.IRP_MJ_DEVICE_CONTROL,
            expected_pointer_width=8 if ctx.is_64bit else 4,
            unsupported_forms=unsupported_forms,
            documented_external_call=documented_external_call)
        return finalize_registration_scan(result, expired=expired())
    except Exception:
        return {**base, "status": "partial",
            "reason_code": "driver_entry_registration_scan_failed"}


def _inf_is_64() -> bool:
    try:
        import ida_ida

        return bool(ida_ida.inf_is_64bit())
    except Exception:
        return True


def _find_driver_entry(ctx: DriverContext) -> None:
    for name in core.DRIVER_ENTRY_NAMES:
        ea = ctx.functions_map.get(name)
        if ea is not None:
            ctx.driver_entry_ea = ea
            ctx.driver_entry_name = name
            return
    ctx.limitations.append("no DriverEntry symbol; not a driver-shaped binary")


def _classify_framework(ctx: DriverContext) -> None:
    for import_name, label in core.DRIVER_FRAMEWORK_MARKERS:
        if import_name in ctx.imports_map:
            ctx.framework = label
            ctx.framework_evidence = [import_name]
            return
    ctx.framework = "WDM"
    ctx.framework_evidence = []
    ctx.limitations.append("no framework import marker; assuming WDM-shaped")


def _unwrap_entry_stub(ctx: DriverContext) -> None:
    """Follow a tiny GsDriverEntry-style stub to the real entry (read-only)."""
    ea = ctx.driver_entry_ea
    if ea is None:
        return
    ctx.real_entry_ea = ea
    func = idaapi.get_func(ea)
    size = (func.end_ea - func.start_ea) if func else 0
    if ctx.driver_entry_name != "GsDriverEntry" and size >= 64:
        return
    try:
        for item_ea in iter_func_items(ea, 64):
            try:
                mnem = idc.print_insn_mnem(item_ea)
            except Exception:
                continue
            if mnem not in ("call", "jmp"):
                continue
            _name, target = call_target(item_ea)
            if target is None:
                continue
            try:
                target_func = idaapi.get_func(target)
            except Exception:
                continue
            if target_func is not None and target_func.start_ea != ea:
                ctx.real_entry_ea = target_func.start_ea
                return
    except Exception:
        pass


def references_iocontrolcode(func_ea: int, is_64bit: bool) -> tuple[bool, str]:
    """Check whether a function reads the IRP's IoControlCode field.

    On x64 this matches decoded displacement operands ([.+0xB8] feeding a
    later [reg+0x18] read); struct-annotated listings match by field name on
    any width. 32-bit raw offsets are intentionally not guessed.
    """
    iostack_regs: set[int] = set()
    saw_b8 = False
    try:
        for item_ea in iter_func_items(func_ea):
            insn = idaapi.insn_t()
            if idaapi.decode_insn(insn, item_ea) <= 0:
                continue
            if is_64bit:
                try:
                    mnem = idc.print_insn_mnem(item_ea) or ""
                except Exception:
                    mnem = ""
                dest_reg: int | None = None
                if insn.ops and insn.ops[0].type == idaapi.o_reg:
                    dest_reg = int(insn.ops[0].reg)
                for position, op in enumerate(insn.ops):
                    if op.type != idaapi.o_displ or position == 0:
                        continue
                    if op.addr == _X64_IOSTACK_OFFSET:
                        if mnem == "mov" and dest_reg is not None:
                            iostack_regs.add(dest_reg)
                            saw_b8 = True
                    elif op.addr == _X64_IOCTLCODE_OFFSET and int(op.reg) in iostack_regs:
                        return True, "iostack+0x18 read fed by irp+0xb8"
            try:
                line = idc.GetDisasm(item_ea) or ""
            except Exception:
                continue
            if "IoControlCode" in line:
                return True, "struct-annotated IoControlCode reference"
    except Exception:
        return False, "scan failed"
    if saw_b8:
        return False, "iostack load without control-code read"
    return False, "no IoControlCode reference found"


def _store_slot(item_ea: int, slots: set[int]) -> int | None:
    """Return the MajorFunction slot matched by a store, if any."""
    insn = idaapi.insn_t()
    if idaapi.decode_insn(insn, item_ea) <= 0:
        return None
    if not insn.ops:
        return None
    dst = insn.ops[0]
    if dst.type != idaapi.o_displ:
        return None
    try:
        if int(dst.addr) in slots:
            return int(dst.addr)
    except Exception:
        return None
    return None


def _resolve_store_target(store_ea: int, func_ea: int) -> int | None:
    """Resolve the handler stored by a MajorFunction slot assignment.

    Handles `mov [slot], offset Handler`, `mov [slot], reg` with a preceding
    `lea reg, Handler`, and rip-relative forms via operand values.
    """
    insn = idaapi.insn_t()
    if idaapi.decode_insn(insn, store_ea) <= 0 or len(insn.ops) < 2:
        return None
    src = insn.ops[1]
    if src.type in (idaapi.o_mem, idaapi.o_near, idaapi.o_far):
        return int(src.addr)
    if src.type == idaapi.o_imm:
        value = int(src.value) & 0xFFFFFFFFFFFFFFFF
        return value or None
    if src.type != idaapi.o_reg:
        return None
    wanted = src.reg
    try:
        cursor = idc.prev_head(store_ea, func_ea)
    except Exception:
        return None
    for _ in range(8):
        if cursor == idaapi.BADADDR or cursor < func_ea or expired():
            break
        probe = idaapi.insn_t()
        if idaapi.decode_insn(probe, cursor) > 0 and probe.ops:
            dst = probe.ops[0]
            if dst.type == idaapi.o_reg and dst.reg == wanted and len(probe.ops) >= 2:
                try:
                    value = int(idc.get_operand_value(cursor, 1))
                except Exception:
                    value = 0
                if value and value != idaapi.BADADDR:
                    return value
                break
        try:
            cursor = idc.prev_head(cursor, func_ea)
        except Exception:
            break
    return None


def discover_dispatchers(ctx: DriverContext) -> list[dict]:
    """Scan every function for MajorFunction slot stores (read-only).

    Works regardless of framework and regardless of whether the assignment
    lives in DriverEntry or a helper, since the scan is binary-wide.
    """
    ptr_size = 8 if ctx.is_64bit else 4
    try:
        slot_dc = core.major_function_slot_offset(ptr_size, core.IRP_MJ_DEVICE_CONTROL)
        slot_idc = core.major_function_slot_offset(ptr_size, core.IRP_MJ_INTERNAL_DEVICE_CONTROL)
    except ValueError:
        ctx.limitations.append("unsupported pointer width for slot derivation")
        return []
    slots = {slot_dc: "device_control", slot_idc: "internal_device_control"}
    found: dict[int, dict] = {}
    try:
        functions = list(idautils.Functions())
    except Exception:
        return []
    for func_ea in functions:
        if expired():
            ctx.limitations.append("dispatcher scan hit the tool deadline (partial)")
            break
        for item_ea in iter_func_items(func_ea):
            slot = _store_slot(item_ea, set(slots))
            if slot is None:
                continue
            target = _resolve_store_target(item_ea, func_ea)
            if target is None or target in found:
                continue
            target_func = idaapi.get_func(target)
            if target_func is not None:
                confidence = "function"
                entry = target_func.start_ea
            else:
                entry = target
                try:
                    confidence = "named" if idc.get_name(target) else "address"
                except Exception:
                    confidence = "address"
            found[target] = {
                "addr": hex(entry),
                "name": func_name(entry),
                "kind": slots[slot],
                "slot": hex(slot),
                "store_site": hex(item_ea),
                "store_function": func_name(func_ea),
                "confidence": confidence,
                "method": "MajorFunction slot-store scan",
            }
    if not found:
        ctx.limitations.append("no MajorFunction slot store resolved to a handler")
    return list(found.values())
