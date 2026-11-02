"""Structural Hex-Rays selector-member validation with injected SDK modules."""

import hashlib
import json

from ida_pro_mcp.flow_core import driver_triage as core

IOCTL_SELECTOR_MEMBER_PATH = ("Parameters", "DeviceIoControl", "IoControlCode")
IRP_CURRENT_STACK_MEMBER_PATH = ("Tail", "Overlay", "CurrentStackLocation")
REGISTRATION_PRODUCER_CONTRACT_ID = "ida.driver-trigger-registration-producer.v1"
REGISTRATION_PROOF_SCHEMA = "driver-entry-registration-proof/1"


def structural_selector_binding(expression, cfunc, ida_hexrays, ida_typeinf,
                                expected_pointer_width=None) -> dict | None:
    """Resolve one exact ctree UDT member chain without rendered text.

    ``cexpr_t.m`` is a byte offset for structures and a member ordinal for
    unions. Every selected member must match both its exact IDB name and the
    resulting ctree expression type. Casts, locals merely named like fields,
    ambiguous offsets, and incomplete type metadata fail closed.
    """
    return structural_selector_analysis(expression, cfunc, ida_hexrays, ida_typeinf,
        expected_pointer_width)[0]


def structural_selector_fact_producer(expression, cfunc, ida_hexrays, ida_typeinf,
                                      expected_pointer_width=None):
    """Return a typed terminal disposition only for an exact unsupported selector suffix."""
    return structural_selector_analysis(expression, cfunc, ida_hexrays, ida_typeinf,
        expected_pointer_width)[1]


def structural_selector_analysis(expression, cfunc, ida_hexrays, ida_typeinf,
                                 expected_pointer_width=None):
    try:
        selector_path = _typed_member_path_proof(expression,
            IOCTL_SELECTOR_MEMBER_PATH, ida_hexrays, ida_typeinf)
        if selector_path is None:
            return None, None
        current, selector_offsets = selector_path
        selector_type = ida_typeinf.tinfo_t(expression.type)
        if selector_type.is_ptr() or int(selector_type.get_size()) != 4:
            return None, {
                "contract_id": "ida.driver-ioctl-selector-producer.v1",
                "version": 1,
                "status": "unsupported",
                "reason_code": "selector_root_provenance_unsupported",
                "source_ea": hex(int(expression.ea)),
            }
        if current.op == ida_hexrays.cot_cast:
            return None, None
        source_ea = int(expression.ea)
        if source_ea < 0 or source_ea in {0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF}:
            return None, None
        root_provenance = _selector_root_provenance(
            current, expression, source_ea, cfunc, ida_hexrays, ida_typeinf,
            expected_pointer_width)
        if root_provenance is None:
            return None, {
                "contract_id": "ida.driver-ioctl-selector-producer.v1",
                "version": 1,
                "status": "unsupported",
                "reason_code": "selector_root_provenance_unsupported",
                "source_ea": hex(source_ea),
            }
        canonical = core.driver_trigger_abi_member_offsets(
            root_provenance["pointer_width_bytes"])
        if (tuple(root_provenance["current_stack_member_offsets_bytes"])
                != canonical["irp_current_stack"]
                or selector_offsets != canonical["ioctl_selector"]):
            return None, {
                "contract_id": "ida.driver-ioctl-selector-producer.v1",
                "version": 1,
                "status": "unsupported",
                "reason_code": "selector_root_provenance_unsupported",
                "source_ea": hex(source_ea),
            }
        return {
            "kind": "typed_member_path",
            "member_path": list(IOCTL_SELECTOR_MEMBER_PATH),
            "source_ea": hex(source_ea),
            "selector_member_offsets_bytes": list(selector_offsets),
            "root_provenance": root_provenance,
        }, None
    except Exception:
        return None, None


def _structural_member_chain(expression, ida_hexrays, ida_typeinf):
    current = expression
    leaf_to_root: list[str] = []
    member_ops = {ida_hexrays.cot_memptr, ida_hexrays.cot_memref}
    while current.op in member_ops:
        parent_expression = current.x
        selected = _exact_udt_member(parent_expression, current,
            ida_hexrays, ida_typeinf, None)
        if selected is None:
            raise ValueError("unproven ctree member")
        name = selected[0].name
        if not isinstance(name, str) or not name:
            raise ValueError("unnamed ctree member")
        leaf_to_root.append(name)
        current = parent_expression
    return current, tuple(reversed(leaf_to_root))


def _typed_member_path_root(expression, expected_path, ida_hexrays, ida_typeinf):
    proof = _typed_member_path_proof(
        expression, expected_path, ida_hexrays, ida_typeinf)
    return None if proof is None else proof[0]


def _typed_member_path_proof(expression, expected_path, ida_hexrays, ida_typeinf):
    current = expression
    leaf_to_root_offsets = []
    member_ops = {ida_hexrays.cot_memptr, ida_hexrays.cot_memref}
    for expected_name in reversed(expected_path):
        if current.op not in member_ops:
            return None
        parent = current.x
        selected = _exact_udt_member(parent, current, ida_hexrays, ida_typeinf,
            expected_name)
        if selected is None:
            return None
        leaf_to_root_offsets.append(int(selected[0].begin()) // 8)
        current = parent
    return current, tuple(reversed(leaf_to_root_offsets))


def _number_value(expression) -> int | None:
    value = getattr(getattr(expression, "n", None), "_value", None)
    return int(value) if type(value) is int and value >= 0 else None


def _exact_udt_member(parent_expression, member_expression, ida_hexrays, ida_typeinf,
                      expected_name: str | None):
    parent_type = ida_typeinf.tinfo_t(parent_expression.type)
    if member_expression.op == ida_hexrays.cot_memptr:
        if not parent_type.is_ptr() or parent_type.is_shifted_ptr():
            return None
        parent_type = parent_type.get_pointed_object()
    if not parent_type.is_udt():
        return None
    details = ida_typeinf.udt_type_data_t()
    if not parent_type.get_udt_details(details) or len(details) == 0:
        return None
    if details.is_union:
        ordinal = int(member_expression.m)
        if not 0 <= ordinal < len(details):
            return None
        selected = details[ordinal]
    else:
        offset_bits = int(member_expression.m) * 8
        matches = [member for member in details
                   if not member.is_bitfield() and member.begin() == offset_bits]
        if len(matches) != 1:
            return None
        selected = matches[0]
    if expected_name is not None and selected.name != expected_name:
        return None
    selected_type = ida_typeinf.tinfo_t(selected.type)
    result_type = ida_typeinf.tinfo_t(member_expression.type)
    if (not selected_type.equals_to(result_type)
            or int(selected_type.get_size()) != int(result_type.get_size())):
        return None
    return selected, selected_type


def registration_slot_write_form(expression, first_lvar_index: int, ida_hexrays,
                                 ida_typeinf, resolve_function_entry,
                                 *, device_control_index: int):
    """Classify every write that may target the original argument's dispatch slot."""
    try:
        assignment = ida_hexrays.is_assignment(expression.op)
        update = ida_hexrays.is_prepost(expression.op)
        if not assignment and not update:
            return None
        left = expression.x
        if left.op != ida_hexrays.cot_idx or left.x.op != ida_hexrays.cot_memptr:
            return None
        base = left.x.x
        identity = _strip_representation_casts(base, ida_hexrays)
        cast = identity is not base
        if identity.op != ida_hexrays.cot_var or int(identity.v.idx) != first_lvar_index:
            return None
        if _exact_udt_member(base, left.x, ida_hexrays, ida_typeinf,
                "MajorFunction") is None:
            return None
        if left.y.op != ida_hexrays.cot_num:
            return "dynamic"
        index = _number_value(left.y)
        if index is None:
            return "dynamic"
        if index != device_control_index:
            return None
        if cast:
            return "cast"
        if expression.op != ida_hexrays.cot_asg:
            return "unknown"
        right = expression.y
        right_cast = right.op == ida_hexrays.cot_cast
        rhs = right.x if right_cast else right
        if rhs.op != ida_hexrays.cot_obj:
            return "unknown"
        rhs_ea = int(rhs.obj_ea)
        if resolve_function_entry(rhs_ea) != rhs_ea:
            return "unknown"
        return "cast" if right_cast else "direct"
    except Exception:
        return None


def unmodeled_lvar_derived_write(expression, lvar_index: int, ida_hexrays,
                                 ida_typeinf) -> bool:
    """Reject writes through derived/alternate addressing of a protected lvar."""
    try:
        if not (ida_hexrays.is_assignment(expression.op)
                or ida_hexrays.is_prepost(expression.op)):
            return False
        left = expression.x
        if (_expression_is_lvar_identity(left, lvar_index, ida_hexrays)
                or not expression_contains_lvar(left, lvar_index, ida_hexrays)):
            return False
        if left.op == ida_hexrays.cot_memptr:
            base = left.x
            if (_strip_representation_casts(base, ida_hexrays) is base
                    and _expression_is_lvar_identity(base, lvar_index, ida_hexrays)
                    and _exact_udt_member(base, left, ida_hexrays, ida_typeinf,
                        None) is not None):
                return False
        if left.op == ida_hexrays.cot_idx and left.x.op == ida_hexrays.cot_memptr:
            member = left.x
            base = member.x
            if (_strip_representation_casts(base, ida_hexrays) is base
                    and _expression_is_lvar_identity(base, lvar_index, ida_hexrays)):
                selected = _exact_udt_member(base, member, ida_hexrays,
                    ida_typeinf, None)
                if selected is not None and (selected[0].name != "MajorFunction"
                        or left.y.op == ida_hexrays.cot_num
                        and _number_value(left.y) is not None):
                    return False
        return True
    except Exception:
        return True


def expression_contains_lvar(expression, lvar_index: int, ida_hexrays) -> bool:
    """Cycle-safe structural ctree walk without a proof-depth cutoff."""
    seen = set()
    pending = [expression]
    while pending:
        item = pending.pop()
        identity = _ctree_node_identity(item)
        if item is None or identity in seen:
            continue
        seen.add(identity)
        try:
            if item.op == ida_hexrays.cot_var and int(item.v.idx) == lvar_index:
                return True
        except Exception:
            continue
        for name in ("x", "y", "z"):
            pending.append(getattr(item, name, None))
        try:
            pending.extend(item.a)
        except Exception:
            pass
    return False


def _ctree_node_identity(item):
    if item is None:
        return None
    target = getattr(item, "target", item)
    try:
        return ("swig", int(target.this))
    except Exception:
        return ("python", id(target))


def expression_nodes(expression):
    seen, pending, output = set(), [expression], []
    while pending:
        item = pending.pop()
        identity = _ctree_node_identity(item)
        if item is None or identity in seen:
            continue
        seen.add(identity)
        output.append(item)
        pending.extend(getattr(item, name, None) for name in ("x", "y", "z"))
        try:
            pending.extend(item.a)
        except Exception:
            pass
    return output


def _expression_is_lvar_identity(expression, lvar_index: int, ida_hexrays) -> bool:
    """Match the exact lvar value through representation-only casts."""
    item = _strip_representation_casts(expression, ida_hexrays)
    return (item is not None and item.op == ida_hexrays.cot_var
            and int(getattr(getattr(item, "v", None), "idx", -1)) == lvar_index)


def _strip_representation_casts(expression, ida_hexrays):
    item, seen = expression, set()
    while item is not None and item.op == ida_hexrays.cot_cast:
        identity = _ctree_node_identity(item)
        if identity in seen:
            raise ValueError("cyclic cast expression")
        seen.add(identity)
        item = item.x
    return item


def _expression_returns_lvar_alias(expression, lvar_index: int, ida_hexrays) -> bool:
    """Match expression forms whose result is the original pointer value."""
    try:
        result_type = expression.type
        if result_type.is_ptr() and expression_contains_lvar(
                expression, lvar_index, ida_hexrays):
            return True
    except Exception:
        pass
    pending, seen = [expression], set()
    while pending:
        item = pending.pop()
        identity = _ctree_node_identity(item)
        if item is None or identity in seen:
            continue
        seen.add(identity)
        item = _strip_representation_casts(item, ida_hexrays)
        if item is None:
            continue
        if (item.op == ida_hexrays.cot_var
                and int(getattr(getattr(item, "v", None), "idx", -1)) == lvar_index):
            return True
        if item.op == getattr(ida_hexrays, "cot_comma", None):
            pending.append(item.y)
        elif item.op == getattr(ida_hexrays, "cot_tern", None):
            pending.extend((item.y, item.z))
    return False


def lvar_definition_hazard(expression, lvar_index: int, ida_hexrays,
                           documented_external_call, *, after_registration: bool):
    """Classify rebinding, aliasing, address escape, or unmodeled calls."""
    try:
        if ida_hexrays.is_assignment(expression.op):
            left, right = expression.x, expression.y
            if _expression_is_lvar_identity(left, lvar_index, ida_hexrays):
                return "driver_object_argument_rebound_unsupported"
            if (expression.op == ida_hexrays.cot_asg
                    and _expression_returns_lvar_alias(right, lvar_index, ida_hexrays)):
                return "driver_object_alias_unsupported"
        if (ida_hexrays.is_prepost(expression.op)
                and _expression_is_lvar_identity(expression.x, lvar_index, ida_hexrays)):
            return "driver_object_argument_rebound_unsupported"
        ref_op = getattr(ida_hexrays, "cot_ref", None)
        if ref_op is not None:
            pending, seen = [expression], set()
            while pending:
                item = pending.pop()
                identity = _ctree_node_identity(item)
                if item is None or identity in seen:
                    continue
                seen.add(identity)
                if item.op == ref_op and expression_contains_lvar(
                        item, lvar_index, ida_hexrays):
                    return "driver_object_address_escape_unsupported"
                pending.extend(getattr(item, name, None) for name in ("x", "y", "z"))
                try:
                    pending.extend(item.a)
                except Exception:
                    pass
        if expression.op == getattr(ida_hexrays, "cot_call", None):
            arguments = list(expression.a)
            if any(expression_contains_lvar(item, lvar_index, ida_hexrays)
                   for item in arguments):
                callee = expression.x
                callee_ea = int(callee.obj_ea) if callee.op == ida_hexrays.cot_obj else None
                if after_registration:
                    return "post_registration_driver_object_escape_unsupported"
                if callee_ea is None or not documented_external_call(callee_ea):
                    return "helper_registration_form_unsupported"
    except Exception:
        return "driver_object_definition_analysis_unavailable"
    return None


def _collect_cfunc_expressions(cfunc, ida_hexrays):
    base_visitor = getattr(ida_hexrays, "ctree_visitor_t", None) or getattr(
        ida_hexrays, "cfunc_visitor_t", None)
    if base_visitor is None:
        return None

    class ExpressionVisitor(base_visitor):  # type: ignore[misc,valid-type]
        def __init__(self):
            base_visitor.__init__(self, ida_hexrays.CV_FAST)
            self.expressions = []
            self.instructions = []

        def visit_insn(self, item):
            self.instructions.append(item)
            return 0

        def visit_expr(self, item):
            self.expressions.append(item)
            return 0

    visitor = ExpressionVisitor()
    visitor.apply_to(cfunc.body, None)
    return visitor.expressions, visitor.instructions


def _top_level_statements(cfunc):
    statements = cfunc.body.cblock
    return [statements[index] for index in range(len(statements))]


def _same_ctree_expression(left, right) -> bool:
    if left is right:
        return True
    try:
        return bool(left == right)
    except Exception:
        return False


def call_is_proven_pre_registration(expression, allowed_calls) -> bool:
    return any(_same_ctree_expression(expression, item) for item in allowed_calls)


def _direct_call_target(expression, ida_hexrays, resolve_function_entry):
    item = _strip_representation_casts(expression, ida_hexrays)
    if item is None or item.op != ida_hexrays.cot_call:
        return None
    callee = _strip_representation_casts(item.x, ida_hexrays)
    if callee is None or callee.op != ida_hexrays.cot_obj:
        return None
    target = int(callee.obj_ea)
    return (item, target) if resolve_function_entry(target) == target else None


def _top_level_return_expression(statement, ida_hexrays):
    if statement.op != ida_hexrays.cit_return:
        return None
    return getattr(getattr(statement, "creturn", None), "expr", None)


def _major_function_array(expression, lvar_index: int, ida_hexrays, ida_typeinf,
                          pointer_width: int):
    item = _strip_representation_casts(expression, ida_hexrays)
    if item is None or item.op != ida_hexrays.cot_memptr:
        return None
    base = item.x
    if base.op != ida_hexrays.cot_var or int(base.v.idx) != lvar_index:
        return None
    parent_type = ida_typeinf.tinfo_t(base.type)
    if (not parent_type.is_ptr() or parent_type.is_shifted_ptr()
            or int(parent_type.get_size()) != pointer_width):
        return None
    parent_type = parent_type.get_pointed_object()
    details = ida_typeinf.udt_type_data_t()
    if not parent_type.is_udt() or not parent_type.get_udt_details(details):
        return None
    matches = [member for member in details
        if member.begin() == int(item.m) * 8 and str(member.name) == "MajorFunction"]
    if len(matches) != 1:
        return None
    member = matches[0]
    member_type = ida_typeinf.tinfo_t(member.type)
    array = ida_typeinf.array_type_data_t()
    if (not member_type.is_array() or not member_type.get_array_details(array)
            or int(member.begin()) // 8
              != core.major_function_slot_offset(pointer_width, 0)
            or int(array.nelems) != 28
            or int(member_type.get_size()) != 28 * pointer_width):
        return None
    element = ida_typeinf.tinfo_t(array.elem_type)
    if not element.is_ptr() or int(element.get_size()) != pointer_width:
        return None
    return member


def _bulk_major_function_store(expression, lvar_index: int, ida_hexrays,
                               ida_typeinf, resolve_function_entry,
                               pointer_width: int):
    item = _strip_representation_casts(expression, ida_hexrays)
    if item is None or item.op != ida_hexrays.cot_call or len(item.a) != 3:
        return None
    callee = _strip_representation_casts(item.x, ida_hexrays)
    expected_helper = "memset64" if pointer_width == 8 else "memset32"
    if (callee.op != getattr(ida_hexrays, "cot_helper", None)
            or str(getattr(callee, "helper", "")) != expected_helper):
        return None
    if (_major_function_array(item.a[0], lvar_index, ida_hexrays, ida_typeinf,
            pointer_width) is None or _number_value(item.a[2]) != 28):
        return None
    handler_ea = _exact_handler_target(item.a[1], ida_hexrays,
        resolve_function_entry, pointer_width)
    return (item, handler_ea) if handler_ea is not None else None


def _exact_handler_target(expression, ida_hexrays, resolve_function_entry,
                          pointer_width: int):
    handler = expression
    seen = set()
    while handler.op == ida_hexrays.cot_cast:
        identity = _ctree_node_identity(handler)
        if identity in seen:
            return None
        seen.add(identity)
        try:
            if int(handler.type.get_size()) != pointer_width:
                return None
        except Exception:
            return None
        handler = handler.x
    if handler is None or handler.op != ida_hexrays.cot_obj:
        return None
    handler_ea = int(handler.obj_ea)
    return handler_ea if resolve_function_entry(handler_ea) == handler_ea else None


def _raw_argument_write_offset(expression, lvar_index: int, ida_hexrays,
                               pointer_width: int):
    if expression.op != ida_hexrays.cot_asg:
        return None
    if (expression_contains_lvar(expression.y, lvar_index, ida_hexrays)
            or any(ida_hexrays.is_assignment(node.op)
              or ida_hexrays.is_prepost(node.op)
              or node.op == ida_hexrays.cot_call
              for node in expression_nodes(expression.y))):
        return None
    left = _strip_representation_casts(expression.x, ida_hexrays)
    if left is None or left.op != getattr(ida_hexrays, "cot_ptr", None):
        return None
    address = _strip_representation_casts(left.x, ida_hexrays)
    if address is None or address.op != getattr(ida_hexrays, "cot_add", None):
        return None
    for base, offset in ((address.x, address.y), (address.y, address.x)):
        if (base.op == ida_hexrays.cot_var and int(base.v.idx) == lvar_index
                and offset.op == ida_hexrays.cot_num):
            try:
                width = int(expression.x.type.get_size())
            except Exception:
                width = pointer_width
            return _number_value(offset), width
    return None


def _prove_nonoverlap_post_helper(cfunc, ida_hexrays, pointer_width: int):
    try:
        argidx = [int(value) for value in cfunc.argidx]
        if not argidx:
            return None
        lvar_index = argidx[0]
        lvar_type = cfunc.get_lvars()[lvar_index].type
        lvar_type = lvar_type() if callable(lvar_type) else lvar_type
        if int(lvar_type.get_size()) != pointer_width:
            return None
        matched = []
        for statement in _top_level_statements(cfunc):
            if statement.op == ida_hexrays.cit_return:
                returned = _top_level_return_expression(statement, ida_hexrays)
                if returned is not None and (expression_contains_lvar(
                        returned, lvar_index, ida_hexrays)
                        or any(ida_hexrays.is_assignment(node.op)
                          or node.op == ida_hexrays.cot_call
                          for node in expression_nodes(returned))):
                    return None
                continue
            if statement.op != ida_hexrays.cit_expr:
                return None
            item = statement.cexpr
            if any(node.op == ida_hexrays.cot_call for node in expression_nodes(item)):
                return None
            if not expression_contains_lvar(item, lvar_index, ida_hexrays):
                continue
            raw = _raw_argument_write_offset(item, lvar_index, ida_hexrays,
                pointer_width)
            if raw is None:
                return None
            matched.append((item, raw))
        if len(matched) != 1:
            return None
        item, (offset, width) = matched[0]
        if (offset != core.driver_object_fast_io_dispatch_offset(pointer_width)
                or width != pointer_width):
            return None
        return {"kind": "canonical_fast_io_dispatch_write",
            "write_ea": hex(int(item.ea)), "offset_bytes": offset,
            "width_bytes": width}
    except Exception:
        return None


def _major_function_write_index(expression, lvar_index: int, ida_hexrays,
                                ida_typeinf, pointer_width: int):
    try:
        if not ida_hexrays.is_assignment(expression.op):
            return None
        left = expression.x
        if left.op != ida_hexrays.cot_idx or left.x.op != ida_hexrays.cot_memptr:
            return None
        if _major_function_array(left.x, lvar_index, ida_hexrays, ida_typeinf,
                pointer_width) is None:
            return None
        return _number_value(left.y) if left.y.op == ida_hexrays.cot_num else "dynamic"
    except Exception:
        return None


def collect_typed_major_function_store_leads(cfunc, ida_hexrays, ida_typeinf,
                                             resolve_function_entry,
                                             pointer_width: int) -> list[tuple[int, int]]:
    """Return (slot index, handler) only for a typed DRIVER_OBJECT member write.

    This is a triage lead, not registration proof: control flow and intervening
    writes are deliberately left to the stronger registration producer.
    """
    try:
        arguments = [int(value) for value in cfunc.argidx]
        lvars = cfunc.get_lvars()
        driver_arguments = []
        for index in arguments:
            value = lvars[index].type
            value = value() if callable(value) else value
            identity = _pointer_udt_identity(value, ida_typeinf,
                {"DRIVER_OBJECT", "_DRIVER_OBJECT"})
            if identity is not None and identity[2] == pointer_width:
                driver_arguments.append(index)
        if not driver_arguments:
            return []
        collected = _collect_cfunc_expressions(cfunc, ida_hexrays)
        if collected is None:
            return []
        leads = set()
        for expression in collected[0]:
            for index in driver_arguments:
                slot = _major_function_write_index(expression, index,
                    ida_hexrays, ida_typeinf, pointer_width)
                if type(slot) is not int or not 0 <= slot < 28:
                    continue
                handler = _exact_handler_target(expression.y, ida_hexrays,
                    resolve_function_entry, pointer_width)
                if handler is not None:
                    leads.add((slot, handler))
        return sorted(leads)
    except Exception:
        return []


def _helper_caller_binding(cfunc, driver_entry_ea: int, ida_hexrays,
                           ida_typeinf, resolve_function_entry,
                           expected_pointer_width: int):
    if int(cfunc.entry_ea) != driver_entry_ea:
        return None
    args = [int(value) for value in cfunc.argidx]
    if not args:
        return None
    lvar_index = args[0]
    raw_type = cfunc.get_lvars()[lvar_index].type
    raw_type = raw_type() if callable(raw_type) else raw_type
    identity = _pointer_udt_identity(raw_type, ida_typeinf,
        {"DRIVER_OBJECT", "_DRIVER_OBJECT"})
    if identity is None or identity[2] != expected_pointer_width:
        return None
    calls = []
    top_level = _top_level_statements(cfunc)
    for index, statement in enumerate(top_level):
        returned = _top_level_return_expression(statement, ida_hexrays)
        if returned is None:
            continue
        direct = _direct_call_target(returned, ida_hexrays, resolve_function_entry)
        if direct is not None and list(direct[0].a):
            first_arg = direct[0].a[0]
            if (first_arg.op == ida_hexrays.cot_var
                    and int(first_arg.v.idx) == lvar_index):
                calls.append((index, statement, direct))
    if len(calls) != 1:
        return None
    selected_index, selected_statement, (selected, helper_ea) = calls[0]
    for statement in top_level[:selected_index]:
        if statement.op == ida_hexrays.cit_return:
            return None
        if statement.op not in {ida_hexrays.cit_expr, ida_hexrays.cit_if}:
            return None
    collected = _collect_cfunc_expressions(cfunc, ida_hexrays)
    if collected is None:
        return None
    for instruction in collected[1]:
        if instruction.op != ida_hexrays.cit_return \
                or _same_ctree_expression(instruction, selected_statement):
            continue
        returned = _top_level_return_expression(instruction, ida_hexrays)
        if returned is None or returned.op != ida_hexrays.cot_num:
            return None
        value = _number_value(returned)
        if value is None or (value & 0x80000000) == 0:
            return None
    for item in collected[0]:
        if _same_ctree_expression(item, selected):
            continue
        hazard = lvar_definition_hazard(item, lvar_index, ida_hexrays,
            lambda _ea: False, after_registration=False)
        if hazard is not None or unmodeled_lvar_derived_write(
                item, lvar_index, ida_hexrays, ida_typeinf):
            return None
    return lvar_index, selected, helper_ea


def collect_helper_driver_registration(caller_cfunc, driver_entry_ea: int,
                                       ida_hexrays, ida_typeinf,
                                       resolve_function_entry, decompile_function,
                                       *, device_control_index: int,
                                       expected_pointer_width: int):
    """Prove one exact DriverEntry tail helper and canonical bulk slot initialization."""
    base = {"contract_id": REGISTRATION_PRODUCER_CONTRACT_ID, "version": 1,
        "driver_entry_ea": hex(driver_entry_ea), "registrations": []}
    try:
        caller = _helper_caller_binding(caller_cfunc, driver_entry_ea,
            ida_hexrays, ida_typeinf, resolve_function_entry,
            expected_pointer_width)
        if caller is None:
            return None
        caller_lvar, caller_call, helper_ea = caller
        helper = decompile_function(helper_ea)
        if helper is None:
            return {**base, "status": "partial",
                "reason_code": "helper_registration_decompile_unavailable"}
        helper_args = [int(value) for value in helper.argidx]
        if not helper_args:
            return {**base, "status": "partial",
                "reason_code": "helper_registration_argument_unavailable"}
        helper_lvar = helper_args[0]
        helper_type = helper.get_lvars()[helper_lvar].type
        helper_type = helper_type() if callable(helper_type) else helper_type
        identity = _pointer_udt_identity(helper_type, ida_typeinf,
            {"DRIVER_OBJECT", "_DRIVER_OBJECT"})
        if identity is None or identity[2] != expected_pointer_width:
            return {**base, "status": "unsupported",
                "reason_code": "helper_registration_argument_unsupported"}
        return _collect_helper_registration_body(base, helper, caller_lvar,
            caller_call, helper_ea, helper_lvar, identity[1], ida_hexrays,
            ida_typeinf, resolve_function_entry, decompile_function,
            device_control_index, expected_pointer_width)
    except Exception:
        return {**base, "status": "partial",
            "reason_code": "helper_registration_scan_failed"}


def _collect_helper_registration_body(base, helper, caller_lvar, caller_call,
                                      helper_ea, helper_lvar, pointee_name,
                                      ida_hexrays, ida_typeinf,
                                      resolve_function_entry, decompile_function,
                                      device_control_index, pointer_width):
    statements = _top_level_statements(helper)
    bulk_rows = []
    for index, statement in enumerate(statements):
        if statement.op != ida_hexrays.cit_expr:
            continue
        bulk = _bulk_major_function_store(statement.cexpr, helper_lvar,
            ida_hexrays, ida_typeinf, resolve_function_entry, pointer_width)
        if bulk is not None:
            bulk_rows.append((index, *bulk))
    if len(bulk_rows) != 1:
        return {**base, "status": "unsupported",
            "reason_code": "helper_registration_bulk_store_unsupported"}
    bulk_index, bulk_call, handler_ea = bulk_rows[0]
    collected = _collect_cfunc_expressions(helper, ida_hexrays)
    if collected is None:
        return {**base, "status": "partial",
            "reason_code": "helper_registration_scan_failed"}
    success = []
    all_success_returns = []
    for instruction in collected[1]:
        returned = _top_level_return_expression(instruction, ida_hexrays)
        if (returned is not None and returned.op == ida_hexrays.cot_num
                and _number_value(returned) == 0):
            all_success_returns.append(instruction)
    for index, statement in enumerate(statements[bulk_index + 1:], bulk_index + 1):
        returned = _top_level_return_expression(statement, ida_hexrays)
        if (returned is not None and returned.op == ida_hexrays.cot_num
                and _number_value(returned) == 0):
            success.append((index, returned))
    if len(success) != 1 or len(all_success_returns) != 1:
        return {**base, "status": "unsupported",
            "reason_code": "helper_registration_success_path_unsupported"}
    success_index, success_return = success[0]
    prefix_calls = []
    for statement in statements[:bulk_index]:
        if statement.op != ida_hexrays.cit_expr:
            return {**base, "status": "unsupported",
                "reason_code": "helper_registration_prefix_control_unsupported"}
        expression = statement.cexpr
        hazard = lvar_definition_hazard(expression, helper_lvar, ida_hexrays,
            lambda _ea: False, after_registration=False)
        if (hazard is not None or unmodeled_lvar_derived_write(
                    expression, helper_lvar, ida_hexrays, ida_typeinf)):
            return {**base, "status": "unsupported",
                "reason_code": "helper_registration_prefix_state_unsupported"}
        for node in expression_nodes(expression):
            if node.op != ida_hexrays.cot_call:
                continue
            args = list(node.a)
            if any(expression_contains_lvar(arg, helper_lvar, ida_hexrays)
                    for arg in args):
                return {**base, "status": "unsupported",
                    "reason_code": "helper_registration_prefix_call_unsupported"}
    post_call_proofs = []
    for statement in statements[bulk_index + 1:success_index]:
        if statement.op != ida_hexrays.cit_expr:
            return {**base, "status": "unsupported",
                "reason_code": "helper_registration_post_store_control_unsupported"}
        expression = statement.cexpr
        slot_index = _major_function_write_index(expression, helper_lvar,
            ida_hexrays, ida_typeinf, pointer_width)
        if slot_index is not None:
            if slot_index == "dynamic" or slot_index == device_control_index:
                return {**base, "status": "unsupported",
                        "reason_code": "helper_registration_competing_write_unsupported"}
            if (_exact_handler_target(expression.y, ida_hexrays,
                    resolve_function_entry, pointer_width) is None
                    or any(node.op == ida_hexrays.cot_call
                      for node in expression_nodes(expression.y))):
                return {**base, "status": "unsupported",
                    "reason_code": "helper_registration_override_value_unsupported"}
            continue
        direct = _direct_call_target(expression, ida_hexrays,
            resolve_function_entry)
        direct_args = list(direct[0].a) if direct is not None else []
        carries_driver = [index for index, arg in enumerate(direct_args)
            if expression_contains_lvar(arg, helper_lvar, ida_hexrays)]
        if direct is not None and carries_driver:
            if (carries_driver != [0] or direct_args[0].op != ida_hexrays.cot_var
                    or int(direct_args[0].v.idx) != helper_lvar):
                return {**base, "status": "unsupported",
                    "reason_code": "helper_registration_post_call_unproven"}
            callee = decompile_function(direct[1])
            if callee is None:
                return {**base, "status": "partial",
                    "reason_code": "helper_post_call_decompile_unavailable"}
            proof = _prove_nonoverlap_post_helper(callee, ida_hexrays, pointer_width)
            if proof is None:
                return {**base, "status": "unsupported",
                    "reason_code": "helper_registration_post_call_unproven"}
            post_call_proofs.append({"call_ea": hex(int(direct[0].ea)),
                "callee_ea": hex(direct[1]), **proof})
            continue
        if expression_contains_lvar(expression, helper_lvar, ida_hexrays):
            return {**base, "status": "unsupported",
                "reason_code": "helper_registration_post_store_escape_unsupported"}
    registration = {"schema_version": "driver-helper-registration-proof/1",
        "driver_entry_ea": base["driver_entry_ea"],
        "helper_call_ea": hex(int(caller_call.ea)), "helper_ea": hex(helper_ea),
        "bulk_store_ea": hex(int(bulk_call.ea)),
        "success_return_ea": hex(int(success_return.ea)),
        "caller_base_lvar_index": caller_lvar,
        "helper_base_lvar_index": helper_lvar, "base_argument_index": 0,
        "base_type_kind": "plain_pointer_to_driver_object_udt",
        "base_pointee_type_name": pointee_name, "member_name": "MajorFunction",
        "member_offset_bytes": core.major_function_slot_offset(pointer_width, 0),
        "major_function_index": device_control_index,
        "pointer_width_bytes": pointer_width,
        "target_architecture_bits": pointer_width * 8,
        "derived_slot_offset_bytes": core.major_function_slot_offset(
            pointer_width, device_control_index),
        "bulk_element_count": 28, "rhs_target_ea": hex(handler_ea),
        "top_level_success_path": True, "pre_bulk_call_eas": sorted(set(prefix_calls)),
        "post_call_proofs": post_call_proofs}
    return {**base, "status": "complete", "reason_code": None,
        "registrations": [registration]}


def _top_level_selector_index(cfunc, source_ea: int, root_kind: str,
                              root_lvar_index: int, irp_lvar_index: int,
                              ida_hexrays, ida_typeinf):
    positions = []
    for index, statement in enumerate(_top_level_statements(cfunc)):
        expression = None
        if statement.op == ida_hexrays.cit_expr:
            expression = statement.cexpr
        elif statement.op == getattr(ida_hexrays, "cit_switch", None):
            expression = getattr(getattr(statement, "cswitch", None), "expr", None)
        if expression is None:
            continue
        candidate_root = _typed_member_path_root(expression,
            IOCTL_SELECTOR_MEMBER_PATH, ida_hexrays, ida_typeinf)
        if candidate_root is None or int(expression.ea) != source_ea:
            continue
        same_root = (_expression_is_lvar_identity(
            candidate_root, root_lvar_index, ida_hexrays)
            if root_kind == "local_assignment"
            else _current_stack_source(candidate_root, irp_lvar_index,
                ida_hexrays, ida_typeinf) is not None)
        if same_root:
            positions.append(index)
    return positions[0] if len(positions) == 1 else None


def _pointer_udt_identity(raw_type, ida_typeinf, allowed_names):
    pointer = ida_typeinf.tinfo_t(raw_type)
    if not pointer.is_ptr() or pointer.is_shifted_ptr():
        return None
    width = int(pointer.get_size())
    pointee = pointer.get_pointed_object()
    if width not in {4, 8} or not pointee.is_udt():
        return None
    name = pointee.get_type_name()
    return (pointer, name, width) if name in allowed_names else None


def _current_stack_source(expression, irp_lvar_index: int, ida_hexrays, ida_typeinf):
    proof = _typed_member_path_proof(expression, IRP_CURRENT_STACK_MEMBER_PATH,
        ida_hexrays, ida_typeinf)
    if proof is None:
        return None
    root, offsets = proof
    if (root.op != ida_hexrays.cot_var
            or int(getattr(getattr(root, "v", None), "idx", -1)) != irp_lvar_index):
        return None
    return expression, offsets


def _selector_irp_path_write_hazard(expression, irp_lvar_index: int,
                                    ida_hexrays, ida_typeinf) -> bool:
    try:
        if not (ida_hexrays.is_assignment(expression.op)
                or ida_hexrays.is_prepost(expression.op)):
            return False
        left = expression.x
        if not expression_contains_lvar(left, irp_lvar_index, ida_hexrays):
            return False
        root, path = _structural_member_chain(left, ida_hexrays, ida_typeinf)
        if not _expression_is_lvar_identity(root, irp_lvar_index, ida_hexrays):
            return True
        shared = min(len(path), len(IRP_CURRENT_STACK_MEMBER_PATH))
        return tuple(path[:shared]) == IRP_CURRENT_STACK_MEMBER_PATH[:shared]
    except Exception:
        return True


def _selector_root_provenance(root, _selector_expression, source_ea: int, cfunc, ida_hexrays,
                              ida_typeinf, expected_pointer_width=None) -> dict | None:
    try:
        dispatch_ea = int(cfunc.entry_ea)
        argument_indices = [int(value) for value in cfunc.argidx]
        if len(argument_indices) < 2:
            return None
        lvars = cfunc.get_lvars()
        irp_lvar_index = argument_indices[1]
        irp_lvar = lvars[irp_lvar_index]
        irp_type = irp_lvar.type() if callable(irp_lvar.type) else irp_lvar.type
        irp_identity = _pointer_udt_identity(
            irp_type, ida_typeinf, {"IRP", "_IRP"})
        root_identity = _pointer_udt_identity(
            root.type, ida_typeinf, {"IO_STACK_LOCATION", "_IO_STACK_LOCATION"})
        if (irp_identity is None or root_identity is None
                or irp_identity[2] != root_identity[2]):
            return None
        expected_width = expected_pointer_width
        if expected_width is None:
            expected_width = getattr(cfunc, "target_pointer_width", irp_identity[2])
        if expected_width not in {4, 8} or irp_identity[2] != expected_width:
            return None
        collected = _collect_cfunc_expressions(cfunc, ida_hexrays)
        if collected is None:
            return None
        expressions, instructions = collected
        direct = _current_stack_source(root, irp_lvar_index, ida_hexrays, ida_typeinf)
        if direct is not None:
            root_kind = "direct_member_path"
            root_lvar_index = irp_lvar_index
            current_stack_offsets = direct[1]
        else:
            if root.op != ida_hexrays.cot_var:
                return None
            root_lvar_index = int(getattr(getattr(root, "v", None), "idx", -1))
            if root_lvar_index < 0 or root_lvar_index == irp_lvar_index:
                return None
            root_kind = "local_assignment"
        unsupported_control_ops = {value for value in (
            getattr(ida_hexrays, "cit_goto", None),
            getattr(ida_hexrays, "cit_asm", None),
            getattr(ida_hexrays, "cit_try", None),
            getattr(ida_hexrays, "cit_throw", None),
        ) if value is not None}
        if any(item.op in unsupported_control_ops for item in instructions):
            return None
        top_level_selector_index = _top_level_selector_index(cfunc, source_ea,
            root_kind, root_lvar_index, irp_lvar_index, ida_hexrays, ida_typeinf)
        if top_level_selector_index is None:
            return None
        selector_positions = []
        for index, item in enumerate(expressions):
            candidate_root = _typed_member_path_root(item,
                IOCTL_SELECTOR_MEMBER_PATH, ida_hexrays, ida_typeinf)
            if candidate_root is None:
                continue
            same_root = (_expression_is_lvar_identity(
                candidate_root, root_lvar_index, ida_hexrays)
                if root_kind == "local_assignment"
                else _current_stack_source(candidate_root, irp_lvar_index,
                    ida_hexrays, ida_typeinf) is not None)
            if not same_root:
                return None
            if int(item.ea) == source_ea:
                selector_positions.append(index)
        if len(selector_positions) != 1:
            return None
        definition = None
        if root_kind == "local_assignment":
            definitions = []
            for statement in _top_level_statements(cfunc)[:top_level_selector_index]:
                if statement.op != ida_hexrays.cit_expr:
                    continue
                item = statement.cexpr
                if not ((ida_hexrays.is_assignment(item.op)
                        or ida_hexrays.is_prepost(item.op))
                        and _expression_is_lvar_identity(
                            item.x, root_lvar_index, ida_hexrays)):
                    continue
                if (item.op != ida_hexrays.cot_asg
                        or _current_stack_source(item.y, irp_lvar_index,
                            ida_hexrays, ida_typeinf) is None):
                    return None
                definitions.append(item)
            if len(definitions) != 1:
                return None
            definition = definitions[0]
            current_stack_offsets = _current_stack_source(
                definition.y, irp_lvar_index, ida_hexrays, ida_typeinf)[1]
            definition_type = ida_typeinf.tinfo_t(definition.y.type)
            root_type = ida_typeinf.tinfo_t(root.type)
            if not definition_type.equals_to(root_type):
                return None
        prior = expressions[:selector_positions[0]]
        for item in prior:
            supported_source_assignment = (root_kind == "local_assignment"
                and _same_ctree_expression(item, definition)
                and item.op == ida_hexrays.cot_asg
                and _expression_is_lvar_identity(
                    item.x, root_lvar_index, ida_hexrays)
                and _current_stack_source(item.y, irp_lvar_index,
                    ida_hexrays, ida_typeinf) is not None)
            irp_hazard = None if supported_source_assignment else lvar_definition_hazard(
                item, irp_lvar_index, ida_hexrays,
                lambda _ea: False, after_registration=False)
            if (irp_hazard is not None or unmodeled_lvar_derived_write(
                    item, irp_lvar_index, ida_hexrays, ida_typeinf)
                    or _selector_irp_path_write_hazard(
                        item, irp_lvar_index, ida_hexrays, ida_typeinf)):
                return None
        if root_kind == "direct_member_path":
            assignment_ea = None
        else:
            for item in prior:
                is_assignment = ida_hexrays.is_assignment(item.op)
                is_update = ida_hexrays.is_prepost(item.op)
                if ((is_assignment or is_update)
                        and _expression_is_lvar_identity(
                            item.x, root_lvar_index, ida_hexrays)):
                    if (not _same_ctree_expression(item, definition)
                            or item.op != ida_hexrays.cot_asg
                            or _current_stack_source(item.y, irp_lvar_index,
                                ida_hexrays, ida_typeinf) is None):
                        return None
                    continue
                root_hazard = lvar_definition_hazard(item, root_lvar_index,
                    ida_hexrays, lambda _ea: False, after_registration=False)
                if root_hazard is not None or unmodeled_lvar_derived_write(
                        item, root_lvar_index, ida_hexrays, ida_typeinf):
                    return None
            root_kind = "local_assignment"
            assignment_ea = hex(int(definition.ea))
        return {
            "schema_version": "driver-irp-current-stack-proof/1",
            "abi_contract_id": core.DRIVER_TRIGGER_ABI_CONTRACT_ID,
            "dispatch_function_ea": hex(dispatch_ea),
            "irp_argument_index": 1,
            "irp_lvar_index": irp_lvar_index,
            "irp_pointee_type_name": irp_identity[1],
            "pointer_width_bytes": irp_identity[2],
            "target_architecture_bits": expected_width * 8,
            "root_kind": root_kind,
            "root_lvar_index": root_lvar_index,
            "assignment_ea": assignment_ea,
            "current_stack_member_path": list(IRP_CURRENT_STACK_MEMBER_PATH),
            "current_stack_member_offsets_bytes": list(current_stack_offsets),
        }
    except Exception:
        return None


def collect_driver_entry_registrations(cfunc, driver_entry_ea: int, ida_hexrays,
                                       ida_typeinf, resolve_function_entry,
                                       *, device_control_index: int,
                                       expected_pointer_width: int,
                                       unsupported_forms=(),
                                       documented_external_call=lambda _ea: False) -> dict:
    """Collect only direct top-level DriverEntry MajorFunction assignments."""
    base = {
        "contract_id": REGISTRATION_PRODUCER_CONTRACT_ID,
        "version": 1,
        "driver_entry_ea": hex(driver_entry_ea),
    }
    try:
        if int(cfunc.entry_ea) != driver_entry_ea or cfunc.body.op != ida_hexrays.cit_block:
            return {**base, "status": "partial",
                "reason_code": "driver_entry_ctree_binding_unavailable", "registrations": []}
        argidx = [int(value) for value in cfunc.argidx]
        if not argidx:
            return {**base, "status": "partial",
                "reason_code": "driver_entry_argument_identity_unavailable", "registrations": []}
        lvars = cfunc.get_lvars()
        first_lvar_index = argidx[0]
        first_lvar = lvars[first_lvar_index]
        first_lvar_type = first_lvar.type() if callable(first_lvar.type) else first_lvar.type
        pointer_type = ida_typeinf.tinfo_t(first_lvar_type)
        if not pointer_type.is_ptr() or pointer_type.is_shifted_ptr():
            return {**base, "status": "partial",
                "reason_code": "driver_entry_first_argument_type_unavailable", "registrations": []}
        pointer_width = int(pointer_type.get_size())
        if expected_pointer_width not in {4, 8} or pointer_width != expected_pointer_width:
            return {**base, "status": "unsupported",
                "reason_code": "typed_major_function_registration_form_unsupported",
                "registrations": []}
        pointee = pointer_type.get_pointed_object()
        if not pointee.is_udt():
            return {**base, "status": "partial",
                "reason_code": "driver_entry_first_argument_type_unavailable", "registrations": []}
        pointee_name = pointee.get_type_name()
        if pointee_name not in {"DRIVER_OBJECT", "_DRIVER_OBJECT"}:
            return {**base, "status": "partial",
                "reason_code": "driver_entry_first_argument_type_unavailable", "registrations": []}
        registrations = []
        unsupported_form = False
        local_unsupported = []
        for statement in cfunc.body.cblock:
            if statement.op in {ida_hexrays.cit_return, ida_hexrays.cit_goto}:
                break
            if statement.op != ida_hexrays.cit_expr:
                continue
            assignment = statement.cexpr
            form = registration_slot_write_form(assignment, first_lvar_index,
                ida_hexrays, ida_typeinf, resolve_function_entry,
                device_control_index=device_control_index)
            if form != "direct":
                if form == "cast":
                    local_unsupported.append("cast_registration_form_unsupported")
                elif form == "dynamic":
                    local_unsupported.append("ambiguous_registration_form_unsupported")
                elif form == "unknown":
                    local_unsupported.append(
                        "typed_major_function_registration_form_unsupported")
                elif unmodeled_lvar_derived_write(assignment, first_lvar_index,
                        ida_hexrays, ida_typeinf):
                    local_unsupported.append(
                        "ambiguous_registration_form_unsupported")
                hazard = lvar_definition_hazard(assignment, first_lvar_index, ida_hexrays,
                    documented_external_call, after_registration=bool(registrations))
                if hazard is not None:
                    local_unsupported.append(hazard)
                continue
            left, right = assignment.x, assignment.y
            if left.op != ida_hexrays.cot_idx or left.y.op != ida_hexrays.cot_num:
                continue
            if _number_value(left.y) != device_control_index:
                continue
            member_expression = left.x
            if member_expression.op != ida_hexrays.cot_memptr:
                continue
            argument = member_expression.x
            if argument.op != ida_hexrays.cot_var or int(argument.v.idx) != first_lvar_index:
                continue
            selected = _exact_udt_member(argument, member_expression,
                ida_hexrays, ida_typeinf, "MajorFunction")
            if selected is None:
                continue
            member, member_type = selected
            array = ida_typeinf.array_type_data_t()
            if (pointer_width not in {4, 8} or not member_type.is_array()
                    or not member_type.get_array_details(array)):
                unsupported_form = True
                continue
            element_type = ida_typeinf.tinfo_t(array.elem_type)
            if (not element_type.is_ptr() or int(element_type.get_size()) != pointer_width
                    or int(array.nelems) != 28
                    or int(member_type.get_size()) != 28 * pointer_width
                    or not 0 <= device_control_index < int(array.nelems)):
                unsupported_form = True
                continue
            if right.op != ida_hexrays.cot_obj:
                continue
            rhs_ea = int(right.obj_ea)
            resolved = resolve_function_entry(rhs_ea)
            if resolved is None or int(resolved) != rhs_ea:
                continue
            assignment_ea = int(assignment.ea)
            if assignment_ea < 0:
                continue
            member_offset = int(member.begin()) // 8
            canonical_slot = core.major_function_slot_offset(
                pointer_width, device_control_index)
            if (member_offset + device_control_index * pointer_width
                    != canonical_slot):
                unsupported_form = True
                continue
            registrations.append({
                "schema_version": REGISTRATION_PROOF_SCHEMA,
                "driver_entry_ea": hex(driver_entry_ea),
                "assignment_ea": hex(assignment_ea),
                "base_argument_index": 0,
                "base_lvar_index": first_lvar_index,
                "base_type_kind": "plain_pointer_to_driver_object_udt",
                "base_pointee_type_name": pointee_name,
                "member_name": "MajorFunction",
                "member_offset_bytes": member_offset,
                "major_function_index": device_control_index,
                "pointer_width_bytes": pointer_width,
                "target_architecture_bits": expected_pointer_width * 8,
                "derived_slot_offset_bytes": member_offset
                    + device_control_index * pointer_width,
                "rhs_target_ea": hex(rhs_ea),
                "top_level_unconditional": True,
            })
        all_unsupported = sorted(set([*unsupported_forms, *local_unsupported]))
        if len(registrations) > 1:
            return {**base, "status": "unsupported",
                "reason_code": "ambiguous_registration_form_unsupported",
                "registrations": []}
        if all_unsupported:
            return {**base, "status": "unsupported",
                "reason_code": all_unsupported[0], "registrations": []}
        if unsupported_form:
            return {**base, "status": "unsupported",
                "reason_code": "typed_major_function_registration_form_unsupported",
                "registrations": []}
        if registrations:
            return {**base, "status": "complete", "reason_code": None,
                "registrations": registrations}
        return {**base, "status": "complete", "reason_code": None, "registrations": []}
    except Exception:
        return {**base, "status": "partial",
            "reason_code": "driver_entry_registration_scan_failed", "registrations": []}


def finalize_registration_scan(result: dict, *, expired: bool) -> dict:
    """Discard every tentative disposition when the structural walk timed out."""
    if not expired:
        return result
    return {
        "contract_id": REGISTRATION_PRODUCER_CONTRACT_ID,
        "version": 1,
        "driver_entry_ea": result.get("driver_entry_ea"),
        "status": "partial",
        "reason_code": "driver_entry_registration_scan_timeout",
        "registrations": [],
    }


def _host_digest(contract_id: str, value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256((contract_id + "\0" + encoded).encode("utf-8")).hexdigest()


def _normalize_selector_root_provenance(value: object, function_address: object,
                                        source_ea: object):
    keys = {
        "schema_version", "dispatch_function_ea", "irp_argument_index",
        "irp_lvar_index", "irp_pointee_type_name", "pointer_width_bytes",
        "root_kind", "root_lvar_index", "assignment_ea",
        "current_stack_member_path", "current_stack_member_offsets_bytes",
        "abi_contract_id", "target_architecture_bits",
    }
    if (not isinstance(value, dict) or set(value) != keys
            or value.get("schema_version") != "driver-irp-current-stack-proof/1"
            or value.get("abi_contract_id") != core.DRIVER_TRIGGER_ABI_CONTRACT_ID
            or value.get("dispatch_function_ea") != function_address
            or value.get("irp_argument_index") != 1
            or type(value.get("irp_lvar_index")) is not int
            or value.get("irp_lvar_index") < 0
            or value.get("irp_pointee_type_name") not in {"IRP", "_IRP"}
            or value.get("pointer_width_bytes") not in {4, 8}
            or value.get("target_architecture_bits")
              != value.get("pointer_width_bytes") * 8
            or value.get("root_kind") not in {"local_assignment", "direct_member_path"}
            or type(value.get("root_lvar_index")) is not int
            or value.get("root_lvar_index") < 0
            or value.get("current_stack_member_path")
              != list(IRP_CURRENT_STACK_MEMBER_PATH)
            or value.get("current_stack_member_offsets_bytes")
              != list(core.driver_trigger_abi_member_offsets(
                  value.get("pointer_width_bytes"))["irp_current_stack"])):
        return None
    if value["root_kind"] == "local_assignment":
        if (value["root_lvar_index"] == value["irp_lvar_index"]
                or not isinstance(value.get("assignment_ea"), str)
                or not value["assignment_ea"].startswith("0x")
                or not isinstance(source_ea, str) or not source_ea.startswith("0x")):
            return None
        try:
            if int(value["assignment_ea"], 16) >= int(source_ea, 16):
                return None
        except ValueError:
            return None
    elif (value["root_lvar_index"] != value["irp_lvar_index"]
            or value.get("assignment_ea") is not None):
        return None
    return value


def build_ioctl_selector_fact(registration_producer: dict, candidate: dict, *,
                              device_control_code: int) -> dict | None:
    """Build the replayable fact only from exact structural selector bindings."""
    function_address = candidate.get("function_addr")
    source_ea = candidate.get("addr")
    binding = candidate.get("selector_binding")
    root_provenance = _normalize_selector_root_provenance(
        binding.get("root_provenance") if isinstance(binding, dict) else None,
        function_address, source_ea)
    selector_offsets = (binding.get("selector_member_offsets_bytes")
        if isinstance(binding, dict) else None)
    if (
        candidate.get("method_detail") != "ctree_case"
        or candidate.get("confidence") != "high"
        or type(candidate.get("code_int")) is not int
        or type(candidate.get("function_code")) is not int
        or candidate["function_code"] != ((candidate["code_int"] >> 2) & 0xFFF)
        or root_provenance is None
        or selector_offsets != list(core.driver_trigger_abi_member_offsets(
            root_provenance["pointer_width_bytes"])["ioctl_selector"])
        or binding
        != {
            "kind": "typed_member_path",
            "member_path": list(IOCTL_SELECTOR_MEMBER_PATH),
            "source_ea": candidate.get("addr"),
            "selector_member_offsets_bytes": selector_offsets,
            "root_provenance": root_provenance,
        }
    ):
        return None
    if not (
        isinstance(function_address, str)
        and isinstance(source_ea, str)
        and function_address.startswith("0x")
        and source_ea.startswith("0x")
        and type(device_control_code) is int
    ):
        return None
    if (not isinstance(registration_producer, dict)
        or registration_producer.get("contract_id") != REGISTRATION_PRODUCER_CONTRACT_ID
        or registration_producer.get("version") != 1
        or registration_producer.get("status") != "complete"
        or registration_producer.get("reason_code") is not None
        or not isinstance(registration_producer.get("registrations"), list)):
        return None
    matching = [item for item in registration_producer["registrations"]
                if item.get("rhs_target_ea") == function_address]
    if len(registration_producer["registrations"]) != 1 or len(matching) != 1:
        return None
    registration = matching[0]
    pointer_width = registration.get("pointer_width_bytes")
    member_offset = registration.get("member_offset_bytes")
    helper_registration = registration.get("schema_version") \
        == "driver-helper-registration-proof/1"
    base_lvar_index = (registration.get("helper_base_lvar_index")
        if helper_registration else registration.get("base_lvar_index"))
    assignment_key = "bulk_store_ea" if helper_registration else "assignment_ea"
    top_level_success = (registration.get("top_level_success_path")
        if helper_registration else registration.get("top_level_unconditional"))
    if (registration.get("schema_version") not in {
            REGISTRATION_PROOF_SCHEMA, "driver-helper-registration-proof/1"}
        or registration.get("driver_entry_ea")
          != registration_producer.get("driver_entry_ea")
        or registration.get("base_argument_index") != 0
        or type(base_lvar_index) is not int
        or registration.get("base_type_kind") != "plain_pointer_to_driver_object_udt"
        or registration.get("base_pointee_type_name") not in {"DRIVER_OBJECT", "_DRIVER_OBJECT"}
        or registration.get("member_name") != "MajorFunction"
        or registration.get("major_function_index") != device_control_code
        or pointer_width not in {4, 8}
        or registration.get("target_architecture_bits") != pointer_width * 8
        or root_provenance["pointer_width_bytes"] != pointer_width
        or type(member_offset) is not int or member_offset < 0
        or registration.get("derived_slot_offset_bytes")
          != member_offset + device_control_code * pointer_width
        or top_level_success is not True
        or helper_registration and (registration.get("bulk_element_count") != 28
          or not isinstance(registration.get("post_call_proofs"), list)
          or any(item.get("kind") != "canonical_fast_io_dispatch_write"
            or item.get("offset_bytes")
              != core.driver_object_fast_io_dispatch_offset(pointer_width)
            or item.get("width_bytes") != pointer_width
            for item in registration["post_call_proofs"]))
        or not all(isinstance(registration.get(key), str)
          and registration[key].startswith("0x") for key in (
            "driver_entry_ea", assignment_key, "rhs_target_ea"))):
        return None
    code_int = candidate["code_int"]
    value_hex = f"0x{code_int:08x}"
    operation_selector_sha256 = _host_digest(
        "aasystem.dynamic-static-driver-ioctl-selector.v1",
        {"codeInt": code_int, "functionAddr": function_address},
    )
    value_sha256 = _host_digest(
        "aasystem.dynamic-trigger-field-value.v1",
        {"interpretation": "unsigned_little_endian", "valueHex": value_hex,
         "widthBytes": 4},
    )
    discriminator_hex = f"0x{device_control_code:02x}"
    discriminator_sha256 = _host_digest(
        "aasystem.dynamic-trigger-field-value.v1",
        {"interpretation": "unsigned_little_endian", "valueHex": discriminator_hex,
         "widthBytes": 1},
    )
    node_id = "driver-selector-v1:" + _host_digest(
        "aasystem.driver-ioctl-selector-node.v1",
        {"functionAddress": function_address, "sourceEa": source_ea,
         "valueHex": value_hex},
    )
    return {
        "schema_version": "driver-ioctl-selector-fact/1",
        "selector_proven": True,
        "operation_kind": "device_control",
        "operation_selector_sha256": operation_selector_sha256,
        "field_predicate": {
            "field_key": "operation.selector",
            "member_path": ["device_control", "io_control_code"],
            "offset_bytes": 0,
            "width_bytes": 4,
            "interpretation": "unsigned_little_endian",
            "relation": "equals",
            "value_sha256": value_sha256,
            "value_hex": value_hex,
        },
        "operation_discriminator": {
            "field_key": "operation.major_function",
            "member_path": ["irp_stack", "major_function"],
            "offset_bytes": 0,
            "width_bytes": 1,
            "interpretation": "unsigned_little_endian",
            "value_sha256": discriminator_sha256,
            "value_hex": discriminator_hex,
            "source": registration,
        },
        "source": {
            "function_addr": function_address,
            "source_ea": source_ea,
            "node_id": node_id,
            "method": "ctree_case",
            "confidence": "high",
            "selector_member_offsets_bytes": selector_offsets,
            "root_provenance": root_provenance,
        },
        "effect_link": {
            "kind": "dispatch_case",
            "function_addr": function_address,
            "source_ea": source_ea,
        },
    }
