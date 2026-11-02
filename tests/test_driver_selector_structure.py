import importlib.util
import json
from pathlib import Path
import unittest


MODULE_PATH = (Path(__file__).resolve().parents[1] / "src/ida_pro_mcp/ida_mcp/driver"
               / "selector_structure.py")
SPEC = importlib.util.spec_from_file_location("selector_structure_test_adapter", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
selector_structure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(selector_structure)


class Member:
    def __init__(self, name, typ, offset_bits=0):
        self.name, self.type, self.offset_bits = name, typ, offset_bits

    def begin(self):
        return self.offset_bits

    def is_bitfield(self):
        return False


class Udt(list):
    is_union = False


class Type:
    def __init__(self, value=None, *, kind=None, members=(), pointed=None, name=None,
                 is_union=False, size=0, element=None, count=0):
        if isinstance(value, Type):
            self.__dict__.update(value.__dict__)
        else:
            self.kind, self.members, self.pointed = kind, tuple(members), pointed
            self.name, self.is_union = name, is_union
            self.size, self.element, self.count = size, element, count

    def is_ptr(self):
        return self.kind == "pointer"

    def is_shifted_ptr(self):
        return False

    def get_pointed_object(self):
        return self.pointed

    def is_udt(self):
        return self.kind == "udt"

    def get_udt_details(self, out):
        if not self.is_udt():
            return False
        out.extend(self.members)
        out.is_union = self.is_union
        return True

    def equals_to(self, other):
        return isinstance(other, Type) and self.name == other.name

    def get_type_name(self):
        return self.name

    def get_size(self):
        return self.size

    def is_array(self):
        return self.kind == "array"

    def get_array_details(self, out):
        if not self.is_array():
            return False
        out.elem_type, out.nelems = self.element, self.count
        return True


class Expr:
    def __init__(self, op, typ=None, *, x=None, y=None, z=None, member=0, ea=0x1010,
                 number=None, lvar_index=None, obj_ea=None, arguments=(), rendered="",
                 helper=""):
        self.op, self.type, self.x, self.y, self.z = op, typ, x, y, z
        self.m, self.ea, self.obj_ea = member, ea, obj_ea
        self.n = type("Number", (), {"_value": number})() if number is not None else None
        self.v = type("Variable", (), {"idx": lvar_index})() if lvar_index is not None else None
        self.a = list(arguments)
        self.rendered = rendered
        self.helper = helper

    def dstr(self):
        return self.rendered


class Hexrays:
    cot_memptr, cot_memref, cot_cast, cot_var = 1, 2, 3, 4
    cot_idx, cot_num, cot_obj, cot_asg = 5, 6, 7, 8
    cot_call, cot_ref = 9, 10
    cot_asgbor, cot_asgxor, cot_asgband, cot_asgadd = 11, 12, 13, 14
    cot_asgsub, cot_asgmul, cot_asgsshr, cot_asgushr = 15, 16, 17, 18
    cot_asgshl, cot_asgsdiv, cot_asgudiv, cot_asgsmod, cot_asgumod = 19, 25, 26, 27, 28
    cot_postinc, cot_postdec, cot_preinc, cot_predec = 29, 30, 31, 32
    cot_comma, cot_tern = 33, 34
    cot_ptr, cot_add = 35, 36
    cot_land, cot_lor = 37, 38
    cot_helper = 46
    cit_block, cit_expr, cit_return, cit_goto, cit_if = 20, 21, 22, 23, 24
    cit_switch, cit_for, cit_while, cit_do, cit_asm, cit_try, cit_throw = (
        39, 40, 41, 42, 43, 44, 45)
    CV_FAST = 0

    @staticmethod
    def is_assignment(op):
        return op in {Hexrays.cot_asg, Hexrays.cot_asgbor, Hexrays.cot_asgxor,
            Hexrays.cot_asgband, Hexrays.cot_asgadd, Hexrays.cot_asgsub,
            Hexrays.cot_asgmul, Hexrays.cot_asgsshr, Hexrays.cot_asgushr,
            Hexrays.cot_asgshl, Hexrays.cot_asgsdiv, Hexrays.cot_asgudiv,
            Hexrays.cot_asgsmod, Hexrays.cot_asgumod}

    @staticmethod
    def is_prepost(op):
        return op in {Hexrays.cot_postinc, Hexrays.cot_postdec,
            Hexrays.cot_preinc, Hexrays.cot_predec}


class Array:
    elem_type = None
    nelems = 0


class Typeinf:
    tinfo_t, udt_type_data_t = Type, Udt
    array_type_data_t = Array


def expression(*, cast=False, leaf_name="IoControlCode", pointer_width=8, root=None):
    u32 = Type(kind="scalar", name="ULONG", size=4)
    opaque = Type(kind="scalar", name="PVOID")
    device = Type(kind="udt", name="DeviceIoControl", members=(
        Member("OutputBufferLength", u32, 0),
        Member("InputBufferLength", u32, 32),
        Member(leaf_name, u32, (128 if pointer_width == 8 else 64)),
    ))
    parameters = Type(kind="udt", name="Parameters", is_union=True, members=(
        Member("Create", opaque), Member("DeviceIoControl", device),
    ))
    stack = Type(kind="udt", name="IO_STACK_LOCATION", members=(
        Member("MajorFunction", u32, 0),
        Member("Parameters", parameters, (8 if pointer_width == 8 else 4) * 8),
    ))
    base = root if root is not None else Expr(Hexrays.cot_var,
        Type(kind="pointer", pointed=stack, name="PIO_STACK_LOCATION",
            size=pointer_width), lvar_index=4,
        rendered="Parameters.DeviceIoControl.IoControlCode")
    if cast:
        base = Expr(Hexrays.cot_cast, base.type, x=base,
            rendered="Parameters.DeviceIoControl.IoControlCode")
    parameters_expr = Expr(Hexrays.cot_memptr, parameters, x=base,
        member=8 if pointer_width == 8 else 4)
    device_expr = Expr(Hexrays.cot_memref, device, x=parameters_expr, member=1)
    return Expr(Hexrays.cot_memref, u32, x=device_expr,
        member=16 if pointer_width == 8 else 8,
        rendered="Parameters.DeviceIoControl.IoControlCode")


class Statement:
    def __init__(self, op, cexpr=None, children=()):
        self.op, self.cexpr = op, cexpr
        self.creturn = type("Return", (), {"expr": cexpr})() if op == Hexrays.cit_return else None
        self.children = list(children)


class Body:
    def __init__(self, statements):
        self.op, self.cblock = Hexrays.cit_block, statements


class Lvar:
    def __init__(self, typ):
        self.type = typ


class Cfunc:
    def __init__(self, statements, first_argument_type, *, argidx=(3,), entry_ea=0x800,
                 lvar_types=None):
        self.entry_ea, self.argidx, self.body = entry_ea, argidx, Body(statements)
        lvar_types = {} if lvar_types is None else lvar_types
        count = max([4, *(int(value) + 1 for value in argidx),
                     *(int(value) + 1 for value in lvar_types)])
        self._lvars = [Lvar(Type(kind="scalar", name=f"local{index}"))
                       for index in range(count)]
        if argidx:
            self._lvars[argidx[0]] = Lvar(first_argument_type)
        for index, typ in lvar_types.items():
            self._lvars[index] = Lvar(typ)

    def get_lvars(self):
        return self._lvars


def registration_cfunc(*, base_lvar=3, index=0x0E, right_kind=None, rhs=0x1000,
                       cast=False, rhs_cast=False, conditional=False, after_return=False,
                       pointer_width=8, member_name="MajorFunction", member_type="array"):
    function_pointer = Type(kind="pointer", name="PDRIVER_DISPATCH", size=pointer_width,
        pointed=Type(kind="function", name="DRIVER_DISPATCH"))
    major = Type(kind="array", name="MajorFunctionArray", size=pointer_width * 28,
        element=function_pointer, count=28) if member_type == "array" else Type(
        kind="scalar", name="UnsupportedMajorFunction", size=pointer_width)
    driver = Type(kind="udt", name="_DRIVER_OBJECT", size=0x150, members=(
        Member("Type", Type(kind="scalar", name="CSHORT", size=2), 0),
        Member(member_name, major, 0x70 * 8 if pointer_width == 8 else 0x38 * 8),
    ))
    pointer = Type(kind="pointer", name="PDRIVER_OBJECT", size=pointer_width,
        pointed=driver)
    base = Expr(Hexrays.cot_var, pointer, lvar_index=base_lvar)
    if cast:
        base = Expr(Hexrays.cot_cast, pointer, x=base)
    member = Expr(Hexrays.cot_memptr, major, x=base,
        member=0x70 if pointer_width == 8 else 0x38)
    subscript = Expr(Hexrays.cot_idx, function_pointer, x=member,
        y=Expr(Hexrays.cot_num, Type(kind="scalar", name="int", size=4), number=index))
    right_op = Hexrays.cot_obj if right_kind is None else right_kind
    right = Expr(right_op, function_pointer, obj_ea=rhs)
    if rhs_cast:
        right = Expr(Hexrays.cot_cast, function_pointer, x=right)
    assignment = Expr(Hexrays.cot_asg, function_pointer, x=subscript, y=right, ea=0x900)
    statement = Statement(Hexrays.cit_expr, assignment)
    statements = [Statement(Hexrays.cit_if, None)] if conditional else [statement]
    if after_return:
        statements = [Statement(Hexrays.cit_return), statement]
    return Cfunc(statements, pointer)


def registration_scan(cfunc, unsupported_forms=()):
    first = (cfunc.get_lvars()[int(cfunc.argidx[0])].type
        if cfunc.argidx else Type(kind="pointer", size=8))
    return selector_structure.collect_driver_entry_registrations(
        cfunc, 0x800, Hexrays, Typeinf,
        lambda ea: ea if ea == 0x1000 else None,
        device_control_index=0x0E,
        expected_pointer_width=first.get_size(),
        unsupported_forms=unsupported_forms,
    )


def helper_registration_fixture(pointer_width=8, *, bulk_count=28,
                                override_index=None, post_offset=None):
    direct = registration_cfunc(pointer_width=pointer_width)
    pointer = direct.get_lvars()[3].type
    template_member = direct.body.cblock[0].cexpr.x.x
    member = Expr(Hexrays.cot_memptr, template_member.type,
        x=Expr(Hexrays.cot_var, pointer, lvar_index=0), member=template_member.m)
    function_pointer = direct.body.cblock[0].cexpr.type
    caller_call = Expr(Hexrays.cot_call, Type(kind="scalar", name="NTSTATUS", size=4),
        x=Expr(Hexrays.cot_obj, obj_ea=0x2000),
        arguments=[Expr(Hexrays.cot_var, pointer, lvar_index=0)], ea=0x810)
    caller = Cfunc([Statement(Hexrays.cit_return, caller_call)], pointer,
        argidx=(0,), entry_ea=0x800)
    bulk = Expr(Hexrays.cot_call, Type(kind="scalar", name="void"),
        x=Expr(Hexrays.cot_helper,
            helper="memset64" if pointer_width == 8 else "memset32"),
        arguments=[member,
            Expr(Hexrays.cot_cast, Type(kind="scalar", name="uintptr_t",
                size=pointer_width), x=Expr(Hexrays.cot_obj,
                    function_pointer, obj_ea=0x3000)),
            Expr(Hexrays.cot_num, Type(kind="scalar", name="size_t",
                size=pointer_width), number=bulk_count)], ea=0x2100)
    statements = [Statement(Hexrays.cit_expr, bulk)]
    if override_index is not None:
        override = registration_cfunc(pointer_width=pointer_width,
            index=override_index, rhs=0x3001).body.cblock[0]
        override.cexpr.x.x.x.v.idx = 0
        override.cexpr.ea = 0x2110
        statements.append(override)
    helpers = {}
    if post_offset is not None:
        post_call = Expr(Hexrays.cot_call, Type(kind="scalar", name="void"),
            x=Expr(Hexrays.cot_obj, obj_ea=0x4000),
            arguments=[Expr(Hexrays.cot_var, pointer, lvar_index=0)], ea=0x2120)
        statements.append(Statement(Hexrays.cit_expr, post_call))
        raw_type = Type(kind="scalar", name="uintptr_t", size=pointer_width)
        raw_base = Expr(Hexrays.cot_var, raw_type, lvar_index=0)
        address = Expr(Hexrays.cot_add, raw_type, x=raw_base,
            y=Expr(Hexrays.cot_num, raw_type, number=post_offset))
        left = Expr(Hexrays.cot_ptr,
            Type(kind="pointer", name="PVOID", size=pointer_width), x=address)
        write = Expr(Hexrays.cot_asg, left.type, x=left,
            y=Expr(Hexrays.cot_obj, obj_ea=0x5000), ea=0x4010)
        helpers[0x4000] = Cfunc([Statement(Hexrays.cit_expr, write)], raw_type,
            argidx=(0,), entry_ea=0x4000)
    statements.append(Statement(Hexrays.cit_return,
        Expr(Hexrays.cot_num, Type(kind="scalar", name="NTSTATUS", size=4),
            number=0, ea=0x21F0)))
    helper = Cfunc(statements, pointer, argidx=(0,), entry_ea=0x2000)
    helpers[0x2000] = helper
    def resolve(ea):
        return ea if ea in {0x2000, 0x3000, 0x3001, 0x4000} else None
    return caller, helpers, resolve


class FakeCtreeVisitor:
    def __init__(self, _flags):
        pass

    def apply_to(self, body, _parent):
        seen = set()

        def visit(expression):
            if expression is None or id(expression) in seen:
                return
            seen.add(id(expression))
            self.visit_expr(ExpressionProxy(expression))
            for name in ("x", "y", "z"):
                visit(getattr(expression, name, None))
            for argument in getattr(expression, "a", ()):
                visit(argument)

        def visit_statement(statement):
            visit_insn = getattr(self, "visit_insn", None)
            if visit_insn is not None:
                visit_insn(statement)
            visit(getattr(statement, "cexpr", None))
            visit(getattr(getattr(statement, "creturn", None), "expr", None))
            for child in getattr(statement, "children", ()):
                visit_statement(child)

        for statement in body.cblock:
            visit_statement(statement)
        return 0


class ExpressionProxy:
    def __init__(self, target):
        self.target = target

    def __getattr__(self, name):
        return getattr(self.target, name)

    def __eq__(self, other):
        return self.target is getattr(other, "target", other)


Hexrays.ctree_visitor_t = FakeCtreeVisitor


def selector_cfunc(selector_expression, *, pointer_width=8, prefix=(),
                   before_selector=(), statements=()):
    stack_pointer = selector_expression.x.x.x.type
    tail_offset, overlay_offset, current_offset = (
        (0x78, 0x00, 0x40) if pointer_width == 8 else (0x40, 0x00, 0x20))
    current = Member("CurrentStackLocation", stack_pointer, current_offset * 8)
    overlay = Type(kind="udt", name="Overlay", members=(current,))
    tail = Type(kind="udt", name="Tail", members=(
        Member("Overlay", overlay, overlay_offset * 8),))
    irp = Type(kind="udt", name="_IRP", members=(
        Member("Tail", tail, tail_offset * 8),))
    irp_pointer = Type(kind="pointer", name="PIRP", size=pointer_width, pointed=irp)
    device_pointer = Type(kind="pointer", name="PDEVICE_OBJECT", size=pointer_width,
        pointed=Type(kind="udt", name="_DEVICE_OBJECT"))
    irp_root = Expr(Hexrays.cot_var, irp_pointer, lvar_index=1)
    tail_expr = Expr(Hexrays.cot_memptr, tail, x=irp_root,
        member=tail_offset, ea=0x1004)
    overlay_expr = Expr(Hexrays.cot_memref, overlay, x=tail_expr,
        member=overlay_offset, ea=0x1004)
    current_expr = Expr(Hexrays.cot_memref, stack_pointer, x=overlay_expr,
        member=current_offset, ea=0x1004)
    assignment = Expr(Hexrays.cot_asg, stack_pointer,
        x=Expr(Hexrays.cot_var, stack_pointer, lvar_index=4),
        y=current_expr, ea=0x1005)
    cfunc = Cfunc([*prefix, Statement(Hexrays.cit_expr, assignment), *before_selector,
        Statement(Hexrays.cit_expr, selector_expression), *statements],
        device_pointer, argidx=(0, 1), entry_ea=0x1000,
        lvar_types={1: irp_pointer, 4: stack_pointer})
    cfunc.target_pointer_width = pointer_width
    return cfunc


def selector_binding_expected(pointer_width=8, *, root_kind="local_assignment"):
    return {
        "kind": "typed_member_path",
        "member_path": ["Parameters", "DeviceIoControl", "IoControlCode"],
        "source_ea": "0x1010",
        "selector_member_offsets_bytes": [8 if pointer_width == 8 else 4, 0,
            16 if pointer_width == 8 else 8],
        "root_provenance": {
            "schema_version": "driver-irp-current-stack-proof/1",
            "abi_contract_id": "aasystem.windows-driver-trigger-abi.v1",
            "dispatch_function_ea": "0x1000",
            "irp_argument_index": 1,
            "irp_lvar_index": 1,
            "irp_pointee_type_name": "_IRP",
            "pointer_width_bytes": pointer_width,
            "target_architecture_bits": pointer_width * 8,
            "root_kind": root_kind,
            "root_lvar_index": 4 if root_kind == "local_assignment" else 1,
            "assignment_ea": "0x1005" if root_kind == "local_assignment" else None,
            "current_stack_member_path": ["Tail", "Overlay", "CurrentStackLocation"],
            "current_stack_member_offsets_bytes": ([0x78, 0, 0x40]
                if pointer_width == 8 else [0x40, 0, 0x20]),
        },
    }


class StructuralSelectorTests(unittest.TestCase):
    def test_helper_bulk_registration_proves_exact_mj14_on_x86_x64(self):
        for pointer_width in (4, 8):
            caller, helpers, resolve = helper_registration_fixture(
                pointer_width, post_offset=(0x28 if pointer_width == 4 else 0x50))
            result = selector_structure.collect_helper_driver_registration(
                caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
                device_control_index=0x0E, expected_pointer_width=pointer_width)
            self.assertEqual(result["status"], "complete")
            proof = result["registrations"][0]
            self.assertEqual(proof["schema_version"],
                "driver-helper-registration-proof/1")
            self.assertEqual(proof["rhs_target_ea"], "0x3000")
            self.assertEqual(proof["bulk_element_count"], 28)
            self.assertEqual(proof["post_call_proofs"][0]["kind"],
                "canonical_fast_io_dispatch_write")

    def test_helper_registration_rejects_incomplete_bulk_competing_mj14_and_post_escape(self):
        cases = [
            (helper_registration_fixture(8, bulk_count=27),
                "helper_registration_bulk_store_unsupported"),
            (helper_registration_fixture(8, override_index=14),
                "helper_registration_competing_write_unsupported"),
            (helper_registration_fixture(8, post_offset=0x48),
                "helper_registration_post_call_unproven"),
        ]
        for (caller, helpers, resolve), reason in cases:
            result = selector_structure.collect_helper_driver_registration(
                caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
                device_control_index=0x0E, expected_pointer_width=8)
            self.assertEqual(result["status"], "unsupported")
            self.assertEqual(result["reason_code"], reason)

    def test_helper_registration_rejects_multiple_calls_aliases_dynamic_and_conditional_forms(self):
        caller, helpers, resolve = helper_registration_fixture(8)
        caller.body.cblock.append(Statement(Hexrays.cit_return,
            caller.body.cblock[0].creturn.expr))
        self.assertIsNone(selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=8))

        caller, helpers, resolve = helper_registration_fixture(8)
        pointer = caller.get_lvars()[0].type
        alias = Expr(Hexrays.cot_asg, pointer,
            x=Expr(Hexrays.cot_var, pointer, lvar_index=2),
            y=Expr(Hexrays.cot_var, pointer, lvar_index=0), ea=0x805)
        caller.body.cblock.insert(0, Statement(Hexrays.cit_expr, alias))
        self.assertIsNone(selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=8))

        caller, helpers, resolve = helper_registration_fixture(8, override_index=13)
        helper = helpers[0x2000]
        helper.body.cblock[1].cexpr.x.y = Expr(Hexrays.cot_var,
            Type(kind="scalar", name="int", size=4), lvar_index=2)
        result = selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=8)
        self.assertEqual(result["reason_code"],
            "helper_registration_competing_write_unsupported")

        caller, helpers, resolve = helper_registration_fixture(8)
        helper = helpers[0x2000]
        helper.body.cblock[0].op = Hexrays.cit_if
        result = selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=8)
        self.assertEqual(result["reason_code"],
            "helper_registration_bulk_store_unsupported")

        caller, helpers, resolve = helper_registration_fixture(8, override_index=13)
        helper = helpers[0x2000]
        pointer = helper.get_lvars()[0].type
        helper.body.cblock[1].cexpr.y = Expr(Hexrays.cot_call,
            helper.body.cblock[1].cexpr.type,
            x=Expr(Hexrays.cot_obj, obj_ea=0x4000),
            arguments=[Expr(Hexrays.cot_var, pointer, lvar_index=0)])
        result = selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=8)
        self.assertEqual(result["reason_code"],
            "helper_registration_override_value_unsupported")

    def test_helper_registration_missing_decompile_is_partial_and_timeout_downgrades(self):
        caller, _helpers, resolve = helper_registration_fixture(8)
        result = selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, lambda _ea: None,
            device_control_index=0x0E, expected_pointer_width=8)
        self.assertEqual(result["status"], "partial")
        timed = selector_structure.finalize_registration_scan(result, expired=True)
        self.assertEqual(timed["reason_code"],
            "driver_entry_registration_scan_timeout")

    def test_helper_caller_requires_tail_call_to_dominate_every_success_exit(self):
        caller, helpers, resolve = helper_registration_fixture(8)
        caller.body.cblock.insert(0, Statement(Hexrays.cit_return,
            Expr(Hexrays.cot_num, Type(kind="scalar", name="NTSTATUS", size=4),
                number=0, ea=0x801)))
        self.assertIsNone(selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=8))

        caller, helpers, resolve = helper_registration_fixture(8)
        failed = Statement(Hexrays.cit_return,
            Expr(Hexrays.cot_num, Type(kind="scalar", name="NTSTATUS", size=4),
                number=0xC0000001, ea=0x802))
        caller.body.cblock.insert(0, Statement(Hexrays.cit_if, children=[failed]))
        result = selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=8)
        self.assertEqual(result["status"], "complete")

        for returned in (
            Expr(Hexrays.cot_num, Type(kind="scalar", name="NTSTATUS", size=4),
                number=0, ea=0x803),
            Expr(Hexrays.cot_var, Type(kind="scalar", name="NTSTATUS", size=4),
                lvar_index=2, ea=0x803),
        ):
            caller, helpers, resolve = helper_registration_fixture(8)
            caller.body.cblock.insert(0, Statement(Hexrays.cit_if,
                children=[Statement(Hexrays.cit_return, returned)]))
            self.assertIsNone(selector_structure.collect_helper_driver_registration(
                caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
                device_control_index=0x0E, expected_pointer_width=8))

        caller, helpers, resolve = helper_registration_fixture(8)
        tail = caller.body.cblock.pop()
        caller.body.cblock.append(Statement(Hexrays.cit_if, children=[tail]))
        self.assertIsNone(selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=8))

    def test_helper_registration_rejects_prefix_rebind_early_success_and_post_control(self):
        caller, helpers, resolve = helper_registration_fixture(8)
        helper = helpers[0x2000]
        pointer = helper.get_lvars()[0].type
        rebind = Expr(Hexrays.cot_asg, pointer,
            x=Expr(Hexrays.cot_var, pointer, lvar_index=0),
            y=Expr(Hexrays.cot_var, pointer, lvar_index=2), ea=0x2050)
        helper.body.cblock.insert(0, Statement(Hexrays.cit_expr, rebind))
        result = selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=8)
        self.assertEqual(result["reason_code"],
            "helper_registration_prefix_state_unsupported")

        caller, helpers, resolve = helper_registration_fixture(8)
        helper = helpers[0x2000]
        pointer = helper.get_lvars()[0].type
        nested_rebind = Expr(Hexrays.cot_asg, pointer,
            x=Expr(Hexrays.cot_var, pointer, lvar_index=0),
            y=Expr(Hexrays.cot_var, pointer, lvar_index=2), ea=0x2050)
        helper.body.cblock.insert(0, Statement(Hexrays.cit_if, nested_rebind))
        result = selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=8)
        self.assertEqual(result["reason_code"],
            "helper_registration_prefix_control_unsupported")

        caller, helpers, resolve = helper_registration_fixture(8)
        helper = helpers[0x2000]
        pointer = helper.get_lvars()[0].type
        escaping = Expr(Hexrays.cot_call, Type(kind="scalar", name="void"),
            x=Expr(Hexrays.cot_obj, obj_ea=0x4000),
            arguments=[Expr(Hexrays.cot_var, pointer, lvar_index=0)], ea=0x2050)
        helper.body.cblock.insert(0, Statement(Hexrays.cit_expr, escaping))
        result = selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=8)
        self.assertEqual(result["reason_code"],
            "helper_registration_prefix_state_unsupported")

        caller, helpers, resolve = helper_registration_fixture(8)
        helpers[0x2000].body.cblock.insert(0, Statement(Hexrays.cit_return,
            Expr(Hexrays.cot_num, Type(kind="scalar", name="NTSTATUS", size=4),
                number=0, ea=0x2050)))
        result = selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=8)
        self.assertEqual(result["reason_code"],
            "helper_registration_success_path_unsupported")

        caller, helpers, resolve = helper_registration_fixture(8, post_offset=0x50)
        helpers[0x4000].body.cblock.insert(0, Statement(Hexrays.cit_if))
        result = selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=8)
        self.assertEqual(result["reason_code"],
            "helper_registration_post_call_unproven")

        caller, helpers, resolve = helper_registration_fixture(8, post_offset=0x50)
        post = helpers[0x4000]
        outer = post.body.cblock[0].cexpr
        raw_type = post.get_lvars()[0].type
        nested_address = Expr(Hexrays.cot_add, raw_type,
            x=Expr(Hexrays.cot_var, raw_type, lvar_index=0),
            y=Expr(Hexrays.cot_num, raw_type, number=0xE0))
        nested_left = Expr(Hexrays.cot_ptr,
            Type(kind="pointer", name="PVOID", size=8), x=nested_address)
        outer.y = Expr(Hexrays.cot_asg, nested_left.type, x=nested_left,
            y=Expr(Hexrays.cot_obj, obj_ea=0x3001), ea=0x4018)
        result = selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=8)
        self.assertEqual(result["reason_code"],
            "helper_registration_post_call_unproven")

        caller, helpers, resolve = helper_registration_fixture(8, post_offset=0x50)
        post = helpers[0x4000]
        raw_type = post.get_lvars()[0].type
        address = Expr(Hexrays.cot_add, raw_type,
            x=Expr(Hexrays.cot_var, raw_type, lvar_index=0),
            y=Expr(Hexrays.cot_num, raw_type, number=0xE0))
        left = Expr(Hexrays.cot_ptr,
            Type(kind="pointer", name="PVOID", size=8), x=address)
        returned_write = Expr(Hexrays.cot_asg, left.type, x=left,
            y=Expr(Hexrays.cot_obj, obj_ea=0x3001), ea=0x4020)
        post.body.cblock.append(Statement(Hexrays.cit_return, returned_write))
        result = selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=8)
        self.assertEqual(result["reason_code"],
            "helper_registration_post_call_unproven")

    def test_helper_registration_binds_post_call_argument_position_and_fill_width(self):
        caller, helpers, resolve = helper_registration_fixture(8, post_offset=0x50)
        post_call = helpers[0x2000].body.cblock[1].cexpr
        post_call.a.insert(0, Expr(Hexrays.cot_num,
            Type(kind="scalar", name="int", size=4), number=0))
        result = selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=8)
        self.assertEqual(result["reason_code"],
            "helper_registration_post_call_unproven")

        caller, helpers, resolve = helper_registration_fixture(4)
        helpers[0x2000].body.cblock[0].cexpr.x.helper = "memset64"
        result = selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=4)
        self.assertEqual(result["reason_code"],
            "helper_registration_bulk_store_unsupported")

        caller, helpers, resolve = helper_registration_fixture(8)
        bulk = helpers[0x2000].body.cblock[0].cexpr
        original_base = bulk.a[0].x
        narrow_pointer = Type(kind="pointer", name="PDRIVER_OBJECT32", size=4,
            pointed=original_base.type.pointed)
        bulk.a[0].x = Expr(Hexrays.cot_cast, narrow_pointer, x=original_base)
        result = selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=8)
        self.assertEqual(result["reason_code"],
            "helper_registration_bulk_store_unsupported")

        caller, helpers, resolve = helper_registration_fixture(8)
        original = caller.body.cblock[0].creturn.expr.a[0]
        caller.body.cblock[0].creturn.expr.a[0] = Expr(Hexrays.cot_cast,
            Type(kind="scalar", name="uint32_t", size=4), x=original)
        self.assertIsNone(selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=8))

        caller, helpers, resolve = helper_registration_fixture(8)
        bulk = helpers[0x2000].body.cblock[0].cexpr
        bulk.a[1].type = Type(kind="scalar", name="uint32_t", size=4)
        result = selector_structure.collect_helper_driver_registration(
            caller, 0x800, Hexrays, Typeinf, resolve, helpers.get,
            device_control_index=0x0E, expected_pointer_width=8)
        self.assertEqual(result["reason_code"],
            "helper_registration_bulk_store_unsupported")

    def test_exact_struct_and_union_metadata_produces_the_binding(self):
        selector = expression()
        self.assertEqual(selector_structure.structural_selector_binding(
            selector, selector_cfunc(selector), Hexrays, Typeinf),
            selector_binding_expected())

    def test_rendered_text_and_renamed_member_cannot_produce_the_binding(self):
        misleading = Expr(Hexrays.cot_var, Type(kind="scalar", name="ULONG"),
            rendered="Parameters.DeviceIoControl.IoControlCode")
        self.assertIsNone(selector_structure.structural_selector_binding(
            misleading, selector_cfunc(expression()), Hexrays, Typeinf))
        renamed = expression(leaf_name="IoControlCodeRenamed")
        self.assertIsNone(selector_structure.structural_selector_binding(
            renamed, selector_cfunc(renamed), Hexrays, Typeinf))

    def test_cast_between_base_and_member_chain_fails_closed(self):
        cast = expression(cast=True)
        self.assertIsNone(selector_structure.structural_selector_binding(
            cast, selector_cfunc(cast), Hexrays, Typeinf))

    def test_unrelated_typed_global_cannot_become_a_selector_root(self):
        unrelated = expression()
        root = unrelated.x.x.x
        root.op, root.obj_ea, root.v = Hexrays.cot_obj, 0xDEADBEEF, None
        self.assertIsNone(selector_structure.structural_selector_binding(
            unrelated, selector_cfunc(unrelated), Hexrays, Typeinf))
        self.assertEqual(selector_structure.structural_selector_fact_producer(
            unrelated, selector_cfunc(unrelated), Hexrays, Typeinf), {
                "contract_id": "ida.driver-ioctl-selector-producer.v1",
                "version": 1,
                "status": "unsupported",
                "reason_code": "selector_root_provenance_unsupported",
                "source_ea": "0x1010",
            })

    def test_selector_root_provenance_is_exact_on_x86_x64_and_direct_irp_path(self):
        for pointer_width in (4, 8):
            selector = expression(pointer_width=pointer_width)
            cfunc = selector_cfunc(selector, pointer_width=pointer_width)
            self.assertEqual(selector_structure.structural_selector_binding(
                selector, cfunc, Hexrays, Typeinf),
                selector_binding_expected(pointer_width))
            current_stack = cfunc.body.cblock[0].cexpr.y
            direct = expression(pointer_width=pointer_width, root=current_stack)
            cfunc.body.cblock = [Statement(Hexrays.cit_expr, direct)]
            self.assertEqual(selector_structure.structural_selector_binding(
                direct, cfunc, Hexrays, Typeinf),
                selector_binding_expected(pointer_width,
                    root_kind="direct_member_path"))

    def test_named_selector_paths_with_noncanonical_offsets_or_width_stay_unsupported(self):
        for pointer_width in (4, 8):
            selector = expression(pointer_width=pointer_width)
            cfunc = selector_cfunc(selector, pointer_width=pointer_width)
            selector.x.x.m += 1
            selector.x.x.x.type.pointed.members[1].offset_bits += 8
            self.assertIsNone(selector_structure.structural_selector_binding(
                selector, cfunc, Hexrays, Typeinf))

            selector = expression(pointer_width=pointer_width)
            cfunc = selector_cfunc(selector, pointer_width=pointer_width)
            selector.x.x.type.members[1].offset_bits = 8
            self.assertIsNone(selector_structure.structural_selector_binding(
                selector, cfunc, Hexrays, Typeinf))

            selector = expression(pointer_width=pointer_width)
            cfunc = selector_cfunc(selector, pointer_width=pointer_width)
            selector.m += 1
            selector.x.type.members[2].offset_bits += 8
            self.assertIsNone(selector_structure.structural_selector_binding(
                selector, cfunc, Hexrays, Typeinf))

            selector = expression(pointer_width=pointer_width)
            cfunc = selector_cfunc(selector, pointer_width=pointer_width)
            wide = Type(kind="scalar", name="ULONG", size=8)
            selector.type = wide
            selector.x.type.members[2].type = wide
            self.assertIsNone(selector_structure.structural_selector_binding(
                selector, cfunc, Hexrays, Typeinf))

    def test_named_irp_current_stack_prefix_with_noncanonical_offsets_is_unsupported(self):
        for pointer_width in (4, 8):
            for component in range(3):
                selector = expression(pointer_width=pointer_width)
                cfunc = selector_cfunc(selector, pointer_width=pointer_width)
                current = cfunc.body.cblock[0].cexpr.y
                expressions = [current.x.x, current.x, current]
                members = [current.x.x.x.type.pointed.members[0],
                    current.x.x.type.members[0], current.x.type.members[0]]
                expressions[component].m += 1
                members[component].offset_bits += 8
                self.assertIsNone(selector_structure.structural_selector_binding(
                    selector, cfunc, Hexrays, Typeinf))

    def test_fake_stack_helper_cast_alias_and_mutation_cannot_prove_selector_root(self):
        selector = expression()
        cfunc = selector_cfunc(selector)
        definition = cfunc.body.cblock[0].cexpr
        definition.y = Expr(Hexrays.cot_obj, definition.y.type,
            obj_ea=0xDEADBEEF, ea=0x1004)
        self.assertIsNone(selector_structure.structural_selector_binding(
            selector, cfunc, Hexrays, Typeinf))

        for rhs in (
            Expr(Hexrays.cot_call, definition.y.type,
                x=Expr(Hexrays.cot_obj, obj_ea=0x2000), arguments=[], ea=0x1004),
            Expr(Hexrays.cot_cast, definition.y.type,
                x=selector_cfunc(selector).body.cblock[0].cexpr.y, ea=0x1004),
        ):
            candidate = selector_cfunc(selector)
            candidate.body.cblock[0].cexpr.y = rhs
            self.assertIsNone(selector_structure.structural_selector_binding(
                selector, candidate, Hexrays, Typeinf))

        stack_type = selector.x.x.x.type
        alias = Expr(Hexrays.cot_asg, stack_type,
            x=Expr(Hexrays.cot_var, stack_type, lvar_index=5),
            y=Expr(Hexrays.cot_var, stack_type, lvar_index=4), ea=0x1008)
        aliased = selector_cfunc(selector,
            before_selector=[Statement(Hexrays.cit_expr, alias)])
        self.assertIsNone(selector_structure.structural_selector_binding(
            selector, aliased, Hexrays, Typeinf))

        mutation = Expr(Hexrays.cot_asgadd, stack_type,
            x=Expr(Hexrays.cot_var, stack_type, lvar_index=4),
            y=Expr(Hexrays.cot_num, Type(kind="scalar", name="int"), number=1),
            ea=0x1008)
        mutated = selector_cfunc(selector,
            before_selector=[Statement(Hexrays.cit_expr, mutation)])
        self.assertIsNone(selector_structure.structural_selector_binding(
            selector, mutated, Hexrays, Typeinf))

    def test_irp_mutation_and_competing_selector_root_fail_closed(self):
        selector = expression()
        cfunc = selector_cfunc(selector)
        irp_type = cfunc.get_lvars()[1].type
        irp_mutation = Expr(Hexrays.cot_preinc, irp_type,
            x=Expr(Hexrays.cot_var, irp_type, lvar_index=1), ea=0x1002)
        mutated = selector_cfunc(selector,
            prefix=[Statement(Hexrays.cit_expr, irp_mutation)])
        self.assertIsNone(selector_structure.structural_selector_binding(
            selector, mutated, Hexrays, Typeinf))

        other_root = Expr(Hexrays.cot_var, selector.x.x.x.type, lvar_index=5,
            ea=0x1009)
        competing_selector = expression(root=other_root)
        competing = selector_cfunc(selector,
            statements=[Statement(Hexrays.cit_expr, competing_selector)])
        self.assertIsNone(selector_structure.structural_selector_binding(
            selector, competing, Hexrays, Typeinf))

    def test_irp_current_stack_prefix_and_alternate_writes_fail_closed_x86_x64(self):
        for pointer_width in (4, 8):
            for prefix_depth in (1, 2, 3):
                selector = expression(pointer_width=pointer_width)
                cfunc = selector_cfunc(selector, pointer_width=pointer_width)
                current = cfunc.body.cblock[0].cexpr.y
                left = {1: current.x.x, 2: current.x, 3: current}[prefix_depth]
                overwrite = Expr(Hexrays.cot_asg, left.type, x=left,
                    y=Expr(Hexrays.cot_var, left.type, lvar_index=6), ea=0x1003)
                cfunc.body.cblock.insert(0, Statement(Hexrays.cit_expr, overwrite))
                self.assertIsNone(selector_structure.structural_selector_binding(
                    selector, cfunc, Hexrays, Typeinf))

            selector = expression(pointer_width=pointer_width)
            cfunc = selector_cfunc(selector, pointer_width=pointer_width)
            irp_type = cfunc.get_lvars()[1].type
            byte_pointer = Type(kind="pointer", name="PCHAR", size=pointer_width,
                pointed=Type(kind="scalar", name="CHAR", size=1))
            derived = Expr(Hexrays.cot_add, byte_pointer,
                x=Expr(Hexrays.cot_cast, byte_pointer,
                    x=Expr(Hexrays.cot_var, irp_type, lvar_index=1)),
                y=Expr(Hexrays.cot_num,
                    Type(kind="scalar", name="size_t", size=pointer_width), number=1))
            alternate_left = Expr(Hexrays.cot_ptr,
                Type(kind="scalar", name="ULONG_PTR", size=pointer_width), x=derived)
            alternate = Expr(Hexrays.cot_asg, alternate_left.type, x=alternate_left,
                y=Expr(Hexrays.cot_num, alternate_left.type, number=0), ea=0x1003)
            cfunc.body.cblock.insert(0, Statement(Hexrays.cit_expr, alternate))
            self.assertIsNone(selector_structure.structural_selector_binding(
                selector, cfunc, Hexrays, Typeinf))

    def test_conditional_and_loop_nested_stack_definitions_never_prove_dominance(self):
        for pointer_width in (4, 8):
            for container_op in (Hexrays.cot_tern, Hexrays.cot_land, Hexrays.cot_lor):
                selector = expression(pointer_width=pointer_width)
                cfunc = selector_cfunc(selector, pointer_width=pointer_width)
                definition = cfunc.body.cblock[0].cexpr
                condition = Expr(Hexrays.cot_var,
                    Type(kind="scalar", name="bool"), lvar_index=7)
                container = Expr(container_op, definition.type, x=condition,
                    y=definition,
                    z=Expr(Hexrays.cot_num, definition.type, number=0), ea=0x1005)
                cfunc.body.cblock[0] = Statement(Hexrays.cit_expr, container)
                self.assertIsNone(selector_structure.structural_selector_binding(
                    selector, cfunc, Hexrays, Typeinf))

            for statement_op in (Hexrays.cit_if, Hexrays.cit_switch,
                                 Hexrays.cit_for, Hexrays.cit_while, Hexrays.cit_do):
                selector = expression(pointer_width=pointer_width)
                cfunc = selector_cfunc(selector, pointer_width=pointer_width)
                definition = cfunc.body.cblock[0].cexpr
                cfunc.body.cblock[0] = Statement(statement_op, definition)
                self.assertIsNone(selector_structure.structural_selector_binding(
                    selector, cfunc, Hexrays, Typeinf))

    def test_suffix_mutation_with_backedge_cannot_reach_a_later_selector_iteration(self):
        for pointer_width in (4, 8):
            selector = expression(pointer_width=pointer_width)
            cfunc = selector_cfunc(selector, pointer_width=pointer_width)
            stack_type = selector.x.x.x.type
            mutation = Expr(Hexrays.cot_asgadd, stack_type,
                x=Expr(Hexrays.cot_var, stack_type, lvar_index=4),
                y=Expr(Hexrays.cot_num,
                    Type(kind="scalar", name="int"), number=1), ea=0x1020)
            cfunc.body.cblock.extend([
                Statement(Hexrays.cit_expr, mutation),
                Statement(Hexrays.cit_goto),
            ])
            self.assertIsNone(selector_structure.structural_selector_binding(
                selector, cfunc, Hexrays, Typeinf))

            selector = expression(pointer_width=pointer_width)
            cfunc = selector_cfunc(selector, pointer_width=pointer_width)
            current = cfunc.body.cblock[0].cexpr.y
            indexed_left = Expr(Hexrays.cot_idx, current.type, x=current,
                y=Expr(Hexrays.cot_var, Type(kind="scalar", name="int"), lvar_index=6))
            dynamic = Expr(Hexrays.cot_asg, current.type, x=indexed_left,
                y=Expr(Hexrays.cot_num, current.type, number=0), ea=0x1003)
            cfunc.body.cblock.insert(0, Statement(Hexrays.cit_expr, dynamic))
            self.assertIsNone(selector_structure.structural_selector_binding(
                selector, cfunc, Hexrays, Typeinf))

    def test_direct_driver_entry_registration_binds_original_argument_and_rhs(self):
        scan = registration_scan(registration_cfunc())
        self.assertEqual(scan["status"], "complete")
        self.assertEqual(scan["registrations"], [{
            "schema_version": "driver-entry-registration-proof/1",
            "driver_entry_ea": "0x800",
            "assignment_ea": "0x900",
            "base_argument_index": 0,
            "base_lvar_index": 3,
            "base_type_kind": "plain_pointer_to_driver_object_udt",
            "base_pointee_type_name": "_DRIVER_OBJECT",
            "member_name": "MajorFunction",
            "member_offset_bytes": 0x70,
            "major_function_index": 0x0E,
            "pointer_width_bytes": 8,
            "target_architecture_bits": 64,
            "derived_slot_offset_bytes": 0xE0,
            "rhs_target_ea": "0x1000",
            "top_level_unconditional": True,
        }])

    def test_x86_slot_is_derived_from_typed_member_offset_and_pointer_width(self):
        producer = registration_scan(registration_cfunc(pointer_width=4))
        registration = producer["registrations"][0]
        self.assertEqual(registration["pointer_width_bytes"], 4)
        self.assertEqual(registration["member_offset_bytes"], 0x38)
        self.assertEqual(registration["derived_slot_offset_bytes"], 0x70)
        projection = json.loads((Path(__file__).resolve().parent / "fixtures"
            / "driver_ioctl_selector_projection.json").read_text())
        candidate = projection["structuredContent"]["candidates"][0]
        candidate["selector_binding"]["root_provenance"]["pointer_width_bytes"] = 4
        candidate["selector_binding"]["root_provenance"]["target_architecture_bits"] = 32
        candidate["selector_binding"]["root_provenance"][
            "current_stack_member_offsets_bytes"] = [0x40, 0, 0x20]
        candidate["selector_binding"]["selector_member_offsets_bytes"] = [4, 0, 8]
        fact = selector_structure.build_ioctl_selector_fact(
            producer, candidate, device_control_code=0x0E)
        self.assertEqual(fact["operation_discriminator"]["source"], registration)

    def test_named_major_function_with_noncanonical_layout_is_unsupported(self):
        for pointer_width, wrong_offset in ((4, 0x10), (8, 0x10)):
            cfunc = registration_cfunc(pointer_width=pointer_width)
            assignment = cfunc.body.cblock[0].cexpr
            assignment.x.x.m = wrong_offset
            assignment.x.x.x.type.pointed.members[1].offset_bits = wrong_offset * 8
            scan = registration_scan(cfunc)
            self.assertEqual(scan["status"], "unsupported")
            self.assertEqual(scan["reason_code"],
                "typed_major_function_registration_form_unsupported")
            short = registration_cfunc(pointer_width=pointer_width)
            member_type = short.body.cblock[0].cexpr.x.x.type
            member_type.count = 14
            member_type.size = 14 * pointer_width
            scan = registration_scan(short)
            self.assertEqual(scan["status"], "unsupported")

    def test_type_pointer_width_must_match_captured_database_architecture(self):
        for pointer_width, wrong_width in ((8, 4), (4, 8)):
            cfunc = registration_cfunc(pointer_width=pointer_width)
            scan = selector_structure.collect_driver_entry_registrations(
                cfunc, 0x800, Hexrays, Typeinf,
                lambda ea: ea if ea == 0x1000 else None,
                device_control_index=0x0E,
                expected_pointer_width=wrong_width)
            self.assertEqual(scan["status"], "unsupported")
            selector = expression(pointer_width=pointer_width)
            dispatch = selector_cfunc(selector, pointer_width=pointer_width)
            self.assertIsNone(selector_structure.structural_selector_binding(
                selector, dispatch, Hexrays, Typeinf, wrong_width))

    def test_unrelated_offset_index_and_unreachable_writes_stay_unknown(self):
        cases = [
            registration_cfunc(base_lvar=2),
            registration_cfunc(index=0x0F),
            registration_cfunc(after_return=True),
            registration_cfunc(member_name="PrivateCallbackAtSameOffset"),
        ]
        for cfunc in cases:
            scan = registration_scan(cfunc)
            self.assertEqual(scan["status"], "complete")
            self.assertEqual(scan["registrations"], [])

    def test_exact_slot_write_with_unbound_rhs_is_typed_unsupported(self):
        for cfunc in (registration_cfunc(right_kind=Hexrays.cot_var),
                      registration_cfunc(rhs=0x1001)):
            scan = registration_scan(cfunc)
            self.assertEqual(scan["status"], "unsupported")
            self.assertEqual(scan["reason_code"],
                "typed_major_function_registration_form_unsupported")

    def test_explicit_typed_registration_form_unsupported_differs_from_partial(self):
        unsupported = registration_scan(registration_cfunc(member_type="scalar"))
        self.assertEqual(unsupported["status"], "unsupported")
        self.assertEqual(unsupported["reason_code"],
            "typed_major_function_registration_form_unsupported")
        partial = registration_scan(Cfunc([], Type(kind="scalar", name="not_pointer"),
            argidx=()))
        self.assertEqual(partial["status"], "partial")
        self.assertEqual(partial["reason_code"],
            "driver_entry_argument_identity_unavailable")

    def test_expired_scan_downgrades_tentative_unsupported_to_partial(self):
        tentative = registration_scan(registration_cfunc(member_type="scalar"))
        self.assertEqual(tentative["status"], "unsupported")
        expired = selector_structure.finalize_registration_scan(
            tentative, expired=True)
        self.assertEqual(expired, {
            "contract_id": "ida.driver-trigger-registration-producer.v1",
            "version": 1,
            "driver_entry_ea": "0x800",
            "status": "partial",
            "reason_code": "driver_entry_registration_scan_timeout",
            "registrations": [],
        })

    def test_complete_helper_conditional_and_cast_forms_are_typed_unsupported(self):
        for reason in (
            "helper_registration_form_unsupported",
            "conditional_registration_form_unsupported",
            "cast_registration_form_unsupported",
        ):
            scan = registration_scan(registration_cfunc(conditional=True), [reason])
            self.assertEqual(scan["status"], "unsupported")
            self.assertEqual(scan["reason_code"], reason)
        cast_assignment = registration_cfunc(cast=True).body.cblock[0].cexpr
        self.assertEqual(selector_structure.registration_slot_write_form(
            cast_assignment, 3, Hexrays, Typeinf,
            lambda ea: ea if ea == 0x1000 else None,
            device_control_index=0x0E), "cast")
        rhs_cast_assignment = registration_cfunc(rhs_cast=True).body.cblock[0].cexpr
        self.assertEqual(selector_structure.registration_slot_write_form(
            rhs_cast_assignment, 3, Hexrays, Typeinf,
            lambda ea: ea if ea == 0x1000 else None,
            device_control_index=0x0E), "cast")

    def test_multiple_direct_registration_assignments_are_typed_unsupported(self):
        first = registration_cfunc()
        second = registration_cfunc()
        ambiguous = Cfunc([first.body.cblock[0], second.body.cblock[0]],
            first.get_lvars()[3].type)
        scan = registration_scan(ambiguous)
        self.assertEqual(scan["status"], "unsupported")
        self.assertEqual(scan["reason_code"],
            "ambiguous_registration_form_unsupported")

    def test_original_argument_rebind_before_direct_assignment_is_unsupported(self):
        direct = registration_cfunc()
        pointer = direct.get_lvars()[3].type
        rebind = Expr(Hexrays.cot_asg, pointer,
            x=Expr(Hexrays.cot_var, pointer, lvar_index=3),
            y=Expr(Hexrays.cot_var, pointer, lvar_index=2), ea=0x880)
        cfunc = Cfunc([Statement(Hexrays.cit_expr, rebind), direct.body.cblock[0]], pointer)
        scan = registration_scan(cfunc)
        self.assertEqual(scan["status"], "unsupported")
        self.assertEqual(scan["reason_code"],
            "driver_object_argument_rebound_unsupported")

    def test_original_argument_alias_and_address_escape_are_unsupported(self):
        direct = registration_cfunc()
        pointer = direct.get_lvars()[3].type
        for right in (
            Expr(Hexrays.cot_var, pointer, lvar_index=3),
            Expr(Hexrays.cot_cast, pointer,
                 x=Expr(Hexrays.cot_var, pointer, lvar_index=3)),
        ):
            alias = Expr(Hexrays.cot_asg, pointer,
                x=Expr(Hexrays.cot_var, pointer, lvar_index=6), y=right, ea=0x880)
            scan = registration_scan(Cfunc([Statement(Hexrays.cit_expr, alias),
                direct.body.cblock[0]], pointer))
            self.assertEqual(scan["reason_code"],
                "driver_object_alias_unsupported")
        address = Expr(Hexrays.cot_ref, pointer,
            x=Expr(Hexrays.cot_var, pointer, lvar_index=3), ea=0x880)
        scan = registration_scan(Cfunc([Statement(Hexrays.cit_expr, address),
            direct.body.cblock[0]], pointer))
        self.assertEqual(scan["reason_code"],
            "driver_object_address_escape_unsupported")

    def test_comma_and_ternary_results_cannot_create_an_original_argument_alias(self):
        direct = registration_cfunc()
        pointer = direct.get_lvars()[3].type
        def original():
            return Expr(Hexrays.cot_var, pointer, lvar_index=3)

        def other():
            return Expr(Hexrays.cot_var, pointer, lvar_index=2)
        for right in (
            Expr(Hexrays.cot_comma, pointer, x=other(), y=original()),
            Expr(Hexrays.cot_cast, pointer,
                x=Expr(Hexrays.cot_comma, pointer, x=other(), y=original())),
            Expr(Hexrays.cot_tern, pointer, x=other(), y=original(), z=other()),
            Expr(Hexrays.cot_tern, pointer, x=other(), y=other(), z=original()),
        ):
            alias = Expr(Hexrays.cot_asg, pointer,
                x=Expr(Hexrays.cot_var, pointer, lvar_index=6), y=right, ea=0x880)
            scan = registration_scan(Cfunc([Statement(Hexrays.cit_expr, alias),
                direct.body.cblock[0]], pointer))
            self.assertEqual(scan["reason_code"],
                "driver_object_alias_unsupported")

    def test_every_sdk_compound_and_prepost_write_rebinds_the_original_argument(self):
        for pointer_width in (4, 8):
            direct = registration_cfunc(pointer_width=pointer_width)
            pointer = direct.get_lvars()[3].type
            mutation_ops = [op for op in (
                Hexrays.cot_asgbor, Hexrays.cot_asgxor, Hexrays.cot_asgband,
                Hexrays.cot_asgadd, Hexrays.cot_asgsub, Hexrays.cot_asgmul,
                Hexrays.cot_asgsshr, Hexrays.cot_asgushr, Hexrays.cot_asgshl,
                Hexrays.cot_asgsdiv, Hexrays.cot_asgudiv, Hexrays.cot_asgsmod,
                Hexrays.cot_asgumod)]
            for op in mutation_ops:
                mutation = Expr(op, pointer,
                    x=Expr(Hexrays.cot_var, pointer, lvar_index=3),
                    y=Expr(Hexrays.cot_num, pointer, number=1), ea=0x880)
                scan = registration_scan(Cfunc([Statement(Hexrays.cit_expr, mutation),
                    direct.body.cblock[0]], pointer))
                self.assertEqual(scan["reason_code"],
                    "driver_object_argument_rebound_unsupported")
            for op in (Hexrays.cot_postinc, Hexrays.cot_postdec,
                       Hexrays.cot_preinc, Hexrays.cot_predec):
                mutation = Expr(op, pointer,
                    x=Expr(Hexrays.cot_var, pointer, lvar_index=3), ea=0x880)
                scan = registration_scan(Cfunc([Statement(Hexrays.cit_expr, mutation),
                    direct.body.cblock[0]], pointer))
                self.assertEqual(scan["reason_code"],
                    "driver_object_argument_rebound_unsupported")

    def test_direct_assignment_plus_helper_or_cast_competitor_is_unsupported(self):
        direct = registration_cfunc()
        pointer = direct.get_lvars()[3].type
        helper = Expr(Hexrays.cot_call, Type(kind="scalar", name="NTSTATUS"),
            x=Expr(Hexrays.cot_obj, obj_ea=0x1100),
            arguments=[Expr(Hexrays.cot_var, pointer, lvar_index=3)], ea=0x980)
        helper_cfunc = Cfunc([direct.body.cblock[0],
            Statement(Hexrays.cit_expr, helper)], pointer)
        helper_scan = registration_scan(helper_cfunc)
        self.assertEqual(helper_scan["status"], "unsupported")
        self.assertEqual(helper_scan["reason_code"],
            "post_registration_driver_object_escape_unsupported")
        cast = registration_cfunc(rhs_cast=True)
        cast_cfunc = Cfunc([direct.body.cblock[0], cast.body.cblock[0]], pointer)
        cast_scan = registration_scan(cast_cfunc)
        self.assertEqual(cast_scan["status"], "unsupported")
        self.assertEqual(cast_scan["reason_code"], "cast_registration_form_unsupported")
        double_cast = registration_cfunc(cast=True)
        double_cast_expr = double_cast.body.cblock[0].cexpr
        base = double_cast_expr.x.x.x
        double_cast_expr.x.x.x = Expr(Hexrays.cot_cast, pointer, x=base)
        double_cast_scan = registration_scan(Cfunc([direct.body.cblock[0],
            double_cast.body.cblock[0]], pointer))
        self.assertEqual(double_cast_scan["reason_code"],
            "cast_registration_form_unsupported")

    def test_direct_assignment_plus_unknown_or_dynamic_slot_overwrite_is_unsupported(self):
        direct = registration_cfunc()
        pointer = direct.get_lvars()[3].type
        for rhs in (
            Expr(Hexrays.cot_num, Type(kind="scalar", name="int", size=4), number=0),
            Expr(Hexrays.cot_var, pointer, lvar_index=2),
        ):
            overwrite = registration_cfunc()
            overwrite_expr = overwrite.body.cblock[0].cexpr
            overwrite_expr.y, overwrite_expr.ea = rhs, 0x980
            scan = registration_scan(Cfunc([direct.body.cblock[0],
                overwrite.body.cblock[0]], pointer))
            self.assertEqual(scan["status"], "unsupported")
            self.assertEqual(scan["reason_code"],
                "typed_major_function_registration_form_unsupported")
        dynamic = registration_cfunc()
        dynamic_expr = dynamic.body.cblock[0].cexpr
        dynamic_expr.x.y = Expr(Hexrays.cot_var,
            Type(kind="scalar", name="int", size=4), lvar_index=2)
        dynamic_expr.ea = 0x980
        scan = registration_scan(Cfunc([direct.body.cblock[0],
            dynamic.body.cblock[0]], pointer))
        self.assertEqual(scan["status"], "unsupported")
        self.assertEqual(scan["reason_code"],
            "ambiguous_registration_form_unsupported")

    def test_direct_assignment_plus_compound_or_prepost_slot_update_is_unsupported(self):
        direct = registration_cfunc()
        pointer = direct.get_lvars()[3].type
        for op in (Hexrays.cot_asgadd, Hexrays.cot_asgsub,
                   Hexrays.cot_preinc, Hexrays.cot_postdec):
            update = registration_cfunc()
            update_expr = update.body.cblock[0].cexpr
            update_expr.op, update_expr.ea = op, 0x980
            if Hexrays.is_prepost(op):
                update_expr.y = None
            else:
                update_expr.y = Expr(Hexrays.cot_num,
                    Type(kind="scalar", name="int", size=4), number=1)
            scan = registration_scan(Cfunc([direct.body.cblock[0],
                update.body.cblock[0]], pointer))
            self.assertEqual(scan["status"], "unsupported")
            self.assertEqual(scan["reason_code"],
                "typed_major_function_registration_form_unsupported")

    def test_direct_assignment_plus_pointer_arithmetic_slot_write_is_unsupported(self):
        direct = registration_cfunc()
        pointer = direct.get_lvars()[3].type
        byte_pointer = Type(kind="pointer", name="PCHAR", size=8,
            pointed=Type(kind="scalar", name="CHAR", size=1))
        derived = Expr(Hexrays.cot_add, byte_pointer,
            x=Expr(Hexrays.cot_cast, byte_pointer,
                x=Expr(Hexrays.cot_var, pointer, lvar_index=3)),
            y=Expr(Hexrays.cot_num, Type(kind="scalar", name="size_t", size=8),
                number=0xE0))
        left = Expr(Hexrays.cot_ptr,
            Type(kind="pointer", name="PDRIVER_DISPATCH", size=8),
            x=Expr(Hexrays.cot_cast,
                Type(kind="pointer", name="PPDRIVER_DISPATCH", size=8), x=derived))
        alternate = Expr(Hexrays.cot_asg, left.type, x=left,
            y=Expr(Hexrays.cot_num, Type(kind="scalar", name="int", size=4), number=0),
            ea=0x980)
        scan = registration_scan(Cfunc([direct.body.cblock[0],
            Statement(Hexrays.cit_expr, alternate)], pointer))
        self.assertEqual(scan["status"], "unsupported")
        self.assertEqual(scan["reason_code"],
            "ambiguous_registration_form_unsupported")

    def test_arithmetic_derived_driver_object_alias_is_unsupported_on_x86_x64(self):
        for pointer_width in (4, 8):
            direct = registration_cfunc(pointer_width=pointer_width)
            pointer = direct.get_lvars()[3].type
            alias = Expr(Hexrays.cot_asg, pointer,
                x=Expr(Hexrays.cot_var, pointer, lvar_index=6),
                y=Expr(Hexrays.cot_add, pointer,
                    x=Expr(Hexrays.cot_var, pointer, lvar_index=3),
                    y=Expr(Hexrays.cot_num,
                        Type(kind="scalar", name="size_t", size=pointer_width), number=1)),
                ea=0x880)
            scan = registration_scan(Cfunc([Statement(Hexrays.cit_expr, alias),
                direct.body.cblock[0]], pointer))
            self.assertEqual(scan["status"], "unsupported")
            self.assertEqual(scan["reason_code"],
                "driver_object_alias_unsupported")

    def test_documented_external_before_registration_is_read_only_but_after_is_escape(self):
        direct = registration_cfunc()
        pointer = direct.get_lvars()[3].type
        def external(ea):
            return ea == 0x2000
        call = Expr(Hexrays.cot_call, Type(kind="scalar", name="NTSTATUS"),
            x=Expr(Hexrays.cot_obj, obj_ea=0x2000),
            arguments=[Expr(Hexrays.cot_var, pointer, lvar_index=3)], ea=0x700)
        before = Cfunc([Statement(Hexrays.cit_expr, call), direct.body.cblock[0]], pointer)
        result = selector_structure.collect_driver_entry_registrations(
            before, 0x800, Hexrays, Typeinf,
            lambda ea: ea if ea == 0x1000 else None, device_control_index=0x0E,
            expected_pointer_width=8,
            documented_external_call=external)
        self.assertEqual(result["status"], "complete")
        call.ea = 0x980
        after = Cfunc([direct.body.cblock[0], Statement(Hexrays.cit_expr, call)], pointer)
        result = selector_structure.collect_driver_entry_registrations(
            after, 0x800, Hexrays, Typeinf,
            lambda ea: ea if ea == 0x1000 else None, device_control_index=0x0E,
            expected_pointer_width=8,
            documented_external_call=external)
        self.assertEqual(result["status"], "unsupported")

    def test_registration_call_order_is_structural_not_machine_ea_order(self):
        for pointer_width in (4, 8):
            pointer = registration_cfunc(pointer_width=pointer_width).get_lvars()[3].type
            before = Expr(Hexrays.cot_call, Type(kind="scalar", name="NTSTATUS"),
                x=Expr(Hexrays.cot_obj, obj_ea=0x2000),
                arguments=[Expr(Hexrays.cot_var, pointer, lvar_index=3)], ea=0x900)
            later_lower_ea = Expr(Hexrays.cot_call,
                Type(kind="scalar", name="NTSTATUS"),
                x=Expr(Hexrays.cot_obj, obj_ea=0x2000),
                arguments=[Expr(Hexrays.cot_var, pointer, lvar_index=3)], ea=0x100)
            self.assertTrue(selector_structure.call_is_proven_pre_registration(
                ExpressionProxy(before), [before]))
            self.assertFalse(selector_structure.call_is_proven_pre_registration(
                later_lower_ea, [before]))
            self.assertIsNone(selector_structure.lvar_definition_hazard(
                before, 3, Hexrays, lambda ea: ea == 0x2000,
                after_registration=False))
            self.assertEqual(selector_structure.lvar_definition_hazard(
                later_lower_ea, 3, Hexrays, lambda ea: ea == 0x2000,
                after_registration=True),
                "post_registration_driver_object_escape_unsupported")

    def test_documented_external_result_assignment_before_registration_is_not_aliasing(self):
        direct = registration_cfunc()
        pointer = direct.get_lvars()[3].type
        call = Expr(Hexrays.cot_call, Type(kind="scalar", name="NTSTATUS"),
            x=Expr(Hexrays.cot_obj, obj_ea=0x2000),
            arguments=[Expr(Hexrays.cot_var, pointer, lvar_index=3)], ea=0x700)
        status_assignment = Expr(Hexrays.cot_asg, Type(kind="scalar", name="NTSTATUS"),
            x=Expr(Hexrays.cot_var, Type(kind="scalar", name="NTSTATUS"), lvar_index=7),
            y=call, ea=0x700)
        cfunc = Cfunc([Statement(Hexrays.cit_expr, status_assignment),
            direct.body.cblock[0]], pointer)
        result = selector_structure.collect_driver_entry_registrations(
            cfunc, 0x800, Hexrays, Typeinf,
            lambda ea: ea if ea == 0x1000 else None, device_control_index=0x0E,
            expected_pointer_width=8,
            documented_external_call=lambda ea: ea == 0x2000)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(len(result["registrations"]), 1)

    def test_deep_cycle_safe_lvar_walk_has_no_depth_cutoff(self):
        pointer = registration_cfunc().get_lvars()[3].type
        value = Expr(Hexrays.cot_var, pointer, lvar_index=3)
        for _ in range(96):
            value = Expr(Hexrays.cot_cast, pointer, x=value)
        self.assertTrue(selector_structure.expression_contains_lvar(value, 3, Hexrays))
        value.x = value
        self.assertFalse(selector_structure.expression_contains_lvar(value, 4, Hexrays))

    def test_shared_projection_is_built_from_the_exact_structural_binding(self):
        projection = json.loads((Path(__file__).resolve().parent / "fixtures"
            / "driver_ioctl_selector_projection.json").read_text())
        candidate = projection["structuredContent"]["candidates"][0]
        selector = expression()
        self.assertEqual(selector_structure.structural_selector_binding(
            selector, selector_cfunc(selector), Hexrays, Typeinf),
            candidate["selector_binding"])
        producer = registration_scan(registration_cfunc())
        self.assertEqual(selector_structure.build_ioctl_selector_fact(
            producer, candidate, device_control_code=0x0E),
            candidate["selector_fact"])
        self.assertIsNone(selector_structure.build_ioctl_selector_fact(
            producer, {**candidate, "method_detail": "immediate"},
            device_control_code=0x0E))


if __name__ == "__main__":
    unittest.main()
