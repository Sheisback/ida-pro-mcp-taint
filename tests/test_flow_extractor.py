"""Strict adapter boundaries and actual two-anchor extraction receipts."""

import importlib.util
import json
import re
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from ida_pro_mcp.flow_core import ContractError, canonical_json, digest
from ida_pro_mcp.flow_core.contracts import (
    Block,
    Diagnostic,
    FunctionInput,
    Operand,
    Snapshot,
    Site,
)
from ida_pro_mcp.flow_core.summaries import (
    ReturnEffect,
    ReviewedSummary,
    SummaryCatalog,
    SummaryIdentity,
)
from ida_pro_mcp.flow_core.states import StorageLocation

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "src/ida_pro_mcp/ida_mcp/flow/extractor.py"
SPEC = importlib.util.spec_from_file_location("pure_extractor_test", PATH)
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)
CATALOG_PATH = ROOT / "src/ida_pro_mcp/ida_mcp/flow/summary_catalog.py"
CATALOG_SPEC = importlib.util.spec_from_file_location(
    "pure_summary_catalog_test", CATALOG_PATH
)
catalog_adapter = importlib.util.module_from_spec(CATALOG_SPEC)
CATALOG_SPEC.loader.exec_module(catalog_adapter)
MANIFESTS = ROOT / "tests/flow_fixtures/manifests"


def read(name):
    return json.loads((MANIFESTS / name).read_text())


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


@pytest.mark.parametrize("anchor", ["x64", "a64"])
def test_real_extraction_roundtrip_and_single_lifting(anchor):
    receipt = read("extraction_" + anchor + ".json")
    # These are immutable historical G005 receipts. New G011 receipts below pin
    # the current extractor; changing adapter code must not relabel old evidence.
    assert re.fullmatch(r"[0-9a-f]{64}", receipt["extractor_sha256"])
    snapshot = Snapshot.from_data(receipt["snapshot"])
    assert digest(snapshot) == receipt["canonical_digest"]
    assert Snapshot.from_json(canonical_json(snapshot)) == snapshot
    assert (
        receipt["repeat_equal"]
        and receipt["roundtrip_equal"]
        and receipt["namespace_isolated"]
    )
    assert receipt["target_executed"] is False
    p0_receipt = read(anchor + ".json")
    assert (
        snapshot.identity.binary_digest == "sha256-v1:" + p0_receipt["binary"]["sha256"]
    )
    p0 = p0_receipt["probes"][0]

    def check_sites(block_index, instruction_index, operands, parent=()):
        for index, operand in enumerate(operands):
            path = parent + (index,)
            snapshot.validate_site(Site(block_index, instruction_index, path))
            children = operand.children
            if operand.call is not None:
                children = operand.call.arguments + operand.call.return_operands
            check_sites(block_index, instruction_index, children, path)

    for block in snapshot.function.blocks:
        for instruction in block.instructions:
            check_sites(block.index, instruction.index, instruction.operands)
    assert snapshot.identity.maturity == "MMAT_CALLS"
    assert len(snapshot.function.blocks) == p0["block_count"]
    assert (
        sum(len(b.instructions) for b in snapshot.function.blocks)
        == p0["instruction_count"]
    )
    counts = Counter()
    for node in walk(snapshot.function.to_data()):
        if "opcode" in node:
            counts[node["opcode"]] += 1
        if node.get("kind") == "expression":
            counts[node["operation"]] += 1
        if node.get("kind") == "void":
            assert node["width_bits"] is None
        if node.get("kind") == "callinfo":
            call = node["call"]
            assert call["arguments"] and call["spoiled_locations"]["register_bytes"]
            assert call["return_type_code"] > 0
            assert call["unresolved"]
    assert dict(counts) == p0["opcode_counts"]  # No duplicate ISA effects.
    eas = {
        ea
        for b in snapshot.function.blocks
        for i in b.instructions
        for ea in i.source_eas
    }
    assert set(p0["source_map"]["unique_eas"]) <= eas
    assert {d.code for d in snapshot.function.diagnostics} == {
        "call_effects_unresolved",
        "chains_not_serialized",
        "native_origins_incomplete",
    }
    rebuilt = adapter.make_snapshot(
        snapshot.function,
        snapshot.identity.environment,
        receipt["profile"],
        snapshot.identity.namespace,
        snapshot.identity.binary_digest.split(":")[1],
    )
    assert rebuilt == snapshot
    for key, value in [
        ("namespace", "other-owner"),
        ("maturity", "MMAT_GLBOPT3"),
        ("profile_digest", digest({"other": True})),
        ("function_id", "other-function"),
    ]:
        assert (
            replace(snapshot.identity, **{key: value}).snapshot_id
            != snapshot.snapshot_id
        )


def test_core_void_and_cfg_negative_contracts():
    assert Operand.from_data(Operand("void", None).to_data()).width_bits is None
    with pytest.raises(ContractError):
        Operand("void", 8)
    with pytest.raises(ContractError):
        Operand("constant", None, constant=0)
    with pytest.raises(ContractError):
        FunctionInput("f", 0, (Block(0, (), (), (1,)), Block(1, (), ())))
    with pytest.raises(ContractError):
        FunctionInput("f", 0, (Block(0, (), ()), Block(1, (0,), ())))
    with pytest.raises(ContractError):
        Operand("unknown", None)
    with pytest.raises(ContractError):
        FunctionInput(
            "f",
            0,
            (Block(0, (), ()),),
            (Diagnostic("z", "last"), Diagnostic("a", "first")),
        )
    bad = Operand("void", None).to_data()
    bad["role"] = "guess"
    with pytest.raises(ContractError):
        Operand.from_data(bad)
    assert FunctionInput("f", 0, (Block(0, (), (), (1,)), Block(1, (0,), ()))).blocks[
        0
    ].successors == (1,)


def test_main_thread_guard_before_other_sdk_access(monkeypatch):
    monkeypatch.setitem(sys.modules, "ida_pro", NS(is_main_thread=lambda: False))
    with pytest.raises(RuntimeError, match="main thread"):
        adapter.extract_snapshot(0, namespace="owner", function_key="f", profile={})


def fake_sdk(monkeypatch, tmp_path):
    binary = tmp_path / "static.bin"
    binary.write_bytes(b"not executed")
    empty = NS(t=0, size=-1)
    ins = NS(opcode=2, ea=0x100, l=NS(t=999, size=4), r=empty, d=empty, next=None)
    block = NS(head=ins, npred=lambda: 0, nsucc=lambda: 0, type=0)
    mba = NS(qty=1, maturity=6, get_mblock=lambda i: block)
    hx = NS(
        MMAT_CALLS=6,
        BLT_STOP=1,
        m_mov=1,
        m_ext=2,
        mop_z=0,
        mop_n=1,
        mop_r=2,
        mop_f=3,
        mop_v=4,
        mop_b=5,
        mop_S=6,
        mop_d=7,
        mop_a=8,
        init_hexrays_plugin=lambda: True,
        get_hexrays_version=lambda: "test",
        hexrays_failure_t=lambda: NS(),
        mba_ranges_t=lambda f: f,
        gen_microcode=lambda *args: mba,
    )
    modules = {
        "ida_pro": NS(is_main_thread=lambda: True),
        "ida_funcs": NS(get_func=lambda ea: NS(start_ea=ea)),
        "ida_hexrays": hx,
        "ida_ida": NS(
            inf_is_64bit=lambda: True,
            inf_is_be=lambda: False,
            inf_get_procname=lambda: "metapc",
            inf_get_filetype=lambda: 42,
            f_MACHO=42,
        ),
        "ida_idaapi": NS(BADADDR=-1),
        "ida_kernwin": NS(get_kernel_version=lambda: "test"),
        "ida_nalt": NS(
            get_input_file_path=lambda: str(binary), get_imagebase=lambda: 0
        ),
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    return adapter.anchor_profile(
        read("p0_inventory.json"),
        "X64-LE",
        "darwin-x86_64-sysv-derived",
        read("build.json"),
    )


def direct_call_sdk(monkeypatch, tmp_path, *, argument=7):
    profile = fake_sdk(monkeypatch, tmp_path)
    hx = sys.modules["ida_hexrays"]
    hx.m_call = 8
    locations = NS(
        reg=NS(empty=lambda: False, last=lambda: 11, has=lambda i: 8 <= i <= 11),
        mem=NS(all_values=lambda: False, nivls=lambda: 0),
    )
    ci = NS(
        callee=0x1200,
        cc=112,
        args=[NS(t=hx.mop_n, size=4, nnn=NS(value=argument))],
        retregs=[NS(t=hx.mop_r, size=4, r=8)],
        return_type=NS(
            get_size=lambda: 4, get_realtype=lambda: 20, is_void=lambda: False
        ),
        return_regs=locations,
        spoiled=locations,
    )
    ins = hx.gen_microcode().get_mblock(0).head
    ins.opcode = hx.m_call
    ins.ea = 0x1110
    ins.l = NS(t=hx.mop_z, size=-1)
    ins.r = NS(t=hx.mop_z, size=-1)
    ins.d = NS(t=hx.mop_f, size=0, f=ci)
    sys.modules["ida_nalt"].get_imagebase = lambda: 0x1000
    return profile


def test_unknown_operands_remain_opaque_and_no_width_is_invented(monkeypatch, tmp_path):
    profile = fake_sdk(monkeypatch, tmp_path)
    result = adapter.extract_snapshot(
        0x100, namespace="owner", function_key="fixture-0", profile=profile
    )
    ins = result.function.blocks[0].instructions[0]
    assert ins.opcode == "m_ext"
    assert ins.operands[0].kind == "unknown" and ins.operands[0].width_bits == 32
    assert ins.operands[0].diagnostic.code == "unsupported_operand"
    assert ins.operands[1].width_bits is None
    assert {d.code for d in result.function.diagnostics} >= {
        "opaque_microcode",
        "unsupported_operand",
    }
    assert Snapshot.from_json(canonical_json(result)) == result
    with pytest.raises(InterruptedError):
        adapter.extract_snapshot(
            0x100,
            namespace="owner",
            function_key="fixture-0",
            profile=profile,
            cancelled=lambda: True,
        )
    with pytest.raises(ContractError, match="maturity"):
        adapter.extract_snapshot(
            0x100,
            namespace="owner",
            function_key="fixture-0",
            profile={**profile, "maturity": "MMAT_GLBOPT3"},
        )


@pytest.mark.parametrize(
    "referent,expected_kind,expected_address",
    (
        ("stack", "stack_address", 8),
        ("global", "address", 0x1000),
        ("register", "unknown", None),
    ),
)
def test_address_of_operand_preserves_only_verified_referents(
    monkeypatch, tmp_path, referent, expected_kind, expected_address
):
    profile = fake_sdk(monkeypatch, tmp_path)
    hx = sys.modules["ida_hexrays"]
    ins = hx.gen_microcode().get_mblock(0).head
    ref = (
        NS(t=hx.mop_S, size=-1, s=NS(off=8))
        if referent == "stack"
        else NS(t=hx.mop_v, size=-1, g=0x1000)
        if referent == "global"
        else NS(t=hx.mop_r, size=-1, r=8)
    )
    ins.l = NS(t=hx.mop_a, size=8, a=ref)
    snapshot = adapter.extract_snapshot(
        0x100, namespace="owner", function_key="fixture-0", profile=profile
    )
    operand = snapshot.function.blocks[0].instructions[0].operands[0]
    assert operand.kind == expected_kind
    assert operand.address == expected_address
    assert Operand.from_data(operand.to_data()) == operand
    if expected_kind == "unknown":
        assert operand.diagnostic.code == "unsupported_operand"
        assert "mop_r" in operand.diagnostic.detail
    else:
        assert not any(
            d.code == "unsupported_operand" for d in snapshot.function.diagnostics
        )


def test_native_stop_block_becomes_value_less_exit_not_fabricated_return(
    monkeypatch, tmp_path
):
    profile = fake_sdk(monkeypatch, tmp_path)
    hx = sys.modules["ida_hexrays"]
    mba = hx.gen_microcode()
    entry = mba.get_mblock(0)
    entry.nsucc = lambda: 1
    entry.succ = lambda index: 1
    terminal = NS(
        head=None,
        type=hx.BLT_STOP,
        npred=lambda: 1,
        pred=lambda index: 0,
        nsucc=lambda: 0,
    )
    mba.qty = 2
    mba.get_mblock = lambda index: (entry, terminal)[index]
    snapshot = adapter.extract_snapshot(
        0x100, namespace="owner", function_key="fixture-0", profile=profile
    )
    marker = snapshot.function.blocks[1].instructions[0]
    assert marker.opcode == "m_exit" and marker.synthetic
    assert marker.operands == () and marker.source_eas == ()

    terminal.type = 2  # BLT_0WAY-like unresolved/non-returning leaf.
    unresolved = adapter.extract_snapshot(
        0x100, namespace="owner", function_key="fixture-0", profile=profile
    )
    assert unresolved.function.blocks[1].instructions == ()


def test_typed_scalar_return_requires_exact_register_roundtrip(monkeypatch, tmp_path):
    profile = fake_sdk(monkeypatch, tmp_path)
    hx = sys.modules["ida_hexrays"]
    mba = hx.gen_microcode()
    entry = mba.get_mblock(0)
    entry.nsucc = lambda: 1
    entry.succ = lambda index: 1
    terminal = NS(
        head=None,
        type=hx.BLT_STOP,
        npred=lambda: 1,
        pred=lambda index: 0,
        nsucc=lambda: 0,
    )
    mba.qty = 2
    mba.get_mblock = lambda index: (entry, terminal)[index]

    class TypeInfo:
        def get_func_details(self, details):
            details.is_noret = lambda: False
            details.rettype = NS(get_size=lambda: 4)
            details.retloc = NS(is_reg1=lambda: True, regoff=lambda: 0, reg1=lambda: 0)
            details.append(
                NS(
                    type=NS(get_size=lambda: 4),
                    argloc=NS(is_reg1=lambda: True, regoff=lambda: 0, reg1=lambda: 7),
                )
            )
            return True

    class FuncDetails(list):
        pass

    monkeypatch.setitem(
        sys.modules, "ida_typeinf", NS(tinfo_t=TypeInfo, func_type_data_t=FuncDetails)
    )
    sys.modules["ida_nalt"].get_tinfo = lambda tif, ea: True
    hx.reg2mreg = lambda reg: 8 if reg == 0 else 56
    hx.mreg2reg = lambda reg, size: {8: 0, 56: 7}.get(reg, -1)
    snapshot = adapter.extract_snapshot(
        0x100, namespace="owner", function_key="fixture-0", profile=profile
    )
    instruction = snapshot.function.blocks[1].instructions[0]
    assert instruction.opcode == "m_ret" and instruction.synthetic
    assert instruction.source_eas == ()
    result = instruction.operands[0]
    assert result.storage == StorageLocation("microregister", "microregister", 64, 32)
    assert result.native_kind == "typed_return_argloc"
    assert {d.code for d in snapshot.function.diagnostics} >= {"typed_return_location"}
    marker = snapshot.function.blocks[0].instructions[-1]
    assert marker.opcode == "m_arg" and marker.synthetic
    assert marker.operands[0].constant == 0
    assert marker.operands[1].storage == StorageLocation(
        "microregister", "microregister", 448, 32
    )
    assert marker.operands[1].native_kind == "typed_argument_argloc"

    class PointerTypeInfo(TypeInfo):
        def get_func_details(self, details):
            assert super().get_func_details(details)
            details[0].type = NS(get_size=lambda: 8, is_ptr=lambda: True)
            return True

    sys.modules["ida_typeinf"].tinfo_t = PointerTypeInfo
    pointer = adapter.extract_snapshot(
        0x100, namespace="owner", function_key="fixture-0", profile=profile
    )
    pointer_arg = pointer.function.blocks[0].instructions[-1].operands[1]
    assert pointer_arg.storage == StorageLocation(
        "microregister", "microregister", 448, 64
    )
    assert pointer_arg.native_kind == "typed_pointer_argument_argloc"

    class NarrowTypeInfo(TypeInfo):
        def get_func_details(self, details):
            assert super().get_func_details(details)
            details.rettype = NS(get_size=lambda: 1)
            details[0].type = NS(get_size=lambda: 1)
            return True

    sys.modules["ida_typeinf"].tinfo_t = NarrowTypeInfo
    # IDA 9.3 returns AL/DIL rather than RAX/RDI for a one-byte roundtrip.
    # Both aliases must still map back to the exact same microregister byte.
    hx.reg2mreg = lambda reg: {0: 8, 7: 56, 16: 8, 27: 56}.get(reg, -1)
    hx.mreg2reg = lambda reg, size: {8: 16, 56: 27}.get(reg, -1) if size == 1 else -1
    narrow = adapter.extract_snapshot(
        0x100, namespace="owner", function_key="fixture-0", profile=profile
    )
    assert narrow.function.blocks[1].instructions[0].opcode == "m_ret"
    assert narrow.function.blocks[1].instructions[0].operands[0].storage == (
        StorageLocation("microregister", "microregister", 64, 8)
    )
    narrow_arg = narrow.function.blocks[0].instructions[-1]
    assert narrow_arg.opcode == "m_arg"
    assert narrow_arg.operands[1].storage == StorageLocation(
        "microregister", "microregister", 448, 8
    )

    hx.mreg2reg = lambda reg, size: -1
    unknown = adapter.extract_snapshot(
        0x100, namespace="owner", function_key="fixture-0", profile=profile
    )
    assert unknown.function.blocks[1].instructions[0].opcode == "m_exit"


def test_typed_void_and_stack_argument_have_distinct_unmapped_reasons(
    monkeypatch, tmp_path
):
    profile = fake_sdk(monkeypatch, tmp_path)
    hx = sys.modules["ida_hexrays"]
    mba = hx.gen_microcode()
    entry = mba.get_mblock(0)
    entry.nsucc = lambda: 1
    entry.succ = lambda index: 1
    mba.qty = 2
    mba.get_mblock = lambda index: (
        entry,
        NS(
            head=None,
            type=hx.BLT_STOP,
            npred=lambda: 1,
            pred=lambda index: 0,
            nsucc=lambda: 0,
        ),
    )[index]

    class TypeInfo:
        def get_func_details(self, details):
            details.is_noret = lambda: False
            details.rettype = NS(get_size=lambda: 0, is_void=lambda: True)
            details.retloc = NS(is_reg1=lambda: False)
            details.append(
                NS(
                    type=NS(get_size=lambda: 4),
                    argloc=NS(is_reg1=lambda: False),
                )
            )
            return True

    class FuncDetails(list):
        pass

    monkeypatch.setitem(
        sys.modules,
        "ida_typeinf",
        NS(tinfo_t=TypeInfo, func_type_data_t=FuncDetails),
    )
    sys.modules["ida_nalt"].get_tinfo = lambda tif, ea: True
    snapshot = adapter.extract_snapshot(
        0x100, namespace="owner", function_key="fixture-0", profile=profile
    )
    assert snapshot.function.blocks[1].instructions[0].opcode == "m_exit"
    assert not any(
        instruction.opcode == "m_arg"
        for block in snapshot.function.blocks
        for instruction in block.instructions
    )
    assert {item.code for item in snapshot.function.diagnostics} >= {
        "typed_void_return",
        "typed_argument_unmapped",
    }

    class NoReturnTypeInfo(TypeInfo):
        def get_func_details(self, details):
            assert super().get_func_details(details)
            details.is_noret = lambda: True
            details.clear()
            return True

    sys.modules["ida_typeinf"].tinfo_t = NoReturnTypeInfo
    noreturn = adapter.extract_snapshot(
        0x100, namespace="owner", function_key="fixture-0", profile=profile
    )
    assert noreturn.function.blocks[1].instructions[0].opcode == "m_noreturn"
    assert any(
        item.code == "typed_noreturn" and item.severity == "unsupported"
        for item in noreturn.function.diagnostics
    )


def test_profile_and_no_display_parsing_boundary():
    inventory = read("p0_inventory.json")
    profile = adapter.anchor_profile(
        inventory,
        "X64-LE",
        "darwin-x86_64-sysv-derived",
        read("build.json"),
    )
    assert profile["mode"] == "X64"
    assert profile["normal_status"] == profile["fallback_status"] == "unverified"
    assert profile["receipt_status"] == "success"
    assert profile["receipt_evidence"]["file_name"] == "x64.json"
    assert profile["receipt_evidence"]["roundtrip_equal"] is True
    assert profile["registry_digest"].startswith("sha256-v1:")
    with pytest.raises(ContractError):
        adapter.anchor_profile(inventory, "X64-LE", "windows-x64", read("build.json"))
    with pytest.raises(ContractError):
        adapter.anchor_profile(inventory, "MIPS32-LE", "mips-o32", read("build.json"))
    source = PATH.read_text()
    for forbidden in (
        ".dstr(",
        ".print(",
        "generate_disasm_line",
        "get_reg_name",
        "print_operand",
    ):
        assert forbidden not in source
    assert "native_effects" in source and "preserve_once" in source


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("profile_id", "MIPS32-LE"),
        ("mode", "MIPS32"),
        ("processor", "guess"),
        ("bitness", 32),
        ("normal_status", "available"),
        ("registry_digest", "sha256-v1:" + "0" * 64),
        ("receipt_evidence", {}),
    ],
)
def test_registry_driven_extractor_rejects_unmeasured_or_drifted_profile(
    monkeypatch, tmp_path, key, value
):
    profile = fake_sdk(monkeypatch, tmp_path)
    profile[key] = value

    def forbidden_init():
        raise AssertionError("Unmeasured profile must fail before Hex-Rays")

    sys.modules["ida_hexrays"].init_hexrays_plugin = forbidden_init
    with pytest.raises(ContractError, match="Unmeasured extraction profile"):
        adapter.extract_snapshot(
            0x100, namespace="owner", function_key="fixture-0", profile=profile
        )


def test_indirect_call_metadata_preserves_unresolved_target(monkeypatch, tmp_path):
    profile = fake_sdk(monkeypatch, tmp_path)
    hx = sys.modules["ida_hexrays"]
    mba = hx.gen_microcode()
    hx.m_icall = 3
    locations = NS(
        reg=NS(empty=lambda: False, last=lambda: 11, has=lambda i: 8 <= i <= 11),
        mem=NS(all_values=lambda: False, nivls=lambda: 0),
    )
    ci = NS(
        callee=-1,
        cc=112,
        args=[NS(t=hx.mop_n, size=4, nnn=NS(value=7))],
        retregs=[NS(t=hx.mop_r, size=4, r=8)],
        return_type=NS(
            get_size=lambda: 4, get_realtype=lambda: 20, is_void=lambda: False
        ),
        return_regs=locations,
        spoiled=locations,
    )
    ins = mba.get_mblock(0).head
    ins.opcode = hx.m_icall
    ins.l = NS(t=hx.mop_r, size=8, r=24)
    ins.d = NS(t=hx.mop_f, size=0, f=ci)
    result = adapter.extract_snapshot(
        0x100, namespace="owner", function_key="fixture-0", profile=profile
    )
    call = result.function.blocks[0].instructions[0].operands[2].call
    assert call.callee_ea is None and call.convention == 112
    assert call.arguments[0].role == "argument" and call.arguments[0].constant == 7
    assert call.return_operands[0].role == "return"
    assert call.spoiled_locations.register_bytes == (8, 9, 10, 11)
    assert call.return_width_bits == 32 and not call.return_is_void
    assert call.unresolved
    assert Snapshot.from_json(canonical_json(result)) == result


def test_direct_mop_v_call_target_recovers_missing_callinfo_callee(
    monkeypatch, tmp_path
):
    profile = direct_call_sdk(monkeypatch, tmp_path)
    hx = sys.modules["ida_hexrays"]
    ins = hx.gen_microcode().get_mblock(0).head
    ins.l = NS(t=hx.mop_v, size=8, g=0x1200)
    ins.d.f.callee = -1
    extracted = adapter.extract_snapshot(
        0x1100,
        namespace="owner",
        function_key="caller",
        profile=profile,
        include_calls=True,
    )
    assert extracted.calls[0].call.callee_ea == 0x1200
    assert (
        extracted.snapshot.function.blocks[0].instructions[0].operands[2].call
        == extracted.calls[0].call
    )
    assert "call_target_from_direct_operand" in {
        item.code for item in extracted.snapshot.function.diagnostics
    }
    assert Snapshot.from_data(extracted.snapshot.to_data()) == extracted.snapshot


def test_direct_target_conflict_and_indirect_global_stay_unresolved(
    monkeypatch, tmp_path
):
    profile = direct_call_sdk(monkeypatch, tmp_path)
    hx = sys.modules["ida_hexrays"]
    ins = hx.gen_microcode().get_mblock(0).head
    ins.l = NS(t=hx.mop_v, size=8, g=0x1300)
    conflict = adapter.extract_snapshot(
        0x1100,
        namespace="owner",
        function_key="caller",
        profile=profile,
        include_calls=True,
    )
    assert conflict.calls[0].call.callee_ea is None
    assert "call_target_conflict" in conflict.calls[0].call.unresolved
    assert "call_target_conflict" in {
        item.code for item in conflict.snapshot.function.diagnostics
    }

    hx.m_icall = 9
    ins.opcode = hx.m_icall
    ins.d.f.callee = -1
    indirect = adapter.extract_snapshot(
        0x1100,
        namespace="owner",
        function_key="caller",
        profile=profile,
        include_calls=True,
    )
    assert indirect.calls[0].call.callee_ea is None
    assert "call_target_from_direct_operand" not in {
        item.code for item in indirect.snapshot.function.diagnostics
    }


def test_nested_direct_call_target_reaches_observation(monkeypatch, tmp_path):
    profile = direct_call_sdk(monkeypatch, tmp_path)
    hx = sys.modules["ida_hexrays"]
    outer = hx.gen_microcode().get_mblock(0).head
    nested = NS(
        opcode=hx.m_call,
        ea=outer.ea,
        l=NS(t=hx.mop_v, size=8, g=0x1200),
        r=NS(t=hx.mop_z, size=-1),
        d=outer.d,
    )
    nested.d.f.callee = -1
    outer.opcode = hx.m_mov
    outer.l = NS(t=hx.mop_d, size=4, d=nested)
    outer.d = NS(t=hx.mop_r, size=4, r=8)
    result = adapter.extract_snapshot(
        0x1100,
        namespace="owner",
        function_key="caller",
        profile=profile,
        include_calls=True,
    )
    assert len(result.calls) == 1
    assert result.calls[0].call.callee_ea == 0x1200
    expression = result.snapshot.function.blocks[0].instructions[0].operands[0]
    assert expression.kind == "expression" and expression.operation == "m_call"
    assert expression.children[2].call == result.calls[0].call


def test_catalog_digest_scopes_snapshot_identity_without_changing_legacy_default():
    receipt = read("extraction_x64.json")
    historical = Snapshot.from_data(receipt["snapshot"])
    rebuilt = adapter.make_snapshot(
        historical.function,
        historical.identity.environment,
        receipt["profile"],
        historical.identity.namespace,
        historical.identity.binary_digest.split(":", 1)[1],
    )
    assert rebuilt == historical
    scoped = adapter.make_snapshot(
        historical.function,
        historical.identity.environment,
        receipt["profile"],
        historical.identity.namespace,
        historical.identity.binary_digest.split(":", 1)[1],
        summary_digest=catalog_adapter.EMPTY_CATALOG.catalog_digest,
    )
    assert (
        scoped.identity.summary_digest == catalog_adapter.EMPTY_CATALOG.catalog_digest
    )
    assert scoped.snapshot_id != historical.snapshot_id


def test_direct_call_binds_only_full_pinned_identity(monkeypatch, tmp_path):
    profile = direct_call_sdk(monkeypatch, tmp_path)
    baseline_callee = adapter.extract_snapshot(
        0x1200,
        namespace="owner",
        function_key="callee-rva:512",
        profile=profile,
    )
    observed = adapter.extract_snapshot(
        0x1100,
        namespace="owner",
        function_key="caller-rva:256",
        profile=profile,
        include_calls=True,
    )
    assert observed.image_base == 0x1000
    assert len(observed.calls) == 1 and observed.calls[0].instruction_ea == 0x1110
    identity = catalog_adapter.target_identity(
        observed.snapshot, observed.calls[0].call, 0x200, baseline_callee
    )
    reviewed = ReviewedSummary(
        identity,
        "display-metadata-only",
        "identity",
        (ReturnEffect("argument", 32, argument_index=0),),
        (),
        (),
        "fixture-review",
        digest("fixture-review"),
    )
    catalog = SummaryCatalog((reviewed,))
    caller = adapter.extract_snapshot(
        0x1100,
        namespace="owner",
        function_key="caller-rva:256",
        profile=profile,
        summary_digest=catalog.catalog_digest,
        include_calls=True,
    )
    binding = catalog_adapter.bind_call(
        caller, caller.calls[0], catalog, {0x200: baseline_callee}
    )
    assert binding.site.instruction_rva == 0x110
    assert binding.plan.branches[0].summary == reviewed
    assert binding.plan.unknown_remainder is None
    assert binding.candidates == (identity,)
    callee_snapshots = {0x200: baseline_callee}
    composition = catalog_adapter.compose_binding(
        caller,
        binding,
        catalog,
        callee_snapshots=callee_snapshots,
    )
    assert composition.status == "complete_in_scope"
    assert composition.return_value.value.value == 7
    assert composition.plan_digest == binding.plan.plan_digest
    with pytest.raises(ContractError, match="catalog digest"):
        catalog_adapter.compose_binding(
            caller,
            binding,
            catalog_adapter.EMPTY_CATALOG,
            callee_snapshots=callee_snapshots,
        )

    for forged_site in (
        replace(
            binding.site,
            caller_snapshot_id=baseline_callee.snapshot_id,
        ),
        replace(binding.site, caller_function_id="forged-caller"),
        replace(binding.site, kind="indirect"),
    ):
        forged = replace(
            binding,
            site=forged_site,
            plan=replace(binding.plan, site=forged_site),
        )
        with pytest.raises(ContractError, match="site/origin mismatch"):
            catalog_adapter.compose_binding(
                caller,
                forged,
                catalog,
                callee_snapshots=callee_snapshots,
            )

    branch = binding.plan.branches[0]
    rogue_summary = replace(branch.summary, display_name="rogue-not-in-catalog")
    rogue = replace(
        binding,
        plan=replace(
            binding.plan,
            branches=(replace(branch, summary=rogue_summary),),
        ),
    )
    with pytest.raises(ContractError, match="exact catalog member"):
        catalog_adapter.compose_binding(
            caller,
            rogue,
            catalog,
            callee_snapshots=callee_snapshots,
        )

    with pytest.raises(ContractError, match="candidates do not match"):
        catalog_adapter.compose_binding(
            caller,
            replace(binding, candidates=()),
            catalog,
            callee_snapshots=callee_snapshots,
        )

    changed = SummaryCatalog(
        (replace(reviewed, identity=replace(identity, callee_rva=0x201)),)
    )
    wrong_caller = adapter.extract_snapshot(
        0x1100,
        namespace="owner",
        function_key="caller-rva:256",
        profile=profile,
        summary_digest=changed.catalog_digest,
        include_calls=True,
    )
    unresolved = catalog_adapter.bind_call(
        wrong_caller,
        wrong_caller.calls[0],
        changed,
        {0x200: baseline_callee},
    )
    assert unresolved.plan.branches == ()
    assert unresolved.plan.unknown_remainder.reasons == ("missing_reviewed_summary",)
    assert "reviewed_summary_unavailable" in unresolved.limitations

    unresolved_composition = catalog_adapter.compose_binding(
        wrong_caller,
        unresolved,
        changed,
        callee_snapshots=callee_snapshots,
    )
    assert unresolved_composition.status == "partial"


def test_direct_call_rejects_catalog_member_retargeting(monkeypatch, tmp_path):
    profile = direct_call_sdk(monkeypatch, tmp_path)
    baseline_callee = adapter.extract_snapshot(
        0x1200,
        namespace="owner",
        function_key="callee-rva:512",
        profile=profile,
    )
    alternate_callee = adapter.extract_snapshot(
        0x1200,
        namespace="alternate-owner",
        function_key="callee-rva:512",
        profile=profile,
    )
    observed = adapter.extract_snapshot(
        0x1100,
        namespace="owner",
        function_key="caller-rva:256",
        profile=profile,
        include_calls=True,
    )
    expected_identity = catalog_adapter.target_identity(
        observed.snapshot,
        observed.calls[0].call,
        0x200,
        baseline_callee,
    )
    different_rva_identity = replace(expected_identity, callee_rva=0x201)
    different_snapshot_identity = catalog_adapter.target_identity(
        observed.snapshot,
        observed.calls[0].call,
        0x200,
        alternate_callee,
    )
    effect = (ReturnEffect("argument", 32, argument_index=0),)

    def reviewed(identity, name):
        return ReviewedSummary(
            identity,
            name,
            "identity",
            effect,
            (),
            (),
            "fixture-review",
            digest(name + "-review"),
        )

    expected = reviewed(expected_identity, "expected")
    different_rva = reviewed(different_rva_identity, "different-rva")
    different_snapshot = reviewed(
        different_snapshot_identity,
        "different-snapshot",
    )
    catalog = SummaryCatalog(
        tuple(
            sorted(
                (expected, different_rva, different_snapshot),
                key=lambda item: item.identity.sort_key,
            )
        )
    )
    caller = adapter.extract_snapshot(
        0x1100,
        namespace="owner",
        function_key="caller-rva:256",
        profile=profile,
        summary_digest=catalog.catalog_digest,
        include_calls=True,
    )
    callee_snapshots = {0x200: baseline_callee}
    binding = catalog_adapter.bind_call(
        caller,
        caller.calls[0],
        catalog,
        callee_snapshots,
    )
    assert binding.plan.branches[0].summary == expected

    def retarget(replacement_summary):
        branch = binding.plan.branches[0]
        frame = replace(
            branch.context.frames[-1],
            target=replacement_summary.identity,
        )
        context = replace(
            branch.context,
            frames=branch.context.frames[:-1] + (frame,),
        )
        return replace(
            binding,
            candidates=(replacement_summary.identity,),
            plan=replace(
                binding.plan,
                branches=(
                    replace(
                        branch,
                        summary=replacement_summary,
                        context=context,
                    ),
                ),
            ),
        )

    for replacement_summary in (different_rva, different_snapshot):
        with pytest.raises(ContractError, match="direct target identity mismatch"):
            catalog_adapter.compose_binding(
                caller,
                retarget(replacement_summary),
                catalog,
                callee_snapshots=callee_snapshots,
            )

    missing_catalog = catalog_adapter.EMPTY_CATALOG
    missing_caller = adapter.extract_snapshot(
        0x1100,
        namespace="owner",
        function_key="caller-rva:256",
        profile=profile,
        summary_digest=missing_catalog.catalog_digest,
        include_calls=True,
    )
    blocked = catalog_adapter.bind_call(
        missing_caller,
        missing_caller.calls[0],
        missing_catalog,
        callee_snapshots,
    )
    remainder = blocked.plan.unknown_remainder
    assert remainder is not None
    forged_blocked = replace(
        blocked,
        candidates=(different_rva_identity,),
        plan=replace(
            blocked.plan,
            unknown_remainder=replace(
                remainder,
                blocked_targets=(different_rva_identity,),
            ),
        ),
    )
    with pytest.raises(ContractError, match="direct target identity mismatch"):
        catalog_adapter.compose_binding(
            missing_caller,
            forged_blocked,
            missing_catalog,
            callee_snapshots=callee_snapshots,
        )


def test_indirect_candidates_require_observed_identity_compatibility(
    monkeypatch, tmp_path
):
    profile = fake_sdk(monkeypatch, tmp_path)
    hx = sys.modules["ida_hexrays"]
    hx.m_icall = 3
    locations = NS(
        reg=NS(empty=lambda: False, last=lambda: 11, has=lambda i: 8 <= i <= 11),
        mem=NS(all_values=lambda: False, nivls=lambda: 0),
    )
    ci = NS(
        callee=-1,
        cc=112,
        args=[NS(t=hx.mop_n, size=4, nnn=NS(value=7))],
        retregs=[NS(t=hx.mop_r, size=4, r=8)],
        return_type=NS(
            get_size=lambda: 4, get_realtype=lambda: 20, is_void=lambda: False
        ),
        return_regs=locations,
        spoiled=locations,
    )
    ins = hx.gen_microcode().get_mblock(0).head
    ins.opcode = hx.m_icall
    ins.ea = 0x110
    ins.l = NS(t=hx.mop_r, size=8, r=24)
    ins.d = NS(t=hx.mop_f, size=0, f=ci)
    baseline = adapter.extract_snapshot(
        0x100,
        namespace="owner",
        function_key="indirect-caller",
        profile=profile,
        include_calls=True,
    )
    call = baseline.calls[0].call
    common = {
        "binary_sha256": baseline.snapshot.identity.binary_digest.split(":", 1)[1],
        "callee_snapshot_id": baseline.snapshot.snapshot_id,
        "profile_digest": baseline.snapshot.identity.profile_digest,
        "calling_convention": catalog_adapter.calling_convention(
            baseline.snapshot, call
        ),
    }
    compatible = SummaryIdentity(
        callee_rva=0x200,
        signature_digest=catalog_adapter.signature_digest(call),
        **common,
    )
    incompatible = SummaryIdentity(
        callee_rva=0x201,
        signature_digest=digest({"incompatible": True}),
        **common,
    )
    effect = (ReturnEffect("argument", 32, argument_index=0),)
    catalog = SummaryCatalog(
        tuple(
            sorted(
                (
                    ReviewedSummary(
                        compatible,
                        "compatible",
                        "identity",
                        effect,
                        (),
                        (),
                        "fixture-review",
                        digest("compatible-review"),
                    ),
                    ReviewedSummary(
                        incompatible,
                        "incompatible",
                        "identity",
                        effect,
                        (),
                        (),
                        "fixture-review",
                        digest("incompatible-review"),
                    ),
                ),
                key=lambda item: item.identity.sort_key,
            )
        )
    )
    caller = adapter.extract_snapshot(
        0x100,
        namespace="owner",
        function_key="indirect-caller",
        profile=profile,
        summary_digest=catalog.catalog_digest,
        include_calls=True,
    )
    binding = catalog_adapter.bind_call(
        caller,
        caller.calls[0],
        catalog,
        {},
        indirect_candidates=(compatible, incompatible),
        exhaustive=True,
    )
    assert [branch.summary.display_name for branch in binding.plan.branches] == [
        "compatible"
    ]
    assert binding.plan.unknown_remainder is not None
    assert incompatible in binding.plan.unknown_remainder.blocked_targets
    assert "nonexhaustive_indirect" in binding.plan.unknown_remainder.reasons
    assert "incompatible_indirect_candidate" in binding.limitations
    result = catalog_adapter.compose_binding(caller, binding, catalog)
    assert result.status == "partial"


def test_global_load_argument_is_width_correct_unknown_provenance():
    loaded = catalog_adapter._operand_value(
        Operand("global", 32, role="argument", address=0x1_0000_2008)
    )
    assert loaded.value.width_bits == 32 and loaded.value.value is None
    assert loaded.labels.unknown_provenance is True

    address = catalog_adapter._operand_value(
        Operand("address", 64, role="argument", address=0x1_0000_2008)
    )
    assert address.value.value == 0x1_0000_2008
    assert address.labels.unknown_provenance is False


def test_missing_image_base_api_is_explicit(monkeypatch, tmp_path):
    profile = fake_sdk(monkeypatch, tmp_path)
    delattr(sys.modules["ida_nalt"], "get_imagebase")
    with pytest.raises(RuntimeError, match="image-base API unavailable"):
        adapter.extract_snapshot(
            0x100,
            namespace="owner",
            function_key="fixture-0",
            profile=profile,
        )


def test_extracted_call_observation_must_match_structured_instruction(
    monkeypatch, tmp_path
):
    profile = direct_call_sdk(monkeypatch, tmp_path)
    function = adapter.extract_snapshot(
        0x1100,
        namespace="owner",
        function_key="caller",
        profile=profile,
        include_calls=True,
    )
    with pytest.raises(ContractError, match="native origin mismatch"):
        replace(
            function,
            calls=(replace(function.calls[0], instruction_ea=0x1111),),
        )


def test_signature_ignores_argument_values_but_pins_available_type_metadata(
    monkeypatch, tmp_path
):
    profile = direct_call_sdk(monkeypatch, tmp_path, argument=7)
    first = (
        adapter.extract_snapshot(
            0x1100,
            namespace="owner",
            function_key="caller",
            profile=profile,
            include_calls=True,
        )
        .calls[0]
        .call
    )
    sys.modules["ida_hexrays"].gen_microcode().get_mblock(0).head.d.f.args[
        0
    ].nnn.value = 9
    second = (
        adapter.extract_snapshot(
            0x1100,
            namespace="owner",
            function_key="caller",
            profile=profile,
            include_calls=True,
        )
        .calls[0]
        .call
    )
    assert first.arguments[0].constant != second.arguments[0].constant
    assert catalog_adapter.signature_digest(first) == catalog_adapter.signature_digest(
        second
    )
    assert catalog_adapter.signature_projection(first) == {
        "version": 1,
        "argument_width_bits": [32],
        "return_width_bits": 32,
        "return_is_void": False,
        "return_type_code": 20,
        "return_operand_width_bits": [32],
    }


def test_owned_callee_closure_is_bounded_and_keeps_recursive_boundary(
    monkeypatch, tmp_path
):
    profile = direct_call_sdk(monkeypatch, tmp_path)
    caller = adapter.extract_snapshot(
        0x1100,
        namespace="owner",
        function_key="caller",
        profile=profile,
        include_calls=True,
    )
    callee = adapter.extract_snapshot(
        0x1200,
        namespace="owner",
        function_key="callee",
        profile=profile,
        include_calls=True,
    )
    closure, boundaries = catalog_adapter.bounded_callee_closure(
        (0x100,), {0x100: caller, 0x200: callee}, max_depth=4, max_functions=2
    )
    assert closure == (0x100, 0x200)
    assert [(boundary.callee_rva, boundary.reason) for boundary in boundaries] == [
        (0x200, "recursive_boundary")
    ]
    limited, limited_boundaries = catalog_adapter.bounded_callee_closure(
        (0x100,), {0x100: caller, 0x200: callee}, max_depth=4, max_functions=1
    )
    assert limited == (0x100,)
    assert [
        (boundary.instruction_rva, boundary.callee_rva, boundary.reason)
        for boundary in limited_boundaries
    ] == [(0x110, 0x200, "function_limit")]


def test_synthetic_instruction_retains_nested_origins(monkeypatch, tmp_path):
    profile = fake_sdk(monkeypatch, tmp_path)
    hx = sys.modules["ida_hexrays"]
    ins = hx.gen_microcode().get_mblock(0).head
    empty = NS(t=hx.mop_z, size=-1)
    ins.opcode = hx.m_mov
    ins.ea = -1
    ins.l = NS(
        t=hx.mop_d,
        size=4,
        d=NS(
            opcode=hx.m_mov,
            ea=0x200,
            l=NS(t=hx.mop_n, size=4, nnn=NS(value=9)),
            r=empty,
            d=empty,
        ),
    )
    result = adapter.extract_snapshot(
        0x100, namespace="owner", function_key="fixture-0", profile=profile
    )
    instruction = result.function.blocks[0].instructions[0]
    assert instruction.synthetic and instruction.source_eas == (0x200,)
    assert not instruction.operands[0].synthetic
    assert instruction.operands[0].source_eas == (0x200,)


@pytest.mark.parametrize("filetype", [1, 2, 3])
def test_wrong_loader_format_rejected_before_hexrays(monkeypatch, tmp_path, filetype):
    profile = fake_sdk(monkeypatch, tmp_path)
    sys.modules["ida_ida"].inf_get_filetype = lambda: filetype

    def forbidden_init():
        raise AssertionError("Wrong format must fail before microcode generation")

    sys.modules["ida_hexrays"].init_hexrays_plugin = forbidden_init
    with pytest.raises(ContractError, match="Binary format mismatch"):
        adapter.extract_snapshot(
            0x100, namespace="owner", function_key="fixture-0", profile=profile
        )


def test_format_identity_and_profile_consistency():
    receipt = read("extraction_x64.json")
    snapshot = Snapshot.from_data(receipt["snapshot"])
    env = snapshot.identity.environment
    assert env.format_id == receipt["profile"]["format_id"] == "FMT-MACHO"
    assert env.platform_tag == receipt["profile"]["platform_tag"] == "darwin"
    assert receipt["profile"]["abi_provenance"]["kind"] == "measured_anchor_build"
    changed = replace(env, format_id="FMT-PE")
    assert (
        replace(snapshot.identity, environment=changed).snapshot_id
        != snapshot.snapshot_id
    )
    with pytest.raises(ContractError, match="profile/format/platform"):
        adapter.make_snapshot(
            snapshot.function,
            changed,
            receipt["profile"],
            snapshot.identity.namespace,
            snapshot.identity.binary_digest.split(":")[1],
        )
    with pytest.raises(ContractError):
        replace(env, format_id="guessed")
    with pytest.raises(ContractError):
        replace(env, platform_tag="")


def test_negative_pe_receipt_and_build_provenance():
    receipt = read("extraction_negative_pe.json")
    build = next(
        b for b in read("s0_build.json") if b["source"] == "tests/typed_fixture.c"
    )
    assert receipt["binary_sha256"] == build["binary_sha256"]
    assert receipt["actual_format"] == "FMT-PE"
    assert receipt["requested_format"] == "FMT-MACHO"
    assert receipt["exit_code"] != 0 and receipt["successful_receipt_created"] is False
    assert receipt["target_executed"] is False
    with pytest.raises(ContractError, match="build receipt"):
        adapter.anchor_profile(
            read("p0_inventory.json"), "X64-LE", "darwin-x86_64-sysv-derived", []
        )
