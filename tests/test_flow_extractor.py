"""Strict adapter boundaries and actual two-anchor extraction receipts."""

import hashlib
import importlib.util
import json
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

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "src/ida_pro_mcp/ida_mcp/flow/extractor.py"
SPEC = importlib.util.spec_from_file_location("pure_extractor_test", PATH)
adapter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adapter)
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
    assert receipt["extractor_sha256"] == hashlib.sha256(PATH.read_bytes()).hexdigest()
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
    block = NS(head=ins, npred=lambda: 0, nsucc=lambda: 0)
    mba = NS(qty=1, maturity=6, get_mblock=lambda i: block)
    hx = NS(
        MMAT_CALLS=6,
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
        "ida_nalt": NS(get_input_file_path=lambda: str(binary)),
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    return adapter.anchor_profile(
        read("p0_inventory.json"),
        "X64-LE",
        "darwin-x86_64-sysv-derived",
        read("build.json"),
    )


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


def test_profile_and_no_display_parsing_boundary():
    inventory = read("p0_inventory.json")
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
