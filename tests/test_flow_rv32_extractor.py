"""Hostile SDK-mock tests for the Phase-0 RV32 structured capture."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from ida_pro_mcp.flow_core.rv32_capture import (
    BACKEND_IDENTITY,
    REQUEST_SCHEMA,
    CaptureBudgets,
    CaptureRequest,
    FixtureEvidence,
    FunctionSelector,
)
from ida_pro_mcp.flow_core.serialization import ContractError, digest


CONTRACT_FILE = sys.modules[CaptureRequest.__module__].__file__
assert CONTRACT_FILE is not None
CONTRACT_PATH = Path(CONTRACT_FILE)
EXTRACTOR_PATH = CONTRACT_PATH.parents[1] / "ida_mcp/flow/rv32_extractor.py"
SPEC = importlib.util.spec_from_file_location("pure_rv32_extractor_test", EXTRACTOR_PATH)
assert SPEC is not None and SPEC.loader is not None
extractor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(extractor)


def _sha(character: str) -> str:
    return "sha256-v1:" + character * 64


def _binary() -> bytearray:
    value = bytearray(0x300)
    value[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<H", value, 18, 243)
    struct.pack_into("<I", value, 36, 1)
    return value


def _fixture(binary: bytes) -> FixtureEvidence:
    values = {
        "profile_id": "RV32-LE",
        "profile_version": 1,
        "mode": "RV32",
        "processor": "riscv",
        "bitness": 32,
        "data_endian": "LE",
        "instruction_endian": "LE",
        "format_id": "FMT-ELF",
        "abi_id": "riscv-ilp32",
        "target_triple": "riscv32-linux-gnu",
        "platform_tag": "linux",
        "source_sha256": _sha("1"),
        "build_manifest_sha256": _sha("2"),
        "command_sha256": _sha("3"),
        "binary_sha256": "sha256-v1:" + hashlib.sha256(binary).hexdigest(),
        "binary_size": len(binary),
        "fresh_builds": 2,
        "binary_sha256_equal": True,
    }
    profile = {
        key: values[key]
        for key in (
            "profile_id",
            "profile_version",
            "mode",
            "processor",
            "bitness",
            "data_endian",
            "instruction_endian",
            "format_id",
            "platform_tag",
        )
    }
    abi = {
        key: values[key]
        for key in (
            "abi_id",
            "target_triple",
            "source_sha256",
            "build_manifest_sha256",
            "command_sha256",
            "binary_sha256",
            "fresh_builds",
            "binary_sha256_equal",
        )
    }
    return FixtureEvidence(
        **values,
        profile_evidence_digest=digest(profile),
        abi_evidence_digest=digest(abi),
    )


class _ForbiddenModule:
    def __getattr__(self, name):
        raise AssertionError(f"forbidden SDK access: {name}")


def _install_sdk(
    monkeypatch,
    tmp_path,
    *,
    sizes: tuple[int, ...] = (8, 2, 2, 2, 2, 2),
    unknown_operand: bool = False,
):
    image_base = 0x1000
    rvas = tuple(0x100 + index * 0x10 for index in range(6))
    data = _binary()
    for index, (rva, size) in enumerate(zip(rvas, sizes)):
        data[rva : rva + size] = bytes([index + 1]) * size
    binary = tmp_path / "rv32.elf"
    binary.write_bytes(data)
    processor_dir = tmp_path / "ida" / "procs"
    processor_dir.mkdir(parents=True, exist_ok=True)
    processor_module = processor_dir / "riscv.dylib"
    processor_module.write_bytes(b"pinned test processor module")
    processor_digest = "sha256-v1:" + hashlib.sha256(
        processor_module.read_bytes()
    ).hexdigest()
    contract_source = CONTRACT_PATH
    assert extractor.__file__ is not None
    extractor_source = Path(extractor.__file__)
    implementation_digest = digest(
        {
            "src/ida_pro_mcp/flow_core/rv32_capture.py": "sha256-v1:"
            + hashlib.sha256(contract_source.read_bytes()).hexdigest(),
            "src/ida_pro_mcp/ida_mcp/flow/rv32_extractor.py": "sha256-v1:"
            + hashlib.sha256(extractor_source.read_bytes()).hexdigest(),
        }
    )
    fixture = _fixture(bytes(data))
    symbols = tuple(f"fixture_{index}" for index in range(6))
    selectors = tuple(
        FunctionSelector(index, symbol, rva)
        for index, (symbol, rva) in enumerate(zip(symbols, rvas))
    )
    request = CaptureRequest(
        REQUEST_SCHEMA,
        BACKEND_IDENTITY,
        fixture,
        selectors,
        CaptureBudgets(),
        "9.3",
        processor_digest,
        implementation_digest,
    )
    eas = tuple(image_base + rva for rva in rvas)
    functions = {
        ea: NS(start_ea=ea, end_ea=ea + size)
        for ea, size in zip(eas, sizes)
    }
    symbol_eas = dict(zip(symbols, eas))
    size_by_ea = dict(zip(eas, sizes))
    state = {
        "decode_result": None,
        "idb_bytes": None,
        "register_calls": 0,
        "register_drift": False,
        "kernel_calls": 0,
        "processor_module": processor_module,
    }

    class Instruction:
        size = 0

        def is_canon_insn(self):
            return True

        def is_macro(self):
            return self.size == 8

        def get_canon_feature(self):
            return 0x202 if self.size == 8 else 0x100

    def decode_insn(instruction, ea):
        size = size_by_ea[ea]
        instruction.size = size
        instruction.itype = 1000 + ea
        instruction.auxpref = 0
        instruction.segpref = 0
        instruction.insnpref = 0
        instruction.flags = 0
        operand_type = 99 if unknown_operand else 7 if size == 8 else 1
        instruction.ops = (
            NS(
                type=operand_type,
                dtype=2,
                reg=1,
                phrase=0,
                value=0,
                addr=eas[-1] if size == 8 else 0,
                specval=0,
                specflag1=1 if unknown_operand else 0,
                specflag2=0,
                specflag3=0,
                specflag4=0,
                flags=0,
                offb=0,
                offo=0,
            ),
            NS(type=0),
        )
        return size if state["decode_result"] is None else state["decode_result"]

    def get_bytes(ea, size):
        if state["idb_bytes"] is not None:
            return state["idb_bytes"]
        offset = ea - image_base
        return bytes(data[offset : offset + size])

    def regnames():
        state["register_calls"] += 1
        if state["register_drift"] and state["register_calls"] > 1:
            return ("zero", "changed")
        return ("zero", "ra")

    def kernel_version():
        state["kernel_calls"] += 1
        return "9.3"

    modules = {
        "ida_bytes": NS(get_bytes=get_bytes),
        "ida_diskio": NS(idadir=lambda _kind: str(processor_dir)),
        "ida_funcs": NS(
            get_func=lambda ea: functions.get(ea),
            func_tail_iterator_t=lambda function: (
                NS(start_ea=function.start_ea, end_ea=function.end_ea),
            ),
        ),
        "ida_gdl": NS(
            FC_NOEXT=1,
            FlowChart=lambda function, flags: (
                NS(
                    id=0,
                    start_ea=function.start_ea,
                    end_ea=function.end_ea,
                    preds=lambda: (),
                    succs=lambda: (),
                ),
            ),
        ),
        "ida_ida": NS(
            f_ELF=18,
            inf_get_filetype=lambda: 18,
            inf_get_procname=lambda: "riscv",
            inf_is_32bit_exactly=lambda: True,
            inf_is_be=lambda: False,
        ),
        "ida_idaapi": NS(BADADDR=-1),
        "ida_idp": NS(
            get_idp_name=lambda: "riscv",
            ph_get_regnames=regnames,
            ph_get_id=lambda: 15,
            ph_get_version=lambda: 1,
            ph_get_flag=lambda: 0,
            ph_get_cnbits=lambda: 8,
            ph_get_dnbits=lambda: 8,
        ),
        "ida_kernwin": NS(get_kernel_version=kernel_version),
        "ida_loader": NS(get_fileregion_offset=lambda ea: ea - image_base),
        "ida_name": NS(get_name_ea=lambda _bad, symbol: symbol_eas.get(symbol, -1)),
        "ida_nalt": NS(
            get_input_file_path=lambda: str(binary),
            retrieve_input_file_sha256=lambda: hashlib.sha256(data).digest(),
            get_imagebase=lambda: image_base,
        ),
        "ida_pro": NS(is_main_thread=lambda: True),
        "ida_ua": NS(
            insn_t=Instruction,
            decode_insn=decode_insn,
            o_void=0,
            o_reg=1,
            o_mem=2,
            o_phrase=3,
            o_displ=4,
            o_imm=5,
            o_far=6,
            o_near=7,
        ),
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    for name in ("ida_hexrays", "ida_dbg", "ida_idd", "unicorn"):
        monkeypatch.setitem(sys.modules, name, _ForbiddenModule())
    return request, state, modules


def test_capture_uses_structured_sdk_only_and_preserves_macro_operand_evidence(
    monkeypatch, tmp_path
):
    request, state, _ = _install_sdk(monkeypatch, tmp_path, unknown_operand=True)
    capture = extractor.capture(request)
    assert capture.backend == BACKEND_IDENTITY
    assert capture.implementation_digest == request.implementation_digest
    assert capture.processor_adapter.module_sha256 == (
        "sha256-v1:" + hashlib.sha256(state["processor_module"].read_bytes()).hexdigest()
    )
    assert capture.target_executed is False
    assert capture.support_status == "unverified"
    assert len(capture.functions) == 6
    first = capture.functions[0].blocks[0].instructions[0]
    assert first.size == 8
    assert first.is_macro is True
    assert first.is_canon is True
    assert first.canonical_feature_bits == 0x202
    assert first.operands[0].operand_type == 99
    assert first.operands[0].specflag1 == 1
    assert {item.code for item in capture.diagnostics} == {
        "capture_only_unverified",
        "opaque_operand_type",
        "operand_spec_layout_unreviewed",
    }
    assert not ({"mnemonic", "disassembly", "text"} & set(first.to_data()))


def test_cancellation_and_deadline_precede_environment_capture(monkeypatch, tmp_path):
    request, state, _ = _install_sdk(monkeypatch, tmp_path)
    with pytest.raises(InterruptedError, match="cancelled"):
        extractor.capture(request, cancelled=lambda: True)
    assert state["kernel_calls"] == 0

    moments = iter((0.0, 31.0))
    with pytest.raises(TimeoutError, match="deadline"):
        extractor.capture(request, monotonic=lambda: next(moments))
    assert state["kernel_calls"] == 0


@pytest.mark.parametrize(
    ("module", "field", "value", "message"),
    [
        ("ida_ida", "inf_get_filetype", lambda: 99, "ELF loader"),
        ("ida_ida", "inf_get_procname", lambda: "metapc", "RISC-V"),
        ("ida_ida", "inf_is_32bit_exactly", lambda: False, "exactly 32-bit"),
        ("ida_ida", "inf_is_be", lambda: True, "little-endian"),
        ("ida_kernwin", "get_kernel_version", lambda: "9.2", "kernel version"),
    ],
)
def test_runtime_identity_near_misses_fail_closed(
    monkeypatch, tmp_path, module, field, value, message
):
    request, _, modules = _install_sdk(monkeypatch, tmp_path)
    setattr(modules[module], field, value)
    with pytest.raises(ContractError, match=message):
        extractor.capture(request)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing_adapter", "artifact unavailable"),
        ("adapter_hash", "processor module digest mismatch"),
        ("ambiguous_idp", "processor module identity mismatch"),
        ("implementation_hash", "implementation digest mismatch"),
    ],
)
def test_request_provenance_is_compared_to_independently_observed_artifacts(
    monkeypatch, tmp_path, mutation, message
):
    request, state, modules = _install_sdk(monkeypatch, tmp_path)
    if mutation == "missing_adapter":
        state["processor_module"].unlink()
    elif mutation == "adapter_hash":
        state["processor_module"].write_bytes(b"different processor module")
    elif mutation == "ambiguous_idp":
        modules["ida_idp"].get_idp_name = lambda: "riscv-or-other"
    else:
        request = replace(request, implementation_digest=_sha("f"))
    with pytest.raises(ContractError, match=message):
        extractor.capture(request)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("decode", "Decode failed"),
        ("missing_bytes", "Missing IDB instruction bytes"),
        ("different_bytes", "IDB instruction bytes differ"),
        ("missing_function", "Missing fixture function selector"),
    ],
)
def test_missing_or_inconsistent_native_evidence_fails_closed(
    monkeypatch, tmp_path, mutation, message
):
    request, state, modules = _install_sdk(monkeypatch, tmp_path)
    if mutation == "decode":
        state["decode_result"] = 0
    elif mutation == "missing_bytes":
        state["idb_bytes"] = b""
    elif mutation == "different_bytes":
        state["idb_bytes"] = b"\xff" * 8
    else:
        modules["ida_name"].get_name_ea = lambda _bad, _symbol: -1
    with pytest.raises(ContractError, match=message):
        extractor.capture(request)


def test_environment_drift_and_output_budget_fail_closed(monkeypatch, tmp_path):
    request, state, _ = _install_sdk(monkeypatch, tmp_path)
    state["register_drift"] = True
    with pytest.raises(ContractError, match="environment drift"):
        extractor.capture(request)

    request, _, _ = _install_sdk(monkeypatch, tmp_path)
    request = replace(request, budgets=replace(request.budgets, max_output_bytes=1))
    with pytest.raises(ContractError, match="output budget"):
        extractor.capture(request)


def test_capture_request_json_has_no_runner_command_or_shell_extension(
    monkeypatch, tmp_path
):
    request, _, _ = _install_sdk(monkeypatch, tmp_path)
    value = request.to_data()
    serialized = json.dumps(value, sort_keys=True)
    assert not ({"command", "args", "shell", "ida_path"} & set(value))
    assert "MMAT_" not in serialized
    assert "hexrays" not in serialized.lower()
