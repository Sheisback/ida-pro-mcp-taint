"""IDA-only static snapshot recorder for the pinned BinCAT Windows x64 PE."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_name
import ida_nalt
import idautils
import idc


EXPECTED_BINARY_SHA256 = (
    "687a36f98a8b62fc0411e0e9e8d09c42608f201a7fe68d2e3ea4272b98fe0a70"
)
SELECTORS = ("custom_crc32", "compute_hash", "main")
LEGACY_X86_TUTORIAL_ANALYSIS_EP = 0x93B


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _instruction(ea: int, image_base: int) -> dict:
    return {
        "rva": ea - image_base,
        "mnemonic": idc.print_insn_mnem(ea),
        "disassembly": idc.generate_disasm_line(ea, 0) or "",
    }


def _function(name: str, image_base: int) -> dict:
    ea = idc.get_name_ea_simple(name)
    if ea == ida_idaapi.BADADDR:
        raise RuntimeError(f"Missing PDB-selected function: {name}")
    function = ida_funcs.get_func(ea)
    if function is None or function.start_ea != ea:
        raise RuntimeError(f"Invalid PDB-selected function: {name}")
    rva = ea - image_base
    if rva == LEGACY_X86_TUTORIAL_ANALYSIS_EP:
        raise RuntimeError("Rejected BinCAT x86 tutorial address for the x64 PE")

    calls = []
    observations = []
    for head in idautils.FuncItems(ea):
        row = _instruction(head, image_base)
        text = row["disassembly"]
        if (
            row["mnemonic"] == "call"
            or "info." in text
            or "[info" in text
            or "_Buffer" in text
            or "byte ptr [" in text
            or " buf" in text
        ):
            observations.append(row)
        if not ida_idp.is_call_insn(head):
            continue
        targets = []
        for target in idautils.CodeRefsFrom(head, False):
            target_function = ida_funcs.get_func(target)
            targets.append(
                {
                    "name": ida_name.get_name(target),
                    "rva": target - image_base,
                    "in_function": target_function is not None,
                }
            )
        calls.append(
            {
                "site_rva": head - image_base,
                "disassembly": text,
                "resolution": "direct" if targets else "unresolved_indirect",
                "targets": targets,
            }
        )
    function_bytes = ida_bytes.get_bytes(ea, function.end_ea - ea)
    if function_bytes is None:
        raise RuntimeError(f"IDA could not read bytes for {name}")
    return {
        "name": name,
        "rva": rva,
        "size": function.end_ea - ea,
        "bytes_sha256": hashlib.sha256(function_bytes).hexdigest(),
        "calls": calls,
        "observations": observations,
    }


def main() -> None:
    ida_auto.auto_wait()
    if len(idc.ARGV) != 2:
        raise RuntimeError("Expected one JSON output path")
    output = Path(idc.ARGV[1])
    input_path = Path(ida_nalt.get_input_file_path())
    input_sha256 = _sha256(input_path)
    if input_sha256 != EXPECTED_BINARY_SHA256:
        raise RuntimeError("IDA input does not match the pinned BinCAT x64 PE")
    if not ida_ida.inf_is_64bit() or ida_ida.inf_get_procname() != "metapc":
        raise RuntimeError("IDA did not load the BinCAT PE as x86-64")
    image_base = ida_nalt.get_imagebase()
    receipt = {
        "schema_version": "bincat-x64-ida-static/1",
        "ida_version": ida_kernwin.get_kernel_version(),
        "processor": ida_ida.inf_get_procname(),
        "bitness": 64,
        "image_base": image_base,
        "input": {
            "sha256": input_sha256,
            "size": input_path.stat().st_size,
        },
        "selector_source": "PDB names plus snapshot-local x64 RVAs",
        "legacy_x86_tutorial_analysis_ep": LEGACY_X86_TUTORIAL_ANALYSIS_EP,
        "functions": [_function(name, image_base) for name in SELECTORS],
        "target_executed": False,
        "debugger_attached": False,
    }
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    idc.qexit(0)


main()
