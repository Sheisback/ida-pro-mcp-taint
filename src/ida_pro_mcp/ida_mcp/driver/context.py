"""Per-run driver-triage state and shared IDA helpers.

Mirrors the role of ``utils.AnalysisContext`` plus the small shared lookups in
the reference workflow. All helpers are read-only; expensive walks honor the
current tool deadline and stop with partial results instead of overrunning.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterator

import idaapi
import idautils
import idc

from ..sync import get_tool_deadline


@dataclass
class DriverContext:
    """Mutable per-run state threaded through every triage stage."""

    is_pe: bool = False
    is_64bit: bool = True
    driver_entry_ea: int | None = None
    driver_entry_name: str | None = None
    real_entry_ea: int | None = None
    framework: str = "unknown"
    framework_evidence: list[str] = field(default_factory=list)
    dispatchers: list[dict] = field(default_factory=list)
    imports_map: dict[str, list[int]] = field(default_factory=dict)
    functions_map: dict[str, int] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)


def expired() -> bool:
    """True when the current tool call has passed its deadline."""
    deadline = get_tool_deadline()
    return deadline is not None and time.monotonic() >= deadline


def func_name(ea: int) -> str:
    """Best-effort function name for an address (never raises)."""
    try:
        name = idc.get_func_name(ea) or idc.get_name(ea) or ""
    except Exception:
        return ""
    return name


def func_range(ea: int) -> tuple[int, int] | None:
    """Return (start, end) of the function containing ea, or None."""
    try:
        func = idaapi.get_func(ea)
    except Exception:
        return None
    if func is None:
        return None
    return (func.start_ea, func.end_ea)


def is_library_func(ea: int) -> bool:
    """True when IDA flags the function as library (FLIRT) code."""
    try:
        func = idaapi.get_func(ea)
        return bool(func and func.flags & idaapi.FUNC_LIB)
    except Exception:
        return False


def iter_func_items(ea: int, limit: int = 20000) -> Iterator[int]:
    """Yield instruction/data heads of a function, bounded and deadline-aware."""
    try:
        for index, item_ea in enumerate(idautils.FuncItems(ea)):
            if index >= limit or expired():
                break
            yield item_ea
    except Exception:
        return


def strip_import_name(raw: str) -> str:
    """Normalize a call operand or import label to a plain API name."""
    name = (raw or "").strip().split(":")[-1]
    for prefix in ("__imp_", "_", "imp_"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    return name.split("@")[0]


def _is_thunk_func(func) -> bool:
    """True when a function only forwards to another target (jump thunk)."""
    try:
        if func.flags & idaapi.FUNC_THUNK:
            return True
        tiny = (func.end_ea - func.start_ea) <= 32
        first_mnem = idc.print_insn_mnem(func.start_ea) or ""
        return bool(tiny and first_mnem == "jmp")
    except Exception:
        return False


def _through_thunk(target_ea: int | None) -> int | None:
    """Follow jump-thunk forwarders (e.g. mingw `*_0` thunks) to the import."""
    target = target_ea
    for _ in range(2):
        if target in (None, idaapi.BADADDR):
            return None
        try:
            func = idaapi.get_func(target)
        except Exception:
            return target
        if func is None or target != func.start_ea:
            return target
        if not _is_thunk_func(func):
            return target
        try:
            nxt = int(idc.get_operand_value(func.start_ea, 0))
        except Exception:
            return target
        if nxt in (0, idaapi.BADADDR, target):
            return target
        target = nxt
    return target


def _thunk_followers(import_ea: int) -> list[tuple[int, int]]:
    """Return (thunk_start, thunk_end) ranges forwarding to an import."""
    ranges: list[tuple[int, int]] = []
    try:
        for xref in idautils.XrefsTo(import_ea, 0):
            if xref.iscode:
                continue
            try:
                func = idaapi.get_func(xref.frm)
            except Exception:
                continue
            if func is None or not _is_thunk_func(func):
                continue
            ranges.append((func.start_ea, func.end_ea))
    except Exception:
        pass
    return ranges


def import_call_sites(import_ea: int, cap: int = 2000) -> list[int]:
    """Call sites reaching an import directly or through a jump thunk.

    Forwarding jumps inside the thunks themselves are excluded so each
    logical call site is counted once.
    """
    sites: list[int] = []
    seen: set[int] = set()
    thunk_ranges = _thunk_followers(import_ea)

    def _inside_thunk(ea: int) -> bool:
        return any(start <= ea < end for start, end in thunk_ranges)

    def _add(ea: int) -> None:
        if ea not in seen and len(sites) < cap:
            seen.add(ea)
            sites.append(ea)

    try:
        for ref in idautils.CodeRefsTo(import_ea, 0):
            if not _inside_thunk(ref):
                _add(ref)
    except Exception:
        pass
    for start, _end in thunk_ranges:
        try:
            for ref in idautils.CodeRefsTo(start, 0):
                _add(ref)
        except Exception:
            continue
    return sites


def call_target(call_ea: int) -> tuple[str | None, int | None]:
    """Resolve a call site to (api_name, target_ea); either may be None."""
    try:
        target = idc.get_operand_value(call_ea, 0)
    except Exception:
        target = None
    target = _through_thunk(target)
    name: str | None = None
    if target is not None and target != idaapi.BADADDR:
        try:
            raw = idc.get_name(target) or ""
        except Exception:
            raw = ""
        name = strip_import_name(raw) or None
    if name is None:
        try:
            operand = idc.print_operand(call_ea, 0) or ""
        except Exception:
            operand = ""
        name = strip_import_name(operand) or None
    target_ea = target if target not in (None, idaapi.BADADDR) else None
    return name, target_ea


def calls_in_func(ea: int, limit: int = 20000) -> list[tuple[int, str | None, int | None]]:
    """Collect (call_ea, api_name, target_ea) for direct calls in a function."""
    found: list[tuple[int, str | None, int | None]] = []
    for item_ea in iter_func_items(ea, limit):
        try:
            if idc.print_insn_mnem(item_ea) != "call":
                continue
        except Exception:
            continue
        name, target = call_target(item_ea)
        found.append((item_ea, name, target))
    return found


def count_code_xrefs(ea: int, cap: int = 200) -> tuple[int, bool]:
    """Count code xrefs to ea up to cap. Returns (count, capped)."""
    total = 0
    try:
        for _ in idautils.CodeRefsTo(ea, 0):
            total += 1
            if total >= cap:
                return total, True
    except Exception:
        return total, False
    return total, False


def collect_imports() -> tuple[dict[str, list[int]], list[dict]]:
    """Collect imports as (name -> eas, rows). Read-only import-table walk."""
    import ida_nalt

    by_name: dict[str, list[int]] = {}
    rows: list[dict] = []
    try:
        module_qty = ida_nalt.get_import_module_qty()
    except Exception:
        return by_name, rows
    for index in range(module_qty):
        try:
            module = ida_nalt.get_import_module_name(index) or "<unnamed>"
        except Exception:
            module = "<unnamed>"
        collected: list[tuple[int, str]] = []

        def _cb(ea: int, symbol: str | None, ordinal: int) -> bool:
            collected.append((ea, symbol or f"#{ordinal}"))
            return True

        try:
            ida_nalt.enum_import_names(index, _cb)
        except Exception:
            continue
        for ea, name in collected:
            plain = strip_import_name(name)
            by_name.setdefault(plain, []).append(ea)
            rows.append({"addr": hex(ea), "name": name, "module": module})
    return by_name, rows


def collect_function_names(limit: int = 100000) -> dict[str, int]:
    """Map function names to entry addresses (first occurrence wins)."""
    mapping: dict[str, int] = {}
    try:
        for index, ea in enumerate(idautils.Functions()):
            if index >= limit or expired():
                break
            name = func_name(ea)
            if name and name not in mapping:
                mapping[name] = ea
    except Exception:
        pass
    return mapping


def read_c_string(ea: int, max_len: int = 512) -> str | None:
    """Read a narrow string at ea by manual walk; None when empty.

    A manual walk is used instead of get_strlit_contents, which merges
    across adjacent literals on some databases.
    """
    import ida_bytes

    try:
        out = bytearray()
        for offset in range(max_len):
            if not ida_bytes.is_loaded(ea + offset):
                break
            byte = ida_bytes.get_byte(ea + offset)
            if byte == 0:
                break
            out.append(byte)
    except Exception:
        return None
    if not out:
        return None
    try:
        return bytes(out).decode("utf-8", errors="replace")
    except Exception:
        return None


def looks_like_ascii_text(text: str | None, min_len: int = 2) -> bool:
    """True when text is plausible ASCII (rejects wide-misread garbage)."""
    if not text or len(text) < min_len:
        return False
    return all(0x20 <= ord(char) <= 0x7E for char in text)


def read_best_string(ea: int) -> str | None:
    """Read a string trying wide first, then narrow, with ASCII validation.

    Drivers speak UNICODE_STRING, so wide wins ties. Each side must decode
    as plausible ASCII so a misread encoding cannot shadow the real one.
    """
    wide = read_wide_string(ea)
    if looks_like_ascii_text(wide):
        return wide
    narrow = read_c_string(ea)
    if looks_like_ascii_text(narrow):
        return narrow
    return None


def read_wide_string(ea: int, max_chars: int = 256) -> str | None:
    """Read a UTF-16LE string at ea; None when unreadable or empty."""
    import ida_bytes

    try:
        chars: list[str] = []
        for offset in range(max_chars):
            if not ida_bytes.is_loaded(ea + offset * 2):
                break
            code = ida_bytes.get_word(ea + offset * 2)
            if code == 0:
                break
            chars.append(chr(code))
    except Exception:
        return None
    return "".join(chars) or None


def hexrays_ready() -> bool:
    """True when the Hex-Rays decompiler initializes in this session."""
    try:
        import ida_hexrays

        return bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        return False


def try_decompile(ea: int):
    """Decompile ea, returning the cfunc or None on any failure."""
    try:
        import ida_hexrays

        if not ida_hexrays.init_hexrays_plugin():
            return None
        failure = ida_hexrays.hexrays_failure_t()
        cfunc = ida_hexrays.decompile(ea, failure)
        return cfunc or None
    except Exception:
        return None
