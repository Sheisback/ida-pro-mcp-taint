"""Device-name and symbolic-link discovery (read-only).

Mirrors the reference ``device_name_finder`` stage: harvest object-manager
device paths from the string database and resolve ``IoCreateSymbolicLink``
arguments by bounded back-walk. No FLOSS-style carving or memory scanning is
performed; only IDA's own decoded strings and code references are used.
"""

from __future__ import annotations

import idaapi
import idc

from ida_pro_mcp.flow_core import driver_triage as core

from ..api_core import _get_strings_cache
from .context import (
    DriverContext,
    expired,
    func_name,
    import_call_sites,
    read_best_string,
)

#: Back-walk budget before an IoCreateSymbolicLink call site.
_SYMLINK_LOOKBACK = 64


def find_device_names(ctx: DriverContext, limit: int = 200) -> tuple[list[dict], dict]:
    """Harvest device paths from IDA's string database (read-only)."""
    matches: list[dict] = []
    lowered_prefixes = tuple(p.lower() for p in core.DEVICE_PATH_PREFIXES)
    try:
        strings = _get_strings_cache()
    except Exception:
        return matches, {"strings_scanned": 0, "truncated": False}
    for ea, text in strings:
        if expired():
            ctx.limitations.append("device-name scan hit the tool deadline (partial)")
            break
        lowered = text.lower()
        if any(lowered.startswith(p) for p in lowered_prefixes):
            matches.append({"addr": hex(ea), "text": text, "source": "strings"})
            if len(matches) >= limit:
                break
    return matches, {"strings_scanned": len(strings), "truncated": len(matches) >= limit}


def _lea_string_target(item_ea: int) -> tuple[int | None, str | None]:
    """Resolve `lea reg, [addr]` to (addr, string) when it points at text."""
    try:
        if idc.print_insn_mnem(item_ea) != "lea":
            return None, None
        target = int(idc.get_operand_value(item_ea, 1))
    except Exception:
        return None, None
    if target in (0, idaapi.BADADDR):
        return None, None
    text = read_best_string(target)
    if not text or ("\\" not in text and "/" not in text):
        return None, None
    return target, text


def find_symbolic_links(ctx: DriverContext) -> tuple[list[dict], dict]:
    """Resolve IoCreateSymbolicLink path arguments by bounded back-walk."""
    links: list[dict] = []
    stats = {"call_sites": 0, "resolved": 0, "unresolved": 0}
    import_eas: list[int] = []
    for name in ("IoCreateSymbolicLink", "NtCreateSymbolicLinkObject"):
        import_eas.extend(ctx.imports_map.get(name, []))
    for import_ea in import_eas:
        for site in import_call_sites(import_ea):
            if expired():
                ctx.limitations.append("symlink scan hit the tool deadline (partial)")
                return links, stats
            stats["call_sites"] += 1
            try:
                func = idaapi.get_func(site)
                func_start = func.start_ea if func else 0
            except Exception:
                func_start = 0
            found: list[dict] = []
            cursor = site
            for _ in range(_SYMLINK_LOOKBACK):
                try:
                    cursor = idc.prev_head(cursor, func_start)
                except Exception:
                    break
                if cursor == idaapi.BADADDR or cursor <= func_start:
                    break
                target, text = _lea_string_target(cursor)
                if target is not None and text is not None:
                    found.append({"addr": hex(target), "text": text})
                    if len(found) >= 2:
                        break
            if found:
                stats["resolved"] += 1
            else:
                stats["unresolved"] += 1
            links.append(
                {
                    "call_site": hex(site),
                    "function": func_name(site),
                    "paths": found,
                    "attribution": "nearest path-like lea operands; argument order unverified",
                    "method": f"back-walk up to {_SYMLINK_LOOKBACK} instructions",
                }
            )
    return links, stats
