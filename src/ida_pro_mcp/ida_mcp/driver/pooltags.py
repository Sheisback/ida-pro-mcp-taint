"""Pool-tag collection from pool-allocator call sites (read-only).

Mirrors the reference ``dump_pool_tags`` stage: resolve the tag argument of
``ExAllocatePool*`` calls by bounded back-walk. Only tags that decode as four
printable bytes are reported; anything else stays unresolved rather than
guessed.
"""

from __future__ import annotations

import idaapi
import idc

from ida_pro_mcp.flow_core import driver_triage as core

from .context import (
    DriverContext,
    expired,
    func_name,
    import_call_sites,
)

#: Back-walk budget when resolving a tag argument.
_TAG_LOOKBACK = 10


def _decode_tag(raw: int) -> str | None:
    """Decode a 32-bit tag candidate; None unless four printable bytes."""
    chars = [(raw >> shift) & 0xFF for shift in (0, 8, 16, 24)]
    if all(0x20 <= byte <= 0x7E for byte in chars):
        return "".join(chr(byte) for byte in chars)
    return None


def _x64_tag(site: int, func_start: int) -> tuple[str | None, str | None]:
    """Resolve the tag (3rd arg, r8/r8d) on x64 by back-walk."""
    cursor = site
    for _ in range(_TAG_LOOKBACK):
        try:
            cursor = idc.prev_head(cursor, func_start)
        except Exception:
            break
        if cursor == idaapi.BADADDR or cursor <= func_start:
            break
        try:
            if idc.print_insn_mnem(cursor) != "mov":
                continue
            dst = (idc.print_operand(cursor, 0) or "").lower()
        except Exception:
            continue
        if dst not in ("r8", "r8d"):
            continue
        try:
            raw = int(idc.get_operand_value(cursor, 1)) & 0xFFFFFFFF
        except Exception:
            continue
        tag = _decode_tag(raw)
        if tag is not None:
            return tag, hex(cursor)
    return None, None


def _x86_tags(site: int, func_start: int) -> list[tuple[str, str]]:
    """Collect plausible tags from x86 push-immediate sequences."""
    tags: list[tuple[str, str]] = []
    cursor = site
    for _ in range(_TAG_LOOKBACK):
        try:
            cursor = idc.prev_head(cursor, func_start)
        except Exception:
            break
        if cursor == idaapi.BADADDR or cursor <= func_start:
            break
        try:
            if idc.print_insn_mnem(cursor) != "push":
                continue
            raw = int(idc.get_operand_value(cursor, 0)) & 0xFFFFFFFF
        except Exception:
            continue
        tag = _decode_tag(raw)
        if tag is not None:
            tags.append((tag, hex(cursor)))
    return tags


def collect(ctx: DriverContext, max_sites: int = 500) -> tuple[list[dict], dict]:
    """Collect pool tags from allocator call sites."""
    tags: list[dict] = []
    stats = {"call_sites": 0, "resolved": 0, "unresolved": 0}
    for allocator in sorted(core.POOL_ALLOCATORS):
        for import_ea in ctx.imports_map.get(allocator, []):
            sites = import_call_sites(import_ea)
            for site in sites:
                if stats["call_sites"] >= max_sites or expired():
                    ctx.limitations.append("pool-tag scan capped or timed out (partial)")
                    return tags, stats
                stats["call_sites"] += 1
                try:
                    func = idaapi.get_func(site)
                    func_start = func.start_ea if func else 0
                except Exception:
                    func_start = 0
                if ctx.is_64bit:
                    tag, at = _x64_tag(site, func_start)
                    resolved = [(tag, at)] if tag else []
                else:
                    resolved = _x86_tags(site, func_start)
                if resolved:
                    stats["resolved"] += 1
                    for tag_text, tag_ea in resolved:
                        tags.append(
                            {
                                "tag": tag_text,
                                "allocator": allocator,
                                "call_site": hex(site),
                                "tag_site": tag_ea,
                                "function": func_name(site),
                                "method": "argument back-walk",
                            }
                        )
                else:
                    stats["unresolved"] += 1
    if stats["unresolved"]:
        ctx.limitations.append(
            "some pool tags are computed at runtime and cannot be resolved statically"
        )
    return tags, stats
