"""Privileged-instruction collection (read-only).

Mirrors the reference opcode stage in its scoped form: scan handler-reachable
functions for port I/O, control/debug-register moves, and machine-control
instructions. Whole-segment linear scanning is intentionally not offered; it
is noisy and the scoped form covers the triage need.
"""

from __future__ import annotations

import re

import idc

from ida_pro_mcp.flow_core import driver_triage as core

from .context import (
    DriverContext,
    expired,
    func_name,
    iter_func_items,
)

#: Matches cr0-cr15 / dr0-dr15 register operands.
_CONTROL_REG = re.compile(r"\b[cd]r(?:1[0-5]|[0-9])\b", re.IGNORECASE)


def collect(
    ctx: DriverContext,
    func_eas: list[int],
    max_hits: int = 500,
) -> tuple[list[dict], dict]:
    """Collect privileged instructions across the given functions."""
    hits: list[dict] = []
    stats = {"functions_scanned": 0, "truncated": False}
    for func_ea in func_eas:
        if len(hits) >= max_hits or expired():
            stats["truncated"] = True
            break
        stats["functions_scanned"] += 1
        name = func_name(func_ea) or hex(func_ea)
        for item_ea in iter_func_items(func_ea):
            if len(hits) >= max_hits:
                stats["truncated"] = True
                break
            try:
                mnem = (idc.print_insn_mnem(item_ea) or "").lower()
            except Exception:
                continue
            level = core.PRIVILEGED_MNEMONICS.get(mnem)
            detail = mnem
            if level is None and mnem == "mov":
                try:
                    operands = " ".join(
                        idc.print_operand(item_ea, n) or ""
                        for n in range(2)
                    )
                except Exception:
                    continue
                if _CONTROL_REG.search(operands):
                    level = core.SEV_MEDIUM
                    detail = f"mov {operands.strip()}"
            if level is None:
                continue
            hits.append(
                {
                    "addr": hex(item_ea),
                    "function": name,
                    "mnemonic": mnem,
                    "detail": detail,
                    "severity": core.severity_name(level),
                    "severity_rank": level,
                }
            )
    return hits, stats
