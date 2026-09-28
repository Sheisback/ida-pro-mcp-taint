"""Driver export audit (read-only).

Mirrors the reference exports audit: enumerate PE exports and report the ones
with no internal code cross-references as attack-surface review leads. Entry
points that are never called internally by design (DriverEntry family) are
skipped rather than reported.
"""

from __future__ import annotations

from ida_pro_mcp.flow_core import driver_triage as core

from .. import compat
from .context import (
    DriverContext,
    count_code_xrefs,
    expired,
)


def audit(ctx: DriverContext) -> tuple[list[dict], dict]:
    """Audit exports for zero internal code references."""
    leads: list[dict] = []
    stats = {"exports": 0, "zero_xref": 0, "skipped_entry": 0}
    try:
        total = compat.get_entry_qty()
    except Exception:
        ctx.limitations.append("export enumeration unavailable")
        return leads, stats
    for index in range(total):
        if expired():
            ctx.limitations.append("export audit hit the tool deadline (partial)")
            break
        try:
            ordinal = compat.get_entry_ordinal(index)
            ea = compat.get_entry(ordinal)
            name = compat.get_entry_name(ordinal) or ""
        except Exception:
            continue
        stats["exports"] += 1
        if name in core.DRIVER_ENTRY_NAMES:
            stats["skipped_entry"] += 1
            continue
        count, _capped = count_code_xrefs(ea)
        if count == 0:
            stats["zero_xref"] += 1
            leads.append(
                core.ReviewLead(
                    check="exports_audit",
                    severity=core.SEV_INFO,
                    title=f"Export with no internal callers: {name or hex(ea)}",
                    detail=(
                        "No code in this binary calls the export; external "
                        "callers (user mode, other drivers) may still reach it."
                    ),
                    function=name or None,
                    addr=hex(ea),
                    evidence={"ordinal": ordinal},
                    method="export table plus code-xref count",
                ).as_dict()
            )
    return leads, stats
