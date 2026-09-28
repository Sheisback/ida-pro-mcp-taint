"""Risky-routine flagging surface (read-only).

Mirrors the reference surface scan that matches imports and call sites
against curated C/Windows routine lists. Matches are review starting points
with xref evidence, not findings: names alone never prove a bug.
"""

from __future__ import annotations

from ida_pro_mcp.flow_core import driver_triage as core

from .context import (
    DriverContext,
    count_code_xrefs,
    expired,
    func_name,
    import_call_sites,
)

#: Cap on sampled call sites kept per matched routine.
_SITE_SAMPLE = 10


def flag(
    ctx: DriverContext,
    extra_names: list[str] | None = None,
    max_matches: int = 500,
) -> tuple[list[dict], dict]:
    """Match risky routines against imports and sample their call sites."""
    wanted: dict[str, tuple[str, str]] = {}
    for name, reason in core.RISKY_C_FUNCS.items():
        wanted[name] = ("c", reason)
    for name, reason in core.RISKY_NT_APIS.items():
        wanted.setdefault(name, ("nt", reason))
    for name in extra_names or []:
        wanted.setdefault(name, ("custom", "analyst-supplied watch name"))
    matches: list[dict] = []
    stats = {"routines_matched": 0, "call_sites": 0, "truncated": False}
    for name in sorted(wanted):
        if len(matches) >= max_matches or expired():
            stats["truncated"] = True
            break
        import_eas = ctx.imports_map.get(name, [])
        local_ea = ctx.functions_map.get(name)
        if not import_eas and local_ea is None:
            continue
        category, reason = wanted[name]
        sites: list[str] = []
        xref_total = 0
        capped = False
        for import_ea in import_eas:
            reached = import_call_sites(import_ea, cap=1000)
            xref_total += len(reached)
            capped = capped or len(reached) >= 1000
            for ref in reached:
                if len(sites) >= _SITE_SAMPLE:
                    break
                sites.append(hex(ref))
        if local_ea is not None:
            count, hit_cap = count_code_xrefs(local_ea)
            xref_total += count
            capped = capped or hit_cap
        stats["routines_matched"] += 1
        stats["call_sites"] += xref_total
        matches.append(
            {
                "name": name,
                "category": category,
                "reason": reason,
                "import_addrs": [hex(ea) for ea in import_eas],
                "local_addr": hex(local_ea) if local_ea is not None else None,
                "xref_count": xref_total,
                "xref_capped": capped,
                "sample_sites": sites,
                "sample_function": func_name(int(sites[0], 16)) if sites else None,
            }
        )
    return matches, stats
