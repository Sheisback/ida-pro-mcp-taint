"""Per-IOCTL risk finalization (read-only).

Mirrors the reference ``scoring`` stage: start from the transfer-method and
access-mode base score, then bump codes whose handler closure reaches a
dangerous sink. Attribution in this port is dispatcher-closure granularity,
so every sink bump is capped and labeled imprecise rather than forced.
"""

from __future__ import annotations

from ida_pro_mcp.flow_core import driver_triage as core


def finalize(candidates: list[dict], call_paths: list[dict]) -> list[dict]:
    """Attach severity and risk reasons to every IOCTL candidate."""
    sinks_by_seed: dict[str, set[str]] = {}
    sinks_by_member: dict[str, set[str]] = {}
    for path in call_paths:
        addrs = path.get("node_addrs", [])
        sink = path.get("sink", "")
        if not sink:
            continue
        if addrs:
            sinks_by_seed.setdefault(addrs[0], set()).add(sink)
        for member in addrs:
            sinks_by_member.setdefault(member, set()).add(sink)
    finalized: list[dict] = []
    for candidate in candidates:
        decoded_proxy = {
            "method_name": candidate.get("method", ""),
            "access_name": candidate.get("access", ""),
        }
        level, points, reasons = core.score_ioctl_base(decoded_proxy)
        func_addr = candidate.get("function_addr", "")
        sinks = set(sinks_by_seed.get(func_addr, set()))
        sinks |= set(sinks_by_member.get(func_addr, set()))
        sink_level = max(
            (core.SENSITIVE_SINKS.get(name, core.SEV_MEDIUM) for name in sinks),
            default=core.SEV_INFO,
        )
        bumped, notes = core.apply_sink_bump(
            level, points, sink_level, sinks, precise_attribution=False
        )
        record = dict(candidate)
        record.update(
            {
                "severity": core.severity_name(bumped),
                "severity_rank": bumped,
                "risk_points": points,
                "risk_reasons": reasons + notes,
                "reached_sinks": sorted(sinks),
            }
        )
        finalized.append(record)
    finalized.sort(key=lambda c: (-c["severity_rank"], c["code_int"]))
    return finalized
