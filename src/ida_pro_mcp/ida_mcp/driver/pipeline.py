"""Ordered full-run driver over every triage stage (read-only).

Mirrors the reference ``analysis.run_analysis`` pipeline order: survey the
driver, harvest device/pool evidence, scan dispatchers for IOCTLs, audit
access, trace call chains, run heuristics, audit exports, then finalize
scores. Each stage is isolated so one failure cannot abort the run; the MCP
``driver_*`` tools call the same stages granularly instead of this driver.
"""

from __future__ import annotations

from ida_pro_mcp.flow_core import driver_triage as core

from . import acl as acl_stage
from . import callchain as callchain_stage
from . import devices as devices_stage
from . import dispatch as dispatch_stage
from . import exports_audit as exports_stage
from . import flagging as flagging_stage
from . import heuristics as heuristics_stage
from . import ioctl_scan as ioctl_stage
from . import opcodes as opcode_stage
from . import pooltags as pooltag_stage
from . import scoring as scoring_stage
from .callchain import transitive_callees
from .context import DriverContext, func_range, is_library_func


def _stage(ctx: DriverContext, name: str, func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - stage isolation by design
        ctx.limitations.append(f"stage '{name}' failed: {exc}")
        return None


def _handler_scope(ctx: DriverContext, max_funcs: int = 64) -> list[int]:
    seeds = [int(d["addr"], 16) for d in ctx.dispatchers]
    if not seeds and ctx.real_entry_ea is not None:
        seeds = [ctx.real_entry_ea]
    closure, _info = transitive_callees(seeds, max_depth=4)
    scoped = [f for f in closure if func_range(f) and not is_library_func(f)]
    if len(scoped) > max_funcs:
        ctx.limitations.append(f"handler scope capped at {max_funcs} functions (partial)")
    return sorted(scoped)[:max_funcs]


def run_full(ctx: DriverContext | None = None) -> dict:
    """Run every triage stage and return artifacts plus a summary."""
    ctx = ctx or DriverContext()
    dispatch_stage.populate(ctx)
    artifacts: dict = {"survey": _survey_view(ctx)}
    if not ctx.is_pe or ctx.driver_entry_ea is None:
        artifacts["summary"] = _summarize(ctx, artifacts)
        return artifacts
    devices, _ds = _stage(ctx, "devices", devices_stage.find_device_names, ctx) or ([], {})
    artifacts["device_names"] = devices
    links, _ls = _stage(ctx, "symlinks", devices_stage.find_symbolic_links, ctx) or ([], {})
    artifacts["symbolic_links"] = links
    tags, _ts = _stage(ctx, "pooltags", pooltag_stage.collect, ctx) or ([], {})
    artifacts["pool_tags"] = tags
    dispatch_eas = [int(d["addr"], 16) for d in ctx.dispatchers]
    candidates: list[dict] = []
    scan_out = _stage(ctx, "ioctl_scan", ioctl_stage.scan_dispatchers, ctx, dispatch_eas)
    if scan_out is not None:
        candidates, artifacts["ioctl_stats"] = scan_out
    if not candidates:
        fallback = _stage(
            ctx, "ioctl_fallback", ioctl_stage.scan_iocontrolcode_fallback, ctx, set()
        )
        if fallback is not None:
            candidates, artifacts["ioctl_fallback_stats"] = fallback
    artifacts["ioctls"] = candidates
    acl_leads, _as = _stage(ctx, "acl", acl_stage.audit, ctx) or ([], {})
    artifacts["acl_leads"] = acl_leads
    matches, _fs = _stage(ctx, "flagging", flagging_stage.flag, ctx) or ([], {})
    artifacts["flagged_routines"] = matches
    scope = _handler_scope(ctx)
    artifacts["handler_scope"] = [hex(f) for f in scope]
    paths, _cs = _stage(ctx, "callchain", callchain_stage.trace, ctx, dispatch_eas or scope[:8]) or ([], {})
    artifacts["call_chains"] = paths
    artifacts["ioctls"] = scoring_stage.finalize(candidates, paths)
    opcode_hits, _os = _stage(ctx, "opcodes", opcode_stage.collect, ctx, scope) or ([], {})
    artifacts["privileged_insns"] = opcode_hits
    heur_out = _stage(
        ctx, "heuristics", heuristics_stage.run, ctx, scope,
        dispatchers=set(dispatch_eas), opcode_hits=opcode_hits,
    )
    artifacts["heuristic_leads"] = heur_out[0] if heur_out else []
    export_leads, _es = _stage(ctx, "exports", exports_stage.audit, ctx) or ([], {})
    artifacts["export_leads"] = export_leads
    artifacts["summary"] = _summarize(ctx, artifacts)
    return artifacts


def _survey_view(ctx: DriverContext) -> dict:
    return {
        "is_pe": ctx.is_pe,
        "is_driver": ctx.driver_entry_ea is not None,
        "is_64bit": ctx.is_64bit,
        "driver_entry": (
            {
                "addr": hex(ctx.driver_entry_ea),
                "name": ctx.driver_entry_name,
                "real_entry": hex(ctx.real_entry_ea) if ctx.real_entry_ea else None,
            }
            if ctx.driver_entry_ea is not None
            else None
        ),
        "framework": ctx.framework,
        "framework_evidence": list(ctx.framework_evidence),
        "dispatchers": list(ctx.dispatchers),
        "import_count": sum(len(v) for v in ctx.imports_map.values()),
        "function_count": len(ctx.functions_map),
        "limitations": list(ctx.limitations),
    }


def _summarize(ctx: DriverContext, artifacts: dict) -> dict:
    per_category = {
        key: len(value)
        for key, value in artifacts.items()
        if isinstance(value, list) and key != "handler_scope"
    }
    severity_counts: dict[str, int] = {}
    for bucket in ("acl_leads", "heuristic_leads", "export_leads"):
        for lead in artifacts.get(bucket, []):
            name = lead.get("severity", "INFO")
            severity_counts[name] = severity_counts.get(name, 0) + 1
    for candidate in artifacts.get("ioctls", []):
        name = candidate.get("severity", "INFO")
        severity_counts[name] = severity_counts.get(name, 0) + 1
    return {
        "driver_type": ctx.framework if ctx.driver_entry_ea else "not_driver",
        "per_category": per_category,
        "severity_counts": severity_counts,
        "limitations": list(ctx.limitations),
        "schema_version": core.SCHEMA_VERSION,
    }
