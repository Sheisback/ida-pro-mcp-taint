"""Windows kernel-driver triage tools (read-only static analysis)."""

from typing import Annotated, TypedDict

from ida_pro_mcp.flow_core import driver_triage as core

from .driver import acl as acl_stage
from .driver import callchain as callchain_stage
from .driver import devices as devices_stage
from .driver import dispatch as dispatch_stage
from .driver import exports_audit as exports_stage
from .driver import flagging as flagging_stage
from .driver import heuristics as heuristics_stage
from .driver import ioctl_scan as ioctl_stage
from .driver import opcodes as opcode_stage
from .driver import pooltags as pooltag_stage
from .driver import scoring as scoring_stage
from .driver.callchain import transitive_callees
from .driver.context import DriverContext, func_range, is_library_func
from .rpc import tool
from .sync import idasync, tool_timeout
from .utils import normalize_list_input, paginate, parse_address, pattern_filter


class DriverSurveyResult(TypedDict, total=False):
    is_pe: bool
    is_driver: bool
    is_64bit: bool
    driver_entry: dict | None
    framework: str
    framework_evidence: list[str]
    dispatchers: list[dict]
    import_count: int
    function_count: int
    limitations: list[str]


class DecodeIoctlsResult(TypedDict, total=False):
    results: list[dict]
    ntstatus_source: str
    limitations: list[str]


class FindIoctlsResult(TypedDict, total=False):
    candidates: list[dict]
    next_offset: int | None
    stats: dict
    limitations: list[str]


class FindDevicesResult(TypedDict, total=False):
    device_names: list[dict]
    symbolic_links: list[dict]
    stats: dict
    limitations: list[str]


class LeadsResult(TypedDict, total=False):
    leads: list[dict]
    next_offset: int | None
    stats: dict
    limitations: list[str]


def _fresh_context() -> DriverContext:
    """Build a populated per-call triage context (read-only IDA walks)."""
    return dispatch_stage.populate(DriverContext())


def _resolve_eas(values: list[str] | str) -> list[int]:
    """Resolve address/name inputs to ints, skipping unresolvable entries."""
    resolved: list[int] = []
    for value in normalize_list_input(values):
        try:
            resolved.append(parse_address(value))
        except Exception:
            continue
    return resolved


def _not_driver(ctx: DriverContext) -> dict:
    return {
        "reason": "not a Windows driver binary (no PE driver entry found)",
        "is_pe": ctx.is_pe,
        "limitations": list(ctx.limitations),
    }


@tool
@idasync
@tool_timeout(120.0)
def driver_survey() -> DriverSurveyResult:
    """Survey a Windows driver binary without changing it. Reports PE status, DriverEntry, framework classification, and discovered dispatchers with evidence. Use this first to decide whether the deeper driver_* tools apply to the current database."""
    ctx = _fresh_context()
    entry = None
    if ctx.driver_entry_ea is not None:
        entry = {
            "addr": hex(ctx.driver_entry_ea),
            "name": ctx.driver_entry_name,
            "real_entry": hex(ctx.real_entry_ea) if ctx.real_entry_ea else None,
        }
    return {
        "is_pe": ctx.is_pe,
        "is_driver": ctx.driver_entry_ea is not None,
        "is_64bit": ctx.is_64bit,
        "driver_entry": entry,
        "framework": ctx.framework if ctx.driver_entry_ea is not None else "not_driver",
        "framework_evidence": list(ctx.framework_evidence),
        "dispatchers": list(ctx.dispatchers),
        "import_count": sum(len(v) for v in ctx.imports_map.values()),
        "function_count": len(ctx.functions_map),
        "limitations": list(ctx.limitations),
    }


@tool
@idasync
@tool_timeout(60.0)
def driver_decode_ioctls(
    codes: Annotated[list[str] | str, "IOCTL code(s) as hex (0x222000) or decimal"],
) -> DecodeIoctlsResult:
    """Decode Windows IOCTL codes into device, function, method, and access fields. Each result carries a plausibility verdict, a base triage score, and the NTSTATUS source used for filtering. Works on any binary since decoding needs no driver context."""
    from .driver.ioctl_scan import ntstatus_values_from_db

    extra, source = ntstatus_values_from_db()
    results: list[dict] = []
    for raw in normalize_list_input(codes):
        try:
            code = core.parse_ioctl_code(raw)
        except ValueError as exc:
            results.append({"input": str(raw), "error": str(exc)})
            continue
        decoded = core.decode_ioctl(code)
        ok, reason = core.is_plausible_ioctl(code, extra)
        level, points, reasons = core.score_ioctl_base(decoded)
        results.append(
            {
                "input": str(raw),
                "code": decoded["code"],
                "code_int": decoded["code_int"],
                "device_name": decoded["device_name"],
                "function_code": decoded["function"],
                "method": decoded["method_name"],
                "access": decoded["access_name"],
                "plausible": ok,
                "plausibility": reason,
                "severity": core.severity_name(level),
                "severity_rank": level,
                "risk_points": points,
                "risk_reasons": reasons,
            }
        )
    return {"results": results, "ntstatus_source": source, "limitations": []}


@tool
@idasync
@tool_timeout(240.0)
def driver_find_ioctls(
    dispatchers: Annotated[
        list[str] | str, "Dispatcher address(es)/name(s); empty auto-discovers"
    ] = "",
    include_decompiler: Annotated[bool, "Use Hex-Rays ctree constants when available"] = True,
    include_fallback: Annotated[bool, "Bounded IoControlCode fallback when empty"] = True,
    offset: Annotated[int, "Pagination start index"] = 0,
    count: Annotated[int, "Max candidates (0=all)"] = 200,
) -> FindIoctlsResult:
    """Discover IOCTLs handled by driver dispatchers. Collects decompiler constants, switch-table cases, and gated immediates, excludes outbound codes, and risk-scores each survivor. Returns paginated candidates with collection methods and confidence levels."""
    ctx = _fresh_context()
    if not ctx.is_pe or ctx.driver_entry_ea is None:
        return {"candidates": [], "next_offset": None, "stats": {}, **_not_driver(ctx)}
    wanted = _resolve_eas(dispatchers)
    dispatch_eas = wanted or [int(d["addr"], 16) for d in ctx.dispatchers]
    candidates, stats = ioctl_stage.scan_dispatchers(
        ctx, dispatch_eas, include_decompiler=include_decompiler
    )
    if not candidates and include_fallback and not wanted:
        fallback, fallback_stats = ioctl_stage.scan_iocontrolcode_fallback(ctx, set())
        candidates = fallback
        stats["fallback"] = fallback_stats
    paths, _trace_stats = callchain_stage.trace(ctx, dispatch_eas or [ctx.driver_entry_ea])
    scored = scoring_stage.finalize(candidates, paths)
    page = paginate(scored, offset, count)
    return {
        "candidates": page["data"],
        "next_offset": page["next_offset"],
        "stats": stats,
        "limitations": list(ctx.limitations),
    }


@tool
@idasync
@tool_timeout(120.0)
def driver_find_devices() -> FindDevicesResult:
    """Find device exposure evidence in a driver. Harvests object-manager device paths from strings and resolves IoCreateSymbolicLink arguments by bounded back-walk. Symbolic-link argument order stays unverified and is labeled as such."""
    ctx = _fresh_context()
    if not ctx.is_pe or ctx.driver_entry_ea is None:
        return {"device_names": [], "symbolic_links": [], "stats": {}, **_not_driver(ctx)}
    names, name_stats = devices_stage.find_device_names(ctx)
    links, link_stats = devices_stage.find_symbolic_links(ctx)
    return {
        "device_names": names,
        "symbolic_links": links,
        "stats": {"names": name_stats, "symlinks": link_stats},
        "limitations": list(ctx.limitations),
    }


@tool
@idasync
@tool_timeout(120.0)
def driver_audit_acl() -> LeadsResult:
    """Audit device-creation call sites for access-control review leads. Flags default-ACL IoCreateDevice calls and resolves IoCreateDeviceSecure SDDL strings to spot broadly accessible descriptors. Leads are static approximations, not effective-ACL verdicts."""
    ctx = _fresh_context()
    if not ctx.is_pe or ctx.driver_entry_ea is None:
        return {"leads": [], "next_offset": None, "stats": {}, **_not_driver(ctx)}
    leads, stats = acl_stage.audit(ctx)
    return {
        "leads": leads,
        "next_offset": None,
        "stats": stats,
        "limitations": list(ctx.limitations),
    }


class PooltagsResult(TypedDict, total=False):
    tags: list[dict]
    next_offset: int | None
    stats: dict
    limitations: list[str]


class FlaggedResult(TypedDict, total=False):
    matches: list[dict]
    next_offset: int | None
    stats: dict
    limitations: list[str]


class TraceResult(TypedDict, total=False):
    paths: list[dict]
    stats: dict
    limitations: list[str]


@tool
@idasync
@tool_timeout(120.0)
def driver_find_pooltags(
    max_sites: Annotated[int, "Max allocator call sites to inspect"] = 500,
    offset: Annotated[int, "Pagination start index"] = 0,
    count: Annotated[int, "Max tags (0=all)"] = 200,
) -> PooltagsResult:
    """Collect pool tags from kernel pool-allocator call sites. Resolves tag arguments by bounded back-walk and reports only values decoding as four printable bytes. Runtime-computed tags stay unresolved instead of being guessed."""
    ctx = _fresh_context()
    if not ctx.is_pe or ctx.driver_entry_ea is None:
        return {"tags": [], "next_offset": None, "stats": {}, **_not_driver(ctx)}
    tags, stats = pooltag_stage.collect(ctx, max_sites=max_sites)
    page = paginate(tags, offset, count)
    return {
        "tags": page["data"],
        "next_offset": page["next_offset"],
        "stats": stats,
        "limitations": list(ctx.limitations),
    }


@tool
@idasync
@tool_timeout(120.0)
def driver_flag_functions(
    extra_names: Annotated[list[str] | str, "Extra routine name(s) to watch"] = "",
    match_filter: Annotated[str, "Glob/regex filter on routine names"] = "",
    offset: Annotated[int, "Pagination start index"] = 0,
    count: Annotated[int, "Max matches (0=all)"] = 200,
) -> FlaggedResult:
    """Flag risky C and kernel routines referenced by the driver. Matches curated routine lists against imports and samples call sites with xref counts. Matches are review starting points; names alone never prove a bug."""
    ctx = _fresh_context()
    if not ctx.is_pe or ctx.driver_entry_ea is None:
        return {"matches": [], "next_offset": None, "stats": {}, **_not_driver(ctx)}
    matches, stats = flagging_stage.flag(ctx, extra_names=_resolve_names(extra_names))
    matches = pattern_filter(matches, match_filter, "name")
    page = paginate(matches, offset, count)
    return {
        "matches": page["data"],
        "next_offset": page["next_offset"],
        "stats": stats,
        "limitations": list(ctx.limitations),
    }


def _resolve_names(values: list[str] | str) -> list[str]:
    return [str(v).strip() for v in normalize_list_input(values) if str(v).strip()]


@tool
@idasync
@tool_timeout(120.0)
def driver_audit_exports() -> LeadsResult:
    """Audit driver exports for missing internal callers. Reports exports with zero internal code references as attack-surface review leads. DriverEntry symbols are skipped since they are never called internally by design."""
    ctx = _fresh_context()
    if not ctx.is_pe or ctx.driver_entry_ea is None:
        return {"leads": [], "next_offset": None, "stats": {}, **_not_driver(ctx)}
    leads, stats = exports_stage.audit(ctx)
    return {
        "leads": leads,
        "next_offset": None,
        "stats": stats,
        "limitations": list(ctx.limitations),
    }


@tool
@idasync
@tool_timeout(180.0)
def driver_trace_calls(
    seeds: Annotated[list[str] | str, "Seed address(es)/name(s); empty uses dispatchers"] = "",
    max_depth: Annotated[int, "Max BFS depth from seeds"] = 6,
    max_paths: Annotated[int, "Max paths to return"] = 50,
) -> TraceResult:
    """Trace bounded call paths from dispatchers to sensitive sinks. Builds a callee map from seeds and searches it breadth-first for documented sink routines. Indirect calls are never guessed and stay unresolved in the stats."""
    ctx = _fresh_context()
    if not ctx.is_pe or ctx.driver_entry_ea is None:
        return {"paths": [], "stats": {}, **_not_driver(ctx)}
    wanted = _resolve_eas(seeds)
    seed_eas = wanted or [int(d["addr"], 16) for d in ctx.dispatchers]
    if not seed_eas and ctx.real_entry_ea is not None:
        seed_eas = [ctx.real_entry_ea]
    paths, stats = callchain_stage.trace(
        ctx, seed_eas, max_depth=max_depth, max_paths=max_paths
    )
    return {"paths": paths, "stats": stats, "limitations": list(ctx.limitations)}


@tool
@idasync
@tool_timeout(300.0)
def driver_triage_leads(
    checks: Annotated[list[str] | str, "Check name(s); empty runs all eleven"] = "",
    max_scope_funcs: Annotated[int, "Max handler-closure functions to scan"] = 64,
    offset: Annotated[int, "Pagination start index"] = 0,
    count: Annotated[int, "Max leads (0=all)"] = 200,
) -> LeadsResult:
    """Run heuristic triage checks over dispatcher-reachable code. Covers unvalidated copies, pool allocation, privileged instructions, physical-memory references, MDL use, IRQL overlap, privilege gates, write shapes, double-fetch, and use-after-free. Every output is a manual-review lead, never a vulnerability verdict."""
    ctx = _fresh_context()
    if not ctx.is_pe or ctx.driver_entry_ea is None:
        return {"leads": [], "next_offset": None, "stats": {}, **_not_driver(ctx)}
    dispatch_eas = [int(d["addr"], 16) for d in ctx.dispatchers]
    seeds = dispatch_eas or ([ctx.real_entry_ea] if ctx.real_entry_ea else [])
    closure, _info = transitive_callees(seeds, max_depth=4)
    scope = sorted(
        f for f in closure if func_range(f) is not None and not is_library_func(f)
    )
    if len(scope) > max_scope_funcs:
        ctx.limitations.append(
            f"handler scope capped at {max_scope_funcs} functions (partial)"
        )
        scope = scope[:max_scope_funcs]
    opcode_hits, _op_stats = opcode_stage.collect(ctx, scope)
    wanted = _resolve_names(checks)
    leads, stats = heuristics_stage.run(
        ctx,
        scope,
        dispatchers=set(dispatch_eas),
        checks=wanted or None,
        opcode_hits=opcode_hits,
    )
    stats["privileged_insn_hits"] = len(opcode_hits)
    page = paginate(leads, offset, count)
    return {
        "leads": page["data"],
        "next_offset": page["next_offset"],
        "stats": stats,
        "limitations": list(ctx.limitations),
    }


__all__ = [
    "driver_survey",
    "driver_decode_ioctls",
    "driver_find_ioctls",
    "driver_find_devices",
    "driver_audit_acl",
    "driver_find_pooltags",
    "driver_flag_functions",
    "driver_audit_exports",
    "driver_trace_calls",
    "driver_triage_leads",
]
