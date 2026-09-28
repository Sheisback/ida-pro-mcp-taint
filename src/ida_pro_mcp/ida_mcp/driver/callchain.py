"""Handler-to-sink call-chain tracing (read-only).

Mirrors the reference ``callchain`` stage: build a bounded callee map from
dispatcher seeds and search it for paths to sensitive sinks. Name matching is
import-aware (an imported call resolves through its ``__imp_`` slot), and
indirect calls are never guessed: they stay unresolved in the reported stats.
"""

from __future__ import annotations

import idaapi

from ida_pro_mcp.flow_core import driver_triage as core

from .context import (
    DriverContext,
    calls_in_func,
    expired,
    func_name,
)


def _display(node: str) -> str:
    if node.startswith("import:"):
        return node[len("import:"):]
    try:
        return func_name(int(node, 16)) or node
    except Exception:
        return node


def _build_adjacency(
    seeds: list[int],
    max_depth: int,
    max_nodes: int,
) -> tuple[dict[str, list[str]], dict]:
    """Build a bounded callee adjacency map from seed functions."""
    adjacency: dict[str, list[str]] = {}
    unresolved_indirect = 0
    frontier = [hex(s) for s in seeds]
    seen = set(frontier)
    for _depth in range(max_depth + 1):
        if expired() or len(seen) >= max_nodes:
            break
        nxt: list[str] = []
        for node in frontier:
            if node.startswith("import:"):
                adjacency.setdefault(node, [])
                continue
            try:
                func_ea = int(node, 16)
            except Exception:
                continue
            callees: list[str] = []
            for _call_ea, api_name, target in calls_in_func(func_ea):
                if target is not None and idaapi.get_func(target) is not None:
                    child = hex(idaapi.get_func(target).start_ea)
                elif api_name:
                    child = f"import:{api_name}"
                else:
                    unresolved_indirect += 1
                    continue
                if child not in callees:
                    callees.append(child)
                if child not in seen and len(seen) < max_nodes:
                    seen.add(child)
                    nxt.append(child)
            adjacency[node] = callees
        frontier = [n for n in nxt if not n.startswith("import:")]
        if not frontier:
            break
    return adjacency, {"unresolved_indirect": unresolved_indirect}


def trace(
    ctx: DriverContext,
    seeds: list[int],
    *,
    max_depth: int = 6,
    max_paths: int = 50,
    max_nodes: int = 5000,
) -> tuple[list[dict], dict]:
    """Trace bounded paths from seeds to sensitive sinks."""
    if not seeds:
        return [], {"paths": 0, "reason": "no seed functions available"}
    adjacency, build_stats = _build_adjacency(seeds, max_depth, max_nodes)
    targets = {f"import:{name}" for name in core.SENSITIVE_SINKS} | {
        node
        for node in adjacency
        if not node.startswith("import:") and _display(node) in core.SENSITIVE_SINKS
    }
    seed_ids = [hex(s) for s in seeds]
    paths, stats = core.trace_paths(
        adjacency, seed_ids, targets,
        max_depth=max_depth, max_paths=max_paths, max_nodes=max_nodes,
    )
    stats.update(build_stats)
    stats["unknown_seeds"] = [
        _display(s) for s in stats.get("unknown_seeds", [])
    ]
    rendered = []
    for path in paths:
        sink_name = _display(path.sink)
        rendered.append(
            {
                "nodes": [_display(n) for n in path.nodes],
                "node_addrs": list(path.nodes),
                "sink": sink_name,
                "sink_severity": core.severity_name(
                    core.SENSITIVE_SINKS.get(sink_name, core.SEV_MEDIUM)
                ),
                "depth": path.depth,
            }
        )
    if build_stats["unresolved_indirect"]:
        ctx.limitations.append(
            "indirect calls are not resolved; chains through them are missing (partial)"
        )
    return rendered, stats


def transitive_callees(
    seeds: list[int],
    max_depth: int = 4,
    max_nodes: int = 2000,
) -> tuple[set[int], dict]:
    """Collect the transitive callee closure of seed functions (bounded)."""
    seen: set[int] = set()
    for seed in seeds:
        try:
            func = idaapi.get_func(seed)
            seen.add(func.start_ea if func else seed)
        except Exception:
            seen.add(seed)
    frontier = list(seen)
    for _depth in range(max_depth):
        if expired() or len(seen) >= max_nodes:
            break
        nxt: list[int] = []
        for func_ea in frontier:
            for _call_ea, _name, target in calls_in_func(func_ea):
                if target is None:
                    continue
                try:
                    target_func = idaapi.get_func(target)
                except Exception:
                    continue
                if target_func is None or idaapi.get_func(target) is None:
                    continue
                entry = target_func.start_ea
                if entry not in seen and len(seen) < max_nodes:
                    seen.add(entry)
                    nxt.append(entry)
        frontier = nxt
        if not frontier:
            break
    return seen, {"closure_size": len(seen), "max_depth": max_depth}
