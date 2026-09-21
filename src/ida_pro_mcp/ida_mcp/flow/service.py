"""Lazy worker adapter. Host metadata only on IDA main thread; core jobs off-thread."""

import hashlib
import os
from pathlib import Path

from ida_pro_mcp.flow_core import digest
from ida_pro_mcp.flow_core.build_identity import BUILD_ID
from ida_pro_mcp.flow_core.host_identity import identity
from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
from ida_pro_mcp.flow_core.persistence import require
from ida_pro_mcp.flow_core.query import Queries, artifact_page, evidence_chunks
from ida_pro_mcp.flow_core.runtime import Handler
from ida_pro_mcp.flow_core.runtime_contracts import RuntimeScope
from ida_pro_mcp.flow_core.ssa import SSAProgram
from ..sync import idasync
from . import extractor, runtime
from .summary_catalog import EMPTY_CATALOG, bind_call, compose_binding


def build_digest():
    return BUILD_ID


def reviewed_catalog(_info=None):
    """Resolve the internal immutable catalog used for this runtime scope.

    The shipped runtime starts empty; licensed static-receipt generation supplies
    an explicit reviewed fixture catalog without adding a public tool or a
    function-name lookup path.
    """

    return EMPTY_CATALOG


def _context(selector=None, requested_profile=None):
    import ida_funcs
    import ida_ida
    import ida_kernwin
    import ida_loader
    import ida_nalt
    from ..utils import parse_address

    require(os.name == "posix", "flow_runtime_unavailable_non_posix")
    dbpath = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    require(bool(dbpath), "open_database_required")
    require(
        ida_ida.inf_get_filetype() == ida_ida.f_MACHO
        and ida_ida.inf_is_64bit()
        and not ida_ida.inf_is_be(),
        "experimental_profile_unavailable",
    )
    processor = ida_ida.inf_get_procname()
    require(processor in {"metapc", "ARM"}, "experimental_profile_unavailable")
    profile_id, abi = (
        ("X64-LE", "darwin-x86_64-sysv-derived")
        if processor == "metapc"
        else ("A64-LE", "darwin-aarch64")
    )
    require(requested_profile in {None, profile_id}, "profile_mismatch")
    profile = {
        "profile_id": profile_id,
        "version": 1,
        "abi": abi,
        "maturity": "MMAT_CALLS",
        "bitness": 64,
        "data_endian": "little",
        "instruction_endian": "little",
        "processor": processor,
        "format_id": "FMT-MACHO",
        "platform_tag": "darwin",
        "abi_provenance": {"kind": "experimental_profile_not_abi_inference"},
    }
    binary = (
        "sha256-v1:"
        + hashlib.sha256(Path(ida_nalt.get_input_file_path()).read_bytes()).hexdigest()
    )
    count = ida_ida.inf_get_database_change_count()
    result = {
        "dbpath": dbpath,
        "profile": profile,
        "binary": binary,
        "count": count,
        "ida": ida_kernwin.get_kernel_version(),
    }
    if selector is not None:
        ea = parse_address(selector)
        func = ida_funcs.get_func(ea)
        require(func is not None and func.start_ea == ea, "function_entry_required")
        result["ea"] = ea
    return result


context = idasync(_context)


def _fingerprint(info):
    return digest(
        {k: info[k] for k in ("dbpath", "binary", "count", "ida")}
        | {"build": build_digest()}
    )


@idasync
def _extract(ctx, request):
    before = _context()
    require(_fingerprint(before) == request["fingerprint"], "stale_database")
    require(
        reviewed_catalog(before).catalog_digest == request["summary_digest"],
        "stale_summary_catalog",
    )
    snapshot = extractor.extract_snapshot(
        request["ea"],
        namespace=request["namespace"],
        function_key=request["function_key"],
        profile=request["profile"],
        summary_digest=request["summary_digest"],
        deadline=ctx.deadline,
        cancelled=ctx.cancel.is_set,
        include_calls=True,
    )
    require(_fingerprint(_context()) == request["fingerprint"], "stale_database")
    return snapshot, request


def _analyze(ctx, extracted):
    function, request = extracted
    snapshot = function.snapshot
    memory = build_memory_graph(snapshot)
    program = memory.program
    ctx.check()
    require(_fingerprint(context()) == request["fingerprint"], "stale_database")
    current = get_runtime(context())
    catalog = reviewed_catalog(context())
    require(current.store.scope.fingerprint == request["fingerprint"], "stale_database")
    require(
        snapshot.identity.summary_digest
        == request["summary_digest"]
        == current.store.scope.summary_digest
        == catalog.catalog_digest,
        "stale_summary_catalog",
    )
    calls = []
    for observation in function.calls:
        binding = bind_call(function, observation, catalog, {})
        composition = compose_binding(function, binding, catalog)
        calls.append(
            {"binding": binding.to_data(), "composition": composition.to_data()}
        )
    sid = current.store.put_artifact("snapshot", snapshot)
    gid = current.store.put_artifact("graph", memory.graph)
    pid = current.store.put_artifact("analysis", program.to_data())
    mid = current.store.put_artifact("analysis", memory.plan.to_data())
    rid = current.store.put_artifact("analysis", memory.result.to_data())
    cid = current.store.put_artifact(
        "analysis",
        {
            "schema_version": "flow-call-compositions/1",
            "catalog_digest": catalog.catalog_digest,
            "calls": calls,
        },
    )
    return {
        "snapshot_artifact": sid,
        "graph_artifact": gid,
        "ssa_artifact": pid,
        "memory_plan_artifact": mid,
        "memory_result_artifact": rid,
        "call_composition_artifact": cid,
        "call_composition_count": len(calls),
        "snapshot_id": snapshot.snapshot_id,
        "graph_digest": program.graph.graph_digest,
        "analysis": program.graph.axes.analysis,
        "memory_diagnostics": list(memory.result.diagnostics),
        "profile": request["profile"]["profile_id"],
        "maturity": "MMAT_CALLS",
        "summary_digest": snapshot.identity.summary_digest,
        "summary_limitations": [
            "Reviewed summaries bind only by full pinned identity; the default runtime catalog is empty.",
            "Indirect, external, recursive, and context-limited calls retain unresolved effects.",
        ],
        "target_executed": False,
    }


HANDLERS = {"snapshot_ssa_v1": Handler(_extract, _analyze)}


def get_runtime(info=None):
    info = info or context()
    catalog = reviewed_catalog(info)
    root = Path(
        os.environ.get("IDA_MCP_FLOW_STATE_ROOT", str(Path.home() / ".ida-mcp-flow"))
    ).absolute()
    namespace, owner = identity(root, info["dbpath"])
    scope = RuntimeScope(
        namespace,
        _fingerprint(info),
        info["binary"],
        digest(info["profile"]),
        digest(extractor.RULES),
        catalog.catalog_digest,
        digest(extractor.POLICY),
    )
    return runtime.refresh_runtime(root / namespace, scope, owner, HANDLERS)


def create(selector, profile, request_key):
    info = context(selector, profile)
    engine = get_runtime(info)
    request = {
        "ea": info["ea"],
        "profile": info["profile"],
        "namespace": engine.store.scope.namespace,
        "fingerprint": engine.store.scope.fingerprint,
        "summary_digest": engine.store.scope.summary_digest,
        "function_key": "function-entry:" + str(info["ea"]),
    }
    return {
        "schema_version": "flow-job/1",
        "job_id": engine.submit("snapshot_ssa_v1", request, request_key, timeout=120),
        "experimental": True,
    }


def job(identifier, cancel=False):
    engine = get_runtime()
    if cancel:
        engine.cancel(identifier)
    row = engine.store.job(identifier)
    return {
        "schema_version": "flow-job/1",
        **{
            k: row.get(k)
            for k in (
                "id",
                "state",
                "revision",
                "progress",
                "budget",
                "error",
                "result",
            )
        },
    }


def page(artifact_id, section, cursor=None, limit=50, evidence_ids=None):
    engine = get_runtime()
    raw = engine.store.artifact(artifact_id)
    if section in {"ssa", "cfg"}:
        program = SSAProgram.from_data(raw)
        graph = program.graph
        items = (
            [{"node_id": node.node_id, **node.to_data()} for node in graph.nodes]
            if section == "ssa"
            else [
                {
                    **block.to_data(),
                    "predecessors": list(
                        graph.snapshot.function.blocks[block.block].predecessors
                    ),
                    "successors": list(
                        graph.snapshot.function.blocks[block.block].successors
                    ),
                }
                for block in program.dominance.blocks
            ]
        )
    else:
        graph = Queries(engine.store).graph(artifact_id)
        if section == "graph":
            items = [
                {"type": "node", "node_id": n.node_id, **n.to_data()}
                for n in graph.nodes
            ] + [
                {"type": "edge", "edge_id": e.edge_id, **e.to_data()}
                for e in graph.edges
            ]
        else:
            require(
                evidence_ids is None
                or (type(evidence_ids) is list and len(evidence_ids) <= 100),
                "invalid_evidence_ids",
            )
            selected = set(evidence_ids) if evidence_ids is not None else None
            available = {e.evidence_id: e for e in graph.evidence}
            items = [
                {"evidence_id": eid, **available[eid].to_data()}
                if eid in available
                else {"evidence_id": eid, "missing": True}
                for eid in sorted(selected if selected is not None else available)
            ]
    if section == "evidence":
        items = evidence_chunks(items)
    meta = {
        "snapshot_id": graph.snapshot.snapshot_id,
        "graph_digest": graph.graph_digest,
        "axes": graph.axes.to_data(),
        "maturity": graph.snapshot.identity.maturity,
        "profile_digest": graph.snapshot.identity.profile_digest,
        "summary_digest": graph.snapshot.identity.summary_digest,
        "environment": graph.snapshot.identity.environment.to_data(),
        "diagnostics": [d.to_data() for d in graph.snapshot.function.diagnostics],
        "memory_dependency_count": sum(
            edge.kind == "memory_data_dependency" for edge in graph.edges
        ),
        "opaque_memory_dependency_count": sum(
            edge.kind == "memory_data_dependency" and edge.axes.precision == "opaque"
            for edge in graph.edges
        ),
        "limitations": [
            "Experimental intra-function value and byte-range memory dependency reachability; conservative auto object roots are not ABI argument numbering, call summaries, implicit flow, or path proof.",
            "Supported-anchor memory edges assume successful flat user-space accesses; TLS/MMIO and null/fault feasibility are unresolved.",
        ],
    }
    return artifact_page(artifact_id, section, items, meta, cursor, limit)


def trace(
    snapshot_artifact,
    graph_artifact,
    source,
    direction,
    request_key,
    edge_kinds,
    budget,
    limit,
):
    queries = Queries(get_runtime().store)
    return queries.start(
        snapshot_artifact,
        graph_artifact,
        source,
        direction,
        request_key,
        edge_kinds=edge_kinds,
        budget=budget,
        limit=limit,
    )


def continue_trace(trace_id, revision, cursor, request_key, limit=50, cancel=False):
    queries = Queries(get_runtime().store)
    return queries.continue_trace(
        trace_id, revision, cursor, request_key, limit=limit, cancel=cancel
    )
