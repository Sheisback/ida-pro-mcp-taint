"""Lazy worker adapter. Host metadata only on IDA main thread; core jobs off-thread."""

import json
import os
import re
from pathlib import Path
from typing import Any, cast

from ida_pro_mcp.flow_core import canonical_json, digest
from ida_pro_mcp.flow_core.analysis import Seed
from ida_pro_mcp.flow_core.build_identity import BUILD_ID
from ida_pro_mcp.flow_core.call_composition import CallCompositionResult
from ida_pro_mcp.flow_core.constraints import ConstraintBindings, ConstraintQuery
from ida_pro_mcp.flow_core.contracts import Graph, Snapshot
from ida_pro_mcp.flow_core.host_identity import identity
from ida_pro_mcp.flow_core.implicit_analysis import (
    ImplicitPolicy,
    ImplicitResult,
    analyze_implicit,
)
from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
from ida_pro_mcp.flow_core.persistence import require
from ida_pro_mcp.flow_core.profile_routing import (
    RoutingMode,
    resolve_open_database_profile,
)
from ida_pro_mcp.flow_core.proof import (
    ProofResult,
    ReferenceProofEngine,
    classify_proof,
    validate_proof_result,
)
from ida_pro_mcp.flow_core.query import Queries, artifact_page, evidence_chunks
from ida_pro_mcp.flow_core.runtime import Handler
from ida_pro_mcp.flow_core.runtime_contracts import RuntimeScope
from ida_pro_mcp.flow_core.ssa import SSAProgram

from ..sync import idasync
from . import extractor, runtime
from .profile_routing import observe_open_database
from .summary_catalog import EMPTY_CATALOG, CallBinding, bind_call, compose_binding


_ROUTING_SELECTION_SCHEMA = "flow-routing-selection/1"


def build_digest():
    return BUILD_ID


def _state_root():
    return Path(
        os.environ.get("IDA_MCP_FLOW_STATE_ROOT", str(Path.home() / ".ida-mcp-flow"))
    ).absolute()


def reviewed_catalog(_info=None):
    """Resolve the internal immutable catalog used for this runtime scope.

    The shipped runtime starts empty; licensed static-receipt generation supplies
    an explicit reviewed fixture catalog without adding a public tool or a
    function-name lookup path.
    """

    return EMPTY_CATALOG


def _runtime_scope(info: dict[str, Any], namespace: str):
    catalog = reviewed_catalog(info)
    return RuntimeScope(
        namespace,
        _fingerprint(info),
        info["binary"],
        digest(info["profile"]),
        digest(extractor.RULES),
        catalog.catalog_digest,
        digest(extractor.POLICY),
    )


def _database_snapshot_digest(info: dict[str, Any]):
    return digest({k: info[k] for k in ("dbpath", "binary", "count", "ida", "hexrays")})


def _routing_selection(info: dict[str, Any], scope) -> dict[str, object]:
    return {
        "schema_version": _ROUTING_SELECTION_SCHEMA,
        "namespace": scope.namespace,
        "database_path_digest": digest(
            {"database_path": str(Path(info["dbpath"]).absolute())}
        ),
        "database_snapshot_digest": _database_snapshot_digest(info),
        "database_fingerprint": scope.fingerprint,
        "database_change_count": info["count"],
        "routing_mode": info["routing"]["routing_mode"],
        "profile_id": info["routing"]["profile_id"],
        "abi_id": info["routing"]["abi_id"],
        "binary_digest": info["binary"],
        "profile_digest": scope.profile_digest,
        "ida_build": info["ida"],
        "hexrays_build": info["hexrays"],
        "extension_build": build_digest(),
        "rule_digest": scope.rule_digest,
        "summary_digest": scope.summary_digest,
        "policy_digest": scope.policy_digest,
        "scope_digest": scope.scope_digest,
    }


def resolve_observed_context(
    dbpath,
    observed,
    count,
    requested_profile=None,
    requested_abi=None,
    routing_mode: RoutingMode = "exact_fixture",
    *,
    retain_selection=True,
):
    """Resolve a route, restoring only an exact owned durable selection."""

    require(type(dbpath) is str and bool(dbpath), "open_database_required")
    require(type(count) is int and count >= 0, "invalid_database_change_count")
    explicit_selection = (
        requested_profile is not None
        or requested_abi is not None
        or routing_mode != "exact_fixture"
    )
    restored = None
    if not explicit_selection:
        restored = runtime.load_routing_selection(_state_root(), dbpath)
        if restored is not None:
            _namespace, selection = restored
            require(
                set(selection)
                == {
                    "schema_version",
                    "namespace",
                    "database_path_digest",
                    "database_snapshot_digest",
                    "database_fingerprint",
                    "database_change_count",
                    "routing_mode",
                    "profile_id",
                    "abi_id",
                    "binary_digest",
                    "profile_digest",
                    "ida_build",
                    "hexrays_build",
                    "extension_build",
                    "rule_digest",
                    "summary_digest",
                    "policy_digest",
                    "scope_digest",
                }
                and selection["schema_version"] == _ROUTING_SELECTION_SCHEMA,
                "invalid_routing_selection",
            )
            require(
                type(selection["database_change_count"]) is int
                and all(
                    type(selection[key]) is str
                    for key in set(selection) - {"database_change_count"}
                ),
                "invalid_routing_selection",
            )
            requested_profile = cast(str, selection["profile_id"])
            requested_abi = cast(str, selection["abi_id"])
            routing_mode = cast(RoutingMode, selection["routing_mode"])
    resolved = resolve_open_database_profile(
        observed,
        requested_profile=requested_profile,
        requested_abi=requested_abi,
        routing_mode=routing_mode,
    )
    info = {
        "dbpath": dbpath,
        "profile": resolved.profile,
        "registry": resolved.registry,
        "binary": observed.binary_digest,
        "count": count,
        "ida": observed.ida_build,
        "hexrays": observed.hexrays_build,
        "routing": {
            "routing_mode": routing_mode,
            "profile_id": resolved.evidence.profile_id,
            "abi_id": resolved.evidence.abi_id,
            "binary_digest": observed.binary_digest,
        },
        "persist_selection": explicit_selection and retain_selection,
    }
    if restored is not None:
        namespace, selection = restored
        scope = _runtime_scope(info, namespace)
        require(selection == _routing_selection(info, scope), "stale_profile_selection")
        info["restored_selection"] = selection
    return info


def _context(
    selector=None,
    requested_profile=None,
    requested_abi=None,
    routing_mode: RoutingMode = "exact_fixture",
    *,
    retain_selection=True,
):
    import ida_funcs
    import ida_hexrays
    import ida_ida
    import ida_kernwin
    import ida_loader
    import ida_nalt

    from ..utils import parse_address

    require(os.name == "posix", "flow_runtime_unavailable_non_posix")
    dbpath = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
    require(bool(dbpath), "open_database_required")
    require(ida_hexrays.init_hexrays_plugin(), "hexrays_unavailable")
    ida_build = ida_kernwin.get_kernel_version()
    hexrays_build = ida_hexrays.get_hexrays_version()
    observed = observe_open_database(
        ida_ida,
        ida_nalt,
        ida_build=ida_build,
        hexrays_build=hexrays_build,
    )
    count = ida_ida.inf_get_database_change_count()
    result = resolve_observed_context(
        dbpath,
        observed,
        count,
        requested_profile,
        requested_abi,
        routing_mode,
        retain_selection=retain_selection,
    )
    if selector is not None:
        ea = parse_address(selector)
        func = ida_funcs.get_func(ea)
        require(func is not None and func.start_ea == ea, "function_entry_required")
        result["ea"] = ea
    return result


context = idasync(_context)


def _fingerprint(info):
    return digest(
        {k: info[k] for k in ("dbpath", "binary", "count", "ida", "hexrays")}
        | {"build": build_digest(), "profile": digest(info["profile"])}
    )


def _context_for_request(request, *, synchronized=False):
    routing = request.get("routing")
    if routing is None:
        # Compatibility for already queued exact-fixture requests.
        return context() if synchronized else _context()
    require(
        type(routing) is dict
        and set(routing) == {"routing_mode", "profile_id", "abi_id", "binary_digest"},
        "invalid_profile_selection",
    )
    reader = context if synchronized else _context
    info = reader(
        requested_profile=routing["profile_id"],
        requested_abi=routing["abi_id"],
        routing_mode=cast(RoutingMode, routing["routing_mode"]),
        retain_selection=False,
    )
    require(info["binary"] == routing["binary_digest"], "stale_profile_selection")
    return info


@idasync
def _extract(ctx, request):
    before = _context_for_request(request)
    require(_fingerprint(before) == request["fingerprint"], "stale_database")
    require(before["profile"] == request["profile"], "stale_profile_evidence")
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
        registry=before["registry"],
    )
    require(
        _fingerprint(_context_for_request(request)) == request["fingerprint"],
        "stale_database",
    )
    return snapshot, request


def _analyze(ctx, extracted):
    function, request = extracted
    snapshot = function.snapshot
    memory = build_memory_graph(snapshot)
    program = memory.program
    ctx.check()
    info = _context_for_request(request, synchronized=True)
    require(_fingerprint(info) == request["fingerprint"], "stale_database")
    current = get_runtime(info)
    catalog = reviewed_catalog(info)
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


def _request_runtime(request, info=None):
    info = info or _context_for_request(request, synchronized=True)
    require(_fingerprint(info) == request["fingerprint"], "stale_database")
    current = get_runtime(info)
    require(
        current.store.scope.scope_digest == request["scope_digest"],
        "stale_context",
    )
    return current


@idasync
def _extract_implicit(ctx, request):
    current = _request_runtime(request, _context_for_request(request))
    program = cast(
        SSAProgram,
        SSAProgram.from_data(current.store.artifact(request["ssa_artifact"])),
    )
    seeds = tuple(cast(Seed, Seed.from_data(item)) for item in request["seeds"])
    policy = ImplicitPolicy(request["max_evaluations"])
    ctx.check()
    return program, seeds, policy, request


def _analyze_implicit(ctx, extracted):
    program, seeds, policy, request = extracted
    ctx.check()
    result = analyze_implicit(program, seeds, policy, checkpoint=ctx.check)
    ctx.check()
    current = _request_runtime(request)
    artifact = {
        "schema_version": "flow-implicit-artifact/1",
        "source_artifact": request["ssa_artifact"],
        "result": result.to_data(),
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
    }
    ctx.check()
    identifier = current.store.put_artifact("analysis", artifact)
    return {
        "implicit_artifact": identifier,
        "status": result.status,
        "frontier_count": len(result.frontier),
        "diagnostics": list(result.diagnostics),
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
    }


def _expected_path_bindings(graph: Graph) -> ConstraintBindings:
    require(
        isinstance(graph.snapshot, Snapshot),
        "path_proof_requires_normal_snapshot",
    )
    assert isinstance(graph.snapshot, Snapshot)
    identity = graph.snapshot.identity
    return ConstraintBindings(
        graph.snapshot.snapshot_id,
        graph.graph_digest,
        identity.profile_digest,
        identity.rule_digest,
        (identity.summary_digest,),
    )


def _validate_path_query(graph: Graph, query: ConstraintQuery) -> None:
    require(
        query.bindings == _expected_path_bindings(graph),
        "path_query_artifact_mismatch",
    )
    available = {item.evidence_id for item in graph.evidence}
    claimed = {
        evidence_id
        for constraint in query.constraints
        for evidence_id in constraint.evidence_ids
    } | {
        evidence_id
        for assumption in query.assumptions
        for evidence_id in assumption.evidence_ids
    }
    require(claimed <= available, "path_query_foreign_evidence")


@idasync
def _extract_path_proof(ctx, request):
    current = _request_runtime(request, _context_for_request(request))
    graph = cast(
        Graph, Graph.from_data(current.store.artifact(request["graph_artifact"]))
    )
    query = cast(ConstraintQuery, ConstraintQuery.from_data(request["query"]))
    _validate_path_query(graph, query)
    ctx.check()
    return graph, query, request


def _analyze_path_proof(ctx, extracted):
    _graph, query, request = extracted
    ctx.check()
    result = classify_proof(query, ReferenceProofEngine(cancelled=ctx.cancel.is_set))
    validate_proof_result(query, result)
    ctx.check()
    current = _request_runtime(request)
    artifact = {
        "schema_version": "flow-path-proof-artifact/1",
        "source_artifact": request["graph_artifact"],
        "query": query.to_data(),
        "proof": result.to_data(),
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
    }
    identifier = current.store.put_artifact("analysis", artifact)
    return {
        "path_proof_artifact": identifier,
        "status": result.status,
        "scope": result.scope,
        "model_kind": result.model_kind,
        "unresolved": list(result.unresolved),
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
    }


HANDLERS = {
    "snapshot_ssa_v1": Handler(_extract, _analyze),
    "implicit_analysis_v1": Handler(_extract_implicit, _analyze_implicit),
    "path_proof_v1": Handler(_extract_path_proof, _analyze_path_proof),
}


def get_runtime(info=None):
    info = info or context()
    root = _state_root()
    namespace, owner = identity(root, info["dbpath"])
    scope = _runtime_scope(info, namespace)
    if "restored_selection" in info:
        require(
            info["restored_selection"] == _routing_selection(info, scope),
            "stale_profile_selection",
        )
    return runtime.refresh_runtime(root / namespace, scope, owner, HANDLERS)


def create(
    selector,
    profile,
    request_key,
    abi=None,
    routing_mode: RoutingMode = "exact_fixture",
):
    info = context(selector, profile, abi, routing_mode)
    engine = get_runtime(info)
    request = {
        "ea": info["ea"],
        "profile": info["profile"],
        "namespace": engine.store.scope.namespace,
        "fingerprint": engine.store.scope.fingerprint,
        "summary_digest": engine.store.scope.summary_digest,
        "function_key": "function-entry:" + str(info["ea"]),
        "routing": info["routing"],
    }
    if info["persist_selection"]:
        runtime.persist_routing_selection(
            engine.store,
            info["dbpath"],
            _routing_selection(info, engine.store.scope),
        )
    job_id = engine.submit("snapshot_ssa_v1", request, request_key, timeout=120)
    return {
        "schema_version": "flow-job/1",
        "job_id": job_id,
        "experimental": True,
    }


def create_implicit(ssa_artifact, seeds, request_key, max_evaluations=100000):
    require(type(seeds) is list, "invalid_implicit_seeds")
    require(
        type(max_evaluations) is int and 0 < max_evaluations <= 1000000,
        "invalid_implicit_budget",
    )
    info = context()
    engine = get_runtime(info)
    request = {
        "ssa_artifact": ssa_artifact,
        "seeds": seeds,
        "max_evaluations": max_evaluations,
        "fingerprint": engine.store.scope.fingerprint,
        "scope_digest": engine.store.scope.scope_digest,
        "routing": info["routing"],
    }
    return {
        "schema_version": "flow-job/1",
        "job_id": engine.submit(
            "implicit_analysis_v1", request, request_key, timeout=120
        ),
        "experimental": True,
    }


def create_path_proof(graph_artifact, query, request_key):
    require(type(query) is dict, "invalid_path_query")
    info = context()
    engine = get_runtime(info)
    request = {
        "graph_artifact": graph_artifact,
        "query": query,
        "fingerprint": engine.store.scope.fingerprint,
        "scope_digest": engine.store.scope.scope_digest,
        "routing": info["routing"],
    }
    return {
        "schema_version": "flow-job/1",
        "job_id": engine.submit("path_proof_v1", request, request_key, timeout=120),
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
        program = cast(SSAProgram, SSAProgram.from_data(raw))
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
        graph = cast(Graph, Queries(engine.store).graph(artifact_id))
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
                or (
                    type(evidence_ids) is list
                    and len(evidence_ids) <= 100
                    and all(
                        type(item) is str
                        and re.fullmatch(r"evidence-v1:[0-9a-f]{64}", item) is not None
                        for item in evidence_ids
                    )
                ),
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
    require(
        isinstance(graph.snapshot, Snapshot),
        "public_runtime_requires_normal_snapshot",
    )
    assert isinstance(graph.snapshot, Snapshot)
    meta = {
        "snapshot_id": graph.snapshot.snapshot_id,
        "graph_digest": graph.graph_digest,
        "axes": graph.axes.to_data(),
        "maturity": graph.snapshot.identity.maturity,
        "profile_digest": graph.snapshot.identity.profile_digest,
        "rule_digest": graph.snapshot.identity.rule_digest,
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
            "This page is intra-function value and byte-range reachability; use the dedicated implicit, bounded-proof, and call-composition artifacts for those distinct semantics.",
            "Supported-anchor memory edges assume successful flat user-space accesses; TLS/MMIO and null/fault feasibility are unresolved.",
        ],
    }
    return artifact_page(artifact_id, section, items, meta, cursor, limit)


def _chunk_large_items(section, items):
    result = []
    for index, item in enumerate(items):
        text = canonical_json(item)
        if len(json.dumps(item)) < 8000:
            result.append(item)
            continue
        item_id = digest({"section": section, "index": index, "item": item})
        for offset in range(0, len(text), 1000):
            result.append(
                {
                    "type": "canonical_json_chunk",
                    "item_id": item_id,
                    "encoding": "canonical-json-text",
                    "offset": offset,
                    "length": len(text[offset : offset + 1000]),
                    "total_length": len(text),
                    "text": text[offset : offset + 1000],
                }
            )
    return result


def _implicit_page(raw):
    require(
        type(raw) is dict
        and set(raw)
        == {
            "schema_version",
            "source_artifact",
            "result",
            "target_executed",
            "no_auto_vulnerability_verdict",
        }
        and raw["schema_version"] == "flow-implicit-artifact/1"
        and raw["target_executed"] is False
        and raw["no_auto_vulnerability_verdict"] is True,
        "invalid_implicit_artifact",
    )
    value = cast(ImplicitResult, ImplicitResult.from_data(raw["result"]))
    items = (
        [{"type": "fact", **item.to_data()} for item in value.facts]
        + [{"type": "control_relation", **item.to_data()} for item in value.relations]
        + [{"type": "frontier", "node_id": node_id} for node_id in value.frontier]
    )
    return items, {
        "source_artifact": raw["source_artifact"],
        "status": value.status,
        "graph_digest": value.graph_digest,
        "source_digest": value.source_digest,
        "policy_digest": value.policy_digest,
        "control_digest": value.control_digest,
        "explicit_result_digest": value.explicit_result_digest,
        "diagnostics": list(value.diagnostics),
        "evaluations": value.evaluations,
        "frontier_count": len(value.frontier),
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
    }


def _proof_page(raw):
    require(
        type(raw) is dict
        and set(raw)
        == {
            "schema_version",
            "source_artifact",
            "query",
            "proof",
            "target_executed",
            "no_auto_vulnerability_verdict",
        }
        and raw["schema_version"] == "flow-path-proof-artifact/1"
        and raw["target_executed"] is False
        and raw["no_auto_vulnerability_verdict"] is True,
        "invalid_path_proof_artifact",
    )
    query = cast(ConstraintQuery, ConstraintQuery.from_data(raw["query"]))
    proof = cast(ProofResult, ProofResult.from_data(raw["proof"]))
    validate_proof_result(query, proof)
    summary = proof.to_data()
    witness = summary.pop("witness")
    diagnostics = summary.pop("diagnostics")
    unresolved = summary.pop("unresolved")
    evidence_ids = summary.pop("evidence_ids")
    items = [{"type": "proof", **summary}]
    if witness is not None:
        items.extend(
            {"type": "witness_assignment", **item} for item in witness["assignments"]
        )
        items.extend(
            {"type": "witness_evaluation", **item} for item in witness["evaluations"]
        )
    items.extend({"type": "evidence", "evidence_id": item} for item in evidence_ids)
    items.extend({"type": "diagnostic", "code": item} for item in diagnostics)
    items.extend({"type": "unresolved", "code": item} for item in unresolved)
    return items, {
        "source_artifact": raw["source_artifact"],
        "query_digest": query.query_digest,
        "query_cache_key": query.cache_key,
        "status": proof.status,
        "scope": proof.scope,
        "model_kind": proof.model_kind,
        "witness_valid": witness is not None and witness["valid"] is True,
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
    }


def _interprocedural_page(raw):
    raw_calls = raw.get("calls") if type(raw) is dict else None
    require(
        type(raw) is dict
        and set(raw) == {"schema_version", "catalog_digest", "calls"}
        and raw["schema_version"] == "flow-call-compositions/1"
        and type(raw_calls) is list,
        "invalid_call_composition_artifact",
    )
    assert type(raw) is dict and type(raw_calls) is list
    calls = []
    partial = 0
    unknown = 0
    for index, item in enumerate(raw_calls):
        require(
            type(item) is dict and set(item) == {"binding", "composition"},
            "invalid_call_composition_artifact",
        )
        binding = cast(CallBinding, CallBinding.from_data(item["binding"]))
        composition = cast(
            CallCompositionResult,
            CallCompositionResult.from_data(item["composition"]),
        )
        require(
            binding.plan.catalog_digest == raw["catalog_digest"]
            and composition.plan_digest == binding.plan.plan_digest,
            "invalid_call_composition_artifact",
        )
        partial += composition.status == "partial"
        unknown += binding.plan.unknown_remainder is not None
        calls.append({"type": "call", "index": index, **item})
    return calls, {
        "catalog_digest": raw["catalog_digest"],
        "call_count": len(calls),
        "partial_count": partial,
        "unknown_remainder_count": unknown,
        "status": "partial" if partial or unknown else "complete_in_scope",
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
    }


def analysis_page(artifact_id, section, cursor=None, limit=50):
    raw = get_runtime().store.artifact(artifact_id)
    if section == "implicit":
        items, metadata = _implicit_page(raw)
    elif section == "path_proof":
        items, metadata = _proof_page(raw)
    elif section == "interprocedural":
        items, metadata = _interprocedural_page(raw)
    else:
        raise ValueError("invalid_analysis_section")
    return artifact_page(
        artifact_id,
        section,
        _chunk_large_items(section, items),
        metadata,
        cursor,
        limit,
    )


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
