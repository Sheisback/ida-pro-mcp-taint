"""Lazy worker adapter. Host metadata only on IDA main thread; core jobs off-thread."""

import json
import os
import re
from pathlib import Path
from typing import Any, cast

from ida_pro_mcp.flow_core import canonical_json, digest
from ida_pro_mcp.flow_core.analysis import BitSeed, Seed
from ida_pro_mcp.flow_core.build_identity import BUILD_ID
from ida_pro_mcp.flow_core.call_composition import CallCompositionResult
from ida_pro_mcp.flow_core.constraints import ConstraintBindings, ConstraintQuery
from ida_pro_mcp.flow_core.derived_calls import (
    DerivedGlobalWriteEffect,
    DerivedIndirectReturnEffect,
    DerivedMemoryWriteEffect,
    DerivedReturnEffect,
    FiniteIndirectTargets,
    derive_direct_memory_write,
    derive_direct_global_write,
    derive_direct_return,
    derive_finite_indirect_return,
    proves_no_memory_effects,
)
from ida_pro_mcp.flow_core.explain import explain_observation
from ida_pro_mcp.flow_core.contracts import CallInfo, Graph, Snapshot
from ida_pro_mcp.flow_core.host_identity import identity
from ida_pro_mcp.flow_core.implicit_analysis import (
    ImplicitPolicy,
    ImplicitResult,
    analyze_implicit,
)
from ida_pro_mcp.flow_core.path_conditions import (
    PathSelector,
    path_bindings,
    prove_path,
)
from ida_pro_mcp.flow_core.memory_graph import (
    bind_memory_graph,
    build_memory_graph,
    memory_access_reasons,
    memory_dependency_cause,
    replay_memory_graph,
)
from ida_pro_mcp.flow_core.memory import MemoryPlan, MemoryResult
from ida_pro_mcp.flow_core.persistence import require
from ida_pro_mcp.flow_core.profile_routing import (
    RoutingMode,
    resolve_open_database_profile,
)
from ida_pro_mcp.flow_core.serialization import ContractError
from ida_pro_mcp.flow_core.proof import (
    ProofResult,
    validate_proof_result,
)
from ida_pro_mcp.flow_core.query import Queries, artifact_page, evidence_chunks
from ida_pro_mcp.flow_core.runtime import Handler
from ida_pro_mcp.flow_core.runtime_contracts import RuntimeScope
from ida_pro_mcp.flow_core.ssa import SSAProgram, argument_bindings

from ..sync import idasync
from . import extractor, runtime
from .profile_routing import observe_open_database
from .summary_catalog import CallBinding
from .call_state import compose_program_calls
from .reviewed_runtime import catalog_for_runtime, extract_callee_closure
from .derived_runtime import extract_local_direct_callees


_ROUTING_SELECTION_SCHEMA = "flow-routing-selection/1"


def build_digest():
    return BUILD_ID


def _state_root():
    return Path(
        os.environ.get("IDA_MCP_FLOW_STATE_ROOT", str(Path.home() / ".ida-mcp-flow"))
    ).absolute()


def reviewed_catalog(info=None):
    """Select only source-packaged full-identity-pinned owned-fixture reviews."""
    return catalog_for_runtime(info)


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
    snapshot = cast(
        extractor.ExtractedFunction,
        extractor.extract_snapshot(
            request["ea"],
            namespace=request["namespace"],
            function_key=request["function_key"],
            profile=request["profile"],
            summary_digest=request["summary_digest"],
            deadline=ctx.deadline,
            cancelled=ctx.cancel.is_set,
            include_calls=True,
            registry=before["registry"],
        ),
    )
    if (
        not reviewed_catalog(before).summaries
        and before.get("routing", {}).get("routing_mode") == "analyst_selected"
    ):
        callees, closure = extract_local_direct_callees(ctx, snapshot, before)
    else:
        callees, closure = extract_callee_closure(ctx, snapshot, before)
    require(
        _fingerprint(_context_for_request(request)) == request["fingerprint"],
        "stale_database",
    )
    return (snapshot, callees, closure), request


def _analyze(ctx, extracted):
    (function, callees, closure), request = extracted
    snapshot = function.snapshot
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
    derived_returns = []
    derived_indirect_returns = []
    derived_memory_writes = []
    if closure.get("mode") == "derived_static_unreviewed":
        for observation in function.calls:
            ctx.check()
            callee_ea = observation.call.callee_ea
            rva = None if callee_ea is None else callee_ea - function.image_base
            callee = callees.get(rva) if rva is not None else None
            if callee is None:
                continue
            try:
                effect = derive_direct_return(
                    snapshot,
                    callee,
                    observation.call,
                    observation.block_index,
                    observation.instruction_index,
                    checkpoint=ctx.check,
                )
            except ContractError:
                effect = None
            try:
                memory_write = derive_direct_memory_write(
                    snapshot,
                    callee,
                    observation.call,
                    observation.block_index,
                    observation.instruction_index,
                    checkpoint=ctx.check,
                )
            except ContractError:
                memory_write = None
            if memory_write is None:
                try:
                    memory_write = derive_direct_global_write(
                        snapshot,
                        callee,
                        observation.call,
                        observation.block_index,
                        observation.instruction_index,
                        checkpoint=ctx.check,
                    )
                except ContractError:
                    memory_write = None
            if effect is None and memory_write is None:
                closure["boundaries"].append(
                    {
                        "caller_rva": function.function_rva,
                        "instruction_rva": observation.instruction_ea
                        - function.image_base,
                        "callee_rva": rva,
                        "reason": "derived_call_effect_unavailable",
                        "callinfo_argument_count": len(observation.call.arguments),
                    }
                )
            if effect is not None:
                derived_returns.append(effect)
            if memory_write is not None:
                derived_memory_writes.append(memory_write)
        by_site = {
            (item.block_index, item.instruction_index): item
            for item in function.calls
        }
        for raw_targets in closure.get("finite_target_sets", []):
            ctx.check()
            targets = cast(
                FiniteIndirectTargets, FiniteIndirectTargets.from_data(raw_targets)
            )
            observation = by_site.get((targets.block, targets.instruction))
            selected = {
                ea: callees[ea - function.image_base]
                for ea in targets.targets
                if ea - function.image_base in callees
            }
            if observation is None or len(selected) != len(targets.targets):
                effect = None
            else:
                try:
                    effect = derive_finite_indirect_return(
                        snapshot,
                        selected,
                        observation.call,
                        targets,
                        checkpoint=ctx.check,
                    )
                except ContractError:
                    effect = None
            if effect is None:
                closure["boundaries"].append(
                    {
                        "caller_rva": function.function_rva,
                        "instruction_rva": (
                            None
                            if observation is None
                            else observation.instruction_ea - function.image_base
                        ),
                        "callee_rva": None,
                        "reason": "finite_indirect_return_unavailable",
                    }
                )
            else:
                derived_indirect_returns.append(effect)
    derived_returns = tuple(sorted(derived_returns, key=lambda effect: effect.sort_key))
    derived_indirect_returns = tuple(
        sorted(derived_indirect_returns, key=lambda effect: effect.sort_key)
    )
    derived_memory_writes = tuple(
        sorted(derived_memory_writes, key=lambda effect: effect.sort_key)
    )
    memory = build_memory_graph(
        snapshot,
        derived_returns=derived_returns,
        derived_indirect_returns=derived_indirect_returns,
        derived_memory_writes=derived_memory_writes,
    )
    program = memory.program
    ctx.check()
    calls = compose_program_calls(function, program, catalog, callees, ctx.check)
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
    derived_evidence = []
    for effect in derived_returns:
        callee = callees[effect.callee_ea - function.image_base]
        identifier = current.store.put_artifact(
            "analysis",
            {
                "schema_version": "flow-derived-call-evidence/1",
                "caller_snapshot_id": snapshot.snapshot_id,
                "callee_snapshot": callee.to_data(),
                "effect": effect.to_data(),
                "target_executed": False,
                "no_auto_vulnerability_verdict": True,
            },
        )
        derived_evidence.append(
            {
                "artifact_id": identifier,
                "callee_snapshot_id": callee.snapshot_id,
                "proof_digest": effect.proof_digest,
            }
        )
    derived_indirect_evidence = []
    for effect in derived_indirect_returns:
        observation = next(
            item for item in function.calls
            if (item.block_index, item.instruction_index) == effect.sort_key
        )
        target_data = next(
            item for item in closure["finite_target_sets"]
            if (item["block"], item["instruction"]) == effect.sort_key
        )
        candidate_snapshots = [
            callees[ea - function.image_base].to_data() for ea in effect.target_eas
        ]
        identifier = current.store.put_artifact(
            "analysis",
            {
                "schema_version": "flow-derived-finite-call-evidence/1",
                "caller_snapshot": snapshot.to_data(),
                "target_proof": target_data,
                "callee_snapshots": candidate_snapshots,
                "call_info": observation.call.to_data(),
                "effect": effect.to_data(),
                "target_executed": False,
                "no_auto_vulnerability_verdict": True,
            },
        )
        derived_indirect_evidence.append(
            {
                "artifact_id": identifier,
                "callee_snapshot_ids": list(effect.callee_snapshot_ids),
                "proof_digest": effect.proof_digest,
            }
        )
    derived_memory_evidence = []
    observations = {
        (item.block_index, item.instruction_index): item for item in function.calls
    }
    for effect in derived_memory_writes:
        callee = callees[effect.callee_ea - function.image_base]
        observation = observations[effect.sort_key]
        identifier = current.store.put_artifact(
            "analysis",
            {
                "schema_version": (
                    "flow-derived-call-global-memory-evidence/1"
                    if isinstance(effect, DerivedGlobalWriteEffect)
                    else "flow-derived-call-memory-evidence/1"
                ),
                "caller_snapshot": snapshot.to_data(),
                "callee_snapshot": callee.to_data(),
                "call_info": observation.call.to_data(),
                "effect": effect.to_data(),
                "target_executed": False,
                "no_auto_vulnerability_verdict": True,
            },
        )
        derived_memory_evidence.append(
            {
                "artifact_id": identifier,
                "callee_snapshot_id": callee.snapshot_id,
                "proof_digest": effect.proof_digest,
            }
        )
    response = {
        "snapshot_artifact": sid,
        "graph_artifact": gid,
        "ssa_artifact": pid,
        "memory_plan_artifact": mid,
        "memory_result_artifact": rid,
        "call_composition_artifact": cid,
        "call_composition_count": len(calls),
        "callee_closure": closure,
        "derived_call_returns": [effect.to_data() for effect in derived_returns],
        "derived_call_evidence": derived_evidence,
        "derived_call_memory_writes": [
            effect.to_data() for effect in derived_memory_writes
        ],
        "derived_call_memory_evidence": derived_memory_evidence,
        "snapshot_id": snapshot.snapshot_id,
        "graph_digest": program.graph.graph_digest,
        "analysis": program.graph.axes.analysis,
        "memory_diagnostics": list(memory.result.diagnostics),
        "profile": request["profile"]["profile_id"],
        "maturity": "MMAT_CALLS",
        "summary_digest": snapshot.identity.summary_digest,
        "summary_limitations": [
            "Reviewed summaries cover only the packaged owned fixtures, with fresh full-identity callee validation; arbitrary libraries remain unresolved.",
            "Incomplete indirect, external, recursive, and context-limited calls retain unresolved effects; complete local finite targets have derived scalar returns only.",
        ],
        "target_executed": False,
    }
    if derived_indirect_returns:
        response["derived_indirect_returns"] = [
            effect.to_data() for effect in derived_indirect_returns
        ]
        response["derived_indirect_evidence"] = derived_indirect_evidence
    return response


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
    seeds = tuple(
        cast(BitSeed, BitSeed.from_data(item))
        if type(item) is dict and item.get("kind") == "bit_range"
        else cast(Seed, Seed.from_data(item))
        for item in request["seeds"]
    )
    policy = ImplicitPolicy(request["max_evaluations"])
    ctx.check()
    return program, seeds, policy, request


def _analyze_implicit(ctx, extracted):
    program, seeds, policy, request = extracted
    ctx.check()
    memory_model = replay_memory_graph(program)
    ctx.check()
    result = analyze_implicit(
        program, seeds, policy, memory_model=memory_model, checkpoint=ctx.check
    )
    ctx.check()
    current = _request_runtime(request)
    plan_artifact = current.store.put_artifact("analysis", memory_model.plan.to_data())
    result_artifact = current.store.put_artifact(
        "analysis", memory_model.result.to_data()
    )
    artifact = {
        "schema_version": "flow-implicit-artifact/2",
        "source_artifact": request["ssa_artifact"],
        "memory_plan_artifact": plan_artifact,
        "memory_result_artifact": result_artifact,
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
    return path_bindings(graph)


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
    require(False, "path_query_not_program_derived")


@idasync
def _extract_path_proof(ctx, request):
    current = _request_runtime(request, _context_for_request(request))
    graph = cast(
        Graph, Graph.from_data(current.store.artifact(request["graph_artifact"]))
    )
    selector = cast(PathSelector, PathSelector.from_data(request["query"]))
    require(
        selector.bindings == _expected_path_bindings(graph),
        "path_query_artifact_mismatch",
    )
    ctx.check()
    return graph, selector, request


def _analyze_path_proof(ctx, extracted):
    graph, selector, request = extracted
    ctx.check()
    query, result = prove_path(graph, selector, cancelled=ctx.cancel.is_set)
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
    PathSelector.from_data(query)
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
    row = engine.status(identifier)
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


def _argument_bindings(program: SSAProgram):
    return argument_bindings(program)


def page(artifact_id, section, cursor=None, limit=50, evidence_ids=None):
    engine = get_runtime()
    raw = engine.store.artifact(artifact_id)
    argument_bindings = []
    if section in {"ssa", "cfg"}:
        program = cast(SSAProgram, SSAProgram.from_data(raw))
        graph = program.graph
        argument_bindings = _argument_bindings(program)
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
        "argument_bindings": argument_bindings,
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
    version = raw.get("schema_version") if type(raw) is dict else None
    common = {
        "schema_version",
        "source_artifact",
        "result",
        "target_executed",
        "no_auto_vulnerability_verdict",
    }
    expected = (
        common | {"memory_plan_artifact", "memory_result_artifact"}
        if version == "flow-implicit-artifact/2"
        else common
    )
    require(
        type(raw) is dict
        and version in {"flow-implicit-artifact/1", "flow-implicit-artifact/2"}
        and set(raw) == expected
        and (
            version != "flow-implicit-artifact/2"
            or type(raw["memory_plan_artifact"]) is str
            and type(raw["memory_result_artifact"]) is str
        )
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
        "memory_plan_artifact": raw.get("memory_plan_artifact"),
        "memory_result_artifact": raw.get("memory_result_artifact"),
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


_ALIAS_POLICY = {
    "untyped_input_current_frame": "may_alias_unknown",
    "typed_input_current_frame": "conditional_no_alias",
    "typed_no_alias_preconditions": [
        "exact full-width IDB pointer type and register argloc",
        "valid source-object pointer provenance; no forged address into the callee frame",
    ],
    "interpretation": "A possible dependency is not a definite flow or safety verdict.",
}


def _untyped_frame_alias_boundary(target_id, source_ids, objects):
    """Name only observed stack/argument candidate pairs, never infer no-alias."""
    pairs = [
        {"source_object_id": source_id, "target_object_id": target_id}
        for source_id in source_ids
        if source_id in objects
        and target_id in objects
        and {objects[source_id].kind, objects[target_id].kind}
        == {"stack", "argument"}
    ]
    if not pairs:
        return None
    return {
        "reason_code": "untyped_input_current_frame_noalias_unproven",
        "status": "unknown",
        "alias_relation": "may_alias",
        "source_target_pairs": pairs,
        "message": (
            "An untyped input pointer may numerically address the current stack "
            "frame; no no-alias proof is available. Preserve possible taint "
            "without treating it as a definite flow."
        ),
    }


def _memory_page(raw):
    result = cast(MemoryResult, MemoryResult.from_data(raw))
    facts = {fact.node_id: fact for fact in result.facts}
    accesses = {access.node_id: access for access in result.accesses}
    objects = {obj.object_id: obj for obj in result.objects}
    boundary_count = 0
    items = [
        {"type": "object", "object_id": obj.object_id, **obj.to_data()}
        for obj in result.objects
    ]
    for access in result.accesses:
        items.append(
            {
                "type": "access",
                **access.to_data(),
                "reasons": list(memory_access_reasons(access, facts)),
            }
        )
    for dependency in result.dependencies:
        reason, source_objects = memory_dependency_cause(dependency, accesses)
        boundary = (
            _untyped_frame_alias_boundary(dependency.object_id, source_objects, objects)
            if reason == "cross_object_may_alias"
            else None
        )
        boundary_count += boundary is not None
        items.append(
            {
                "type": "dependency",
                **dependency.to_data(),
                "reason": reason,
                "source_candidate_object_ids": list(source_objects),
                "alias_boundary": boundary,
                "impact": {
                    "node_id": dependency.target,
                    "scope": "direct_target_load",
                    "downstream": "trace_from_target_node",
                },
            }
        )
    items.extend({"type": "fact", **item.to_data()} for item in result.facts)
    items.extend({"type": "frontier", "node_id": item} for item in result.frontier)
    return items, {
        "status": result.status,
        "plan_digest": result.plan_digest,
        "source_digest": result.source_digest,
        "policy_digest": result.policy_digest,
        "diagnostics": list(result.diagnostics),
        "iterations": result.iterations,
        "frontier_count": len(result.frontier),
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
        "alias_policy": _ALIAS_POLICY,
        "untyped_current_frame_alias_dependency_count": boundary_count,
        "limitation": "Completion is not exact alias precision or proof of no taint; inspect each access and fact.",
    }


def _derived_call_page(raw):
    if (
        type(raw) is dict
        and raw.get("schema_version") == "flow-derived-call-global-memory-evidence/1"
    ):
        return _derived_call_global_memory_page(raw)
    if (
        type(raw) is dict
        and raw.get("schema_version") == "flow-derived-finite-call-evidence/1"
    ):
        return _derived_indirect_call_page(raw)
    if (
        type(raw) is dict
        and raw.get("schema_version") == "flow-derived-call-memory-evidence/1"
    ):
        return _derived_call_memory_page(raw)
    require(
        type(raw) is dict
        and set(raw)
        == {
            "schema_version",
            "caller_snapshot_id",
            "callee_snapshot",
            "effect",
            "target_executed",
            "no_auto_vulnerability_verdict",
        }
        and raw["schema_version"] == "flow-derived-call-evidence/1"
        and raw["target_executed"] is False
        and raw["no_auto_vulnerability_verdict"] is True,
        "invalid_derived_call_evidence",
    )
    callee = cast(Snapshot, Snapshot.from_data(raw["callee_snapshot"]))
    effect = cast(DerivedReturnEffect, DerivedReturnEffect.from_data(raw["effect"]))
    require(
        raw["caller_snapshot_id"] == effect.caller_snapshot_id
        and callee.snapshot_id == effect.callee_snapshot_id,
        "derived_call_evidence_binding_mismatch",
    )
    if effect.memory_effects == "none":
        rebuilt = build_memory_graph(callee)
        require(
            rebuilt.result.status == "complete_in_scope"
            and proves_no_memory_effects(rebuilt.program),
            "derived_call_memory_effect_proof_mismatch",
        )
    return [
        {"type": "derived_return_effect", **effect.to_data()},
        {"type": "callee_snapshot", **callee.to_data()},
    ], {
        "caller_snapshot_id": effect.caller_snapshot_id,
        "callee_snapshot_id": callee.snapshot_id,
        "proof_digest": effect.proof_digest,
        "provenance": "derived_static_unreviewed",
        "memory_effects": effect.memory_effects,
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
        "limitation": (
            "This static callee has no modeled memory effects; scalar call/spoiler effects and the reviewed-summary boundary remain separate."
            if effect.memory_effects == "none"
            else "A scalar return proof does not resolve call memory effects or promote a reviewed summary."
        ),
    }


def _derived_indirect_call_page(raw):
    require(
        type(raw) is dict
        and set(raw)
        == {
            "schema_version",
            "caller_snapshot",
            "target_proof",
            "callee_snapshots",
            "call_info",
            "effect",
            "target_executed",
            "no_auto_vulnerability_verdict",
        }
        and raw["schema_version"] == "flow-derived-finite-call-evidence/1"
        and raw["target_executed"] is False
        and raw["no_auto_vulnerability_verdict"] is True,
        "invalid_finite_indirect_evidence",
    )
    caller = cast(Snapshot, Snapshot.from_data(raw["caller_snapshot"]))
    targets = cast(
        FiniteIndirectTargets, FiniteIndirectTargets.from_data(raw["target_proof"])
    )
    effect = cast(
        DerivedIndirectReturnEffect,
        DerivedIndirectReturnEffect.from_data(raw["effect"]),
    )
    call = cast(CallInfo, CallInfo.from_data(raw["call_info"]))
    candidate_data = raw["callee_snapshots"]
    require(
        type(candidate_data) is list
        and len(candidate_data) == len(targets.targets),
        "finite_indirect_candidate_count_mismatch",
    )
    callees = {
        ea: cast(Snapshot, Snapshot.from_data(data))
        for ea, data in zip(targets.targets, candidate_data, strict=True)
    }
    try:
        verified = derive_finite_indirect_return(caller, callees, call, targets)
    except ContractError:
        verified = None
    require(verified == effect, "finite_indirect_effect_proof_mismatch")
    return [
        {"type": "derived_indirect_return_effect", **effect.to_data()},
        {"type": "finite_target_set", **targets.to_data()},
        {"type": "caller_snapshot", **caller.to_data()},
        {"type": "call_info", **call.to_data()},
        *(
            {"type": "callee_snapshot", "target_ea": ea, **callee.to_data()}
            for ea, callee in sorted(callees.items())
        ),
    ], {
        "caller_snapshot_id": caller.snapshot_id,
        "target_proof_digest": targets.proof_digest,
        "candidate_count": len(targets.targets),
        "candidate_snapshot_ids": list(effect.callee_snapshot_ids),
        "proof_digest": effect.proof_digest,
        "provenance": "derived_static_finite_indirect",
        "memory_effects": effect.memory_effects,
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
        "limitation": "Only the complete proven finite target set has joined scalar returns; no arbitrary indirect target or reviewed library claim.",
    }


def _derived_call_memory_page(raw):
    require(
        type(raw) is dict
        and set(raw)
        == {
            "schema_version",
            "caller_snapshot",
            "callee_snapshot",
            "call_info",
            "effect",
            "target_executed",
            "no_auto_vulnerability_verdict",
        }
        and raw["schema_version"] == "flow-derived-call-memory-evidence/1"
        and raw["target_executed"] is False
        and raw["no_auto_vulnerability_verdict"] is True,
        "invalid_derived_call_memory_evidence",
    )
    caller = cast(Snapshot, Snapshot.from_data(raw["caller_snapshot"]))
    callee = cast(Snapshot, Snapshot.from_data(raw["callee_snapshot"]))
    call = cast(CallInfo, CallInfo.from_data(raw["call_info"]))
    effect = cast(
        DerivedMemoryWriteEffect, DerivedMemoryWriteEffect.from_data(raw["effect"])
    )
    require(
        caller.snapshot_id == effect.caller_snapshot_id
        and callee.snapshot_id == effect.callee_snapshot_id,
        "derived_call_memory_evidence_binding_mismatch",
    )
    try:
        verified = derive_direct_memory_write(
            caller, callee, call, effect.block, effect.instruction
        )
    except ContractError:
        verified = None
    require(verified == effect, "derived_call_memory_effect_proof_mismatch")
    return [
        {"type": "derived_memory_write_effect", **effect.to_data()},
        {"type": "caller_snapshot", **caller.to_data()},
        {"type": "callee_snapshot", **callee.to_data()},
        {"type": "call_info", **call.to_data()},
    ], {
        "caller_snapshot_id": caller.snapshot_id,
        "callee_snapshot_id": callee.snapshot_id,
        "proof_digest": effect.proof_digest,
        "provenance": "derived_static_unreviewed",
        "memory_effects": "single_typed_output_write",
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
        "limitation": "One exact typed output-pointer identity write only; scalar call effects and all other calls remain conservative.",
    }


def _derived_call_global_memory_page(raw):
    require(
        type(raw) is dict
        and set(raw)
        == {
            "schema_version",
            "caller_snapshot",
            "callee_snapshot",
            "call_info",
            "effect",
            "target_executed",
            "no_auto_vulnerability_verdict",
        }
        and raw["schema_version"] == "flow-derived-call-global-memory-evidence/1"
        and raw["target_executed"] is False
        and raw["no_auto_vulnerability_verdict"] is True,
        "invalid_derived_call_global_memory_evidence",
    )
    caller = cast(Snapshot, Snapshot.from_data(raw["caller_snapshot"]))
    callee = cast(Snapshot, Snapshot.from_data(raw["callee_snapshot"]))
    call = cast(CallInfo, CallInfo.from_data(raw["call_info"]))
    effect = cast(
        DerivedGlobalWriteEffect, DerivedGlobalWriteEffect.from_data(raw["effect"])
    )
    require(
        caller.snapshot_id == effect.caller_snapshot_id
        and callee.snapshot_id == effect.callee_snapshot_id,
        "derived_call_global_memory_evidence_binding_mismatch",
    )
    try:
        verified = derive_direct_global_write(
            caller, callee, call, effect.block, effect.instruction
        )
    except ContractError:
        verified = None
    require(verified == effect, "derived_call_global_memory_effect_proof_mismatch")
    return [
        {"type": "derived_global_write_effect", **effect.to_data()},
        {"type": "caller_snapshot", **caller.to_data()},
        {"type": "callee_snapshot", **callee.to_data()},
        {"type": "call_info", **call.to_data()},
    ], {
        "caller_snapshot_id": caller.snapshot_id,
        "callee_snapshot_id": callee.snapshot_id,
        "proof_digest": effect.proof_digest,
        "provenance": "derived_static_unreviewed",
        "memory_effects": "single_fixed_global_write",
        "global_address": effect.global_address,
        "width_bits": effect.width_bits,
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
        "limitation": (
            "One exact fixed-global write only; scalar call effects, other memory "
            "operations, and unrelated calls remain conservative."
        ),
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
    items.extend(
        {"type": "path_constraint", **item.to_data()} for item in query.constraints
    )
    items.extend(
        {"type": "path_variable", **item.to_data()} for item in query.variables
    )
    items.extend(
        {"type": "path_assumption", **item.to_data()} for item in query.assumptions
    )
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
    elif section == "memory":
        items, metadata = _memory_page(raw)
    elif section == "derived_call":
        items, metadata = _derived_call_page(raw)
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


def explain_implicit(
    artifact_id,
    observation_node_id,
    cursor=None,
    limit=50,
    max_nodes=2048,
    max_causes=256,
):
    """Page local structural candidates separately from global partial codes."""
    require(type(observation_node_id) is str, "invalid_observation_node_id")
    current = get_runtime()
    raw = current.store.artifact(artifact_id)
    _implicit_page(raw)  # Strict legacy/current artifact validation.
    result = cast(ImplicitResult, ImplicitResult.from_data(raw["result"]))
    program = cast(
        SSAProgram,
        SSAProgram.from_data(current.store.artifact(raw["source_artifact"])),
    )
    if raw["schema_version"] == "flow-implicit-artifact/2":
        plan = cast(
            MemoryPlan,
            MemoryPlan.from_data(current.store.artifact(raw["memory_plan_artifact"])),
        )
        memory_result = cast(
            MemoryResult,
            MemoryResult.from_data(
                current.store.artifact(raw["memory_result_artifact"])
            ),
        )
        memory = bind_memory_graph(program, plan, memory_result)
    else:
        memory = replay_memory_graph(program)
    explanation = explain_observation(
        program,
        memory,
        result,
        observation_node_id,
        max_nodes=max_nodes,
        max_causes=max_causes,
    )
    objects = {obj.object_id: obj for obj in memory.result.objects}
    cause_items = []
    boundary_count = 0
    for cause in explanation.causes:
        boundary = (
            _untyped_frame_alias_boundary(
                cause.memory_object_id, cause.source_candidate_object_ids, objects
            )
            if cause.reason_code == "cross_object_may_alias"
            else None
        )
        boundary_count += boundary is not None
        cause_items.append({"type": "cause", **cause.to_data(), "alias_boundary": boundary})
    items = cause_items + [
        {"type": "global_diagnostic", "code": item}
        for item in explanation.global_diagnostics
    ]
    metadata = {
        "source_artifact": raw["source_artifact"],
        "memory_plan_artifact": raw.get("memory_plan_artifact"),
        "memory_result_artifact": raw.get("memory_result_artifact"),
        "graph_digest": explanation.graph_digest,
        "analysis_digest": explanation.analysis_digest,
        "observation_node_id": observation_node_id,
        "observation_labels": explanation.labels.to_data(),
        "analysis_status": explanation.analysis_status,
        "local_cause_count": len(explanation.causes),
        "global_diagnostic_count": len(explanation.global_diagnostics),
        "visited_nodes": explanation.visited_nodes,
        "truncated": explanation.truncated,
        "relation_scope": "candidate_structural_backward_slice_not_path_proof",
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
        "alias_policy": _ALIAS_POLICY,
        "untyped_current_frame_alias_cause_count": boundary_count,
    }
    return artifact_page(
        artifact_id,
        f"implicit_explanation:{observation_node_id}:{max_nodes}:{max_causes}",
        _chunk_large_items("implicit_explanation", items),
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
