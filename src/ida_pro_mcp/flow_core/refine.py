"""Opt-in symbolic refinement over v1 path/memory proofs. SDK-free core.

A refinement replays the v1 baseline (or cross-checks a quoted original),
then runs ONLY the explicitly requested symbolic tiers. With a default spec
no solver code runs at all: the refined artifact carries the v1 baseline
verbatim plus ``solver_not_invoked``. Refined artifacts are versioned dicts
with exact-key validation, following the v1 ``flow-path-proof-artifact/1``
pattern; witness integers are hex-encoded so the artifact stays wire-v1
safe at any bit width.

The job runners take an explicit store so the same code serves the IDA
service handlers and SDK-free runtime tests; only scope ownership (which
store) stays host-side.
"""

from dataclasses import dataclass
from typing import Any, Literal, cast

from .contracts import Graph
from .memory import MemoryPlan, MemoryResult
from .memory_symbolic import prove_store_to_load, validate_memory_result
from .path_conditions import PathSelector, path_bindings, prove_path
from .path_symbolic import prove_symbolic_path, validate_symbolic_result
from .symbolic import SymBinding, Z3Backend
from .proof import validate_proof_result
from .serialization import Model, digest
from .states import check_digest, nonempty, require

REFINE_VERSION = "flow-refine/1"
REFINED_PATH_ARTIFACT = "flow-refined-path-artifact/1"
REFINED_MEMORY_ARTIFACT = "flow-refined-memory-artifact/1"
REFINE_MAX_INLINES = 8

Agreement = Literal["consistent", "refined", "contradiction"]


@dataclass(frozen=True)
class RefinementSpec(Model):
    """Explicit opt-in: every symbolic tier defaults OFF."""

    symbolic_path: bool = False
    symbolic_memory: bool = False
    solver_timeout_ms: int = 5000
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        require(self.schema_version == 1, "invalid_refinement_spec_version")
        # Tier flags are strict bools by Model field typing; only the range
        # needs an explicit check here.
        require(
            type(self.solver_timeout_ms) is int
            and 0 < self.solver_timeout_ms <= 120000,
            "invalid_refinement_timeout",
        )


def _disposition(status: str) -> str:
    if status in {"feasible", "feasible_symbolic_v1"}:
        return "sat"
    if status in {"infeasible", "infeasible_smt_bounded_v1"}:
        return "unsat"
    return "unknown"


def refinement_agreement(baseline_status: str, refined_status: str) -> Agreement:
    """Compare v1 and symbolic verdicts. Definite disagreement alarms."""
    base, refined = _disposition(baseline_status), _disposition(refined_status)
    if base == refined:
        return "consistent"
    if base == "unknown" and refined != "unknown":
        return "refined"
    if base != "unknown" and refined == "unknown":
        return "consistent"
    return "contradiction"


def encode_witness(witness) -> list[dict[str, Any]]:
    """Hex-encode bindings so any width stays wire-v1 safe."""
    return [
        {
            "name": item.name,
            "width_bits": item.width_bits,
            "value_hex": hex(item.value),
        }
        for item in witness
    ]


def decode_witness(encoded: list[dict[str, Any]]) -> tuple:
    """Decode hex bindings back to solver model tuples (name, width, value)."""
    decoded = []
    for item in encoded:
        require(
            type(item) is dict
            and set(item) == {"name", "width_bits", "value_hex"},
            "invalid_refined_witness",
        )
        value = int(item["value_hex"], 16)
        require(
            type(item["width_bits"]) is int
            and 0 <= value < (1 << item["width_bits"]),
            "refined_witness_out_of_range",
        )
        decoded.append(SymBinding(item["name"], item["width_bits"], value))
    return tuple(decoded)


def refine_path_proof(
    graph: Graph,
    selector: PathSelector,
    spec: RefinementSpec,
    *,
    backend: Z3Backend | None = None,
    inlines: tuple = (),
    original: dict[str, Any] | None = None,
    cancelled=lambda: False,
):
    """Refine one v1 path proof. Default spec never touches the solver."""
    require(selector.bindings == path_bindings(graph), "path_query_artifact_mismatch")
    base_query, baseline = prove_path(graph, selector, cancelled=cancelled)
    validate_proof_result(base_query, baseline)
    original_link: dict[str, Any] | None = None
    if original is not None:
        from .constraints import ConstraintQuery
        from .proof import ProofResult

        quoted_query = ConstraintQuery.from_data(original["query"])
        quoted_proof = ProofResult.from_data(original["proof"])
        validate_proof_result(quoted_query, quoted_proof)
        require(
            digest(quoted_query.to_data()) == digest(base_query.to_data())
            and digest(quoted_proof.to_data()) == digest(baseline.to_data()),
            "refine_baseline_mismatch",
        )
        original_link = {
            "artifact_id": original.get("artifact_id"),
            "query_digest": quoted_query.query_digest,
            "result_digest": digest(quoted_proof.to_data()),
            "status": quoted_proof.status,
        }
    refined: dict[str, Any]
    if not spec.symbolic_path:
        refined = {
            "attempted": False,
            "status": "unknown",
            "reason": "solver_not_invoked",
        }
    else:
        query, result = prove_symbolic_path(
            graph,
            selector,
            backend=backend,
            timeout_ms=spec.solver_timeout_ms,
            cancelled=cancelled,
            inlines=inlines,
        )
        validate_symbolic_result(query, result)
        refined = {
            "attempted": True,
            "query_digest": query.query_digest,
            "status": result.status,
            "scope": result.scope,
            "model_kind": result.model_kind,
            "engine_version": result.engine_version,
            "solver_stamp": result.solver_stamp,
            "solver_version": result.solver_version,
            "unresolved": list(result.unresolved),
            "diagnostics": list(result.diagnostics),
            "evidence_ids": list(result.evidence_ids),
            "witness": encode_witness(result.witness),
        }
    agreement = (
        "consistent" if not refined["attempted"] else refinement_agreement(
            baseline.status, refined["status"]
        )
    )
    artifact = {
        "schema_version": REFINED_PATH_ARTIFACT,
        "refine_version": REFINE_VERSION,
        "original": original_link,
        "baseline": {
            "query_digest": base_query.query_digest,
            "result_digest": digest(baseline.to_data()),
            "status": baseline.status,
            "scope": baseline.scope,
            "model_kind": baseline.model_kind,
            "unresolved": list(baseline.unresolved),
            "evidence_ids": list(baseline.evidence_ids),
        },
        "refined": refined,
        "agreement": agreement,
        "spec": spec.to_data(),
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
    }
    check_refined_path_artifact(artifact)
    return artifact


def check_refined_path_artifact(raw: dict[str, Any]) -> None:
    """Exact-key validation shared by renderers, jobs, and tests."""
    require(
        type(raw) is dict
        and set(raw)
        == {
            "schema_version",
            "refine_version",
            "original",
            "baseline",
            "refined",
            "agreement",
            "spec",
            "target_executed",
            "no_auto_vulnerability_verdict",
        }
        and raw["schema_version"] == REFINED_PATH_ARTIFACT
        and raw["refine_version"] == REFINE_VERSION
        and raw["agreement"] in {"consistent", "refined", "contradiction"}
        and raw["target_executed"] is False
        and raw["no_auto_vulnerability_verdict"] is True,
        "invalid_refined_path_artifact",
    )
    original: Any = raw["original"]
    if original is not None:
        require(
            type(original) is dict
            and set(original)
            == {"artifact_id", "query_digest", "result_digest", "status"},
            "invalid_refined_original",
        )
        original = cast(dict[str, Any], original)
        check_digest(original["query_digest"])
        check_digest(original["result_digest"])
        nonempty(original["status"])
    baseline: Any = raw["baseline"]
    require(
        type(baseline) is dict
        and set(baseline)
        == {
            "query_digest",
            "result_digest",
            "status",
            "scope",
            "model_kind",
            "unresolved",
            "evidence_ids",
        },
        "invalid_refined_baseline",
    )
    baseline = cast(dict[str, Any], baseline)
    check_digest(baseline["query_digest"])
    check_digest(baseline["result_digest"])
    check_refined_section(raw["refined"], attempted_kind="path")
    RefinementSpec.from_data(raw["spec"])


def check_refined_section(refined: dict[str, Any], *, attempted_kind: str) -> None:
    if not isinstance(refined, dict) or refined.get("attempted") is False:
        require(
            type(refined) is dict
            and set(refined) == {"attempted", "status", "reason"}
            and refined.get("attempted") is False
            and refined.get("status") == "unknown"
            and refined.get("reason") == "solver_not_invoked",
            "invalid_refined_unattempted",
        )
        return
    del attempted_kind
    require(
        type(refined) is dict
        and set(refined)
        == {
            "attempted",
            "query_digest",
            "status",
            "scope",
            "model_kind",
            "engine_version",
            "solver_stamp",
            "solver_version",
            "unresolved",
            "diagnostics",
            "evidence_ids",
            "witness",
        }
        and refined["attempted"] is True,
        "invalid_refined_attempted",
    )
    check_digest(refined["query_digest"])
    nonempty(refined["status"])
    for raw_item in refined["witness"]:
        item: Any = raw_item
        require(
            type(item) is dict
            and set(item) == {"name", "width_bits", "value_hex"},
            "invalid_refined_witness",
        )
        item = cast(dict[str, Any], item)
        int(item["value_hex"], 16)


def refine_memory_proof(
    plan: MemoryPlan,
    graph: Graph,
    memory_result: MemoryResult,
    selector: PathSelector,
    load_id: str,
    store_id: str,
    spec: RefinementSpec,
    *,
    backend: Z3Backend | None = None,
    inlines: tuple = (),
    cancelled=lambda: False,
):
    """Refine one v1 memory pair verdict. Default spec never solves."""
    require(selector.bindings == path_bindings(graph), "path_query_artifact_mismatch")
    require(
        plan.plan_digest == memory_result.plan_digest,
        "refine_plan_mismatch",
    )
    pair = {load_id, store_id}
    baseline = {
        "result_digest": digest(memory_result.to_data()),
        "plan_digest": memory_result.plan_digest,
        "status": memory_result.status,
        "facts": [
            item.to_data()
            for item in memory_result.facts
            if item.node_id in pair
        ],
        "accesses": [
            item.to_data()
            for item in memory_result.accesses
            if item.node_id in pair
        ],
        "dependencies": [
            item.to_data()
            for item in memory_result.dependencies
            if item.source in pair or item.target in pair
        ],
        "diagnostics": list(memory_result.diagnostics),
    }
    refined: dict[str, Any]
    if not spec.symbolic_memory:
        refined = {
            "attempted": False,
            "status": "unknown",
            "reason": "solver_not_invoked",
        }
    else:
        query, result = prove_store_to_load(
            plan,
            graph,
            selector,
            load_id,
            store_id,
            backend=backend,
            timeout_ms=spec.solver_timeout_ms,
            memory_facts=memory_result,
            cancelled=cancelled,
            inlines=inlines,
        )
        validate_memory_result(query, result)
        refined = {
            "attempted": True,
            "query_digest": query.query_digest,
            "status": result.status,
            "scope": result.scope,
            "model_kind": result.model_kind,
            "overlap": result.overlap,
            "value_forward": result.value_forward,
            "engine_version": result.engine_version,
            "solver_stamp": result.solver_stamp,
            "solver_version": result.solver_version,
            "unresolved": list(result.unresolved),
            "diagnostics": list(result.diagnostics),
            "evidence_ids": list(result.evidence_ids),
            "witness": encode_witness(result.witness),
        }
    artifact = {
        "schema_version": REFINED_MEMORY_ARTIFACT,
        "refine_version": REFINE_VERSION,
        "load_id": load_id,
        "store_id": store_id,
        "baseline": baseline,
        "refined": refined,
        "spec": spec.to_data(),
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
    }
    check_refined_memory_artifact(artifact)
    return artifact


def check_refined_memory_artifact(raw: dict[str, Any]) -> None:
    require(
        type(raw) is dict
        and set(raw)
        == {
            "schema_version",
            "refine_version",
            "load_id",
            "store_id",
            "baseline",
            "refined",
            "spec",
            "target_executed",
            "no_auto_vulnerability_verdict",
        }
        and raw["schema_version"] == REFINED_MEMORY_ARTIFACT
        and raw["refine_version"] == REFINE_VERSION
        and raw["target_executed"] is False
        and raw["no_auto_vulnerability_verdict"] is True,
        "invalid_refined_memory_artifact",
    )
    baseline: Any = raw["baseline"]
    require(
        type(baseline) is dict
        and set(baseline)
        == {
            "result_digest",
            "plan_digest",
            "status",
            "facts",
            "accesses",
            "dependencies",
            "diagnostics",
        },
        "invalid_refined_memory_baseline",
    )
    baseline = cast(dict[str, Any], baseline)
    check_digest(baseline["result_digest"])
    check_digest(baseline["plan_digest"])
    refined: Any = raw["refined"]
    if refined.get("attempted") is False:
        check_refined_section(refined, attempted_kind="memory")
        return
    require(
        type(refined) is dict
        and set(refined)
        == {
            "attempted",
            "query_digest",
            "status",
            "scope",
            "model_kind",
            "overlap",
            "value_forward",
            "engine_version",
            "solver_stamp",
            "solver_version",
            "unresolved",
            "diagnostics",
            "evidence_ids",
            "witness",
        }
        and refined["attempted"] is True,
        "invalid_refined_memory_attempted",
    )
    refined = cast(dict[str, Any], refined)
    check_digest(refined["query_digest"])
    RefinementSpec.from_data(raw["spec"])


def resolve_inline_requests(store: Any, entries: list[dict[str, Any]]) -> tuple:
    """Build InlineRequests from stored callee programs. Explicit only.

    Each entry names a callee SSA artifact plus the exact interface
    (blocks, params, return, arguments). No ABI inference happens here;
    the caller asserts the mapping and the fragment records it.
    """
    from .call_symbolic import (
        CalleeBody,
        InlineRequest,
        callee_body_digest,
    )
    from .memory import build_memory_plan
    from .ssa import SSAProgram

    require(
        type(entries) is list and len(entries) <= REFINE_MAX_INLINES,
        "invalid_refine_inline",
    )
    requests = []
    for entry in entries:
        require(
            type(entry) is dict
            and set(entry)
            == {
                "call_id",
                "caller_result_id",
                "callee_ssa_artifact",
                "callee_blocks",
                "entry_params",
                "return_id",
                "arguments",
            },
            "invalid_refine_inline",
        )
        require(
            type(entry["call_id"]) is str
            and type(entry["caller_result_id"]) is str
            and type(entry["callee_ssa_artifact"]) is str
            and type(entry["return_id"]) is str
            and type(entry["callee_blocks"]) is list
            and 0 < len(entry["callee_blocks"]) <= 256
            and all(
                type(block) is int and block >= 0
                for block in entry["callee_blocks"]
            )
            and type(entry["entry_params"]) is list
            and all(type(item) is str for item in entry["entry_params"])
            and type(entry["arguments"]) is list
            and all(type(item) is str for item in entry["arguments"]),
            "invalid_refine_inline",
        )
        program = SSAProgram.from_data(
            store.artifact(entry["callee_ssa_artifact"])
        )
        graph = program.graph
        entry_params = tuple(entry["entry_params"])
        return_id = entry["return_id"] or None
        body = CalleeBody(
            graph=graph,
            plan=build_memory_plan(program),
            entry_params=entry_params,
            return_id=return_id,
            callee_digest=callee_body_digest(graph, entry_params, return_id),
        )
        requests.append(
            InlineRequest(
                entry["call_id"],
                entry["caller_result_id"] or None,
                body,
                tuple(entry["callee_blocks"]),
                tuple(entry["arguments"]),
            )
        )
    return tuple(requests)


def run_path_refinement(store: Any, request: dict[str, Any], *, backend: Z3Backend | None = None, cancelled=lambda: False):
    """Resolve, refine, and store one path refinement. Host-agnostic."""
    from .contracts import Graph

    require(
        type(request) is dict
        and set(request)
        >= {"graph_artifact", "path", "refinement"},
        "invalid_refine_request",
    )
    graph = Graph.from_data(store.artifact(request["graph_artifact"]))
    selector = PathSelector.from_data(request["path"])
    spec = RefinementSpec.from_data(request["refinement"])
    inlines = resolve_inline_requests(store, request.get("inline", []))
    original = None
    if request.get("proof_artifact") is not None:
        raw = store.artifact(request["proof_artifact"])
        require(
            type(raw) is dict
            and raw.get("schema_version") == "flow-path-proof-artifact/1",
            "invalid_refine_original",
        )
        original = {
            "artifact_id": request["proof_artifact"],
            "query": raw["query"],
            "proof": raw["proof"],
        }
    artifact = refine_path_proof(
        graph,
        selector,
        spec,
        backend=backend,
        inlines=inlines,
        original=original,
        cancelled=cancelled,
    )
    identifier = store.put_artifact("analysis", artifact)
    return {
        "refined_path_proof_artifact": identifier,
        "baseline_status": artifact["baseline"]["status"],
        "refined_status": artifact["refined"]["status"],
        "refined_attempted": artifact["refined"]["attempted"],
        "agreement": artifact["agreement"],
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
    }


def run_memory_refinement(store: Any, request: dict[str, Any], *, backend: Z3Backend | None = None, cancelled=lambda: False):
    """Resolve, refine, and store one memory refinement. Host-agnostic."""
    from .contracts import Graph
    from .ssa import SSAProgram

    require(
        type(request) is dict
        and set(request)
        >= {
            "ssa_artifact",
            "memory_plan_artifact",
            "memory_result_artifact",
            "path",
            "load_id",
            "store_id",
            "refinement",
        },
        "invalid_refine_request",
    )
    program = SSAProgram.from_data(store.artifact(request["ssa_artifact"]))
    graph = (
        Graph.from_data(store.artifact(request["graph_artifact"]))
        if request.get("graph_artifact") is not None
        else program.graph
    )
    plan = MemoryPlan.from_data(store.artifact(request["memory_plan_artifact"]))
    memory_result = MemoryResult.from_data(
        store.artifact(request["memory_result_artifact"])
    )
    selector = PathSelector.from_data(request["path"])
    spec = RefinementSpec.from_data(request["refinement"])
    inlines = resolve_inline_requests(store, request.get("inline", []))
    artifact = refine_memory_proof(
        plan,
        graph,
        memory_result,
        selector,
        request["load_id"],
        request["store_id"],
        spec,
        backend=backend,
        inlines=inlines,
        cancelled=cancelled,
    )
    identifier = store.put_artifact("analysis", artifact)
    return {
        "refined_memory_proof_artifact": identifier,
        "refined_status": artifact["refined"]["status"],
        "refined_attempted": artifact["refined"]["attempted"],
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
    }


def refined_path_page(raw: dict[str, Any]):
    """SDK-free item assembly for the refined_path_proof section."""
    check_refined_path_artifact(raw)
    baseline, refined = raw["baseline"], raw["refined"]
    items = [
        {
            "type": "refinement_summary",
            "baseline_status": baseline["status"],
            "refined_status": refined["status"],
            "refined_attempted": refined["attempted"],
            "agreement": raw["agreement"],
        }
    ]
    if raw["original"] is not None:
        items.append({"type": "original_link", **raw["original"]})
    items.append({"type": "baseline", **baseline})
    items.append(
        {
            "type": "refined",
            **{key: value for key, value in refined.items() if key != "witness"},
        }
    )
    items.extend(
        {"type": "witness_binding", **item} for item in refined.get("witness", [])
    )
    items.extend(
        {"type": "evidence", "evidence_id": item}
        for item in refined.get("evidence_ids", [])
    )
    items.extend(
        {"type": "unresolved", "code": item} for item in refined.get("unresolved", [])
    )
    items.extend(
        {"type": "diagnostic", "code": item}
        for item in refined.get("diagnostics", [])
    )
    return items, {
        "baseline_status": baseline["status"],
        "refined_status": refined["status"],
        "refined_attempted": refined["attempted"],
        "agreement": raw["agreement"],
        "baseline_query_digest": baseline["query_digest"],
        "refined_query_digest": refined.get("query_digest"),
        "solver_stamp": refined.get("solver_stamp", ""),
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
    }


def refined_memory_page(raw: dict[str, Any]):
    """SDK-free item assembly for the refined_memory_proof section."""
    check_refined_memory_artifact(raw)
    baseline, refined = raw["baseline"], raw["refined"]
    items = [
        {
            "type": "refinement_summary",
            "load_id": raw["load_id"],
            "store_id": raw["store_id"],
            "refined_status": refined["status"],
            "refined_attempted": refined["attempted"],
        }
    ]
    items.extend({"type": "baseline_fact", **item} for item in baseline["facts"])
    items.extend({"type": "baseline_access", **item} for item in baseline["accesses"])
    items.extend(
        {"type": "baseline_dependency", **item} for item in baseline["dependencies"]
    )
    items.append(
        {
            "type": "refined",
            **{key: value for key, value in refined.items() if key != "witness"},
        }
    )
    items.extend(
        {"type": "witness_binding", **item} for item in refined.get("witness", [])
    )
    items.extend(
        {"type": "evidence", "evidence_id": item}
        for item in refined.get("evidence_ids", [])
    )
    items.extend(
        {"type": "unresolved", "code": item} for item in refined.get("unresolved", [])
    )
    return items, {
        "load_id": raw["load_id"],
        "store_id": raw["store_id"],
        "refined_status": refined["status"],
        "refined_attempted": refined["attempted"],
        "baseline_result_digest": baseline["result_digest"],
        "refined_query_digest": refined.get("query_digest"),
        "solver_stamp": refined.get("solver_stamp", ""),
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
    }
