"""Compile owned C examples and measure seeded provenance through public tools.

PYTHONPATH=src:. uv run python tests/flow_core/native_taint_scenarios.py OUTPUT
Requires local licensed IDA 9.3 and Apple clang. Never executes a target.
This diagnostic receipt is NOT a support promotion or a release-gate receipt.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/flow_fixtures/taint_scenarios.c"
# Independent source-level oracle: first argument may influence observed data or
# control (not pointer address), assuming valid accesses. None is a calibration.
CASES = {
    "identity": True,
    "pointer_identity": None,
    "arithmetic": True,
    "overwrite": False,
    "and_zero": False,
    "multiply_zero": False,
    "xor_self": False,
    "subtract_self": False,
    "independent": False,
    "select_value": True,
    "branch_constant": True,
    "branch_same": False,
    "loop": True,
    "stack_roundtrip": True,
    "stack_overwrite": False,
    "struct_other": False,
    "struct_same": True,
    "array_constant": True,
    "array_index": True,
    "partial_clear": True,
    "full_byte_clear": False,
    "global_roundtrip": True,
    "global_overwrite": False,
    "call_identity": True,
    "call_indirect": True,
    "pointer_only": False,
    "load_before_store": False,
    "store_then_load": True,
}

# These are source/model categories, not an allowlist learned from native rows.
# In particular an untyped incoming pointer may alias a current-frame spill in
# the flat binary model, and an arbitrary function parameter has no closed
# target set. Both require explicit unknown evidence instead of a clean claim.
ALIAS_LIMITED = frozenset({"pointer_only", "load_before_store", "store_then_load"})
DIRECT_CALL = "call_identity"
INDIRECT_CALL = "call_indirect"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def entry_range(node):
    match = re.search(
        r"entry:microregister:microregister:(\d+):(\d+)$",
        node["key"].get("synthetic") or "",
    )
    return tuple(map(int, match.groups())) if match else None


def classify(expected, observed, uncertain):
    if expected is None:
        return "calibration"
    if expected != observed:
        if uncertain:
            return "inconclusive_partial"
        return "overtaint" if observed else "missing_taint"
    return "match_partial" if uncertain else "match"


def proves_caller_bypass(row):
    """Prove a typed-data path that never consumes the unresolved call result.

    An optimizer may retain a call for effects but compute the observer value
    from the caller's input. This is a different proof route from a derived
    callee-return certificate, not permission to label an opaque Call as pure.
    """
    nodes = {item["node_id"]: item for item in row.get("nodes", [])}
    seeds = {item["node_id"] for item in row.get("seeds", []) if "node_id" in item}
    if not nodes or not seeds:
        return False
    allowed = {"InputValue", "Constant", "Copy", "Unary", "Binary", "Select", "Phi"}
    reached = set()
    for observation in row.get("observations", []):
        target = nodes.get(observation.get("node_id"))
        if target is None or target.get("kind") != "Store":
            return False
        roles = target.get("memory_operands") or {}
        data = roles.get("data")
        if data not in nodes:
            return False
        pending = [data]
        seen = set()
        while pending:
            node_id = pending.pop()
            if node_id in seen:
                continue
            node = nodes.get(node_id)
            if node is None or node.get("kind") not in allowed:
                return False
            seen.add(node_id)
            pending.extend(node.get("inputs", []))
            pending.extend(item["node_id"] for item in node.get("phi_inputs", []))
        reached.update(seen)
    return bool(reached & seeds)


def has_type_backed_noalias_scope(row, pointer_index):
    """Require an explicit IDB argloc assumption before accepting exact clean."""
    bindings = (row.get("ssa_metadata") or {}).get("argument_bindings") or []
    typed = any(
        item.get("argument_index") == pointer_index
        and item.get("provenance") == "current_idb_type_and_sdk_reg_argloc"
        and item.get("type_correctness") == "analyst_assumption"
        and item.get("idb_pointer_type_assumption") is True
        and item.get("storage", {}).get("width_bits") == 64
        for item in bindings
    )
    objects = row.get("memory_items") or []
    return typed and any(
        item.get("type") == "object" and item.get("kind") == "typed_entry"
        for item in objects
    )


def acceptance_issues(receipt):
    """Check a predeclared source/precision envelope over the full native matrix."""
    issues = []
    if receipt.get("target_executed") is not False:
        issues.append("target_executed")
    runs = receipt.get("runs", [])
    grid = {(run.get("arch"), run.get("optimization")) for run in runs}
    required_grid = {(arch, opt) for arch in ("x86_64", "arm64") for opt in ("O0", "O1")}
    if len(runs) != 4 or grid != required_grid:
        issues.append("incomplete_architecture_optimization_grid")
    for run in runs:
        context = f"{run.get('arch')}:{run.get('optimization')}"
        if run.get("closed_save_false") is not True or run.get("input_preserved") is not True:
            issues.append(context + ":disposable_input_or_close_unproven")
        rows = run.get("cases", [])
        if len(rows) != len(CASES) or {row.get("case") for row in rows} != set(CASES):
            issues.append(context + ":incomplete_case_coverage")
        for row in rows:
            name = row.get("case")
            if name not in CASES:
                issues.append(context + ":unrecognized_case")
                continue
            label = context + ":" + name
            if row.get("expected_dependency") is not CASES[name]:
                issues.append(label + ":source_oracle_mismatch")
            if row.get("classification") in {
                "error", "source_selection_unavailable", "missing_taint", "overtaint"
            }:
                issues.append(label + ":hard_failure")
                continue
            if (
                row.get("observation_kind") != "dedicated_volatile_store"
                or row.get("native_return_node_count") != 0
                or not row.get("observations")
            ):
                issues.append(label + ":observation_coverage")
            if CASES[name] is True and (row.get("source_absent") or not row.get("seeds")):
                issues.append(label + ":positive_source_unselected")
            metadata = row.get("implicit_metadata") or {}
            explanations = row.get("explanations") or []
            if len(explanations) != len(row.get("observations") or []):
                issues.append(label + ":explanation_coverage")
            cause_rows = []
            for explanation in explanations:
                emeta = explanation.get("metadata") or {}
                if emeta.get("truncated") is not False or emeta.get("target_executed") is not False:
                    issues.append(label + ":explanation_truncated_or_unsafe")
                cause_rows.extend(explanation.get("items") or [])
            local = [item for item in cause_rows if item.get("type") == "cause"]
            global_codes = {
                item.get("code") for item in cause_rows
                if item.get("type") == "global_diagnostic"
            }
            uncertain = metadata.get("status") != "complete_in_scope" or row.get("observation_unknown") is True
            observed = row.get("observed_dependency")
            if name == "pointer_identity":
                ranges = row.get("source_ranges") or []
                if (
                    row.get("classification") != "calibration"
                    or len(ranges) != 1
                    or ranges[0][1] != 64
                    or observed is not True
                    or row.get("observation_unknown") is not False
                    or uncertain
                    or row.get("source_absent") is not False
                ):
                    issues.append(label + ":pointer_calibration")
                continue
            if name == DIRECT_CALL:
                proofs = row.get("snapshot_result", {}).get("derived_call_returns", [])
                global_writes = [
                    item for item in row.get("snapshot_result", {}).get(
                        "derived_call_memory_writes", []
                    )
                    if "global_address" in item
                ]
                memory_evidence = row.get("derived_memory_evidence_pages", [])
                if global_writes and not all(
                    any(
                        page.get("metadata", {}).get("proof_digest")
                        == effect.get("proof_digest")
                        and page["metadata"].get("memory_effects")
                        == "single_fixed_global_write"
                        and page["metadata"].get("target_executed") is False
                        for page in memory_evidence
                    )
                    for effect in global_writes
                ):
                    issues.append(label + ":global_write_evidence_unavailable")
                if global_writes and "unknown_call_or_write" in row.get(
                    "memory_metadata", {}
                ).get("diagnostics", []):
                    issues.append(label + ":proven_global_write_still_havoced")
                callee_proven = any(
                    proof.get("argument_indices") == [0] and proof.get("provenance") == "derived_static"
                    for proof in proofs
                )
                if observed is not True or row.get("observation_unknown") is not False or not (
                    callee_proven or proves_caller_bypass(row)
                ):
                    issues.append(label + ":direct_dependency_unproven")
                if uncertain and not global_codes:
                    issues.append(label + ":direct_call_partial_unexplained")
                if not callee_proven:
                    boundaries = row.get("snapshot_result", {}).get(
                        "callee_closure", {}
                    ).get("boundaries", [])
                    attempted = [
                        item for item in boundaries
                        if item.get("reason") == "derived_call_effect_unavailable"
                    ]
                    if attempted and not all(
                        type(item.get("callinfo_argument_count")) is int
                        and item["callinfo_argument_count"] >= 0
                        for item in attempted
                    ):
                        issues.append(label + ":direct_call_rejection_detail_missing")
                continue
            if name == INDIRECT_CALL:
                if (
                    row.get("observation_unknown") is not True
                    or not uncertain
                    or not {"call_boundary", "unmodeled_callinfo"}
                    & {item.get("reason_code") for item in local}
                ):
                    issues.append(label + ":indirect_unknown_boundary_missing")
                continue
            if name in ALIAS_LIMITED:
                if name == "store_then_load" and observed is not True:
                    issues.append(label + ":store_then_load_source_lost")
                elif CASES[name] is False and observed is True and row.get("observation_unknown") is not True:
                    issues.append(label + ":definite_extra_alias_label")
                elif (
                    name in {"pointer_only", "load_before_store"}
                    and observed is False
                    and row.get("observation_unknown") is False
                    and not has_type_backed_noalias_scope(
                        row, 0 if name == "pointer_only" else 1
                    )
                ):
                    issues.append(label + ":untyped_alias_promoted_without_proof")
                expected_reasons = (
                    {("cross_object_may_alias", "may_alias"),
                     ("possible_uninitialized_memory", "exact")}
                    if name != "store_then_load"
                    else {("cross_object_may_alias", "may_alias"),
                          ("unresolved_access_or_range", "opaque"),
                          ("unknown_address", "range_widened")}
                )
                if uncertain and not any(
                    (item.get("reason_code"), item.get("precision")) in expected_reasons
                    and item.get("evidence_ids")
                    for item in local
                ):
                    issues.append(label + ":untyped_alias_reason_missing")
                if (
                    name == "store_then_load"
                    and "partial_pointer_reload"
                    in row.get("memory_metadata", {}).get("diagnostics", [])
                    and not any(
                        item.get("reason_code") == "cross_object_may_alias"
                        and item.get("alias_boundary", {}).get("status") == "unknown"
                        for item in local
                        if item.get("alias_boundary") is not None
                    )
                ):
                    issues.append(label + ":pointer_spill_clobber_cause_missing")
                if name in {"pointer_only", "load_before_store"} and observed is True:
                    boundaries = [
                        item["alias_boundary"]
                        for item in row.get("memory_items", [])
                        if item.get("alias_boundary") is not None
                    ]
                    if not boundaries or not all(
                        item.get("reason_code")
                        == "untyped_input_current_frame_noalias_unproven"
                        and item.get("status") == "unknown"
                        for item in boundaries
                    ):
                        issues.append(label + ":mcp_untyped_alias_boundary_missing")
                    if not any(
                        item.get("alias_boundary", {}).get("reason_code")
                        == "untyped_input_current_frame_noalias_unproven"
                        for item in local
                        if item.get("alias_boundary") is not None
                    ):
                        issues.append(label + ":mcp_alias_explanation_missing")
                continue
            if observed is not CASES[name] or uncertain or row.get("classification") != "match":
                issues.append(label + ":exact_source_or_precision_mismatch")
            if name == "array_index" and not row.get("bounded_accesses"):
                issues.append(label + ":bounded_two_candidate_access_missing")
    return issues


def source_seeds(nodes, input_ranges):
    """Select exact entry atoms, or one calibrated whole-byte subrange.

    A calibration interval is independent fixture evidence, not an ABI guess.
    Ambiguous containment never silently seeds a whole wider register.
    """
    labels = {
        "explicit": ["argument-0"],
        "control": [],
        "unknown_provenance": False,
        "any_explicit_source": False,
        "any_control_source": False,
    }
    exact = []
    complete = bool(input_ranges)
    for start, width in input_ranges:
        parts = sorted(
            (location[0], location[0] + location[1], node["node_id"])
            for node in nodes
            if node["kind"] == "InputValue"
            and (location := entry_range(node)) is not None
            and start <= location[0]
            and location[0] + location[1] <= start + width
        )
        cursor = start
        for first, last, identifier in parts:
            if first != cursor:
                complete = False
                break
            exact.append({"node_id": identifier, "labels": labels})
            cursor = last
        if cursor != start + width:
            complete = False
    if complete:
        return exact
    if len(input_ranges) != 1:
        return []
    start, width = input_ranges[0]
    if width <= 0 or width > 64 or start % 8 or width % 8:
        return []
    covering = [
        (node, location)
        for node in nodes
        if node["kind"] == "InputValue"
        and (location := entry_range(node)) is not None
        and location[0] <= start
        and start + width <= location[0] + location[1]
    ]
    if len(covering) != 1:
        return []
    node, location = covering[0]
    return [
        {
            "kind": "bit_range",
            "schema_version": 1,
            "node_id": node["node_id"],
            "labels": labels,
            "bit_offset": start - location[0],
            "width_bits": width,
        }
    ]


class Client:
    def __init__(self, module, database, observation_address):
        self.module, self.database = module, database
        self.observation_address = observation_address
        self.calls = Counter()
        self.stage = "initialization"
        self.case_context = {}

    def call(self, name, **arguments):
        response = self.module._handle_tools_call(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": name,
                    "arguments": {"database": self.database, **arguments},
                },
            }
        )
        assert response is not None and not response.get("error"), response
        result = response["result"]
        assert not result.get("isError"), response
        data = result["structuredContent"]
        assert not data.get("error"), data
        assert "_truncated" not in data and "_download_url" not in data, data
        self.calls[name] += 1
        return data

    def wait(self, queued):
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            job = self.call("flow_get_job", job_id=queued["job_id"])
            if job["state"] in {
                "complete",
                "failed",
                "stale",
                "cancelled",
                "interrupted",
            }:
                assert job["state"] == "complete", job
                return job["result"]
            time.sleep(0.05)
        raise TimeoutError(queued)

    def pages(self, name, **arguments):
        items, cursor, chunks = [], None, {}
        while True:
            page = self.call(name, **arguments, cursor=cursor, limit=200)
            for item in page["items"]:
                if item.get("type") != "canonical_json_chunk":
                    items.append(item)
                    continue
                key = item["item_id"]
                text = chunks.setdefault(key, "")
                assert item["offset"] == len(text)
                chunks[key] += item["text"]
                if len(chunks[key]) == item["total_length"]:
                    items.append(json.loads(chunks.pop(key)))
            cursor = page["next_cursor"]
            if cursor is None:
                assert not chunks
                return items, page["metadata"]


def observations(nodes, address):
    by_id = {node["node_id"]: node for node in nodes}
    selected = [
        node
        for node in nodes
        if node["kind"] == "Store"
        and by_id[node["memory_operands"]["address"]]["constant"] == address
    ]
    assert selected, ("missing dedicated observation Store", address, nodes)
    return selected


class SourceSelectionError(ValueError):
    """The public whole-node selector cannot represent the calibrated source."""


def calibrate(nodes, selected, graph):
    """Find ABI input ranges from an identity's actual observed dependencies.

    Do not seed all InputValues (that would also taint frame/unused registers).
    Calibration is only source selection; the C oracle is independent.
    """
    by_id = {node["node_id"]: node for node in nodes}
    pending = [node["memory_operands"]["data"] for node in selected]
    seen, ranges = set(), set()
    while pending:
        nid = pending.pop()
        if nid in seen:
            continue
        seen.add(nid)
        node = by_id[nid]
        if node["kind"] == "InputValue" and (location := entry_range(node)):
            ranges.add(location)
        if node["kind"] == "Load":
            pending.extend(
                edge["source"]
                for edge in graph
                if edge.get("type") == "edge"
                and edge["kind"] == "memory_data_dependency"
                and edge["target"] == nid
            )
        elif node["kind"] == "Store":
            pending.append(node["memory_operands"]["data"])
        else:
            pending.extend(node["inputs"])
        pending.extend(p["node_id"] for p in node["phi_inputs"])
    if not ranges:
        raise SourceSelectionError("identity exposes no content-dependent ABI input")
    return sorted(ranges)


def run_case(client, name, expected, profile, abi, input_ranges, *, explain=False):
    client.stage = "snapshot"
    client.case_context = {"expected_dependency": expected}
    result = client.wait(
        client.call(
            "flow_create_snapshot",
            function="_taint_" + name,
            profile=profile,
            abi=abi,
            routing_mode="analyst_selected",
            request_key="snapshot-" + name,
        )
    )
    assert result["target_executed"] is False
    client.case_context["snapshot_result"] = result
    derived_memory_evidence_pages = []
    if name == DIRECT_CALL:
        for entry in result.get("derived_call_memory_evidence", []):
            evidence_items, evidence_metadata = client.pages(
                "flow_get_derived_call_evidence",
                artifact_id=entry["artifact_id"],
            )
            derived_memory_evidence_pages.append(
                {"metadata": evidence_metadata, "items": evidence_items}
            )
    nodes, ssa_meta = client.pages(
        "flow_get_function_ssa", artifact_id=result["ssa_artifact"]
    )
    graph, graph_meta = client.pages(
        "flow_get_graph", artifact_id=result["graph_artifact"]
    )
    calls, call_meta = client.pages(
        "flow_get_call_compositions", artifact_id=result["call_composition_artifact"]
    )
    memory_items, memory_meta = client.pages(
        "flow_get_memory_analysis", artifact_id=result["memory_result_artifact"]
    )
    assert memory_meta["target_executed"] is False
    assert memory_meta["alias_policy"]["untyped_input_current_frame"] == (
        "may_alias_unknown"
    )
    memory_objects = {
        item["object_id"]: item for item in memory_items if item["type"] == "object"
    }
    bounded_accesses = [
        item
        for item in memory_items
        if item["type"] == "access"
        and len(item["candidates"]) == 2
        and item["precision"] == "may_alias"
        and all(
            memory_objects[candidate["object_id"]]["kind"] == "stack"
            and candidate["interval"] is not None
            and candidate["interval"]["end"] - candidate["interval"]["start"] == 4
            for candidate in item["candidates"]
        )
        and abs(
            item["candidates"][0]["interval"]["start"]
            - item["candidates"][1]["interval"]["start"]
        )
        == 4
    ]
    if name == "array_index":
        assert bounded_accesses, "array[n & 1] lost its two bounded stack candidates"
    client.case_context.update(
        {
            "nodes": nodes,
            "graph": graph,
            "ssa_metadata": ssa_meta,
            "graph_metadata": graph_meta,
            "call_metadata": call_meta,
            "call_compositions": calls,
            "memory_items": memory_items,
            "memory_metadata": memory_meta,
            "bounded_accesses": bounded_accesses,
        }
    )
    selected_observations = observations(nodes, client.observation_address)
    client.stage = "source_selection"
    if name in {"identity", "pointer_identity"}:
        input_ranges = calibrate(nodes, selected_observations, graph)
        required_bits = 64 if name == "pointer_identity" else 32
        if len(input_ranges) != 1 or input_ranges[0][1] != required_bits:
            raise SourceSelectionError(
                f"ambiguous identity input ranges: {input_ranges}"
            )
    if input_ranges is None:
        raise SourceSelectionError("prerequisite identity calibration failed")
    seeds = source_seeds(nodes, input_ranges)
    if expected and not seeds:
        exposed = [entry_range(node) for node in nodes if node["kind"] == "InputValue"]
        raise SourceSelectionError(
            f"no exact whole-node seed for {input_ranges}; exposed ranges: {exposed}"
        )
    client.case_context.update({"seeds": seeds, "source_ranges": input_ranges})
    client.stage = "implicit_analysis"
    analysis = client.wait(
        client.call(
            "flow_create_implicit_analysis",
            ssa_artifact=result["ssa_artifact"],
            seeds=sorted(seeds, key=lambda seed: seed["node_id"]),
            request_key="taint-" + name,
        )
    )
    facts, metadata = client.pages(
        "flow_get_implicit_analysis", artifact_id=analysis["implicit_artifact"]
    )
    by_id = {
        item["node_id"]: item["labels"] for item in facts if item["type"] == "fact"
    }
    returns = [
        {"node_id": node["node_id"], "labels": by_id[node["node_id"]]}
        for node in selected_observations
    ]
    explanations = []
    if explain:
        for observed_node in selected_observations:
            cause_items, cause_metadata = client.pages(
                "flow_explain_implicit_analysis",
                artifact_id=analysis["implicit_artifact"],
                observation_node_id=observed_node["node_id"],
            )
            explanations.append(
                {
                    "node_id": observed_node["node_id"],
                    "metadata": cause_metadata,
                    "items": cause_items,
                }
            )
    observed = any(
        "argument-0" in ret["labels"][kind]
        for ret in returns
        for kind in ("explicit", "control")
    )
    unknown = any(ret["labels"]["unknown_provenance"] for ret in returns)
    uncertain = metadata["status"] != "complete_in_scope" or unknown
    row = {
        "case": name,
        "expected_dependency": expected,
        "observed_dependency": observed,
        "observation_unknown": unknown,
        "observation_kind": "dedicated_volatile_store",
        "native_return_node_count": sum(node["kind"] == "Return" for node in nodes),
        "classification": classify(expected, observed, uncertain),
        "label_comparison": (
            "calibration"
            if expected is None
            else "match"
            if expected == observed
            else "extra_label"
            if observed
            else "missing_label"
        ),
        "source_absent": not seeds,
        "source_ranges": input_ranges,
        "seeds": seeds,
        "snapshot_result": result,
        "derived_memory_evidence_pages": derived_memory_evidence_pages,
        "ssa_metadata": ssa_meta,
        "graph_metadata": graph_meta,
        "nodes": nodes,
        "graph": graph,
        "implicit_metadata": metadata,
        "implicit_items": facts,
        "observations": returns,
        "explanations": explanations,
        "call_metadata": call_meta,
        "call_compositions": calls,
        "memory_items": memory_items,
        "memory_metadata": memory_meta,
        "bounded_accesses": bounded_accesses,
    }
    return row, input_ranges


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--details-output",
        type=Path,
        default=ROOT / "build/taint-scenarios-details.json",
    )
    parser.add_argument("--arch", choices=("x86_64", "arm64"), action="append")
    parser.add_argument("--optimization", choices=("O0", "O1"), action="append")
    parser.add_argument("--case", choices=tuple(CASES), action="append")
    parser.add_argument("--explain", action="store_true")
    parser.add_argument("--mode", choices=("diagnostic", "acceptance"), default="diagnostic")
    args = parser.parse_args()
    if args.mode == "acceptance" and (args.arch or args.optimization or args.case):
        parser.error("acceptance requires the complete two-architecture O0/O1 matrix")
    if args.mode == "acceptance":
        args.explain = True
    from ida_pro_mcp import idalib_supervisor as sm
    from ida_pro_mcp.flow_core.build_identity import BUILD_ID

    work = Path(tempfile.mkdtemp(prefix="flow-taint-scenarios-")).resolve()
    print("Disposable build/IDB directory:", work, flush=True)
    os.environ["IDA_MCP_FLOW_STATE_ROOT"] = str(work / "state")
    supervisor = sm.IdalibSupervisor(
        sm.mcp,
        max_workers=1,
        worker_args=["--profile", str(ROOT / "profiles/flow-readonly.txt")],
    )
    sm.supervisor = supervisor
    implementation = [
        *sorted((ROOT / "src/ida_pro_mcp/flow_core").glob("*.py")),
        *sorted((ROOT / "src/ida_pro_mcp/ida_mcp/flow").glob("*.py")),
        ROOT / "src/ida_pro_mcp/ida_mcp/api_flow.py",
    ]
    receipt = {
        "schema_version": "flow-taint-scenarios/1",
        "target_executed": False,
        "scope": "local static diagnostic, not support or vulnerability verdict",
        "validation_mode": args.mode,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "build_id": BUILD_ID,
        "source_sha256": sha(SOURCE),
        "runner_sha256": sha(__file__),
        "implementation_sha256": {
            str(p.relative_to(ROOT)): sha(p) for p in implementation
        },
        "compiler": subprocess.check_output(["clang", "--version"], text=True).strip(),
        "sdk": subprocess.check_output(
            ["xcrun", "--show-sdk-version"], text=True
        ).strip(),
        "work_directory": str(work),
        "runs": [],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.details_output.parent.mkdir(parents=True, exist_ok=True)

    def save():
        args.details_output.write_text(json.dumps(receipt, indent=2) + "\n")
        summary = {
            **receipt,
            "details_path": str(args.details_output),
            "details_sha256": sha(args.details_output),
            "runs": [],
        }
        for run in receipt["runs"]:
            summary["runs"].append(
                {
                    **run,
                    "cases": [
                        {
                            k: v
                            for k, v in row.items()
                            if k
                            not in {
                                "nodes",
                                "graph",
                                "implicit_items",
                                "explanations",
                                "call_compositions",
                                "memory_items",
                            }
                        }
                        for row in run["cases"]
                    ],
                }
            )
        args.output.write_text(json.dumps(summary, indent=2) + "\n")

    try:
        for arch in args.arch or ["x86_64", "arm64"]:
            profile, abi = (
                ("X64-LE", "darwin-x86_64-sysv-derived")
                if arch == "x86_64"
                else ("A64-LE", "darwin-aarch64")
            )
            for opt in args.optimization or ["O0", "O1"]:
                directory = work / (arch + "-" + opt)
                directory.mkdir()
                binary = directory / "taint_scenarios"
                flags = [
                    "-arch",
                    arch,
                    "-" + opt,
                    "-fno-stack-protector",
                    "-fno-optimize-sibling-calls",
                    "-fno-builtin",
                    "-Wl,-no_uuid",
                ]
                subprocess.run(
                    ["clang", *flags, str(SOURCE), "-o", str(binary)], check=True
                )
                disposable = directory / "analysis_copy"
                shutil.copy2(binary, disposable)
                session = supervisor.open_session(
                    str(disposable), mode="force_headless"
                )
                symbols = subprocess.check_output(["nm", "-n", str(binary)], text=True)
                address = int(
                    next(
                        line.split()[0]
                        for line in symbols.splitlines()
                        if line.endswith(" _taint_observation")
                    ),
                    16,
                )
                client = Client(sm, session.session_id, address)
                run = {
                    "arch": arch,
                    "optimization": opt,
                    "profile": profile,
                    "abi": abi,
                    "format": "Mach-O",
                    "flags": flags,
                    "observation_symbol_address": address,
                    "binary_sha256": sha(binary),
                    "cases": [],
                }
                receipt["runs"].append(run)
                try:
                    run["capabilities"] = client.call("flow_get_capabilities")
                    assert run["capabilities"]["environment"]["ida_version"] == "9.3"
                    ranges = {}
                    for name, expected in CASES.items():
                        if args.case and name not in {
                            "identity",
                            "pointer_identity",
                            *args.case,
                        }:
                            continue
                        key = (
                            "pointer"
                            if name in {"pointer_identity", "pointer_only"}
                            else "value"
                        )
                        try:
                            row, selected = run_case(
                                client,
                                name,
                                expected,
                                profile,
                                abi,
                                ranges.get(key),
                                explain=args.explain,
                            )
                            ranges[key] = selected
                        except Exception as exc:
                            row = {
                                **client.case_context,
                                "case": name,
                                "classification": (
                                    "source_selection_unavailable"
                                    if isinstance(exc, SourceSelectionError)
                                    else "error"
                                ),
                                "error_type": type(exc).__name__,
                                "stage": client.stage,
                                "error": repr(exc),
                            }
                        run["cases"].append(row)
                        print(arch, opt, name, row["classification"], flush=True)
                        save()
                    run["calls"] = dict(client.calls)
                finally:
                    supervisor.close_session(session.session_id, save=False)
                    run["closed_save_false"] = True
                    run["input_preserved"] = sha(binary) == sha(disposable)
                    save()
    finally:
        for database in list(supervisor.sessions):
            supervisor.close_session(database, save=False)
        supervisor.shutdown()
    receipt["counts"] = dict(
        Counter(
            row["classification"] for run in receipt["runs"] for row in run["cases"]
        )
    )
    if args.mode == "acceptance":
        issues = acceptance_issues(receipt)
        receipt["acceptance"] = {
            "status": "bounded_partial" if not issues else "failed",
            "issues": issues,
            "support_promoted": False,
            "vulnerability_verdict": False,
        }
    save()
    print(json.dumps(receipt["counts"], indent=2))
    if args.mode == "acceptance":
        if issues:
            print(json.dumps({"acceptance_issues": issues}, indent=2))
            raise SystemExit(1)
        return
    if any(
        receipt["counts"].get(key)
        for key in (
            "error",
            "source_selection_unavailable",
            "missing_taint",
            "overtaint",
            "inconclusive_partial",
        )
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
