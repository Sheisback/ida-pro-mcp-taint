"""Bounded static extraction of exactly reviewed owned-fixture callees."""

from typing import cast

from ida_pro_mcp.flow_core import digest
from ida_pro_mcp.flow_core.reviewed_fixtures import reviewed_fixture
from ida_pro_mcp.flow_core.serialization import ContractError

from . import extractor
from .summary_catalog import EMPTY_CATALOG

MAX_CALLEE_DEPTH = 8
MAX_CALLEE_FUNCTIONS = 64


def runtime_fixture(info):
    if info is None:
        return None
    fixture = reviewed_fixture(info["binary"])
    if fixture is None:
        return None
    baseline = fixture.baselines[0][1]
    if (
        digest(info["profile"]) != baseline.profile_digest
        or digest(extractor.RULES) != baseline.rule_digest
        or digest(extractor.POLICY) != baseline.policy_digest
        or info["ida"] != baseline.environment.ida_build
        or info["hexrays"] != baseline.environment.hexrays_build
    ):
        return None
    return fixture


def catalog_for_runtime(info):
    fixture = runtime_fixture(info)
    return EMPTY_CATALOG if fixture is None else fixture.catalog


def extract_callee_closure(
    ctx,
    root: extractor.ExtractedFunction,
    info,
    *,
    max_depth=MAX_CALLEE_DEPTH,
    max_functions=MAX_CALLEE_FUNCTIONS,
):
    """Re-extract pinned baselines on the IDA thread; never trust cached IDs.

    Baseline namespaces are immutable review identity salts only. These snapshots
    are never stored as authorized runtime artifacts. Every callee body, profile,
    ruleset, environment and summary baseline must reproduce its reviewed ID.
    """
    if max_depth < 0 or max_functions < 1:
        raise ContractError("Invalid callee closure budget")
    fixture = runtime_fixture(info)
    result = {
        "max_depth": max_depth,
        "max_functions": max_functions,
        "visited_rvas": [],
        "boundaries": [],
    }
    if fixture is None:
        return {}, result
    pins = dict(fixture.baselines)
    snapshots = {}
    attempted = {root.function_rva}
    queue: list[tuple[extractor.ExtractedFunction, int, tuple[int, ...]]] = [
        (root, 0, (root.function_rva,))
    ]
    while queue:
        caller, depth, ancestry = queue.pop(0)
        ctx.check()
        for observation in caller.calls:
            ctx.check()
            callee_ea = observation.call.callee_ea
            rva = None if callee_ea is None else callee_ea - caller.image_base
            reason = None
            if rva is None:
                reason = "unresolved_indirect"
            elif rva in ancestry:
                reason = "recursive_boundary"
            elif rva not in pins:
                reason = "external_or_unreviewed_callee"
            elif depth >= max_depth:
                reason = "depth_limit"
            elif rva in attempted:
                # A prior failed extraction must not silently lose its boundary.
                if rva not in snapshots:
                    reason = "callee_snapshot_unavailable"
            elif len(attempted) >= max_functions:
                reason = "function_limit"
            else:
                attempted.add(rva)
                pin = pins[rva]
                try:
                    callee = cast(
                        extractor.ExtractedFunction,
                        extractor.extract_snapshot(
                            callee_ea,
                            namespace=pin.namespace,
                            function_key=pin.function_id,
                            profile=info["profile"],
                            summary_digest=pin.summary_digest,
                            deadline=ctx.deadline,
                            cancelled=ctx.cancel.is_set,
                            include_calls=True,
                            registry=info["registry"],
                        ),
                    )
                except ContractError:
                    reason = "callee_extraction_unavailable"
                else:
                    if callee.snapshot.identity != pin:
                        reason = "stale_callee_snapshot"
                    else:
                        snapshots[rva] = callee.snapshot
                        queue.append((callee, depth + 1, ancestry + (rva,)))
            if reason is not None:
                result["boundaries"].append(
                    {
                        "caller_rva": caller.function_rva,
                        "instruction_rva": observation.instruction_ea
                        - caller.image_base,
                        "callee_rva": rva,
                        "reason": reason,
                    }
                )
    result["visited_rvas"] = sorted(attempted)
    return snapshots, result
