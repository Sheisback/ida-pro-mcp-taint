"""Bounded same-database local callee extraction for unreviewed static proof."""

from typing import cast

from ida_pro_mcp.flow_core.derived_calls import resolve_finite_indirect_targets
from ida_pro_mcp.flow_core.serialization import ContractError, wire_safe_rva
from ida_pro_mcp.flow_core.ssa import build_ssa

from . import extractor

MAX_LOCAL_CALLEES = 8


def extract_local_direct_callees(ctx, root: extractor.ExtractedFunction, info):
    """Read exact direct or completely finite indirect local function entries."""
    import ida_funcs

    result = {
        "mode": "derived_static_unreviewed",
        "max_depth": 1,
        "max_functions": MAX_LOCAL_CALLEES,
        "visited_rvas": [],
        "boundaries": [],
    }
    snapshots = {}
    attempted = {root.function_rva}

    def load_target(callee_ea):
        ctx.check()
        rva = callee_ea - root.image_base
        reason = None
        if rva < 0:
            reason = "callee_outside_image"
        elif rva == root.function_rva:
            reason = "recursive_boundary"
        elif rva in snapshots:
            return rva, None
        elif rva in attempted:
            reason = "callee_extraction_unavailable"
        elif len(attempted) >= MAX_LOCAL_CALLEES + 1:
            reason = "function_limit"
        else:
            fn = ida_funcs.get_func(callee_ea)
            if fn is None or int(fn.start_ea) != callee_ea:
                reason = "no_exact_local_function"
            else:
                attempted.add(rva)
                try:
                    callee = cast(
                        extractor.ExtractedFunction,
                        extractor.extract_snapshot(
                            callee_ea,
                            namespace=root.snapshot.identity.namespace,
                            function_key="function-entry:" + str(callee_ea),
                            profile=info["profile"],
                            summary_digest=root.snapshot.identity.summary_digest,
                            wire_version=root.snapshot.identity.wire_version,
                            deadline=ctx.deadline,
                            cancelled=ctx.cancel.is_set,
                            include_calls=True,
                            registry=info["registry"],
                        ),
                    )
                except (ContractError, RuntimeError):
                    reason = "callee_extraction_unavailable"
                else:
                    ctx.check()
                    identity = callee.snapshot.identity
                    caller = root.snapshot.identity
                    if (
                        identity.binary_digest != caller.binary_digest
                        or identity.profile_digest != caller.profile_digest
                        or identity.rule_digest != caller.rule_digest
                        or identity.policy_digest != caller.policy_digest
                        or identity.environment != caller.environment
                        or identity.summary_digest != caller.summary_digest
                        or identity.wire_version != caller.wire_version
                    ):
                        reason = "foreign_or_stale_callee"
                    else:
                        snapshots[rva] = callee.snapshot
        return rva, reason

    def boundary(observation, rva, reason, **details):
        instruction_rva = wire_safe_rva(
            observation.instruction_ea, root.image_base
        )
        result["boundaries"].append(
            {
                "caller_rva": root.function_rva,
                "instruction_rva": instruction_rva,
                "callee_rva": rva,
                "reason": reason,
                **details,
                **(
                    {"rva_unrepresentable": True}
                    if instruction_rva is None
                    else {}
                ),
            }
        )

    base = None
    for observation in root.calls:
        ctx.check()
        callee_ea = observation.call.callee_ea
        if callee_ea is not None:
            rva, reason = load_target(callee_ea)
            if reason is not None:
                boundary(observation, rva, reason)
            continue
        if base is None:
            try:
                base = build_ssa(root.snapshot, storage_model="memory")
            except ContractError:
                boundary(observation, None, "indirect_target_graph_unavailable")
                continue
        proof = resolve_finite_indirect_targets(
            base, observation.block_index, observation.instruction_index
        )
        if proof is None:
            boundary(observation, None, "unresolved_indirect")
            continue
        if not proof.complete:
            boundary(
                observation,
                None,
                "finite_target_set_incomplete",
                candidate_rvas=[ea - root.image_base for ea in proof.targets],
                target_reasons=list(proof.reasons),
            )
            continue
        missing = False
        for target_ea in proof.targets:
            rva, reason = load_target(target_ea)
            if reason is not None:
                missing = True
                boundary(observation, rva, reason)
        if missing:
            boundary(observation, None, "finite_target_extraction_incomplete")
        else:
            result.setdefault("finite_target_sets", []).append(proof.to_data())
    result["visited_rvas"] = sorted(attempted)
    return snapshots, result
