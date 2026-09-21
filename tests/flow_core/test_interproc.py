"""C02-C04 pure call-plan tests; no target execution or IDA imports."""

from dataclasses import replace

import pytest

from ida_pro_mcp.flow_core import ContractError, canonical_json, digest, stable_id
from ida_pro_mcp.flow_core.interproc import (
    CallContext,
    CallFrame,
    CallPlan,
    CallPolicy,
    CallSite,
    plan_direct_call,
    plan_indirect_call,
)
from ida_pro_mcp.flow_core.summaries import (
    ReturnEffect,
    ReviewedSummary,
    SummaryCatalog,
    SummaryIdentity,
)

POLICY = CallPolicy(max_context_depth=4, max_recursion_depth=1)


def summary_identity(name: str, rva: int) -> SummaryIdentity:
    return SummaryIdentity(
        digest("call-fixture").split(":", 1)[1],
        rva,
        stable_id("snapshot", {"callee": name}),
        digest("profile-v1"),
        "darwin-aarch64",
        digest({"signature": "u32(u32)", "callee": name}),
    )


def reviewed(name: str, rva: int) -> ReviewedSummary:
    return ReviewedSummary(
        summary_identity(name, rva),
        name,
        "identity",
        (ReturnEffect("argument", 32, argument_index=0),),
        (),
        (),
        "fixture-review",
        digest({"reviewed": name}),
    )


def catalog(*summaries: ReviewedSummary) -> SummaryCatalog:
    return SummaryCatalog(
        tuple(sorted(summaries, key=lambda summary: summary.identity.sort_key))
    )


def site(caller: str, rva: int, kind: str = "direct") -> CallSite:
    return CallSite(stable_id("snapshot", caller), caller, rva, kind)


def test_c02_direct_calls_keep_shared_callee_contexts_distinct():
    identity = reviewed("call_identity", 0x100)
    summaries = catalog(identity)
    left = plan_direct_call(
        summaries,
        site("call_context_left", 0x200),
        CallContext(),
        identity.identity,
        POLICY,
    )
    right = plan_direct_call(
        summaries,
        site("call_context_right", 0x240),
        CallContext(),
        identity.identity,
        POLICY,
    )
    assert left.branches[0].summary == right.branches[0].summary
    assert left.branches[0].context != right.branches[0].context
    assert (
        left.branches[0].context.context_digest
        != right.branches[0].context.context_digest
    )
    assert left.unknown_remainder is right.unknown_remainder is None
    assert CallPlan.from_json(canonical_json(left)) == left


def test_c03_recursion_and_context_limits_emit_unknown_effects():
    recursive = reviewed("call_recursive", 0x300)
    summaries = catalog(recursive)
    recursive_site = site("call_recursive", 0x318)
    prior = CallContext((CallFrame(recursive_site, recursive.identity),))
    plan = plan_direct_call(
        summaries, recursive_site, prior, recursive.identity, POLICY
    )
    assert plan.branches == ()
    assert plan.unknown_remainder.reasons == ("recursion_limit",)
    assert plan.unknown_remainder.return_effect == "unknown"
    assert plan.unknown_remainder.memory_effect == "reachable_havoc"
    assert plan.unknown_remainder.lifetime_effect == "reachable_may_change"

    shallow = CallPolicy(max_context_depth=1, max_recursion_depth=4)
    other = reviewed("call_identity", 0x100)
    limited = plan_direct_call(
        catalog(recursive, other),
        site("call_recursive", 0x31C),
        prior,
        other.identity,
        shallow,
    )
    assert limited.branches == ()
    assert limited.unknown_remainder.reasons == ("context_limit",)


def test_c04_indirect_candidates_join_with_unknown_remainder_deterministically():
    identity = reviewed("call_identity", 0x100)
    increment = reviewed("call_candidate_increment", 0x180)
    summaries = catalog(increment, identity)
    indirect_site = site("call_indirect", 0x400, "indirect")
    plan = plan_indirect_call(
        summaries,
        indirect_site,
        CallContext(),
        (increment.identity, identity.identity, increment.identity),
        exhaustive=False,
        policy=POLICY,
    )
    reverse = plan_indirect_call(
        summaries,
        indirect_site,
        CallContext(),
        (identity.identity, increment.identity),
        exhaustive=False,
        policy=POLICY,
    )
    assert [branch.summary.display_name for branch in plan.branches] == [
        "call_identity",
        "call_candidate_increment",
    ]
    assert plan.plan_digest == reverse.plan_digest
    assert plan.unknown_remainder.reasons == ("nonexhaustive_indirect",)
    assert plan.unknown_remainder.memory_effect == "reachable_havoc"


def test_missing_reviewed_candidate_is_not_matched_by_name_or_dropped():
    identity = reviewed("same_name", 0x100)
    unreviewed_identity = replace(identity.identity, callee_rva=0x120)
    plan = plan_indirect_call(
        catalog(identity),
        site("call_indirect", 0x400, "indirect"),
        CallContext(),
        (unreviewed_identity,),
        exhaustive=True,
        policy=POLICY,
    )
    assert plan.branches == ()
    assert plan.unknown_remainder.reasons == ("missing_reviewed_summary",)
    assert plan.unknown_remainder.blocked_targets == (unreviewed_identity,)


def test_empty_or_invalid_call_plans_rejected():
    summaries = SummaryCatalog(())
    unresolved = plan_indirect_call(
        summaries,
        site("caller", 0x10, "indirect"),
        CallContext(),
        (),
        exhaustive=True,
        policy=POLICY,
    )
    assert unresolved.unknown_remainder.reasons == ("no_candidates",)
    empty = site("caller", 0x10)
    with pytest.raises(ContractError, match="empty no-effect"):
        CallPlan(empty, CallContext(), summaries.catalog_digest, (), None)
