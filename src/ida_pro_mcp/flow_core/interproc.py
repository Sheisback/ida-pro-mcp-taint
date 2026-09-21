"""Deterministic reviewed-summary call planning.

Plans retain every known candidate branch.  Non-exhaustive candidate sets and
context/recursion boundaries are represented by an explicit conservative
remainder rather than an empty no-effect result.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from .serialization import Model, digest
from .states import canonical_set, check_digest, check_id, nonempty, require
from .summaries import ReviewedSummary, SummaryCatalog, SummaryIdentity

CallKind = Literal["direct", "indirect"]
RemainderReason = Literal[
    "nonexhaustive_indirect",
    "missing_reviewed_summary",
    "context_limit",
    "recursion_limit",
    "no_candidates",
]


@dataclass(frozen=True)
class CallSite(Model):
    caller_snapshot_id: str
    caller_function_id: str
    instruction_rva: int
    kind: CallKind
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        check_id(self.caller_snapshot_id, "snapshot")
        nonempty(self.caller_function_id)
        require(self.instruction_rva >= 0, "Negative call-site RVA")

    @property
    def site_digest(self) -> str:
        return digest(self)


@dataclass(frozen=True)
class CallFrame(Model):
    site: CallSite
    target: SummaryIdentity


@dataclass(frozen=True)
class CallContext(Model):
    frames: tuple[CallFrame, ...] = ()
    schema_version: Literal[1] = 1

    @property
    def context_digest(self) -> str:
        return digest(self)


@dataclass(frozen=True)
class CallPolicy(Model):
    max_context_depth: int
    max_recursion_depth: int
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        require(self.max_context_depth > 0, "Context bound must be positive")
        require(self.max_recursion_depth > 0, "Recursion bound must be positive")


@dataclass(frozen=True)
class UnknownRemainder(Model):
    reasons: tuple[RemainderReason, ...]
    blocked_targets: tuple[SummaryIdentity, ...] = ()
    return_effect: Literal["unknown"] = "unknown"
    memory_effect: Literal["reachable_havoc"] = "reachable_havoc"
    lifetime_effect: Literal["reachable_may_change"] = "reachable_may_change"
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        require(bool(self.reasons), "Unknown remainder needs a reason")
        canonical_set(self.reasons)
        keys = tuple(target.sort_key for target in self.blocked_targets)
        require(
            keys == tuple(sorted(set(keys))),
            "Blocked targets must be sorted and unique",
        )


@dataclass(frozen=True)
class CallBranch(Model):
    summary: ReviewedSummary
    context: CallContext

    def __post_init__(self):
        super().__post_init__()
        require(bool(self.context.frames), "Call branch needs a callee frame")
        require(
            self.context.frames[-1].target == self.summary.identity,
            "Branch context target differs from summary identity",
        )


@dataclass(frozen=True)
class CallPlan(Model):
    site: CallSite
    base_context: CallContext
    catalog_digest: str
    branches: tuple[CallBranch, ...]
    unknown_remainder: UnknownRemainder | None
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        check_digest(self.catalog_digest)
        keys = tuple(branch.summary.identity.sort_key for branch in self.branches)
        require(
            keys == tuple(sorted(set(keys))),
            "Call branches must be sorted and unique by target",
        )
        require(
            self.site.kind != "direct" or len(self.branches) <= 1,
            "Direct call cannot have multiple known branches",
        )
        require(
            bool(self.branches) or self.unknown_remainder is not None,
            "Call plan cannot be an empty no-effect plan",
        )

    @property
    def plan_digest(self) -> str:
        return digest(self)


def _plan_candidate(
    catalog: SummaryCatalog,
    site: CallSite,
    context: CallContext,
    target: SummaryIdentity,
    policy: CallPolicy,
) -> tuple[CallBranch | None, RemainderReason | None]:
    if len(context.frames) >= policy.max_context_depth:
        return None, "context_limit"
    recursive_depth = sum(frame.target == target for frame in context.frames)
    if recursive_depth >= policy.max_recursion_depth:
        return None, "recursion_limit"
    summary = catalog.lookup(target)
    if summary is None:
        return None, "missing_reviewed_summary"
    next_context = CallContext(context.frames + (CallFrame(site, target),))
    return CallBranch(summary, next_context), None


def build_call_plan(
    catalog: SummaryCatalog,
    site: CallSite,
    context: CallContext,
    candidates: Iterable[SummaryIdentity],
    *,
    exhaustive: bool,
    policy: CallPolicy,
) -> CallPlan:
    """Build a deterministic direct or indirect call plan.

    Candidate order is irrelevant.  Direct calls require one exhaustive target;
    indirect calls may retain an explicit non-exhaustive remainder.
    """

    targets = tuple(sorted(set(candidates), key=lambda target: target.sort_key))
    if site.kind == "direct":
        require(len(targets) == 1 and exhaustive, "Direct call needs one exact target")
    branches = []
    reasons = []
    blocked = []
    for target in targets:
        branch, reason = _plan_candidate(catalog, site, context, target, policy)
        if branch is not None:
            branches.append(branch)
        else:
            reasons.append(reason)
            blocked.append(target)
    if not targets:
        reasons.append("no_candidates")
    if site.kind == "indirect" and not exhaustive:
        reasons.append("nonexhaustive_indirect")
    remainder = None
    if reasons:
        remainder = UnknownRemainder(
            tuple(sorted(set(reasons))),
            tuple(sorted(set(blocked), key=lambda target: target.sort_key)),
        )
    return CallPlan(
        site,
        context,
        catalog.catalog_digest,
        tuple(branches),
        remainder,
    )


def plan_direct_call(
    catalog: SummaryCatalog,
    site: CallSite,
    context: CallContext,
    target: SummaryIdentity,
    policy: CallPolicy,
) -> CallPlan:
    require(site.kind == "direct", "Direct planner needs a direct call site")
    return build_call_plan(
        catalog, site, context, (target,), exhaustive=True, policy=policy
    )


def plan_indirect_call(
    catalog: SummaryCatalog,
    site: CallSite,
    context: CallContext,
    candidates: Iterable[SummaryIdentity],
    *,
    exhaustive: bool,
    policy: CallPolicy,
) -> CallPlan:
    require(site.kind == "indirect", "Indirect planner needs an indirect call site")
    return build_call_plan(
        catalog,
        site,
        context,
        candidates,
        exhaustive=exhaustive,
        policy=policy,
    )
