"""Pure reviewed-summary binding for extracted call metadata.

Names are intentionally absent from every lookup path.  Fixture scripts may use
symbols to discover addresses, but runtime binding is pinned to the binary,
callee RVA and baseline snapshot, profile, calling convention, and structural
signature.
"""

from dataclasses import dataclass
from typing import Literal, Protocol

from ida_pro_mcp.flow_core.call_composition import (
    CallCompositionPolicy,
    CallCompositionResult,
    CallInputs,
    CallState,
    CallValue,
    compose_call,
)
from ida_pro_mcp.flow_core.contracts import CallInfo, Operand, Snapshot
from ida_pro_mcp.flow_core.interproc import (
    CallFrame,
    CallContext,
    CallPlan,
    CallPolicy,
    CallSite,
    UnknownRemainder,
    build_call_plan,
)
from ida_pro_mcp.flow_core.serialization import ContractError, Model, digest
from ida_pro_mcp.flow_core.states import (
    BitValue,
    Labels,
    canonical_set,
    check_id,
    nonempty,
    require,
)
from ida_pro_mcp.flow_core.summaries import SummaryCatalog, SummaryIdentity

DEFAULT_CALL_POLICY = CallPolicy(max_context_depth=8, max_recursion_depth=2)
EMPTY_CATALOG = SummaryCatalog(())


class CallObservationLike(Protocol):
    block_index: int
    instruction_index: int
    instruction_ea: int
    call: CallInfo

    def to_data(self) -> dict: ...


class ExtractedFunctionLike(Protocol):
    snapshot: Snapshot
    image_base: int
    function_ea: int
    calls: tuple[CallObservationLike, ...]

    @property
    def function_rva(self) -> int: ...


def _binary_sha256(snapshot: Snapshot) -> str:
    prefix = "sha256-v1:"
    require(
        snapshot.identity.binary_digest.startswith(prefix),
        "Unsupported binary digest",
    )
    return snapshot.identity.binary_digest[len(prefix) :]


def calling_convention(snapshot: Snapshot, call: CallInfo) -> str:
    """Return a stable convention key without parsing display text."""

    return f"{snapshot.identity.environment.abi}:ida-cc-{call.convention}"


def signature_projection(call: CallInfo) -> dict:
    """Project only type-shape metadata; argument values never affect matching.

    The current microcode contract exposes widths and voidness but not complete
    native type/arglocs.  The projection is deliberately honest about that
    limitation and remains versioned so a later richer contract cannot silently
    collide with these reviewed entries.
    """

    return {
        "version": 1,
        "argument_width_bits": [argument.width_bits for argument in call.arguments],
        "return_width_bits": call.return_width_bits,
        "return_is_void": call.return_is_void,
        "return_type_code": call.return_type_code,
        "return_operand_width_bits": [
            operand.width_bits for operand in call.return_operands
        ],
    }


def signature_digest(call: CallInfo) -> str:
    return digest(signature_projection(call))


@dataclass(frozen=True)
class CallBinding(Model):
    observation: dict
    site: CallSite
    candidates: tuple[SummaryIdentity, ...]
    exhaustive: bool
    plan: CallPlan
    limitations: tuple[str, ...]
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        require(self.site == self.plan.site, "Call binding plan/site mismatch")
        keys = tuple(candidate.sort_key for candidate in self.candidates)
        require(
            keys == tuple(sorted(set(keys))),
            "Call binding candidates must be sorted and unique",
        )
        canonical_set(self.limitations)
        for limitation in self.limitations:
            nonempty(limitation)


@dataclass(frozen=True)
class ClosureBoundary(Model):
    caller_snapshot_id: str
    instruction_rva: int
    callee_rva: int | None
    reason: Literal[
        "unresolved_indirect",
        "external_callee",
        "recursive_boundary",
        "depth_limit",
        "function_limit",
    ]
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        check_id(self.caller_snapshot_id, "snapshot")
        require(self.instruction_rva >= 0, "Negative boundary instruction RVA")
        require(self.callee_rva is None or self.callee_rva >= 0, "Negative callee RVA")


def target_identity(
    caller: Snapshot,
    call: CallInfo,
    callee_rva: int,
    callee_snapshot: Snapshot,
) -> SummaryIdentity:
    """Construct the only identity eligible for this observed direct call."""

    require(
        caller.identity.binary_digest == callee_snapshot.identity.binary_digest,
        "Cross-binary callee snapshot",
    )
    require(
        caller.identity.profile_digest == callee_snapshot.identity.profile_digest,
        "Cross-profile callee snapshot",
    )
    return SummaryIdentity(
        _binary_sha256(caller),
        callee_rva,
        callee_snapshot.snapshot_id,
        caller.identity.profile_digest,
        calling_convention(caller, call),
        signature_digest(call),
    )


def _indirect_identity_compatible(
    caller: Snapshot,
    call: CallInfo,
    candidate: SummaryIdentity,
) -> bool:
    """Check every observed identity component available at an indirect call."""

    return (
        candidate.binary_sha256 == _binary_sha256(caller)
        and candidate.profile_digest == caller.identity.profile_digest
        and candidate.calling_convention == calling_convention(caller, call)
        and candidate.signature_digest == signature_digest(call)
    )


def _unresolved_direct_plan(
    site: CallSite,
    context: CallContext,
    catalog: SummaryCatalog,
) -> CallPlan:
    return CallPlan(
        site,
        context,
        catalog.catalog_digest,
        (),
        UnknownRemainder(("no_candidates",)),
    )


def bind_call(
    caller: ExtractedFunctionLike,
    observation: CallObservationLike,
    catalog: SummaryCatalog,
    callee_snapshots: dict[int, Snapshot],
    *,
    indirect_candidates: tuple[SummaryIdentity, ...] = (),
    exhaustive: bool = False,
    context: CallContext = CallContext(),
    policy: CallPolicy = DEFAULT_CALL_POLICY,
) -> CallBinding:
    """Bind one observation to an exact deterministic call plan.

    Direct calls derive their candidate from the actual callee EA and pinned
    baseline snapshot.  Indirect candidates must be supplied as reviewed full
    identities; a non-exhaustive set retains an explicit unknown remainder.
    """

    require(
        caller.snapshot.identity.summary_digest == catalog.catalog_digest,
        "Snapshot/catalog digest mismatch",
    )
    require(observation in caller.calls, "Call observation not owned by caller")
    instruction_rva = observation.instruction_ea - caller.image_base
    require(instruction_rva >= 0, "Call instruction precedes image base")
    callee_ea = observation.call.callee_ea
    direct = callee_ea is not None
    site = CallSite(
        caller.snapshot.snapshot_id,
        caller.snapshot.function.function_id,
        instruction_rva,
        "direct" if direct else "indirect",
    )
    limitations = set(observation.call.unresolved)
    if direct:
        callee_rva = callee_ea - caller.image_base
        callee = callee_snapshots.get(callee_rva)
        if callee is None or callee_rva < 0:
            limitations.add("callee_snapshot_unavailable")
            return CallBinding(
                observation.to_data(),
                site,
                (),
                True,
                _unresolved_direct_plan(site, context, catalog),
                tuple(sorted(limitations)),
            )
        candidate = target_identity(
            caller.snapshot, observation.call, callee_rva, callee
        )
        plan = build_call_plan(
            catalog,
            site,
            context,
            (candidate,),
            exhaustive=True,
            policy=policy,
        )
        if plan.unknown_remainder is not None:
            limitations.add("reviewed_summary_unavailable")
        candidates = (candidate,)
        exhaustive = True
    else:
        candidates = tuple(
            sorted(set(indirect_candidates), key=lambda item: item.sort_key)
        )
        compatible = tuple(
            candidate
            for candidate in candidates
            if _indirect_identity_compatible(
                caller.snapshot, observation.call, candidate
            )
        )
        incompatible = tuple(
            candidate for candidate in candidates if candidate not in compatible
        )
        plan = build_call_plan(
            catalog,
            site,
            context,
            compatible,
            exhaustive=exhaustive and not incompatible,
            policy=policy,
        )
        limitations.add("indirect_target_set_requires_review")
        if incompatible:
            remainder = plan.unknown_remainder
            remainder_reasons = set(
                remainder.reasons if remainder is not None else ()
            )
            remainder_reasons.add("missing_reviewed_summary")
            plan = CallPlan(
                plan.site,
                plan.base_context,
                plan.catalog_digest,
                plan.branches,
                UnknownRemainder(
                    tuple(sorted(remainder_reasons)),
                    tuple(
                        sorted(
                            set(
                                remainder.blocked_targets
                                if remainder is not None
                                else ()
                            )
                            | set(incompatible),
                            key=lambda item: item.sort_key,
                        )
                    ),
                ),
            )
            limitations.add("incompatible_indirect_candidate")
        if plan.unknown_remainder is not None:
            limitations.add("unknown_call_remainder")
    return CallBinding(
        observation.to_data(),
        site,
        candidates,
        exhaustive,
        plan,
        tuple(sorted(limitations)),
    )


def _operand_value(operand: Operand) -> CallValue:
    """Conservatively project one actual extracted argument into call state."""

    width_bits = operand.width_bits
    require(width_bits is not None, "Call argument width is unavailable")
    assert width_bits is not None
    concrete = None
    if operand.kind == "constant":
        concrete = operand.constant
    elif operand.kind == "address":
        concrete = operand.address
    return CallValue(
        BitValue(width_bits, concrete),
        Labels(unknown_provenance=concrete is None),
    )


def extracted_call_inputs(
    observation: CallObservationLike,
    *,
    state: CallState = CallState(),
) -> CallInputs:
    """Build conservative inputs from the extracted ``CallInfo`` arguments."""

    return CallInputs(
        tuple(_operand_value(argument) for argument in observation.call.arguments),
        state,
    )


def composition_policy(caller: ExtractedFunctionLike, observation: CallObservationLike):
    environment = caller.snapshot.identity.environment
    return CallCompositionPolicy(
        address_space=environment.address_space,
        pointer_width_bits=environment.bitness,
        endian=environment.data_endian,
        unknown_return_width_bits=(
            None
            if observation.call.return_is_void
            else observation.call.return_width_bits
        ),
    )


def compose_binding(
    caller: ExtractedFunctionLike,
    binding: CallBinding,
    catalog: SummaryCatalog,
    *,
    callee_snapshots: dict[int, Snapshot] | None = None,
    inputs: CallInputs | None = None,
    policy: CallCompositionPolicy | None = None,
) -> CallCompositionResult:
    """Compose a bound plan only after revalidating its extracted origin/scope."""

    require(
        caller.snapshot.identity.summary_digest
        == binding.plan.catalog_digest
        == catalog.catalog_digest,
        "Call composition catalog digest mismatch",
    )
    matches = tuple(
        observation
        for observation in caller.calls
        if observation.to_data() == binding.observation
    )
    require(len(matches) == 1, "Call binding observation is not anchored to caller")
    observation = matches[0]
    instruction_rva = observation.instruction_ea - caller.image_base
    expected_site = CallSite(
        caller.snapshot.snapshot_id,
        caller.snapshot.function.function_id,
        instruction_rva,
        "direct" if observation.call.callee_ea is not None else "indirect",
    )
    require(binding.site == expected_site, "Call binding site/origin mismatch")
    branch_targets = []
    for branch in binding.plan.branches:
        reviewed = catalog.lookup(branch.summary.identity)
        require(
            reviewed == branch.summary,
            "Call composition branch is not an exact catalog member",
        )
        require(
            branch.context
            == CallContext(
                binding.plan.base_context.frames
                + (CallFrame(expected_site, branch.summary.identity),)
            ),
            "Call composition branch context mismatch",
        )
        if expected_site.kind == "indirect":
            require(
                _indirect_identity_compatible(
                    caller.snapshot, observation.call, branch.summary.identity
                ),
                "Call composition indirect branch identity mismatch",
            )
        branch_targets.append(branch.summary.identity)
    blocked_targets = (
        ()
        if binding.plan.unknown_remainder is None
        else binding.plan.unknown_remainder.blocked_targets
    )
    planned_candidates = tuple(
        sorted(
            set(branch_targets) | set(blocked_targets),
            key=lambda item: item.sort_key,
        )
    )
    if expected_site.kind == "direct" and planned_candidates:
        callee_ea = observation.call.callee_ea
        assert callee_ea is not None
        callee_rva = callee_ea - caller.image_base
        callee_snapshot = (callee_snapshots or {}).get(callee_rva)
        require(
            callee_snapshot is not None,
            "Call composition direct callee snapshot unavailable",
        )
        assert callee_snapshot is not None
        require(
            planned_candidates
            == (
                target_identity(
                    caller.snapshot,
                    observation.call,
                    callee_rva,
                    callee_snapshot,
                ),
            ),
            "Call composition direct target identity mismatch",
        )
    require(
        binding.candidates == planned_candidates,
        "Call binding candidates do not match planned branches/remainder",
    )
    if expected_site.kind == "indirect" and not binding.exhaustive:
        require(
            binding.plan.unknown_remainder is not None
            and "nonexhaustive_indirect"
            in binding.plan.unknown_remainder.reasons,
            "Non-exhaustive indirect binding lost its unknown remainder",
        )
    inputs = inputs or extracted_call_inputs(observation)
    require(
        len(inputs.arguments) == len(observation.call.arguments),
        "Call composition argument count mismatch",
    )
    for actual, semantic in zip(observation.call.arguments, inputs.arguments):
        require(
            actual.width_bits == semantic.value.width_bits,
            "Call composition argument width mismatch",
        )
    return compose_call(
        binding.plan,
        inputs,
        policy or composition_policy(caller, observation),
    )


def bounded_callee_closure(
    roots: tuple[int, ...],
    functions: dict[int, ExtractedFunctionLike],
    *,
    max_depth: int = 8,
    max_functions: int = 64,
) -> tuple[tuple[int, ...], tuple[ClosureBoundary, ...]]:
    """Compute a deterministic finite direct-callee closure over owned functions."""

    require(max_depth >= 0, "Negative closure depth")
    require(max_functions > 0, "Closure function budget must be positive")
    require(
        all(root in functions for root in roots),
        "Closure root is outside the owned fixture",
    )
    unique_roots = tuple(sorted(set(roots)))
    require(
        len(unique_roots) <= max_functions,
        "Closure roots exceed the function budget",
    )
    queue: list[tuple[int, int, tuple[int, ...], str | None, int | None]] = [
        (root, 0, (), None, None) for root in unique_roots
    ]
    visited = set()
    boundaries = set()
    while queue:
        rva, depth, ancestry, caller_snapshot_id, instruction_rva = queue.pop(0)
        if rva in visited:
            continue
        if len(visited) >= max_functions:
            pending = [(rva, caller_snapshot_id, instruction_rva)] + [
                (remaining, caller, instruction)
                for remaining, _, _, caller, instruction in queue
            ]
            for remaining, caller, instruction in pending:
                if caller is None or instruction is None:
                    raise ContractError(
                        "Closure root unexpectedly exceeded the function budget"
                    )
                boundaries.add(
                    ClosureBoundary(
                        caller,
                        instruction,
                        remaining,
                        "function_limit",
                    )
                )
            break
        visited.add(rva)
        function = functions[rva]
        for observation in function.calls:
            instruction_rva = observation.instruction_ea - function.image_base
            target_ea = observation.call.callee_ea
            if target_ea is None:
                boundaries.add(
                    ClosureBoundary(
                        function.snapshot.snapshot_id,
                        instruction_rva,
                        None,
                        "unresolved_indirect",
                    )
                )
                continue
            target_rva = target_ea - function.image_base
            if target_rva not in functions:
                boundaries.add(
                    ClosureBoundary(
                        function.snapshot.snapshot_id,
                        instruction_rva,
                        target_rva if target_rva >= 0 else None,
                        "external_callee",
                    )
                )
            elif target_rva in ancestry or target_rva == rva:
                boundaries.add(
                    ClosureBoundary(
                        function.snapshot.snapshot_id,
                        instruction_rva,
                        target_rva,
                        "recursive_boundary",
                    )
                )
            elif depth >= max_depth:
                boundaries.add(
                    ClosureBoundary(
                        function.snapshot.snapshot_id,
                        instruction_rva,
                        target_rva,
                        "depth_limit",
                    )
                )
            elif target_rva not in visited:
                queue.append(
                    (
                        target_rva,
                        depth + 1,
                        ancestry + (rva,),
                        function.snapshot.snapshot_id,
                        instruction_rva,
                    )
                )
        queue.sort(key=lambda item: (item[1], item[0], item[2], item[3] or ""))
    ordered_boundaries = tuple(
        sorted(
            boundaries,
            key=lambda item: (
                item.caller_snapshot_id,
                item.instruction_rva,
                -1 if item.callee_rva is None else item.callee_rva,
                item.reason,
            ),
        )
    )
    return tuple(sorted(visited)), ordered_boundaries
