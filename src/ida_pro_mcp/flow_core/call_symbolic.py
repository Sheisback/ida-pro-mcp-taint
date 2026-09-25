"""Bounded callee inline expansion for symbolic path and memory proofs.

A fragment splices ONE callee path into a caller at ONE call site: entry
parameters bind to caller-provided argument values, the callee return payload
binds to a caller result node, callee memory steps splice into the caller
walk, and callee branch predicates conjoin with the caller prefix.

Scope is deliberately narrow and every boundary degrades to unknown:

- Single level only: a nested call inside a callee body becomes memory
  havoc; any value use of a nested call result refuses the fragment.
- The argument mapping is orchestrator-resolved (ABI/calling convention).
  A fragment proves the callee body *given* those argument values; the
  InlineContext records exactly which caller nodes were bound so a wrong
  mapping is auditable, never silent.
- Recursion and depth are refused explicitly; widths must match exactly.
"""

import hashlib
from dataclasses import dataclass, replace
from types import SimpleNamespace

from .constraints import ProofAssumption
from .contracts import Graph, MemoryOperands
from .memory import MemoryPlan
from .path_conditions import PathSelector, path_bindings
from .path_symbolic import (
    SYMBOLIC_THEORY,
    SymVariable,
    SymbolicCoverage,
    SymbolicPathQuery,
    derive_symbolic_path_query,
    project_value_phi,
    symbolic_predicate_summary,
    symbolic_variable_digest,
)
from .serialization import Model, canonical_json, digest
from .states import check_digest, check_id, nonempty, require
from .symbolic import SymExpr, SymbolicBudgetError, translate_node

SYMBOLIC_INLINE_VERSION = "symbolic-inline-v1"
INLINE_RULE = "bounded-callee-inline-v1"


def ordered_path_steps(plan, path):
    """Plan steps on a fixed path, in block order then definition order.

    Shared by the memory solver and the inline splice. Lives here (not in
    the plan module) so the plan module's receipt hash stays untouched.
    """
    definitions = {item.node_id: item for item in plan.program.definitions}
    by_block: dict[int, list] = {}
    for step in plan.steps:
        block = definitions[step.node_id].block
        if block in path:
            by_block.setdefault(block, []).append(step)
    ordered = []
    for block in path:
        ordered.extend(
            sorted(by_block.get(block, []), key=lambda s: definitions[s.node_id].order)
        )
    return ordered, definitions


@dataclass(frozen=True)
class CalleeBody:
    """A callee program plus the entry/return interface for one inline."""

    graph: Graph
    plan: MemoryPlan
    entry_params: tuple[str, ...]
    return_id: str | None
    callee_digest: str


@dataclass(frozen=True)
class InlineRequest:
    """Splice ``body`` along ``callee_blocks`` at ``call_id``."""

    call_id: str
    caller_result_id: str | None
    body: CalleeBody
    callee_blocks: tuple[int, ...]
    arguments: tuple[str, ...]
    context: tuple[str, ...] = ()
    max_depth: int = 4


@dataclass(frozen=True)
class InlineStep:
    """One callee memory step in callee-path order (versions at splice)."""

    node_id: str
    effect: str


@dataclass(frozen=True)
class InlineContext(Model):
    """Serialized inline record: binds tag, body, arguments, and content."""

    tag: str
    call_id: str
    callee_digest: str
    callee_blocks: tuple[int, ...]
    argument_ids: tuple[str, ...]
    result_id: str = ""
    depth: int = 0
    fragment_digest: str = ""
    engine_version: str = SYMBOLIC_INLINE_VERSION

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.tag)
        check_id(self.call_id, "node")
        check_digest(self.callee_digest)
        require(bool(self.callee_blocks), "Inline needs a callee path")
        require(all(block >= 0 for block in self.callee_blocks), "Negative block")
        for identifier in self.argument_ids:
            check_id(identifier, "node")
        if self.result_id:
            check_id(self.result_id, "node")
        require(self.depth >= 0, "Negative inline depth")
        check_digest(self.fragment_digest)
        nonempty(self.engine_version)


@dataclass(frozen=True)
class InlineFragment:
    """Usable splice, or a refusal (``unknown`` set, rest empty)."""

    tag: str
    context: InlineContext | None
    overlay: dict
    renamed: dict
    steps: tuple[InlineStep, ...]
    predicates: tuple
    variables: tuple[SymVariable, ...]
    translated: int
    unknown: str | None


def callee_body_digest(graph, entry_params, return_id) -> str:
    """Content digest over callee node IDs plus the inline interface."""
    return digest(
        {
            "nodes": sorted(node.node_id for node in graph.nodes),
            "entry_params": list(entry_params),
            "return_id": return_id,
        }
    )


def _tag(call_id: str, depth: int) -> str:
    short = hashlib.sha256(call_id.encode("utf-8")).hexdigest()[:12]
    return f"inline-d{depth}-{short}"


def _rename(tag: str, node_id: str) -> str:
    # Fresh valid-format node IDs: opaque, collision-checked at splice.
    return "node-v1:" + hashlib.sha256(f"{tag}\0{node_id}".encode()).hexdigest()


def _stub(width_bits: int, source_id: str) -> SimpleNamespace:
    return SimpleNamespace(
        kind="Copy",
        width_bits=width_bits,
        inputs=(source_id,),
        operation=None,
        constant=None,
        evidence_ids=(),
    )


def _rewrite(expression: SymExpr, arguments: dict, renamed: dict) -> SymExpr:
    if expression.kind == "var":
        assert expression.name is not None
        if expression.name in arguments:
            replacement = arguments[expression.name]
            require(
                replacement.width_bits == expression.width_bits,
                "inline_argument_width_drift",
            )
            return replacement
        require(expression.name in renamed, "inline_variable_escape")
        return SymExpr("var", expression.width_bits, name=renamed[expression.name])
    if expression.kind == "const":
        return expression
    return SymExpr(
        expression.kind,
        expression.width_bits,
        op=expression.op,
        children=tuple(_rewrite(child, arguments, renamed) for child in expression.children),
        name=expression.name,
        value=expression.value,
    )


def _refuse(tag: str, reason: str) -> InlineFragment:
    return InlineFragment(tag, None, {}, {}, (), (), (), 0, reason)


def inline_callee_body(request: InlineRequest, caller_nodes: dict) -> InlineFragment:
    """Build one splice fragment, or refuse it explicitly as unknown."""
    body = request.body
    depth = len(request.context)
    tag = _tag(request.call_id, depth)
    if request.body.callee_digest in request.context:
        return _refuse(tag, "inline_recursion_refused")
    if depth >= request.max_depth:
        return _refuse(tag, "inline_depth_exceeded")
    require(type(request.max_depth) is int and request.max_depth > 0, "Invalid inline depth")
    require(len(request.arguments) == len(body.entry_params), "inline_argument_arity")
    require(request.call_id in caller_nodes, "inline_unknown_call_site")
    require(
        request.caller_result_id is None or request.caller_result_id in caller_nodes,
        "inline_unknown_result_site",
    )
    callee_function = body.graph.snapshot.function
    require(bool(request.callee_blocks), "Inline needs a callee path")
    require(
        request.callee_blocks[0] == callee_function.entry_block,
        "inline_callee_entry",
    )
    require(
        all(
            0 <= block < len(callee_function.blocks)
            and successor in callee_function.blocks[block].successors
            for block, successor in zip(
                request.callee_blocks, request.callee_blocks[1:]
            )
        ),
        "inline_callee_transition",
    )
    callee_nodes = {node.node_id: node for node in body.graph.nodes}
    for param in body.entry_params:
        require(param in callee_nodes, "inline_unknown_param")
        require(callee_nodes[param].kind == "InputValue", "inline_param_must_be_input")
    if body.return_id is not None:
        require(body.return_id in callee_nodes, "inline_unknown_return")
    if body.return_id is None and request.caller_result_id is not None:
        return _refuse(tag, "inline_void_result")
    for argument in request.arguments:
        require(argument in caller_nodes, "inline_unknown_argument")

    renamed = {old: _rename(tag, old) for old in callee_nodes}
    require(len(set(renamed.values())) == len(renamed), "inline_id_collision")
    if any(new in caller_nodes for new in renamed.values()):
        return _refuse(tag, "inline_id_collision")

    # Widths must match exactly: no silent truncation/extension at the ABI.
    for param, argument in zip(body.entry_params, request.arguments):
        param_width = callee_nodes[param].width_bits
        argument_width = caller_nodes[argument].width_bits
        if (
            type(param_width) is not int
            or type(argument_width) is not int
            or param_width != argument_width
        ):
            return _refuse(tag, "inline_argument_width_mismatch")
    if body.return_id is not None and request.caller_result_id is not None:
        return_width = callee_nodes[body.return_id].width_bits
        result_width = caller_nodes[request.caller_result_id].width_bits
        if (
            type(return_width) is not int
            or type(result_width) is not int
            or return_width != result_width
        ):
            return _refuse(tag, "inline_result_width_mismatch")

    projected = project_value_phi(callee_nodes, request.callee_blocks)
    overlay: dict = {}
    for old, node in projected.items():
        operands = node.memory_operands
        if operands is not None:
            operands = MemoryOperands(
                renamed[operands.address],
                segment=(
                    renamed[operands.segment]
                    if operands.segment is not None
                    else None
                ),
                data=renamed[operands.data] if operands.data is not None else None,
            )
        overlay[renamed[old]] = replace(
            node, inputs=tuple(renamed[item] for item in node.inputs),
            memory_operands=operands,
        )
    for param, argument in zip(body.entry_params, request.arguments):
        overlay[renamed[param]] = _stub(
            caller_nodes[argument].width_bits, argument
        )
    if body.return_id is not None and request.caller_result_id is not None:
        overlay[request.caller_result_id] = _stub(
            caller_nodes[request.caller_result_id].width_bits,
            renamed[body.return_id],
        )
    merged = dict(caller_nodes)
    merged.update(overlay)

    translated = 0
    argument_exprs: dict[str, SymExpr] = {}
    try:
        for param, argument in zip(body.entry_params, request.arguments):
            answer = translate_node(merged, argument)
            translated += 1
            if answer.unknowns:
                return _refuse(tag, "inline_argument_unresolved")
            argument_exprs[param] = answer.roots[0]
    except (ValueError, SymbolicBudgetError, KeyError) as exc:
        return _refuse(tag, f"inline_argument_unresolved:{exc}")

    selector = PathSelector(path_bindings(body.graph), request.callee_blocks)
    try:
        callee_query, callee_unresolved, callee_translated = (
            derive_symbolic_path_query(body.graph, selector, callee_prefix=True)
        )
    except (ValueError, KeyError) as exc:
        return _refuse(tag, f"inline_callee_derivation:{exc}")
    translated += callee_translated
    pending = set(callee_unresolved) - {"no_modeled_branch"}
    if pending:
        return _refuse(tag, "inline_callee_unresolved")

    try:
        predicates = tuple(
            replace(
                item,
                constraint_id=f"{tag}:{item.constraint_id}",
                left=_rewrite(item.left, argument_exprs, renamed),
                right=_rewrite(item.right, argument_exprs, renamed),
                origin_id=renamed[item.origin_id],
            )
            for item in callee_query.predicates
        )
    except (ValueError, KeyError) as exc:
        return _refuse(tag, f"inline_predicate_rewrite:{exc}")
    variables, _operators = symbolic_predicate_summary(predicates)

    ordered, _definitions = ordered_path_steps(body.plan, request.callee_blocks)
    steps = tuple(
        InlineStep(renamed[step.node_id], step.effect) for step in ordered
    )

    fragment_digest = digest(
        {
            "tag": tag,
            "predicates": [item.to_data() for item in predicates],
            "steps": [[step.node_id, step.effect] for step in steps],
            "params": [
                [param, argument]
                for param, argument in zip(body.entry_params, request.arguments)
            ],
            "result": request.caller_result_id,
        }
    )
    context = InlineContext(
        tag=tag,
        call_id=request.call_id,
        callee_digest=body.callee_digest,
        callee_blocks=request.callee_blocks,
        argument_ids=request.arguments,
        result_id=request.caller_result_id or "",
        depth=depth,
        fragment_digest=fragment_digest,
    )
    return InlineFragment(
        tag, context, overlay, renamed, steps, predicates, variables,
        translated, None,
    )


def build_inline_fragments(requests, caller_nodes: dict):
    """Build every fragment; collect refusal reasons without raising."""
    fragments: list[InlineFragment] = []
    refused: set[str] = set()
    translated = 0
    for request in requests:
        try:
            fragment = inline_callee_body(request, caller_nodes)
        except (ValueError, KeyError) as exc:
            refused.add(f"inline_malformed_request:{exc}")
            continue
        translated += fragment.translated
        if fragment.unknown is not None:
            refused.add(fragment.unknown)
            continue
        fragments.append(fragment)
    return tuple(fragments), refused, translated


def inline_summary_assumption(fragment: InlineFragment) -> ProofAssumption:
    """Auditable bound display: body, path, arguments, depth, content."""
    require(fragment.unknown is None, "summary needs a usable fragment")
    assert fragment.context is not None
    return ProofAssumption(
        "summary",
        f"inline@{fragment.tag}",
        canonical_json(
            {
                "callee_digest": fragment.context.callee_digest,
                "callee_blocks": list(fragment.context.callee_blocks),
                "argument_ids": list(fragment.context.argument_ids),
                "result_id": fragment.context.result_id or None,
                "depth": fragment.context.depth,
                "fragment_digest": fragment.context.fragment_digest,
                "arguments_orchestrator_resolved": True,
            }
        ),
    )


def merge_inline_query(caller_query: SymbolicPathQuery, fragments) -> SymbolicPathQuery:
    """Conjoin usable fragments into the caller path query."""
    require(bool(fragments), "merge needs at least one fragment")
    predicates = list(caller_query.predicates)
    assumptions = list(caller_query.assumptions)
    for fragment in fragments:
        predicates.extend(fragment.predicates)
        assumptions.append(inline_summary_assumption(fragment))
    merged_predicates = tuple(sorted(predicates, key=lambda item: item.constraint_id))
    variables, operators = symbolic_predicate_summary(merged_predicates)
    return SymbolicPathQuery(
        caller_query.bindings,
        variables,
        merged_predicates,
        tuple(assumptions),
        caller_query.bounds,
        caller_query.budget,
        SymbolicCoverage(
            SYMBOLIC_THEORY,
            tuple(item.name for item in variables),
            symbolic_variable_digest(variables),
            tuple(item.constraint_id for item in merged_predicates),
            operators,
        ),
    )


def splice_inline_steps(ordered, fragments, call_block_of):
    """Replace inlined call steps with callee views; thread versions.

    Returns the spliced step list plus ``node_id -> block`` additions for
    the renamed steps (they execute inside the caller block of the call).
    """
    by_call = {}
    for fragment in fragments:
        assert fragment.context is not None
        require(
            fragment.context.call_id not in by_call, "inline_duplicate_call"
        )
        by_call[fragment.context.call_id] = fragment
    spliced: list = []
    blocks: dict[str, int] = {}
    for step in ordered:
        fragment = by_call.get(step.node_id)
        if fragment is None:
            spliced.append(step)
            continue
        require(step.effect == "havoc", "inline_expects_havoc_call")
        before = step.before
        for index, inline_step in enumerate(fragment.steps):
            last = index == len(fragment.steps) - 1
            after = step.after if last else f"{fragment.tag}:v{index}"
            spliced.append(
                SimpleNamespace(
                    node_id=inline_step.node_id,
                    effect=inline_step.effect,
                    before=before,
                    after=after,
                )
            )
            blocks[inline_step.node_id] = call_block_of[step.node_id]
            before = after
    return spliced, blocks
