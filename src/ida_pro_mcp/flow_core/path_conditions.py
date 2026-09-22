"""Program-owned, acyclic CFG-prefix constraints (no caller equations).

Only complete scalar correspondence may yield a definite bounded result. The
selector names an entry-rooted sequence of blocks; the last block is reached,
not executed. Loops, calls, memory, selects and unsupported SSA remain Unknown.
"""

from dataclasses import dataclass

from .constraints import (
    ConstraintBindings,
    ConstraintExpression,
    ConstraintQuery,
    ConstraintVariable,
    DeclaredCoverage,
    PathConstraint,
    Predicate,
    ProofAssumption,
    ProofBounds,
    ProofBudget,
    variable_domain_digest,
)
from .contracts import Graph, Snapshot
from .proof import EngineAnswer, ReferenceProofEngine, classify_proof
from .serialization import Model, canonical_json
from .states import require


@dataclass(frozen=True)
class PathSelector(Model):
    bindings: ConstraintBindings
    blocks: tuple[int, ...]
    schema_version: int = 1

    def __post_init__(self):
        super().__post_init__()
        require(self.schema_version == 1, "invalid_path_selector_version")
        require(0 < len(self.blocks) <= 256, "invalid_path_length")
        require(all(i >= 0 for i in self.blocks), "invalid_path_block")


def path_bindings(graph: Graph) -> ConstraintBindings:
    require(isinstance(graph.snapshot, Snapshot), "path_proof_requires_normal_snapshot")
    assert isinstance(graph.snapshot, Snapshot)
    identity = graph.snapshot.identity
    return ConstraintBindings(
        graph.snapshot.snapshot_id,
        graph.graph_digest,
        identity.profile_digest,
        identity.rule_digest,
        (identity.summary_digest,),
    )


def derive_path_query(graph: Graph, selector: PathSelector):
    require(selector.bindings == path_bindings(graph), "path_query_artifact_mismatch")
    function = graph.snapshot.function
    path = selector.blocks
    require(path[0] == function.entry_block, "path_must_start_at_entry")
    require(all(i < len(function.blocks) for i in path), "path_foreign_block")
    require(
        all(b in function.blocks[a].successors for a, b in zip(path, path[1:])),
        "path_foreign_transition",
    )
    unresolved = set()
    if any(item.severity != "information" for item in function.diagnostics):
        unresolved.add("function_diagnostics_unresolved")
    if len(set(path)) != len(path):
        unresolved.add("loop_unrolling_unsupported")
    nodes = {n.node_id: n for n in graph.nodes}
    evidence = {e.evidence_id: e for e in graph.evidence}

    def sites(node):
        return tuple(site for eid in node.evidence_ids for site in evidence[eid].sites)

    variable_map: dict[str, ConstraintVariable] = {}
    constraints = []
    active = set()
    expression_visits = 0

    def expression(identifier):
        nonlocal expression_visits
        expression_visits += 1
        if expression_visits > 10000:
            raise ValueError("expression_extraction_budget")
        node = nodes[identifier]
        if len(active) >= 32:
            raise ValueError("expression_depth_budget")
        if identifier in active:
            raise ValueError("cyclic_ssa")
        active.add(identifier)
        try:
            bits = node.width_bits
            if bits is None or not 0 < bits <= 64:
                raise ValueError("unsupported_width")
            if node.kind == "Constant":
                return ConstraintExpression("constant", bits, value=node.constant)
            if node.kind == "InputValue":
                if bits > 8:
                    raise ValueError("input_domain_budget")
                variable_map[identifier] = ConstraintVariable(
                    identifier, bits, tuple(range(1 << bits))
                )
                return ConstraintExpression("variable", bits, variable=identifier)
            if node.kind == "Copy":
                value = expression(node.inputs[0])
                if value.width_bits != bits:
                    raise ValueError("copy_width")
                return value
            if node.kind in {"Unary", "Binary"}:
                supported = {
                    "bit_not",
                    "neg",
                    "add",
                    "sub",
                    "mul",
                    "bit_and",
                    "bit_or",
                    "bit_xor",
                }
                assert node.operation is not None
                operation = {
                    "and": "bit_and",
                    "or": "bit_or",
                    "xor": "bit_xor",
                    "not": "bit_not",
                }.get(node.operation, node.operation)
                if operation not in supported:
                    raise ValueError("unsupported_scalar_operation")
                operands = tuple(expression(i) for i in node.inputs)
                if any(item.width_bits != bits for item in operands):
                    raise ValueError("operand_width")
                if operation in {"add", "mul", "bit_and", "bit_or", "bit_xor"}:
                    operands = tuple(sorted(operands, key=canonical_json))
                return ConstraintExpression(
                    "unary" if node.kind == "Unary" else "binary",
                    bits,
                    operator=operation,
                    operands=operands,
                )
            raise ValueError("unsupported_ssa_" + node.kind)
        finally:
            active.remove(identifier)

    def comparison_expressions(comparison):
        # Exact byte-mask projection: (concat_low(lo8, hi) & mask8) == k8
        # is independent of every high bit. Keep the actual lo8 input domain,
        # never shrink a wide input domain or invent an ABI zero-extension fact.
        left, right = (nodes[i] for i in comparison.inputs)
        if comparison.operation in {"eq", "ne"} and right.kind == "Constant":
            if left.kind == "Binary" and left.operation == "and":
                for concat_id, mask_id in (left.inputs, tuple(reversed(left.inputs))):
                    concat, mask = nodes[concat_id], nodes[mask_id]
                    if (
                        concat.kind != "Binary"
                        or concat.operation != "concat_low"
                        or mask.kind != "Constant"
                    ):
                        continue
                    low, high = (nodes[i] for i in concat.inputs)
                    if (
                        low.width_bits == 8
                        and high.width_bits is not None
                        and concat.width_bits
                        == high.width_bits + 8
                        == left.width_bits
                        == right.width_bits
                        == mask.width_bits
                        and mask.constant is not None
                        and mask.constant < 256
                        and right.constant is not None
                        and right.constant < 256
                    ):
                        operands = tuple(
                            sorted(
                                (
                                    expression(low.node_id),
                                    ConstraintExpression(
                                        "constant", 8, value=mask.constant
                                    ),
                                ),
                                key=canonical_json,
                            )
                        )
                        return (
                            ConstraintExpression(
                                "binary", 8, operator="bit_and", operands=operands
                            ),
                            ConstraintExpression("constant", 8, value=right.constant),
                            "program-path-byte-mask-projection-v1",
                        )
        return expression(left.node_id), expression(right.node_id), "program-path-v1"

    for ordinal, (block_index, successor) in enumerate(zip(path, path[1:])):
        block = function.blocks[block_index]
        local = [
            n
            for n in graph.nodes
            if any(site.block_index == block_index for site in sites(n))
        ]
        if any(
            n.kind
            in {
                "Call",
                "Load",
                "Store",
                "UnknownValue",
                "Allocation",
                "Free",
                "Return",
                "OpaqueEffect",
                "Select",
                "Phi",
                "MemoryPhi",
            }
            for n in local
        ):
            unresolved.add("unsupported_path_effect")
        branches = [n for n in local if n.kind == "Branch"]
        if not branches and len(block.successors) == 1:
            continue
        if len(branches) != 1 or not block.instructions:
            unresolved.add("unsupported_branch_correspondence")
            continue
        branch = branches[0]
        instruction = block.instructions[-1]
        targets = [o.block_index for o in instruction.operands if o.kind == "block"]
        if (
            not any(
                site.block_index == block_index
                and site.instruction_index == instruction.index
                for site in sites(branch)
            )
            or len(targets) != 1
            or targets[0] not in block.successors
        ):
            unresolved.add("unsupported_branch_target")
            continue
        if not branch.inputs:
            if instruction.opcode != "m_goto" or len(block.successors) != 1:
                unresolved.add("unsupported_unconditional_branch")
            continue
        predicates: dict[str, Predicate] = {
            "m_jz": "eq",
            "m_jnz": "ne",
            "m_ja": "ugt",
            "m_jae": "uge",
            "m_jb": "ult",
            "m_jbe": "ule",
            "m_jg": "sgt",
            "m_jge": "sge",
            "m_jl": "slt",
            "m_jle": "sle",
        }
        if len(block.successors) != 2 or instruction.opcode not in predicates:
            unresolved.add("unsupported_branch_semantics")
            continue
        try:
            comparison = nodes[branch.inputs[0]]
            if (
                comparison.kind != "Compare"
                or comparison.operation != predicates[instruction.opcode]
            ):
                raise ValueError("unsupported_predicate_correspondence")
            left, right, rule_id = comparison_expressions(comparison)
            if left.width_bits != right.width_bits:
                raise ValueError("comparison_width")
            predicate = predicates[instruction.opcode]
            constraints.append(
                PathConstraint(
                    f"path-{ordinal:03d}",
                    left,
                    predicate,
                    right,
                    "signed" if predicate.startswith("s") else None,
                    successor == targets[0],
                    rule_id,
                    branch.node_id,
                    tuple(sorted(set(branch.evidence_ids + comparison.evidence_ids))),
                )
            )
        except ValueError as exc:
            unresolved.add(str(exc))
    if not constraints:
        unresolved.add("no_modeled_branch")
        # A program-owned reachability identity covers straight-line/empty prefixes.
        constraints.append(
            PathConstraint(
                "reach-entry",
                ConstraintExpression("constant", 1, value=1),
                "eq",
                ConstraintExpression("constant", 1, value=1),
                None,
                True,
                "program-path-v1",
                graph.snapshot.snapshot_id,
            )
        )
    variables = tuple(variable_map[k] for k in sorted(variable_map))
    constraints = tuple(sorted(constraints, key=lambda c: c.constraint_id))
    assumptions = (
        ProofAssumption("analysis", "cfg_prefix", canonical_json(list(path))),
        ProofAssumption("analysis", "scope", "reaches_last_block_before_execution"),
    )

    # Coverage includes only operators actually present (failed extraction may have visited extra nodes).
    def ops(expr):
        return ({expr.operator} if expr.operator else set()).union(
            *(ops(o) for o in expr.operands)
        )

    operators = set().union(
        *(ops(c.left) | ops(c.right) | {c.predicate} for c in constraints)
    )
    used = set()

    def names(expr):
        if expr.variable:
            used.add(expr.variable)
        for child in expr.operands:
            names(child)

    for constraint in constraints:
        names(constraint.left)
        names(constraint.right)
    variables = tuple(v for v in variables if v.name in used)
    query = ConstraintQuery(
        selector.bindings,
        variables,
        constraints,
        assumptions,
        ProofBounds(0, 0),
        ProofBudget(65536, 1000000, 1000),
        DeclaredCoverage(
            "fixed_width_bitvectors",
            tuple(v.name for v in variables),
            variable_domain_digest(variables),
            tuple(c.constraint_id for c in constraints),
            tuple(sorted(operators)),
        ),
    )
    return query, tuple(sorted(unresolved))


def prove_path(graph: Graph, selector: PathSelector, *, cancelled=lambda: False):
    query, unresolved = derive_path_query(graph, selector)
    engine = ReferenceProofEngine(cancelled=cancelled)
    if unresolved:

        class IncompleteEngine:
            engine_version = ReferenceProofEngine.engine_version

            def solve(self, query):
                return EngineAnswer(
                    query.bindings,
                    query.query_digest,
                    self.engine_version,
                    "incomplete",
                    "unknown",
                    query.assumptions,
                    query.bounds,
                    query.budget,
                    query.coverage,
                    unresolved=unresolved,
                )

        engine = IncompleteEngine()
    return query, classify_proof(query, engine)
