"""Symbolic memory over a flat per-address-space array. Schema v2.

One address space, one byte-indexed Z3 Array per memory version, threaded
along a fixed CFG-prefix path. Existing object partitions are hints only:
no encoding decision depends on an unproven partition, so structural
auto-object guesses can never become proven disjointness (F3).
"""

from dataclasses import dataclass, field
from typing import Literal

from .call_symbolic import (
    InlineContext,
    build_inline_fragments,
    inline_summary_assumption,
    merge_inline_query,
    ordered_path_steps,
    splice_inline_steps,
)
from .constraints import (
    ConstraintBindings,
    ProofAssumption,
    ProofBounds,
    ProofBudget,
)
from .path_conditions import PathSelector, path_bindings
from .path_symbolic import (
    SymbolicCoverage,
    conjunction,
    derive_symbolic_path_query,
    project_value_phi,
)
from .proof import StaleProofEvidenceError
from .serialization import ContractError, Model, canonical_json, digest
from .states import Endian, canonical_set, check_digest, check_id, nonempty, require
from .symbolic import (
    OP_TABLE_VERSION,
    SYMBOLIC_IR_VERSION,
    SymBinding,
    SymExpr,
    SymbolicBudgetError,
    Z3Backend,
    evaluate_sym,
    translate_node,
)

MEMORY_SYMBOLIC_VERSION = "memory-symbolic-v1"
MEMORY_THEORY = "flat_array_bitvectors_symbolic_v1"
MEMORY_RULE = "flat-array-path-memory-v1"
STRUCTURAL_ORDER_STAMP = "memory-order-structural-v1"

MemoryStatus = Literal[
    "must_forward_value_bounded_v1",
    "no_overlap_bounded_v1",
    "may_overlap_example_v1",
    "unknown",
]
OverlapVerdict = Literal["must_overlap", "may_overlap", "no_overlap", "unresolved"]


@dataclass(frozen=True)
class MemorySymbolicQuery(Model):
    bindings: ConstraintBindings
    path_blocks: tuple[int, ...]
    load_id: str
    store_id: str
    load_address: SymExpr
    store_address: SymExpr
    load_bytes: int
    store_bytes: int
    address_space: str
    address_width: int
    endian: Endian
    assumptions: tuple[ProofAssumption, ...]
    bounds: ProofBounds
    budget: ProofBudget
    coverage: SymbolicCoverage
    schema_version: Literal[2] = 2
    inlines: tuple[InlineContext, ...] = field(
        default=(), metadata={"omit_if_default": True}
    )

    def __post_init__(self):
        super().__post_init__()
        require(self.schema_version == 2, "invalid_memory_query_version")
        require(bool(self.path_blocks), "Memory query needs a path")
        check_id(self.load_id, "node")
        check_id(self.store_id, "node")
        require(
            self.load_address.width_bits == self.address_width
            and self.store_address.width_bits == self.address_width,
            "Memory address width mismatch",
        )
        require(self.load_bytes > 0 and self.store_bytes > 0, "Empty access range")
        nonempty(self.address_space)
        require(1 <= self.address_width <= 64, "Address width needs 1..64 bits")

    @property
    def query_digest(self) -> str:
        return digest(self)


@dataclass(frozen=True)
class MemorySymbolicResult(Model):
    query_digest: str
    engine_version: str
    model_kind: Literal["exact", "incomplete"]
    status: MemoryStatus
    overlap: OverlapVerdict
    value_forward: bool
    scope: Literal["path_prefix_only"]
    assumptions: tuple[ProofAssumption, ...]
    bounds: ProofBounds
    budget: ProofBudget
    coverage: SymbolicCoverage
    path_blocks: tuple[int, ...]
    translated_roots: int
    solver_timeout_ms: int
    solver_stamp: str = ""
    solver_version: str = ""
    witness: tuple[SymBinding, ...] = ()
    evidence_ids: tuple[str, ...] = ()
    object_hints: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        check_digest(self.query_digest)
        nonempty(self.engine_version)
        require(bool(self.path_blocks), "Memory result needs its path")
        require(self.translated_roots >= 0, "Negative translation count")
        require(self.solver_timeout_ms > 0, "Solver timeout must be positive")
        canonical_set(tuple(item.name for item in self.witness))
        canonical_set(self.evidence_ids)
        for evidence_id in self.evidence_ids:
            check_id(evidence_id, "evidence")
        canonical_set(self.object_hints)
        canonical_set(self.diagnostics)
        canonical_set(self.unresolved)
        if self.status != "unknown":
            require(self.solver_stamp != "", "Definite memory result needs a stamp")
            require(not self.unresolved, "Definite memory result must resolve")
            require(not self.diagnostics, "Definite memory result must be clean")
        if self.status == "must_forward_value_bounded_v1":
            require(self.overlap == "must_overlap", "Value claim needs must-overlap")
            require(self.value_forward, "Value claim needs value_forward")
        if self.status == "no_overlap_bounded_v1":
            require(self.overlap == "no_overlap", "Mismatch overlap verdict")
            require(not self.value_forward, "Mismatch value verdict")
        if self.status == "may_overlap_example_v1":
            require(self.overlap in {"must_overlap", "may_overlap"}, "Mismatch overlap")
            require(not self.value_forward, "Example claims no value forwarding")
            require(bool(self.witness), "Overlap example needs a witness")


def _access_bytes(node, label: str) -> int:
    width = node.width_bits
    if type(width) is not int or width <= 0 or width % 8 != 0:
        raise ValueError(f"sub_byte_access_unsupported:{label}")
    return width // 8


def _translate_access(nodes, node_id: str, address_width: int, translated: list) -> tuple:
    """Translate one access. Returns (addr, data|None, nbytes). Pure."""
    node = nodes[node_id]
    operands = node.memory_operands
    if operands is None:
        raise ValueError(f"missing_memory_operands:{node_id}")
    if operands.segment is not None:
        segment = translate_node(nodes, operands.segment)
        translated[0] += 1
        if segment.unknowns:
            raise ValueError(f"segmented_address_unsupported:{node_id}")
        if segment.roots[0].kind != "const" or segment.roots[0].value != 0:
            raise ValueError(f"segmented_address_unsupported:{node_id}")
    address = translate_node(nodes, operands.address)
    translated[0] += 1
    if address.unknowns or address.roots[0].width_bits != address_width:
        raise ValueError(f"address_unresolved:{node_id}")
    nbytes = _access_bytes(node, node_id)
    data = None
    if node.kind == "Store":
        if operands.data is None:
            raise ValueError(f"missing_store_data:{node_id}")
        data = translate_node(nodes, operands.data)
        translated[0] += 1
        if data.unknowns:
            raise ValueError(f"store_data_unresolved:{node_id}")
        if data.roots[0].width_bits != nbytes * 8:
            raise ValueError(f"store_data_width:{node_id}")
        data = data.roots[0]
    return address.roots[0], data, nbytes


def _ranges_overlap(load_base: int, load_bytes: int, store_base: int, store_bytes: int, modulus: int) -> bool:
    load = {(load_base + index) % modulus for index in range(load_bytes)}
    store = {(store_base + index) % modulus for index in range(store_bytes)}
    return bool(load & store)


def replay_overlap_example(
    query: MemorySymbolicQuery,
    model: tuple[SymBinding, ...],
) -> bool:
    """Validate a may-overlap witness with the big-int oracle only."""
    try:
        environment = {item.name: item.value for item in model}
        load_base = evaluate_sym(query.load_address, environment)
        store_base = evaluate_sym(query.store_address, environment)
    except Exception:
        return False
    return _ranges_overlap(
        load_base, query.load_bytes, store_base, query.store_bytes,
        1 << query.address_width,
    )


def _byte(value_term, z3, index: int, width_bits: int, endian: str):
    top = width_bits - 1
    if endian == "little":
        return z3.Extract(8 * index + 7, 8 * index, value_term)
    return z3.Extract(top - 8 * index, top - 8 * index - 7, value_term)


def _concat_bytes(z3, terms):
    result = terms[-1]
    for term in reversed(terms[:-1]):
        result = z3.Concat(term, result)
    return result


class _Encoder:
    """Threads one flat byte array through path-ordered steps."""

    def __init__(self, backend, variables, address_width, endian, space):
        self.backend = backend
        self.z3 = backend.require_module()
        self.variables = variables
        self.address_width = address_width
        self.endian = endian
        self.space = space
        self.fresh = 0

    def fresh_array(self, tag: str):
        self.fresh += 1
        name = f"mem_{self.space}_{tag}_{self.fresh}"
        array = self.z3.Array(
            name,
            self.z3.BitVecSort(self.address_width),
            self.z3.BitVecSort(8),
        )
        self.variables[name] = array
        return array

    def convert(self, expression: SymExpr):
        return self.backend.convert_expression(self.z3, expression, self.variables)

    def store_bytes(self, array, address, data, nbytes: int):
        for index in range(nbytes):
            array = self.z3.Store(
                array, address + index,
                _byte(data, self.z3, index, nbytes * 8, self.endian),
            )
        return array

    def load_bytes(self, array, address, nbytes: int):
        terms = [self.z3.Select(array, address + index) for index in range(nbytes)]
        if self.endian == "little":
            terms = list(reversed(terms))
        return _concat_bytes(self.z3, terms)


def _ordered_path_steps(plan, path):
    return ordered_path_steps(plan, path)


def _object_hints(memory_facts, load_id: str, store_id: str) -> tuple[str, ...]:
    if memory_facts is None:
        return ()
    hints = set()
    for dependency in memory_facts.dependencies:
        if dependency.source in {load_id, store_id}:
            hints.add(f"{dependency.object_id}@{dependency.source}")
        if dependency.target in {load_id, store_id}:
            hints.add(f"{dependency.object_id}@{dependency.target}")
    return tuple(sorted(hints))


def _address_width_of(nodes, load_id: str, store_id: str) -> tuple[int, bool]:
    widths = set()
    for identifier in (load_id, store_id):
        node = nodes.get(identifier)
        operands = getattr(node, "memory_operands", None) if node else None
        address = nodes.get(operands.address) if operands else None
        if address is not None and type(address.width_bits) is int:
            widths.add(address.width_bits)
    if len(widths) != 1:
        return 64, False
    return next(iter(widths)), True


def prove_store_to_load(
    plan,
    graph,
    selector: PathSelector,
    load_id: str,
    store_id: str,
    *,
    backend: Z3Backend | None = None,
    timeout_ms: int = 5000,
    memory_facts=None,
    cancelled=lambda: False,
    inlines=(),
):
    """Decide store->load forwarding on a fixed path. Flat array, byte exact.

    ``inlines`` splices bounded callee fragments at listed call sites; the
    load/store under test may live inside a spliced callee body.
    """
    require(type(timeout_ms) is int and timeout_ms > 0, "Invalid solver timeout")
    require(selector.bindings == path_bindings(graph), "path_query_artifact_mismatch")
    inlines = tuple(inlines)
    inlined_calls = frozenset(request.call_id for request in inlines)
    path = selector.blocks
    environment = graph.snapshot.identity.environment
    endian = environment.data_endian
    space = environment.address_space
    nodes = project_value_phi({n.node_id: n for n in graph.nodes}, path)
    translated = [0]

    fragments: tuple = ()
    refused: set[str] = set()
    if inlines:
        fragments, refused, extra_translated = build_inline_fragments(inlines, nodes)
        translated[0] += extra_translated
        if refused:
            # A refused fragment poisons the whole splice: record nothing.
            fragments = ()
        else:
            for fragment in fragments:
                nodes.update(fragment.overlay)
    overrides = None
    if fragments:
        overrides = {}
        for fragment in fragments:
            overrides.update(fragment.overlay)
    path_query, path_unresolved, path_translated = derive_symbolic_path_query(
        graph,
        selector,
        allow_memory_effects=True,
        inlined_calls=inlined_calls,
        overrides=overrides,
    )
    translated[0] += path_translated
    # Straight-line paths carry no branch predicates; that is fully modeled.
    unresolved = set(path_unresolved) - {"no_modeled_branch"}
    unresolved |= refused
    if len(inlined_calls) != len(inlines):
        unresolved.add("inline_duplicate_call")
    if fragments:
        path_query = merge_inline_query(path_query, fragments)

    ordered, _definitions = _ordered_path_steps(plan, path)
    inline_blocks: dict[str, int] = {}
    if fragments:
        call_block_of = {
            item.node_id: item.block for item in plan.program.definitions
        }
        try:
            ordered, inline_blocks = splice_inline_steps(
                ordered, fragments, call_block_of
            )
        except (ValueError, KeyError) as exc:
            unresolved.add(f"inline_splice:{exc}")
    positions = {}
    for rank, step in enumerate(ordered):
        positions.setdefault(step.node_id, rank)
    load_rank = positions.get(load_id)
    store_rank = positions.get(store_id)
    load_node = nodes.get(load_id)
    store_node = nodes.get(store_id)
    store_in_plan = any(
        step.node_id == store_id for step in plan.steps
    ) or store_id in positions
    if load_node is None or load_node.kind != "Load" or load_rank is None:
        unresolved.add("load_not_on_path")
    if store_node is None or store_node.kind != "Store" or not store_in_plan:
        unresolved.add("malformed_store_reference")
    store_off_path = (
        store_rank is None or (load_rank is not None and store_rank >= load_rank)
    )
    address_width, widths_ok = _address_width_of(nodes, load_id, store_id)
    if not widths_ok:
        unresolved.add("address_width_mismatch")

    expressed = {}
    if not unresolved:
        try:
            for identifier in (load_id, store_id):
                expressed[identifier] = _translate_access(
                    nodes, identifier, address_width, translated
                )
        except (ValueError, SymbolicBudgetError) as exc:
            unresolved.add(str(exc))

    load_addr = expressed.get(load_id, (None, None, 1))[0]
    store_addr = expressed.get(store_id, (None, None, 1))[0]
    query = MemorySymbolicQuery(
        selector.bindings,
        path,
        load_id,
        store_id,
        load_addr if load_addr is not None else SymExpr("const", address_width, value=0),
        store_addr if store_addr is not None else SymExpr("const", address_width, value=0),
        expressed.get(load_id, (None, None, 1))[2],
        expressed.get(store_id, (None, None, 1))[2],
        space,
        address_width,
        endian,
        (
            ProofAssumption("analysis", "cfg_prefix", canonical_json(list(path))),
            ProofAssumption("analysis", "scope", "reaches_last_block_before_execution"),
            ProofAssumption("analysis", "symbolic_ir_version", SYMBOLIC_IR_VERSION),
            ProofAssumption("analysis", "op_table_version", OP_TABLE_VERSION),
            ProofAssumption("analysis", "memory_rule", MEMORY_RULE),
        )
        + tuple(inline_summary_assumption(fragment) for fragment in fragments),
        ProofBounds(0, 0),
        ProofBudget(65536, 1000000, 1000),
        SymbolicCoverage(
            MEMORY_THEORY,
            tuple(item.name for item in path_query.variables),
            path_query.coverage.variable_digest,
            tuple(item.constraint_id for item in path_query.predicates),
            tuple(sorted(set(path_query.coverage.operators) | {"select", "store"})),
        ),
        inlines=tuple(
            fragment.context
            for fragment in fragments
            if fragment.context is not None
        ),
    )

    def unknown_result(reason: str):
        return query, MemorySymbolicResult(
            query_digest=query.query_digest,
            engine_version=MEMORY_SYMBOLIC_VERSION,
            model_kind="incomplete",
            status="unknown",
            overlap="unresolved",
            value_forward=False,
            scope="path_prefix_only",
            assumptions=query.assumptions,
            bounds=query.bounds,
            budget=query.budget,
            coverage=query.coverage,
            path_blocks=path,
            translated_roots=translated[0],
            solver_timeout_ms=timeout_ms,
            object_hints=_object_hints(memory_facts, load_id, store_id),
            diagnostics=(reason,),
            unresolved=tuple(sorted(unresolved | {reason})),
        )

    def evidence() -> tuple[str, ...]:
        identifiers = set()
        for item in path_query.predicates:
            identifiers.update(item.evidence_ids)
        for identifier in (load_id, store_id):
            node = nodes.get(identifier)
            if node is not None:
                identifiers.update(getattr(node, "evidence_ids", ()))
        return tuple(sorted(identifiers))

    if unresolved:
        return unknown_result("derivation_unresolved")
    if cancelled():
        return unknown_result("cancelled")
    assert load_rank is not None
    if store_off_path:
        # Structural: a store that never executes before the load on this
        # path cannot affect it. No solver needed.
        order_stamp = (
            f"{STRUCTURAL_ORDER_STAMP}:store_after_load"
            if store_rank is not None
            else f"{STRUCTURAL_ORDER_STAMP}:store_not_on_path"
        )
        return query, MemorySymbolicResult(
            query_digest=query.query_digest,
            engine_version=MEMORY_SYMBOLIC_VERSION,
            model_kind="exact",
            status="no_overlap_bounded_v1",
            overlap="no_overlap",
            value_forward=False,
            scope="path_prefix_only",
            assumptions=query.assumptions,
            bounds=query.bounds,
            budget=query.budget,
            coverage=query.coverage,
            path_blocks=path,
            translated_roots=translated[0],
            solver_timeout_ms=timeout_ms,
            solver_stamp=order_stamp,
            evidence_ids=evidence(),
            object_hints=_object_hints(memory_facts, load_id, store_id),
        )
    if backend is None or not backend.available:
        return unknown_result("solver_unavailable")
    if backend.timeout_ms > timeout_ms:
        return unknown_result("solver_timeout_exceeds_job_budget")

    try:
        return _solve_memory(
            plan, query, path_query, nodes, ordered, load_id, store_id,
            load_rank, expressed, backend, timeout_ms, translated,
            memory_facts, evidence(), inline_blocks,
        )
    except (ValueError, SymbolicBudgetError) as exc:
        unresolved.add(str(exc))
        return unknown_result("memory_encoding_unresolved")


def _solve_memory(
    plan, query, path_query, nodes, ordered, load_id, store_id,
    load_rank, expressed, backend, timeout_ms, translated,
    memory_facts, evidence_ids, inline_blocks=None,
):
    z3 = backend.require_module()
    variables: dict[str, object] = {}
    path_term = backend.convert_expression(
        z3, conjunction(path_query.predicates), variables
    )
    encoder = _Encoder(backend, variables, query.address_width, query.endian, query.address_space)
    definitions = {item.node_id: item.block for item in plan.program.definitions}
    definitions.update(inline_blocks or {})
    phis = {phi.block: phi for phi in plan.phis}
    block_entry = {block.block: block.entry for block in plan.blocks}
    arrays: dict[str, object] = {}
    current: object = encoder.fresh_array("init")
    arrays[block_entry[query.path_blocks[0]]] = current
    accesses: dict[str, tuple] = {}

    for rank, step in enumerate(ordered):
        if rank > load_rank:
            break
        block = definitions[step.node_id]
        if step.before not in arrays:
            if block == query.path_blocks[0]:
                raise ValueError(f"memory_entry_unresolved:{step.node_id}")
            predecessor = query.path_blocks[query.path_blocks.index(block) - 1]
            phi = phis.get(block)
            if phi is None:
                raise ValueError(f"memory_phi_missing:{step.node_id}")
            matches = [i for i in phi.inputs if i.predecessor == predecessor]
            # step.before is the phi OUTPUT (block entry); content comes from
            # the selected predecessor's exit version.
            if len(matches) != 1 or step.before != phi.version_id:
                raise ValueError(f"memory_phi_divergence:{step.node_id}")
            if matches[0].version_id not in arrays:
                raise ValueError(f"memory_version_gap:{step.node_id}")
            current = arrays[matches[0].version_id]
            arrays[step.before] = current
        else:
            current = arrays[step.before]
        if step.effect in {"havoc", "source"}:
            # Forgetting writes is sound (may lose must-facts, never invents).
            current = encoder.fresh_array(step.effect)
            arrays[step.after] = current
            continue
        if step.node_id in expressed:
            addr, data, nbytes = expressed[step.node_id]
        else:
            addr, data, nbytes = _translate_access(
                nodes, step.node_id, query.address_width, translated
            )
        if step.effect == "store":
            assert data is not None
            current = encoder.store_bytes(
                current, encoder.convert(addr), encoder.convert(data), nbytes
            )
            arrays[step.after] = current
            accesses[step.node_id] = (addr, data, nbytes, None)
        elif step.effect == "load":
            value = encoder.load_bytes(current, encoder.convert(addr), nbytes)
            accesses[step.node_id] = (addr, None, nbytes, value)
        else:  # pragma: no cover - plan restricts effects
            raise ValueError(f"memory_effect_unsupported:{step.node_id}")

    load_addr, _, load_nbytes, load_value = accesses[load_id]
    store_addr, store_data, store_nbytes, _ = accesses[store_id]
    assert store_data is not None and load_value is not None
    z3_load_addr = encoder.convert(load_addr)
    z3_store_addr = encoder.convert(store_addr)

    solver = backend.new_solver()
    solver.add(path_term != 0)
    overlap = z3.Or([
        z3_load_addr + i == z3_store_addr + j
        for i in range(load_nbytes)
        for j in range(store_nbytes)
    ])

    def assemble(status, overlap_verdict, value_forward, witness, stamp):
        return query, MemorySymbolicResult(
            query_digest=query.query_digest,
            engine_version=MEMORY_SYMBOLIC_VERSION,
            model_kind="exact",
            status=status,
            overlap=overlap_verdict,
            value_forward=value_forward,
            scope="path_prefix_only",
            assumptions=query.assumptions,
            bounds=query.bounds,
            budget=query.budget,
            coverage=query.coverage,
            path_blocks=query.path_blocks,
            translated_roots=translated[0],
            solver_timeout_ms=timeout_ms,
            solver_stamp=stamp,
            solver_version=backend.version(),
            witness=witness,
            evidence_ids=evidence_ids,
            object_hints=_object_hints(memory_facts, load_id, store_id),
        )

    def unknown_result(reason: str):
        return query, MemorySymbolicResult(
            query_digest=query.query_digest,
            engine_version=MEMORY_SYMBOLIC_VERSION,
            model_kind="incomplete",
            status="unknown",
            overlap="unresolved",
            value_forward=False,
            scope="path_prefix_only",
            assumptions=query.assumptions,
            bounds=query.bounds,
            budget=query.budget,
            coverage=query.coverage,
            path_blocks=query.path_blocks,
            translated_roots=translated[0],
            solver_timeout_ms=timeout_ms,
            object_hints=_object_hints(memory_facts, load_id, store_id),
            diagnostics=(reason,),
            unresolved=(reason,),
        )

    try:
        solver.push()
        solver.add(overlap)
        possible = solver.check()
        example = backend.read_model(solver, variables) if possible == z3.sat else ()
        solver.pop()
    except Exception:
        return unknown_result("solver_error")
    if possible == z3.unsat:
        return assemble("no_overlap_bounded_v1", "no_overlap", False, (), backend.stamp())
    if possible != z3.sat:
        return unknown_result("solver_unknown")

    try:
        solver.push()
        solver.add(z3.Not(overlap))
        covered = solver.check()
        solver.pop()
    except Exception:
        return unknown_result("solver_error")
    if covered != z3.sat and covered != z3.unsat:
        return unknown_result("solver_unknown")
    must_overlap = covered == z3.unsat

    value_forward = False
    if must_overlap and load_nbytes * 8 <= store_nbytes * 8:
        try:
            solver.push()
            solver.add(z3_load_addr != z3_store_addr)
            same_base = solver.check()
            solver.pop()
        except Exception:
            return unknown_result("solver_error")
        if same_base == z3.unsat:
            expected = encoder.convert(store_data)
            load_bits = load_nbytes * 8
            store_bits = store_nbytes * 8
            if load_bits < store_bits:
                if query.endian == "little":
                    expected = z3.Extract(load_bits - 1, 0, expected)
                else:
                    expected = z3.Extract(store_bits - 1, store_bits - load_bits, expected)
            try:
                solver.push()
                solver.add(load_value != expected)
                differs = solver.check()
                solver.pop()
            except Exception:
                return unknown_result("solver_error")
            if differs == z3.unsat:
                value_forward = True
            elif differs != z3.sat:
                return unknown_result("solver_unknown")
        elif same_base != z3.sat:
            return unknown_result("solver_unknown")

    if value_forward:
        return assemble(
            "must_forward_value_bounded_v1", "must_overlap", True, (), backend.stamp()
        )
    if not replay_overlap_example(query, example):
        return unknown_result("witness_replay_failed")
    return assemble(
        "may_overlap_example_v1",
        "must_overlap" if must_overlap else "may_overlap",
        False,
        example,
        backend.stamp(),
    )


def validate_memory_result(query: MemorySymbolicQuery, result: MemorySymbolicResult) -> None:
    """Reject stale/forged memory results."""
    if result.query_digest != query.query_digest:
        raise StaleProofEvidenceError("Stale memory query digest")
    if result.assumptions != query.assumptions:
        raise StaleProofEvidenceError("Stale memory assumptions")
    if result.bounds != query.bounds:
        raise StaleProofEvidenceError("Stale memory bounds")
    if result.budget != query.budget:
        raise StaleProofEvidenceError("Stale memory budget")
    if result.coverage != query.coverage:
        raise StaleProofEvidenceError("Stale memory coverage")
    if result.path_blocks != query.path_blocks:
        raise StaleProofEvidenceError("Stale memory path")
    if result.status != "unknown":
        if not result.solver_stamp:
            raise ContractError("Definite memory result lacks a stamp")
        if result.status == "may_overlap_example_v1" and not replay_overlap_example(
            query, result.witness
        ):
            raise ContractError("Overlap example witness does not replay")
