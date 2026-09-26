"""Replayable, bounded numeric Store-site relations, without SDK/type claims.

A proof states what the Store writes *if reached*. It does not establish path
feasibility, a function target, a typed field, or the final contents of a slot.
"""

from dataclasses import dataclass
from typing import Literal

from .contracts import Node
from .memory import MemoryPolicy
from .memory_graph import (
    FLAT_USERSPACE_ASSUMPTION,
    RV32_FLAT_USERSPACE_ASSUMPTION,
    MemoryGraphAnalysis,
)
from .serialization import ContractError, Model, digest
from .states import canonical_set, check_digest, check_id, nonempty, require


@dataclass(frozen=True)
class StoreProofStep(Model):
    node: Node
    rule: str

    def __post_init__(self):
        super().__post_init__()
        require(
            self.rule in {"inspect", "store_site", "flat_segment"},
            "Unknown Store proof rule",
        )


@dataclass(frozen=True)
class StoreProof(Model):
    status: Literal["proven_in_scope", "unknown", "mismatch"]
    snapshot_id: str
    graph_digest: str
    memory_digest: str
    store_node_id: str
    base_node_id: str
    byte_offset: int
    target_ea: int
    observed_base_node_id: str | None
    observed_byte_offset: int | None
    observed_target_ea: int | None
    width_bits: int | None
    steps: tuple[StoreProofStep, ...]
    evidence_ids: tuple[str, ...]
    assumptions: tuple[str, ...]
    reasons: tuple[str, ...]
    max_nodes: int

    def __post_init__(self):
        super().__post_init__()
        check_id(self.snapshot_id, "snapshot")
        for identifier in (self.store_node_id, self.base_node_id):
            check_id(identifier, "node")
        if self.observed_base_node_id is not None:
            check_id(self.observed_base_node_id, "node")
        for value in (self.graph_digest, self.memory_digest):
            check_digest(value)
        require(1 <= self.max_nodes <= 4096, "Invalid proof budget")
        require(-(1 << 63) <= self.byte_offset < (1 << 63), "Invalid byte offset")
        require(0 <= self.target_ea < (1 << 64) - 1, "Invalid target address")
        require(self.width_bits is None or self.width_bits > 0, "Invalid Store width")
        if self.observed_byte_offset is not None:
            require(
                -(1 << 63) <= self.observed_byte_offset < (1 << 63),
                "Invalid observed offset",
            )
        if self.observed_target_ea is not None:
            require(0 <= self.observed_target_ea < (1 << 64), "Invalid observed target")
        identifiers = tuple(step.node.node_id for step in self.steps)
        require(
            len(identifiers) == len(set(identifiers)) <= self.max_nodes,
            "Invalid proof steps",
        )
        require(
            all(step.node.key.snapshot_id == self.snapshot_id for step in self.steps),
            "Mixed proof snapshots",
        )
        canonical_set(self.evidence_ids)
        for identifier in self.evidence_ids:
            check_id(identifier, "evidence")
        require(
            self.evidence_ids
            == tuple(
                sorted({eid for step in self.steps for eid in step.node.evidence_ids})
            ),
            "Proof evidence/step mismatch",
        )
        canonical_set(self.reasons)
        for value in (*self.assumptions, *self.reasons):
            nonempty(value)
        require(bool(self.assumptions), "Missing scope assumptions")
        require(
            (self.status == "proven_in_scope") == (not self.reasons),
            "Status/reason mismatch",
        )
        if self.status != "unknown":
            require(
                self.width_bits in (16, 32, 64)
                and self.observed_base_node_id is not None
                and self.observed_byte_offset is not None
                and self.observed_target_ea is not None,
                "Incomplete definite proof",
            )
        if self.status == "proven_in_scope":
            require(
                (
                    self.observed_base_node_id,
                    self.observed_byte_offset,
                    self.observed_target_ea,
                )
                == (self.base_node_id, self.byte_offset, self.target_ea),
                "Proven relation mismatch",
            )

    @property
    def proof_digest(self) -> str:
        return digest(self)


class _Unknown(Exception):
    pass


def prove_store(
    memory: MemoryGraphAnalysis,
    store_node_id: str,
    base_node_id: str,
    byte_offset: int,
    target_ea: int,
    *,
    max_nodes: int = 256,
) -> StoreProof:
    """Prove ``Store(base + byte_offset, target_ea)`` at pointer width.

    Displacements use modular machine-address arithmetic. Unknown loads, calls,
    width-changing operations and nonidentical joins are deliberately rejected.
    The base is a caller-selected SSA identity, not an asserted object type.
    """
    require(type(max_nodes) is int and 1 <= max_nodes <= 4096, "Invalid proof budget")
    bits = memory.graph.snapshot.identity.environment.bitness
    require(
        type(byte_offset) is int
        and -(1 << (bits - 1)) <= byte_offset < (1 << (bits - 1)),
        "Invalid byte offset",
    )
    require(
        type(target_ea) is int and 0 <= target_ea < (1 << bits) - 1,
        "Invalid target address",
    )
    nodes = {node.node_id: node for node in memory.graph.nodes}
    steps: list[StoreProofStep] = []
    visited: set[str] = set()
    active: set[str] = set()
    cache: dict[tuple[str, bool], tuple[str | None, int]] = {}
    mask = (1 << bits) - 1

    def record(node: Node, rule: str) -> None:
        if node.node_id not in visited:
            if len(visited) >= max_nodes:
                raise _Unknown("node_budget_exhausted")
            visited.add(node.node_id)
            steps.append(StoreProofStep(node, rule))

    def resolve(identifier: str, address: bool) -> tuple[str | None, int]:
        key = (identifier, address)
        if key in cache:
            return cache[key]
        if identifier in active:
            raise _Unknown("cyclic_expression")
        if len(active) >= 64:
            raise _Unknown("depth_budget_exhausted")
        node = nodes.get(identifier)
        if node is None:
            raise _Unknown("missing_expression_node")
        record(node, "inspect")
        if node.width_bits != bits:
            raise _Unknown("non_pointer_width_expression")
        if address and identifier == base_node_id:
            return identifier, 0
        active.add(identifier)
        try:
            if node.kind == "Constant":
                if node.operation not in {None, "global_address"}:
                    raise _Unknown("non_numeric_address_constant")
                assert node.constant is not None  # Constant Node contract.
                result = (None, node.constant)
            elif node.kind == "Copy" or (
                node.kind == "Unary"
                and node.operation in {"trunc", "zext", "sext", "extract:0"}
            ):
                result = resolve(node.inputs[0], address)
            elif node.kind in {"Phi", "Select"}:
                arms = (
                    tuple(item.node_id for item in node.phi_inputs)
                    if node.kind == "Phi"
                    else node.inputs[1:]
                )
                values = tuple(resolve(arm, address) for arm in arms)
                if not values or any(value != values[0] for value in values):
                    raise _Unknown("nonidentical_join")
                result = values[0]
            elif address and node.kind == "Binary" and node.operation in {"add", "sub"}:
                left = resolve(node.inputs[0], True)
                right = resolve(node.inputs[1], True)
                if right[0] is None:
                    result = (
                        left[0],
                        (left[1] + (right[1] if node.operation == "add" else -right[1]))
                        & mask,
                    )
                elif left[0] is None and node.operation == "add":
                    result = (right[0], (left[1] + right[1]) & mask)
                else:
                    raise _Unknown("non_affine_address")
            else:
                raise _Unknown("unsupported_" + node.kind.lower())
            cache[key] = result
            return result
        finally:
            active.remove(identifier)

    observed_base = None
    observed_offset = None
    observed_target = None
    status = "unknown"
    reasons: tuple[str, ...] = ()
    store = nodes.get(store_node_id)
    segment_assumption = "flat_address_space_zero_segment"
    try:
        if store is None or store.kind != "Store":
            raise _Unknown("not_a_store")
        record(store, "store_site")
        if base_node_id not in nodes:
            raise _Unknown("missing_base_node")
        if store.width_bits != bits:
            raise _Unknown("non_pointer_width_store")
        roles = store.memory_operands
        assert roles is not None and roles.data is not None  # Store Node contract.
        if roles.segment is not None:
            segment = nodes[roles.segment]
            record(segment, "flat_segment")
            if segment.kind != "Constant" or segment.constant != 0:
                assumption = next(
                    (
                        value
                        for value in (
                            FLAT_USERSPACE_ASSUMPTION,
                            RV32_FLAT_USERSPACE_ASSUMPTION,
                        )
                        if digest(MemoryPolicy(flat_segment_assumption=value))
                        == memory.result.policy_digest
                    ),
                    None,
                )
                access = next(
                    (
                        item
                        for item in memory.result.accesses
                        if item.node_id == store_node_id
                    ),
                    None,
                )
                entry_ids = {entry.node_id for entry in memory.program.entry_storage}
                if (
                    assumption is None
                    or "unresolved_segment" in memory.result.diagnostics
                    or access is None
                    or access.address_node != roles.address
                    or access.width_bits != bits
                    or access.evidence_ids != store.evidence_ids
                    or segment.width_bits != 16
                    or not (
                        segment.kind == "Constant"
                        or segment.kind == "InputValue"
                        and segment.node_id in entry_ids
                    )
                ):
                    raise _Unknown("unresolved_segment")
                segment_assumption = assumption
        observed_base, offset = resolve(roles.address, True)
        observed_offset = (
            offset - (1 << bits) if offset >= (1 << (bits - 1)) else offset
        )
        _, observed_target = resolve(roles.data, False)
        if observed_base is None:
            raise _Unknown("destination_not_relative_to_requested_base")
        status = (
            "proven_in_scope"
            if observed_base == base_node_id
            and observed_offset == byte_offset
            and observed_target == target_ea
            else "mismatch"
        )
        if status == "mismatch":
            reasons = ("observed_relation_differs_from_request",)
    except _Unknown as exc:
        reasons = (str(exc),)
    evidence = tuple(sorted({eid for step in steps for eid in step.node.evidence_ids}))
    return StoreProof(
        status,
        memory.graph.snapshot.snapshot_id,
        memory.graph.graph_digest,
        digest(memory),
        store_node_id,
        base_node_id,
        byte_offset,
        target_ea,
        observed_base,
        observed_offset,
        observed_target,
        store.width_bits if store is not None else None,
        tuple(steps),
        evidence,
        (
            "caller_selected_ssa_base_identity",
            "fixed_width_modular_address_arithmetic",
            segment_assumption,
            "store_site_only_if_reached",
            "no_type_function_classification_or_final_slot_state",
        ),
        reasons,
        max_nodes,
    )


def validate_store_proof(memory: MemoryGraphAnalysis, proof: StoreProof) -> bool:
    """Replay against the exact immutable graph and reject any altered payload."""
    try:
        return proof == prove_store(
            memory,
            proof.store_node_id,
            proof.base_node_id,
            proof.byte_offset,
            proof.target_ea,
            max_nodes=proof.max_nodes,
        )
    except (ContractError, AttributeError, TypeError):
        return False
