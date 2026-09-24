"""Version 1 extracted-input and normalized-IR contracts, not an SSA engine.

Snapshot identity hashes the ID-free structured input and immutable configuration.
Derived graph/evidence IDs depend on that identity, never the other way round.
Database namespace is an ownership boundary, not a content fingerprint.
"""

from dataclasses import dataclass, field
from typing import Literal

from .serialization import (
    ContractError,
    Model,
    digest,
    digest_v2,
    stable_id,
    stable_id_v2,
)
from .states import (
    ByteRange,
    Endian,
    MemoryReference,
    StorageLocation,
    canonical_set,
    check_digest,
    check_id,
    nonempty,
    require,
    unique,
    width,
)


def _identity_for_snapshot(kind: str, value: object, snapshot_id: str) -> str:
    return (
        stable_id_v2(kind, value)
        if snapshot_id.startswith("snapshot-v2:")
        else stable_id(kind, value)
    )


def _same_identity_version(*identifiers: str) -> bool:
    return (
        len(
            {
                identifier.split(":", 1)[0].rsplit("-v", 1)[-1]
                for identifier in identifiers
            }
        )
        <= 1
    )


Maturity = Literal["MMAT_CALLS", "MMAT_GLBOPT3"]
NodeKind = Literal[
    "Constant",
    "InputValue",
    "InputMemory",
    "Copy",
    "Unary",
    "Binary",
    "Compare",
    "Select",
    "Phi",
    "Load",
    "Store",
    "MemoryPhi",
    "Call",
    "CallResult",
    "Return",
    "Exit",
    "Branch",
    "Allocation",
    "Free",
    "UnknownValue",
    "OpaqueEffect",
]
EdgeKind = Literal[
    "value_dependency",
    "memory_data_dependency",
    "memory_order",
    "phi_input",
    "address_dependency",
    "control_dependency",
    "call_argument",
    "call_return",
    "summary_effect",
    "opaque_effect",
]
Provenance = Literal[
    "computed", "reviewed_summary", "architecture_rule", "analyst_assumption"
]
Precision = Literal["exact", "must_alias", "may_alias", "range_widened", "opaque"]
Analysis = Literal["complete_in_scope", "partial", "failed"]
Traversal = Literal[
    "frontier_exhausted", "budget_exceeded", "cancelled", "stale_snapshot"
]
Proof = Literal["feasible", "infeasible", "unknown", "not_requested"]
Alias = Literal["must_alias", "may_alias", "no_alias", "unknown"]


@dataclass(frozen=True)
class ResultAxes(Model):
    provenance: Provenance = "computed"
    precision: Precision = "opaque"
    analysis: Analysis = "partial"
    traversal: Traversal = "frontier_exhausted"
    proof: Proof = "not_requested"
    alias: Alias = "unknown"


@dataclass(frozen=True)
class Diagnostic(Model):
    code: str
    detail: str
    severity: Literal["information", "unsupported"] = "unsupported"

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.code)
        nonempty(self.detail)


@dataclass(frozen=True)
class LocationSet(Model):
    register_bytes: tuple[int, ...] = ()
    memory: tuple[ByteRange, ...] = ()
    all_memory: bool = False

    def __post_init__(self):
        super().__post_init__()
        canonical_set(self.register_bytes)
        require(all(r >= 0 for r in self.register_bytes), "Negative register location")
        canonical_set(tuple((r.start, r.end) for r in self.memory))
        require(
            not self.all_memory or not self.memory, "Top memory has explicit ranges"
        )


@dataclass(frozen=True)
class CallInfo(Model):
    callee_ea: int | None
    convention: int
    arguments: tuple["Operand", ...]
    return_operands: tuple["Operand", ...]
    return_width_bits: int | None
    return_locations: LocationSet
    spoiled_locations: LocationSet
    return_type_code: int
    return_is_void: bool
    unresolved: tuple[str, ...] = ()
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        require(self.callee_ea is None or self.callee_ea >= 0, "Invalid call target")
        require(self.convention >= 0, "Invalid calling convention")
        require(self.return_type_code >= 0, "Invalid return type code")
        require(
            not self.return_is_void or self.return_width_bits is None,
            "Void return has no width",
        )
        if self.return_width_bits is not None:
            width(self.return_width_bits)
        canonical_set(self.unresolved)
        for issue in self.unresolved:
            nonempty(issue)


@dataclass(frozen=True)
class Operand(Model):
    kind: Literal[
        "constant",
        "storage",
        "expression",
        "block",
        "unknown",
        "void",
        "address",
        "stack_address",
        "global",
        "callinfo",
    ]
    width_bits: int | None
    constant: int | None = None
    storage: StorageLocation | None = None
    block_index: int | None = None
    operation: str | None = None
    children: tuple["Operand", ...] = ()
    role: Literal[
        "unspecified", "left", "right", "destination", "argument", "return"
    ] = "unspecified"
    source_eas: tuple[int, ...] = ()
    address: int | None = None
    call: CallInfo | None = None
    diagnostic: Diagnostic | None = None
    native_kind: str | None = None
    synthetic: bool = False

    def __post_init__(self):
        super().__post_init__()
        if self.width_bits is not None:
            width(self.width_bits)
        require(
            self.width_bits is not None
            or self.kind
            in (
                "void",
                "unknown",
                "block",
                "address",
                "stack_address",
                "global",
                "callinfo",
            ),
            "Value operand requires width",
        )
        require(
            self.kind != "void" or self.width_bits is None, "Void has no value width"
        )
        canonical_set(self.source_eas)
        require(all(ea >= 0 for ea in self.source_eas), "Invalid operand EA")
        require(
            (self.address is not None)
            == (self.kind in ("address", "stack_address", "global")),
            "Address payload mismatch",
        )
        require(self.address is None or self.address >= 0, "Negative address")
        require(
            (self.call is not None) == (self.kind == "callinfo"),
            "Call payload mismatch",
        )
        require(
            (self.diagnostic is not None) == (self.kind == "unknown"),
            "Diagnostic operand kind mismatch",
        )
        if self.native_kind is not None:
            nonempty(self.native_kind)
        require(
            (self.constant is not None) == (self.kind == "constant"),
            "Constant operand payload mismatch",
        )
        require(
            (self.storage is not None) == (self.kind == "storage"),
            "Storage operand payload mismatch",
        )
        require(
            (self.block_index is not None) == (self.kind == "block"),
            "Block operand payload mismatch",
        )
        require(
            (self.operation is not None) == (self.kind == "expression"),
            "Expression operand payload mismatch",
        )
        require(
            not self.children or self.kind == "expression", "Unexpected child operands"
        )
        if self.constant is not None:
            require(
                self.width_bits is not None
                and self.constant >= 0
                and self.constant.bit_length() <= self.width_bits,
                "Constant outside width",
            )
        if self.storage is not None:
            require(
                self.storage.width_bits == self.width_bits, "Storage width mismatch"
            )
        if self.block_index is not None:
            require(self.block_index >= 0, "Negative block reference")
        if self.operation is not None:
            nonempty(self.operation)


@dataclass(frozen=True)
class Instruction(Model):
    index: int
    opcode: str  # Structured micro-op identity, never parsed display/native assembly.
    operands: tuple[Operand, ...]
    source_eas: tuple[int, ...] = ()
    synthetic: bool = False

    def __post_init__(self):
        super().__post_init__()
        require(self.index >= 0, "Negative instruction index")
        nonempty(self.opcode)
        require(
            self.source_eas == tuple(sorted(set(self.source_eas)))
            and all(ea >= 0 for ea in self.source_eas),
            "Invalid source EAs",
        )


@dataclass(frozen=True)
class Block(Model):
    index: int
    predecessors: tuple[int, ...]
    instructions: tuple[Instruction, ...]
    successors: tuple[int, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        require(
            self.index >= 0 and all(p >= 0 for p in self.predecessors),
            "Negative block index",
        )
        canonical_set(self.successors)
        require(all(s >= 0 for s in self.successors), "Negative successor")
        require(
            self.predecessors == tuple(sorted(set(self.predecessors))),
            "Invalid predecessor set",
        )
        require(
            tuple(i.index for i in self.instructions)
            == tuple(range(len(self.instructions))),
            "Instructions must be in consecutive program order",
        )


@dataclass(frozen=True)
class FunctionInput(Model):
    function_id: str
    entry_block: int
    blocks: tuple[Block, ...]
    diagnostics: tuple[Diagnostic, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.function_id)
        canonical_set(tuple((d.code, d.detail, d.severity) for d in self.diagnostics))
        require(
            tuple(b.index for b in self.blocks) == tuple(range(len(self.blocks))),
            "Blocks must be consecutively indexed",
        )
        indexes = {b.index for b in self.blocks}
        require(self.entry_block in indexes, "Missing entry block")

        def check_operand(operand):
            if operand.block_index is not None:
                require(operand.block_index in indexes, "Dangling block operand")
            for child in operand.children:
                check_operand(child)
            if operand.call is not None:
                for child in operand.call.arguments + operand.call.return_operands:
                    check_operand(child)

        for block in self.blocks:
            require(set(block.predecessors) <= indexes, "Dangling CFG predecessor")
            require(set(block.successors) <= indexes, "Dangling CFG successor")
            for successor in block.successors:
                require(
                    block.index in self.blocks[successor].predecessors,
                    "Asymmetric CFG successor",
                )
            for predecessor in block.predecessors:
                require(
                    block.index in self.blocks[predecessor].successors,
                    "Asymmetric CFG predecessor",
                )
            for instruction in block.instructions:
                for operand in instruction.operands:
                    check_operand(operand)


@dataclass(frozen=True)
class Environment(Model):
    ida_build: str
    hexrays_build: str
    processor: str
    abi: str
    bitness: int
    data_endian: Endian
    instruction_endian: Endian
    address_space: str
    extractor_version: str
    format_id: Literal["FMT-ELF", "FMT-PE", "FMT-MACHO", "FMT-RAW"]
    platform_tag: str

    def __post_init__(self):
        super().__post_init__()
        for value in (
            self.ida_build,
            self.hexrays_build,
            self.processor,
            self.abi,
            self.address_space,
            self.extractor_version,
            self.platform_tag,
        ):
            nonempty(value)
        require(self.bitness in (16, 32, 64), "Unsupported address width")


@dataclass(frozen=True)
class SnapshotIdentity(Model):
    namespace: str
    binary_digest: str
    semantic_digest: str
    function_id: str
    maturity: Maturity
    profile_digest: str
    rule_digest: str
    summary_digest: str
    policy_digest: str
    input_digest: str
    environment: Environment
    schema_version: Literal[1] = 1
    wire_version: Literal["flow-wire/1", "flow-wire/2"] = field(
        default="flow-wire/1", metadata={"omit_if_default": True}
    )

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.namespace)
        nonempty(self.function_id)
        for value in (
            self.binary_digest,
            self.semantic_digest,
            self.profile_digest,
            self.rule_digest,
            self.summary_digest,
            self.policy_digest,
            self.input_digest,
        ):
            check_digest(value)

    @property
    def snapshot_id(self) -> str:
        return (
            stable_id_v2("snapshot", self.to_data())
            if self.wire_version == "flow-wire/2"
            else stable_id("snapshot", self.to_data())
        )


@dataclass(frozen=True)
class StructuredEnvironment(Model):
    """Exact environment for non-Hex-Rays structured-disassembly snapshots."""

    ida_build: str
    processor: str
    abi: str
    bitness: int
    data_endian: Endian
    instruction_endian: Endian
    address_space: str
    backend_id: Literal["ida-disasm-rv32"]
    backend_version: Literal[1]
    extraction_stage: Literal["structured-disassembly"]
    lowering_version: Literal["rv32-lowering/1"]
    processor_adapter_digest: str
    format_id: Literal["FMT-ELF", "FMT-PE", "FMT-MACHO", "FMT-RAW"]
    platform_tag: str

    def __post_init__(self):
        super().__post_init__()
        for value in (
            self.ida_build,
            self.processor,
            self.abi,
            self.address_space,
            self.backend_id,
            self.extraction_stage,
            self.lowering_version,
            self.platform_tag,
        ):
            nonempty(value)
        require(self.bitness in (16, 32, 64), "Unsupported address width")
        check_digest(self.processor_adapter_digest)


@dataclass(frozen=True)
class StructuredSnapshotIdentity(Model):
    """Identity for reviewed structured input, without fake maturity/Hex-Rays data."""

    namespace: str
    binary_digest: str
    semantic_digest: str
    function_id: str
    backend_digest: str
    profile_digest: str
    capture_digest: str
    lowering_rule_digest: str
    summary_digest: str
    policy_digest: str
    input_digest: str
    environment: StructuredEnvironment
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.namespace)
        nonempty(self.function_id)
        for value in (
            self.binary_digest,
            self.semantic_digest,
            self.backend_digest,
            self.profile_digest,
            self.capture_digest,
            self.lowering_rule_digest,
            self.summary_digest,
            self.policy_digest,
            self.input_digest,
        ):
            check_digest(value)

    @property
    def snapshot_id(self) -> str:
        return stable_id("snapshot", self.to_data())


@dataclass(frozen=True)
class Site(Model):
    block_index: int
    instruction_index: int
    operand_path: tuple[int, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        require(
            self.block_index >= 0
            and self.instruction_index >= 0
            and all(i >= 0 for i in self.operand_path),
            "Negative source position",
        )


@dataclass(frozen=True)
class NodeKey(Model):
    snapshot_id: str
    function_id: str
    site: Site | None = None
    synthetic: str | None = None

    def __post_init__(self):
        super().__post_init__()
        check_id(self.snapshot_id, "snapshot")
        nonempty(self.function_id)
        require(
            (self.site is None) != (self.synthetic is None),
            "Choose a site or a stable synthetic discriminator",
        )
        if self.synthetic is not None:
            nonempty(self.synthetic)

    @property
    def node_id(self) -> str:
        return _identity_for_snapshot("node", self.to_data(), self.snapshot_id)


@dataclass(frozen=True)
class Evidence(Model):
    snapshot_id: str
    rule_id: str
    sites: tuple[Site, ...] = ()
    source_eas: tuple[int, ...] = ()
    synthetic: bool = False
    origins: tuple[str, ...] = ()  # Snapshot-local node IDs, checked by Graph.
    assumptions: tuple[str, ...] = ()
    memory_object_id: str | None = None

    def __post_init__(self):
        super().__post_init__()
        check_id(self.snapshot_id, "snapshot")
        nonempty(self.rule_id)
        canonical_set(
            tuple(
                (s.block_index, s.instruction_index, s.operand_path) for s in self.sites
            )
        )
        canonical_set(self.origins)
        canonical_set(self.assumptions)
        require(
            self.source_eas == tuple(sorted(set(self.source_eas)))
            and all(ea >= 0 for ea in self.source_eas),
            "Invalid evidence EAs",
        )
        require(
            bool(self.sites) or self.synthetic, "No-site evidence must be synthetic"
        )
        for origin in self.origins:
            check_id(origin, "node")
        for assumption in self.assumptions:
            nonempty(assumption)
        if self.memory_object_id is not None:
            check_id(self.memory_object_id, "object")

    @property
    def evidence_id(self) -> str:
        return _identity_for_snapshot("evidence", self.to_data(), self.snapshot_id)


@dataclass(frozen=True)
class PhiInput(Model):
    predecessor: int
    node_id: str

    def __post_init__(self):
        super().__post_init__()
        require(self.predecessor >= 0, "Negative phi predecessor")
        check_id(self.node_id, "node")


@dataclass(frozen=True)
class MemoryOperands(Model):
    address: str
    segment: str | None = None
    data: str | None = None

    def __post_init__(self):
        super().__post_init__()
        for value in (self.address, self.segment, self.data):
            if value is not None:
                check_id(value, "node")

    @property
    def ordered_inputs(self):
        return tuple(
            value
            for value in (self.data, self.segment, self.address)
            if value is not None
        )


@dataclass(frozen=True)
class Node(Model):
    key: NodeKey
    kind: NodeKind
    width_bits: int | None
    evidence_ids: tuple[str, ...]
    inputs: tuple[str, ...] = ()
    phi_inputs: tuple[PhiInput, ...] = ()
    phi_block: int | None = None
    operation: str | None = None
    signed: bool | None = None
    constant: int | None = None
    memory: MemoryReference | None = None
    memory_operands: MemoryOperands | None = None

    def __post_init__(self):
        super().__post_init__()
        if self.width_bits is not None:
            width(self.width_bits)
        if self.kind in {
            "Constant",
            "InputValue",
            "Copy",
            "Unary",
            "Binary",
            "Compare",
            "Select",
            "Phi",
            "Load",
            "CallResult",
        }:
            require(self.width_bits is not None, "Value node requires a width")
        arities = {
            "Constant": (0,),
            "InputValue": (0,),
            "InputMemory": (0,),
            "Copy": (1,),
            "Unary": (1,),
            "Binary": (2,),
            "Compare": (2,),
            "Select": (3,),
            "Free": (1,),
            "Return": (0, 1),
            "Exit": (0,),
            "Branch": (0, 1),
        }
        if self.kind in arities:
            require(len(self.inputs) in arities[self.kind], "Invalid node input arity")
        memory_kind = self.kind in {"InputMemory", "Load", "Store"}
        require(
            (self.memory is not None) == memory_kind, "Memory payload/kind mismatch"
        )
        if memory_kind:
            memory = self.memory
            if memory is None:
                raise ContractError("Memory payload/kind mismatch")
            require(
                self.width_bits == 8 * (memory.interval.end - memory.interval.start),
                "Memory node width/range mismatch",
            )
        if self.kind == "Store":
            require(bool(self.inputs), "Store requires a value input")
        require(
            (self.memory_operands is not None) == (self.kind in {"Load", "Store"}),
            "Memory operand roles required only on Load/Store",
        )
        if self.memory_operands is not None:
            require(
                (self.memory_operands.data is not None) == (self.kind == "Store"),
                "Stored-data role mismatch",
            )
            require(
                self.inputs == self.memory_operands.ordered_inputs,
                "Memory operand order/role mismatch",
            )
        if self.kind in {"Unary", "Binary", "Compare"}:
            require(self.operation is not None, "Operator node requires an operation")
        require(bool(self.evidence_ids), "Node requires evidence")
        canonical_set(self.evidence_ids)
        for eid in self.evidence_ids:
            check_id(eid, "evidence")
        for node in self.inputs:
            check_id(node, "node")
        phi = self.kind in ("Phi", "MemoryPhi")
        require(phi == (self.phi_block is not None), "Phi requires a block")
        require(not self.phi_inputs or phi, "Non-phi has phi inputs")
        if phi:
            require(
                self.phi_block is not None
                and self.phi_block >= 0
                and bool(self.phi_inputs)
                and not self.inputs,
                "Invalid phi inputs",
            )
            canonical_set(tuple(p.predecessor for p in self.phi_inputs))
        require(
            (self.constant is not None) == (self.kind == "Constant"),
            "Constant node payload mismatch",
        )
        if self.constant is not None:
            require(
                self.width_bits is not None
                and self.constant >= 0
                and self.constant.bit_length() <= self.width_bits,
                "Constant node outside width",
            )
        if self.operation is not None:
            nonempty(self.operation)

    @property
    def node_id(self) -> str:
        return self.key.node_id


@dataclass(frozen=True)
class Edge(Model):
    source: str
    target: str
    kind: EdgeKind
    evidence_ids: tuple[str, ...]
    axes: ResultAxes
    width_bits: int | None = None
    interval: ByteRange | None = None
    predecessor: int | None = None
    memory_object_id: str | None = None
    memory_rule_id: str | None = None

    def __post_init__(self):
        super().__post_init__()
        check_id(self.source, "node")
        check_id(self.target, "node")
        require(
            _same_identity_version(self.source, self.target),
            "Mixed node identity versions",
        )
        require(bool(self.evidence_ids), "Edge requires evidence")
        canonical_set(self.evidence_ids)
        for eid in self.evidence_ids:
            check_id(eid, "evidence")
        if self.width_bits is not None:
            width(self.width_bits)
        require(
            (self.predecessor is not None) == (self.kind == "phi_input"),
            "Phi edge requires predecessor",
        )
        if self.predecessor is not None:
            require(self.predecessor >= 0, "Negative predecessor")
        require(
            (self.memory_object_id is None) == (self.memory_rule_id is None),
            "Memory edge object/rule must be paired",
        )
        if self.memory_object_id is not None:
            require(
                self.kind == "memory_data_dependency",
                "Memory derivation belongs on a memory-data edge",
            )
            check_id(self.memory_object_id, "object")
            if self.memory_rule_id is None:
                raise ContractError("Memory edge object/rule must be paired")
            nonempty(self.memory_rule_id)

    @property
    def edge_id(self) -> str:
        return (
            stable_id_v2("edge", self.to_data())
            if self.source.startswith("node-v2:")
            else stable_id("edge", self.to_data())
        )


@dataclass(frozen=True)
class Snapshot(Model):
    identity: SnapshotIdentity
    function: FunctionInput
    snapshot_id: str
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        require(
            self.identity.function_id == self.function.function_id,
            "Function identity mismatch",
        )
        require(
            self.identity.input_digest == digest(self.function),
            "Structured input digest mismatch",
        )
        require(
            self.snapshot_id == self.identity.snapshot_id, "Snapshot identity mismatch"
        )
        if self.identity.wire_version == "flow-wire/2":
            from .wire_contracts import validate_model_wire_v2

            validate_model_wire_v2(self.function, self.identity.environment.bitness)

    def validate_site(self, site: Site):
        require(site.block_index < len(self.function.blocks), "Missing site block")
        instructions = self.function.blocks[site.block_index].instructions
        require(site.instruction_index < len(instructions), "Missing site instruction")
        children = instructions[site.instruction_index].operands
        for index in site.operand_path:
            require(index < len(children), "Missing operand path")
            operand = children[index]
            children = operand.children
            if operand.call is not None:
                children = operand.call.arguments + operand.call.return_operands


@dataclass(frozen=True)
class StructuredSnapshot(Model):
    identity: StructuredSnapshotIdentity
    function: FunctionInput
    snapshot_id: str
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        require(
            self.identity.function_id == self.function.function_id,
            "Function identity mismatch",
        )
        require(
            self.identity.input_digest == digest(self.function),
            "Structured input digest mismatch",
        )
        require(
            self.snapshot_id == self.identity.snapshot_id,
            "Structured snapshot identity mismatch",
        )

    def validate_site(self, site: Site):
        require(site.block_index < len(self.function.blocks), "Missing site block")
        instructions = self.function.blocks[site.block_index].instructions
        require(site.instruction_index < len(instructions), "Missing site instruction")
        children = instructions[site.instruction_index].operands
        for index in site.operand_path:
            require(index < len(children), "Missing operand path")
            operand = children[index]
            children = operand.children
            if operand.call is not None:
                children = operand.call.arguments + operand.call.return_operands


@dataclass(frozen=True)
class MemoryObject(Model):
    snapshot_id: str
    key: str
    address_space: str
    size_bytes: int | None = None
    kind: Literal["stack", "global", "argument", "typed_entry", "heap", "unknown"] = (
        "unknown"
    )
    singleton: bool = False
    singleton_evidence: str | None = None
    disjoint: bool = False
    disjoint_evidence: str | None = None

    def __post_init__(self):
        super().__post_init__()
        check_id(self.snapshot_id, "snapshot")
        nonempty(self.key)
        nonempty(self.address_space)
        require(
            self.singleton == (self.singleton_evidence is not None),
            "Singleton proof required",
        )
        require(
            self.disjoint == (self.disjoint_evidence is not None),
            "Disjoint identity proof required",
        )
        for evidence in (self.singleton_evidence, self.disjoint_evidence):
            if evidence is not None:
                nonempty(evidence)
        if self.size_bytes is not None:
            require(self.size_bytes > 0, "Invalid object extent")

    @property
    def object_id(self) -> str:
        return _identity_for_snapshot("object", self.to_data(), self.snapshot_id)


@dataclass(frozen=True)
class MemoryVersion(Model):
    snapshot_id: str
    key: str  # Static program point/discriminator, not a loop iteration counter.
    origin: str | None = None

    def __post_init__(self):
        super().__post_init__()
        check_id(self.snapshot_id, "snapshot")
        nonempty(self.key)
        if self.origin is not None:
            check_id(self.origin, "node")

    @property
    def version_id(self) -> str:
        return _identity_for_snapshot("memory", self.to_data(), self.snapshot_id)


@dataclass(frozen=True)
class ValueSource(Model):
    snapshot_id: str
    node_id: str
    kind: Literal["value"] = "value"

    def __post_init__(self):
        super().__post_init__()
        check_id(self.snapshot_id, "snapshot")
        check_id(self.node_id, "node")


@dataclass(frozen=True)
class MemorySource(Model):
    snapshot_id: str
    reference: MemoryReference
    kind: Literal["memory"] = "memory"

    def __post_init__(self):
        super().__post_init__()
        check_id(self.snapshot_id, "snapshot")


@dataclass(frozen=True)
class Graph(Model):
    snapshot: Snapshot | StructuredSnapshot
    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]
    evidence: tuple[Evidence, ...]
    axes: ResultAxes
    objects: tuple[MemoryObject, ...] = ()
    versions: tuple[MemoryVersion, ...] = ()
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        node_ids = tuple(n.node_id for n in self.nodes)
        evidence_ids = tuple(e.evidence_id for e in self.evidence)
        canonical_set(node_ids)
        canonical_set(evidence_ids)
        canonical_set(tuple(e.edge_id for e in self.edges))
        nodes, evidence = set(node_ids), set(evidence_ids)
        evidence_by_id = {item.evidence_id: item for item in self.evidence}
        by_id = {n.node_id: n for n in self.nodes}
        sid = self.snapshot.snapshot_id
        version = "v2" if sid.startswith("snapshot-v2:") else "v1"
        all_ids = (
            node_ids
            + tuple(edge.edge_id for edge in self.edges)
            + evidence_ids
            + tuple(obj.object_id for obj in self.objects)
            + tuple(item.version_id for item in self.versions)
        )
        require(
            all(
                identifier.split(":", 1)[0].endswith("-" + version)
                for identifier in all_ids
            ),
            "Mixed graph identity versions",
        )
        canonical_set(tuple(o.object_id for o in self.objects))
        memory_objects = {obj.object_id for obj in self.objects}
        canonical_set(tuple(v.version_id for v in self.versions))
        for obj in self.objects:
            require(obj.snapshot_id == sid, "Cross-snapshot memory object")
        for version in self.versions:
            require(version.snapshot_id == sid, "Cross-snapshot memory version")
            require(
                version.origin is None or version.origin in nodes,
                "Dangling memory origin",
            )
        for item in self.evidence:
            require(item.snapshot_id == sid, "Cross-snapshot evidence")
            require(set(item.origins) <= nodes, "Dangling evidence origin")
            require(
                item.memory_object_id is None
                or item.memory_object_id in memory_objects,
                "Dangling evidence memory object",
            )
            for site in item.sites:
                self.snapshot.validate_site(site)
            if item.source_eas:
                eas = {
                    ea
                    for site in item.sites
                    for ea in self.snapshot.function.blocks[site.block_index]
                    .instructions[site.instruction_index]
                    .source_eas
                }
                require(set(item.source_eas) <= eas, "Evidence EA not at cited site")
        for node in self.nodes:
            require(
                node.key.snapshot_id == sid
                and node.key.function_id == self.snapshot.function.function_id,
                "Cross-snapshot node",
            )
            require(set(node.evidence_ids) <= evidence, "Dangling node evidence")
            require(set(node.inputs) <= nodes, "Dangling node input")
            if node.key.site is not None:
                self.snapshot.validate_site(node.key.site)
            if node.memory is not None:
                self.validate_memory(node.memory)
            if node.phi_block is not None:
                require(
                    node.phi_block < len(self.snapshot.function.blocks),
                    "Missing phi block",
                )
                predecessors = set(
                    self.snapshot.function.blocks[node.phi_block].predecessors
                )
                require(
                    {p.predecessor for p in node.phi_inputs} == predecessors,
                    "Phi predecessor coverage mismatch",
                )
                require(
                    all(p.node_id in nodes for p in node.phi_inputs),
                    "Dangling phi reference",
                )
                if node.kind == "Phi":
                    require(
                        all(
                            by_id[p.node_id].width_bits == node.width_bits
                            for p in node.phi_inputs
                        ),
                        "Phi input width mismatch",
                    )
        expected_phi = {
            (p.node_id, n.node_id, p.predecessor)
            for n in self.nodes
            for p in n.phi_inputs
        }
        actual_phi = tuple(
            (e.source, e.target, e.predecessor)
            for e in self.edges
            if e.kind == "phi_input"
        )
        unique(actual_phi)
        require(set(actual_phi) == expected_phi, "Phi node/edge completeness mismatch")
        for edge in self.edges:
            require(edge.source in nodes and edge.target in nodes, "Dangling edge")
            require(set(edge.evidence_ids) <= evidence, "Dangling edge evidence")
            require(
                edge.memory_object_id is None
                or edge.memory_object_id in memory_objects,
                "Dangling edge memory object",
            )
            if edge.memory_object_id is not None:
                require(
                    (edge.interval is None and edge.width_bits is None)
                    or (
                        edge.interval is not None
                        and edge.width_bits
                        == 8 * (edge.interval.end - edge.interval.start)
                    ),
                    "Memory edge width/range mismatch",
                )
                linked = [
                    evidence_by_id[eid]
                    for eid in edge.evidence_ids
                    if evidence_by_id[eid].rule_id == edge.memory_rule_id
                    and evidence_by_id[eid].origins
                    == tuple(sorted((edge.source, edge.target)))
                    and evidence_by_id[eid].memory_object_id == edge.memory_object_id
                    and evidence_by_id[eid].assumptions
                ]
                require(bool(linked), "Missing memory derivation evidence")
            if edge.kind == "phi_input":
                target = by_id[edge.target]
                require(
                    edge.predecessor is not None
                    and PhiInput(edge.predecessor, edge.source) in target.phi_inputs,
                    "Phi edge/input mismatch",
                )
        if (
            isinstance(self.snapshot, Snapshot)
            and self.snapshot.identity.wire_version == "flow-wire/2"
        ):
            from .wire_contracts import validate_model_wire_v2

            validate_model_wire_v2(self, self.snapshot.identity.environment.bitness)

    def validate_memory(self, reference: MemoryReference):
        objects = {o.object_id: o for o in self.objects}
        require(reference.object_id in objects, "Dangling memory object")
        require(
            reference.version_id in {v.version_id for v in self.versions},
            "Dangling memory version",
        )
        obj = objects[reference.object_id]
        require(
            reference.address_space == obj.address_space,
            "Memory address-space mismatch",
        )
        require(
            obj.size_bytes is None or reference.interval.end <= obj.size_bytes,
            "Memory range outside object",
        )
        require(
            reference.endian == self.snapshot.identity.environment.data_endian,
            "Memory endian mismatch",
        )

    def validate_source(self, source: ValueSource | MemorySource):
        require(type(source) in (ValueSource, MemorySource), "Invalid source contract")
        require(
            source.snapshot_id == self.snapshot.snapshot_id, "Cross-snapshot source"
        )
        if isinstance(source, ValueSource):
            require(
                source.node_id in {n.node_id for n in self.nodes},
                "Dangling source node",
            )
        else:
            self.validate_memory(source.reference)

    @property
    def graph_digest(self) -> str:
        return (
            self.graph_digest_v2
            if self.snapshot.snapshot_id.startswith("snapshot-v2:")
            else digest(self)
        )

    @property
    def graph_digest_v2(self) -> str:
        require(
            self.snapshot.snapshot_id.startswith("snapshot-v2:"),
            "graph_digest_v2_requires_wire_v2",
        )
        return digest_v2(self)
