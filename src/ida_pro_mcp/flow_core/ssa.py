"""Range-partitioned scalar SSA over structured microcode. Memory is a boundary."""

from dataclasses import dataclass
from typing import Literal

from .cfg import Dominance, dominance
from .contracts import (
    Edge,
    Evidence,
    Graph,
    MemoryObject,
    MemoryOperands,
    MemoryVersion,
    Node,
    NodeKey,
    PhiInput,
    ResultAxes,
    Site,
    Snapshot,
)
from .serialization import Model
from .states import (
    ByteRange,
    MemoryReference,
    StorageLocation,
    canonical_set,
    check_id,
    require,
)


@dataclass(frozen=True)
class Definition(Model):
    node_id: str
    block: int
    order: int

    def __post_init__(self):
        super().__post_init__()
        check_id(self.node_id, "node")
        require(self.block >= 0 and self.order >= -2, "Invalid definition position")


@dataclass(frozen=True)
class EntryStorage(Model):
    storage: StorageLocation
    node_id: str

    def __post_init__(self):
        super().__post_init__()
        check_id(self.node_id, "node")


@dataclass(frozen=True)
class SSAProgram(Model):
    graph: Graph
    dominance: Dominance
    definitions: tuple[Definition, ...]
    entry_storage: tuple[EntryStorage, ...]
    diagnostics: tuple[str, ...]
    storage_model: Literal["scalar", "memory"] = "scalar"

    def __post_init__(self):
        super().__post_init__()
        canonical_set(self.diagnostics)
        require(
            tuple(d.node_id for d in self.definitions)
            == tuple(n.node_id for n in self.graph.nodes),
            "Definition coverage/order mismatch",
        )
        require(
            self.dominance == dominance(self.graph.snapshot.function),
            "Incorrect dominance certificate",
        )
        definitions = {d.node_id: d for d in self.definitions}
        dom = {b.block: set(b.dominators) for b in self.dominance.blocks}

        def reaches(source, target, edge=False):
            a, b = definitions[source], target
            if b.block not in dom:
                return  # Unreachable predecessor is explicitly diagnosed by builder.
            require(a.block in dom[b.block], "Definition does not dominate use")
            if a.block == b.block and not edge:
                require(a.order < b.order, "Definition does not precede use")

        for node in self.graph.nodes:
            definition = definitions[node.node_id]
            require(
                definition.block in dom
                or definition.block in self.dominance.unreachable,
                "Invalid definition block",
            )
            for source in node.inputs:
                reaches(source, definition)
            for phi in node.phi_inputs:
                reaches(phi.node_id, Definition(node.node_id, phi.predecessor, 0), True)
        canonical_set(
            tuple(
                (
                    e.storage.address_space,
                    e.storage.name,
                    e.storage.bit_offset,
                    e.storage.width_bits,
                )
                for e in self.entry_storage
            )
        )
        graph_nodes = {n.node_id: n for n in self.graph.nodes}
        for entry in self.entry_storage:
            require(entry.node_id in definitions, "Missing entry-storage definition")
            definition = definitions[entry.node_id]
            node = graph_nodes[entry.node_id]
            require(
                node.kind == "InputValue"
                and node.width_bits == entry.storage.width_bits
                and definition.block == self.graph.snapshot.function.entry_block
                and definition.order == -2,
                "Invalid entry-storage binding",
            )


UNARY = {
    "m_neg": "neg",
    "m_bnot": "not",
    "m_lnot": "logical_not",
    "m_xdu": "zext",
    "m_xds": "sext",
    "m_low": "trunc",
    "m_high": "high",
}
BINARY = {
    "m_add": "add",
    "m_sub": "sub",
    "m_mul": "mul",
    "m_and": "and",
    "m_or": "or",
    "m_xor": "xor",
    "m_shl": "shl",
    "m_shr": "lshr",
    "m_sar": "ashr",
}
COMPARE = {
    "m_setz": "eq",
    "m_setnz": "ne",
    "m_setb": "ult",
    "m_setae": "uge",
    "m_seta": "ugt",
    "m_setbe": "ule",
    "m_setl": "slt",
    "m_setge": "sge",
    "m_setg": "sgt",
    "m_setle": "sle",
}
BRANCH = {
    "m_jz",
    "m_jnz",
    "m_ja",
    "m_jae",
    "m_jb",
    "m_jbe",
    "m_jg",
    "m_jge",
    "m_jl",
    "m_jle",
    "m_jcnd",
    "m_jtbl",
}


def build_ssa(
    snapshot: Snapshot,
    *,
    max_nodes: int = 20000,
    max_blocks: int = 1000,
    storage_model: Literal["scalar", "memory"] = "scalar",
) -> SSAProgram:
    """Build a seed-independent graph. Resource refusal is explicit, never no-flow."""
    require(
        type(max_nodes) is int
        and max_nodes > 0
        and type(max_blocks) is int
        and max_blocks > 0,
        "Invalid SSA budget",
    )
    require(len(snapshot.function.blocks) <= max_blocks, "SSA block budget exceeded")
    require(storage_model in {"scalar", "memory"}, "Unknown storage model")
    return _Builder(snapshot, max_nodes, storage_model).build()


class _Builder:
    def __init__(self, snapshot, budget, storage_model):
        self.snapshot, self.budget = snapshot, budget
        self.storage_model = storage_model
        self.prefix = "memory:" if storage_model == "memory" else ""
        self.dom = dominance(snapshot.function)
        self.nodes, self.evidence, self.definitions = {}, {}, {}
        self.objects, self.versions = {}, {}
        self.diagnostics = {f"unreachable_block:{b}" for b in self.dom.unreachable}
        self.diagnostics.update(d.code for d in snapshot.function.diagnostics)
        self.current_block, self.order, self.site = (
            snapshot.function.entry_block,
            0,
            None,
        )
        self.serial = 0
        self.atoms = self.partition()
        self.stacks = {a: [] for a in self.atoms}
        self.phis, self.phi_inputs = {}, {}
        self.entries = []

    def operands(self, operand):
        yield operand
        for child in operand.children:
            yield from self.operands(child)
        if operand.call is not None:
            for arg in operand.call.arguments + operand.call.return_operands:
                yield from self.operands(arg)

    def partition(self):
        groups = {}
        for block in self.snapshot.function.blocks:
            for ins in block.instructions:
                for operand in ins.operands:
                    for op in self.operands(operand):
                        if op.storage:
                            loc = op.storage
                            if (
                                self.storage_model == "memory"
                                and loc.address_space == "stack"
                            ):
                                continue
                            groups.setdefault(
                                (loc.address_space, loc.name), set()
                            ).update((loc.bit_offset, loc.bit_offset + loc.width_bits))
        atoms = []
        for (space, name), boundaries in sorted(groups.items()):
            bounds = sorted(boundaries)
            atoms.extend(
                StorageLocation(space, name, a, b - a)
                for a, b in zip(bounds, bounds[1:])
            )
        return tuple(atoms)

    def matching(self, loc):
        return tuple(
            a
            for a in self.atoms
            if (a.address_space, a.name) == (loc.address_space, loc.name)
            and loc.bit_offset <= a.bit_offset
            and a.bit_offset + a.width_bits <= loc.bit_offset + loc.width_bits
        )

    def emit(
        self,
        kind,
        width,
        inputs=(),
        operation=None,
        constant=None,
        memory=None,
        memory_operands=None,
        tag=None,
        order=None,
    ):
        require(len(self.nodes) < self.budget, "SSA node budget exceeded")
        self.serial += 1
        key = NodeKey(
            self.snapshot.snapshot_id,
            self.snapshot.function.function_id,
            synthetic=self.prefix
            + (tag or f"ssa:b{self.current_block}:n{self.serial}"),
        )
        rule = "scalar-ssa-v1:" + (operation or kind)
        ev = Evidence(
            self.snapshot.snapshot_id,
            rule,
            sites=(self.site,) if self.site else (),
            synthetic=True,
        )
        self.evidence[ev.evidence_id] = ev
        node = Node(
            key,
            kind,
            width,
            (ev.evidence_id,),
            inputs=inputs,
            operation=operation,
            signed=(operation in {"sext", "ashr", "slt", "sle", "sgt", "sge"})
            if operation
            in {
                "sext",
                "zext",
                "ashr",
                "lshr",
                "ult",
                "ule",
                "ugt",
                "uge",
                "slt",
                "sle",
                "sgt",
                "sge",
            }
            else None,
            constant=constant,
            memory=memory,
            memory_operands=memory_operands,
        )
        require(node.node_id not in self.nodes, "Duplicate SSA definition")
        self.nodes[node.node_id] = node
        self.definitions[node.node_id] = Definition(
            node.node_id, self.current_block, self.order if order is None else order
        )
        self.order += 1
        return node.node_id

    def unknown(self, width, inputs, reason):
        self.diagnostics.add(reason)
        return self.emit("UnknownValue", width, inputs, operation=reason)

    def storage_address(self, location):
        require(
            location.bit_offset % 8 == 0,
            "Non-byte stack address requires unknown lowering",
        )
        return self.emit(
            "Constant",
            self.snapshot.identity.environment.bitness,
            constant=location.bit_offset // 8,
            operation="stack_address",
        )

    def read(self, location):
        if self.storage_model == "memory" and location.address_space == "stack":
            address = self.storage_address(location)
            roles = MemoryOperands(address)
            return self.boundary(
                "Load",
                location.width_bits,
                roles.ordered_inputs,
                "memory_load_boundary",
                roles,
            )
        atoms = self.matching(location)
        require(bool(atoms), "Missing storage partition")
        result = self.stacks[atoms[0]][-1]
        bits = atoms[0].width_bits
        for atom in atoms[1:]:
            bits += atom.width_bits
            result = self.emit(
                "Binary", bits, (result, self.stacks[atom][-1]), operation="concat_low"
            )
        return result

    def write(self, location, value):
        if self.storage_model == "memory" and location.address_space == "stack":
            address = self.storage_address(location)
            roles = MemoryOperands(address, data=value)
            self.boundary(
                "Store",
                location.width_bits,
                roles.ordered_inputs,
                "memory_store_boundary",
                roles,
            )
            return
        for atom in self.matching(location):
            if (
                atom.width_bits == self.nodes[value].width_bits
                and atom.bit_offset == location.bit_offset
            ):
                part = value
            else:
                offset = atom.bit_offset - location.bit_offset
                part = self.emit(
                    "Unary", atom.width_bits, (value,), operation=f"extract:{offset}"
                )
            self.stacks[atom].append(part)

    def operand(self, op):
        if op.kind == "constant":
            return self.emit("Constant", op.width_bits, constant=op.constant)
        if op.kind == "storage":
            return self.read(op.storage)
        if op.kind == "global" and self.storage_model == "memory":
            address = self.emit(
                "Constant",
                self.snapshot.identity.environment.bitness,
                constant=op.address,
                operation="global_address",
            )
            roles = MemoryOperands(address)
            return self.boundary(
                "Load",
                op.width_bits,
                roles.ordered_inputs,
                "memory_load_boundary",
                roles,
            )
        if op.kind == "expression":
            return self.operation(op.operation, op.children, op.width_bits)
        if op.kind in {"void", "block"}:
            return None
        if op.kind == "callinfo":
            args = tuple(
                v for arg in op.call.arguments if (v := self.operand(arg)) is not None
            )
            return self.unknown(op.width_bits, args, "unmodeled_callinfo")
        return self.unknown(op.width_bits, (), f"unmodeled_operand:{op.kind}")

    def boundary(self, kind, bits, values, reason, roles=None):
        self.diagnostics.add(reason)
        if kind in {"Load", "Store"}:
            if bits is None or bits <= 0 or bits % 8:
                return self.unknown(bits, values, "unknown_memory_width")
            obj = MemoryObject(
                self.snapshot.snapshot_id,
                f"unresolved:{self.current_block}:{self.serial}",
                self.snapshot.identity.environment.address_space,
            )
            ver = MemoryVersion(self.snapshot.snapshot_id, obj.key)
            self.objects[obj.object_id], self.versions[ver.version_id] = obj, ver
            ref = MemoryReference(
                obj.object_id,
                ver.version_id,
                obj.address_space,
                ByteRange(0, bits // 8),
                self.snapshot.identity.environment.data_endian,
            )
            if kind == "Store" and not values:
                values = (self.unknown(bits, (), "missing_store_value"),)
            return self.emit(kind, bits, values, memory=ref, memory_operands=roles)
        return self.emit(kind, bits, values)

    def operation(self, opcode, operands, bits):
        # m_stx destination is an address input, not a scalar definition.
        source_ops = [
            o
            for o in operands
            if o.role != "destination" or opcode == "m_stx" or o.kind == "callinfo"
        ]
        evaluated = [
            (
                op.role,
                self.emit(
                    "Constant",
                    self.snapshot.identity.environment.bitness,
                    constant=op.address,
                    operation="call_target_address",
                )
                if self.storage_model == "memory"
                and opcode == "m_call"
                and op.role == "left"
                and op.kind == "global"
                else self.operand(op),
            )
            for op in source_ops
        ]
        values = tuple(v for _, v in evaluated if v is not None)
        memory_roles = None
        if opcode in {"m_ldx", "m_stx"}:
            by_role = {}
            for role, value in evaluated:
                if value is not None:
                    require(role not in by_role, "Ambiguous memory operand role")
                    by_role[role] = value
            expected = (
                {"left", "right"}
                if opcode == "m_ldx"
                else {"left", "right", "destination"}
            )
            require(
                set(by_role) == expected,
                "Missing/unknown microcode memory operand roles",
            )
            memory_roles = MemoryOperands(
                by_role["right"] if opcode == "m_ldx" else by_role["destination"],
                by_role["left"] if opcode == "m_ldx" else by_role["right"],
                None if opcode == "m_ldx" else by_role["left"],
            )
            values = memory_roles.ordered_inputs
        if (
            opcode == "m_mov"
            and len(values) == 1
            and bits == self.nodes[values[0]].width_bits
        ):
            return self.emit("Copy", bits, values)
        if opcode in UNARY and len(values) == 1 and bits:
            return self.emit("Unary", bits, values, operation=UNARY[opcode])
        if opcode in BINARY and len(values) == 2 and bits:
            return self.emit("Binary", bits, values, operation=BINARY[opcode])
        if opcode in COMPARE and len(values) == 2 and bits:
            return self.emit("Compare", bits, values, operation=COMPARE[opcode])
        if opcode == "m_select" and len(values) == 3 and bits:
            return self.emit("Select", bits, values)
        if opcode == "m_ldx":
            return self.boundary(
                "Load", bits, values, "memory_load_boundary", memory_roles
            )
        if opcode == "m_stx":
            store_bits = self.nodes[values[0]].width_bits if values else None
            out = self.boundary(
                "Store", store_bits, values, "memory_store_boundary", memory_roles
            )
            self.havoc(values, stack_only=True)
            return out
        if opcode in {"m_call", "m_icall"}:
            out = self.boundary("Call", bits, values, "call_boundary")
            self.havoc(values)
            return out
        if opcode in BRANCH:
            compare = {
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
            if opcode in compare and len(values) == 2:
                condition = self.emit("Compare", 1, values, operation=compare[opcode])
            else:
                condition = (
                    self.unknown(1, values, "branch_predicate_not_lowered")
                    if len(values) != 1
                    else values[0]
                )
            return self.emit("Branch", None, (condition,))
        if opcode == "m_goto":
            return self.emit("Branch", None)
        if opcode == "m_ret":
            if len(values) <= 1:
                return self.emit(
                    "Return",
                    self.nodes[values[0]].width_bits if values else None,
                    values,
                )
        if opcode == "m_nop" and not values:
            return self.emit("OpaqueEffect", None, operation="nop")
        self.havoc(values)
        return self.unknown(bits, values, f"unsupported_opcode:{opcode}")

    def havoc(self, inputs, stack_only=False):
        for atom in self.atoms:
            if not stack_only or atom.address_space != "microregister":
                old = self.stacks[atom][-1]
                self.stacks[atom].append(
                    self.unknown(
                        atom.width_bits,
                        (old,) + inputs,
                        "unmodeled_memory_or_call_effect",
                    )
                )

    def build(self):
        entry = self.snapshot.function.entry_block
        require(
            not self.snapshot.function.blocks[entry].predecessors,
            "Entry backedge requires explicit preheader",
        )
        # Initial scalar locations are symbolic inputs, not fabricated constants.
        for atom in self.atoms:
            nid = self.emit(
                "InputValue",
                atom.width_bits,
                tag=f"entry:{atom.address_space}:{atom.name}:{atom.bit_offset}:{atom.width_bits}",
                order=-2,
            )
            self.stacks[atom].append(nid)
            self.entries.append(EntryStorage(atom, nid))
        df = {b.block: b.frontier for b in self.dom.blocks}
        defs = {a: {entry} for a in self.atoms}
        for b in self.snapshot.function.blocks:
            if b.index not in self.dom.reachable:
                continue
            for ins in b.instructions:
                for op in ins.operands:
                    if (
                        op.role == "destination"
                        and op.storage
                        and ins.opcode != "m_stx"
                    ):
                        for atom in self.matching(op.storage):
                            defs[atom].add(b.index)
                # Boundary effects may define any scalar storage location.
                nested = [
                    o.operation
                    for op in ins.operands
                    for o in self.operands(op)
                    if o.kind == "expression"
                ]
                known = (
                    set(UNARY)
                    | set(BINARY)
                    | set(COMPARE)
                    | BRANCH
                    | {"m_mov", "m_select", "m_ldx", "m_goto", "m_ret", "m_nop"}
                )
                if ins.opcode not in known or any(o not in known for o in nested):
                    for atom in self.atoms:
                        defs[atom].add(b.index)
        for atom in self.atoms:
            todo, placed = sorted(defs[atom]), set()
            while todo:
                b = todo.pop(0)
                for y in df[b]:
                    if y not in placed:
                        placed.add(y)
                        if y not in defs[atom]:
                            todo.append(y)
            for b in sorted(placed):
                key = NodeKey(
                    self.snapshot.snapshot_id,
                    self.snapshot.function.function_id,
                    synthetic=self.prefix
                    + f"phi:{b}:{atom.address_space}:{atom.name}:{atom.bit_offset}:{atom.width_bits}",
                )
                self.phis[(b, atom)] = key
                self.phi_inputs[(b, atom)] = {}
        children = {b: [] for b in self.dom.reachable}
        for info in self.dom.blocks:
            if info.immediate is not None:
                children[info.immediate].append(info.block)
        # Iterative dominator-tree traversal avoids Python recursion on long CFGs.
        events = [(entry, False, None)]
        while events:
            b, exiting, saved = events.pop()
            if exiting:
                for atom, count in saved.items():
                    del self.stacks[atom][count:]
                continue
            saved = {a: len(v) for a, v in self.stacks.items()}
            self.current_block, self.order, self.site = b, 0, None
            for atom in self.atoms:
                if (b, atom) in self.phis:
                    key = self.phis[(b, atom)]
                    self.stacks[atom].append(key.node_id)
                    # Temporary width lookup only; replaced with validated Phi below.
                    self.nodes[key.node_id] = Node(
                        key, "InputValue", atom.width_bits, (self._phi_evidence(),)
                    )
                    self.definitions[key.node_id] = Definition(key.node_id, b, -1)
            for ins in self.snapshot.function.blocks[b].instructions:
                self.site = Site(b, ins.index)
                dest = next(
                    (
                        o
                        for o in ins.operands
                        if o.role == "destination"
                        and (
                            o.storage
                            or (self.storage_model == "memory" and o.kind == "global")
                        )
                    ),
                    None,
                )
                bits = dest.width_bits if dest and ins.opcode != "m_stx" else None
                result = self.operation(ins.opcode, ins.operands, bits)
                if dest and ins.opcode != "m_stx":
                    if self.nodes[result].width_bits != dest.width_bits:
                        result = self.unknown(
                            dest.width_bits, (result,), "destination_width_mismatch"
                        )
                    if dest.kind == "global":
                        address = self.emit(
                            "Constant",
                            self.snapshot.identity.environment.bitness,
                            constant=dest.address,
                            operation="global_address",
                        )
                        roles = MemoryOperands(address, data=result)
                        self.boundary(
                            "Store",
                            dest.width_bits,
                            roles.ordered_inputs,
                            "memory_store_boundary",
                            roles,
                        )
                    else:
                        self.write(dest.storage, result)
            for successor in self.snapshot.function.blocks:
                if b in successor.predecessors:
                    for atom in self.atoms:
                        pair = (successor.index, atom)
                        if pair in self.phi_inputs:
                            self.phi_inputs[pair][b] = self.stacks[atom][-1]
            events.append((b, True, saved))
            events.extend((child, False, None) for child in reversed(children[b]))
        for pair, key in self.phis.items():
            b, atom = pair
            ev = self.nodes[key.node_id].evidence_ids
            inputs = self.phi_inputs[pair]
            for pred in self.snapshot.function.blocks[b].predecessors:
                if pred not in inputs:
                    self.current_block, self.site = pred, None
                    inputs[pred] = self.unknown(
                        atom.width_bits, (), "unreachable_phi_predecessor"
                    )
            self.nodes[key.node_id] = Node(
                key,
                "Phi",
                atom.width_bits,
                ev,
                phi_block=b,
                phi_inputs=tuple(PhiInput(p, n) for p, n in sorted(inputs.items())),
            )
        require(len(self.nodes) <= self.budget, "SSA node budget exceeded")
        edges = []
        for node in self.nodes.values():
            emitted = set()
            for index, source in enumerate(node.inputs):
                if node.memory_operands is not None:
                    kind = (
                        "memory_data_dependency"
                        if node.kind == "Store" and index == 0
                        else "address_dependency"
                    )
                else:
                    kind = (
                        "control_dependency"
                        if node.kind == "Select" and index == 0
                        else "value_dependency"
                    )
                if (source, kind) in emitted:
                    continue
                emitted.add((source, kind))
                edges.append(
                    Edge(
                        source,
                        node.node_id,
                        kind,
                        node.evidence_ids,
                        ResultAxes(precision="exact"),
                    )
                )
            for p in node.phi_inputs:
                edges.append(
                    Edge(
                        p.node_id,
                        node.node_id,
                        "phi_input",
                        node.evidence_ids,
                        ResultAxes(precision="exact"),
                        predecessor=p.predecessor,
                    )
                )
        axes = ResultAxes(
            precision="exact" if not self.diagnostics else "opaque",
            analysis="partial" if self.diagnostics else "complete_in_scope",
        )
        graph = Graph(
            self.snapshot,
            tuple(sorted(self.nodes.values(), key=lambda n: n.node_id)),
            tuple(sorted(edges, key=lambda e: e.edge_id)),
            tuple(sorted(self.evidence.values(), key=lambda e: e.evidence_id)),
            axes,
            tuple(sorted(self.objects.values(), key=lambda o: o.object_id)),
            tuple(sorted(self.versions.values(), key=lambda v: v.version_id)),
        )
        return SSAProgram(
            graph,
            self.dom,
            tuple(sorted(self.definitions.values(), key=lambda d: d.node_id)),
            tuple(self.entries),
            tuple(sorted(self.diagnostics)),
            self.storage_model,
        )

    def _phi_evidence(self):
        evidence = Evidence(
            self.snapshot.snapshot_id, "scalar-ssa-v1:phi", synthetic=True
        )
        self.evidence[evidence.evidence_id] = evidence
        return evidence.evidence_id
