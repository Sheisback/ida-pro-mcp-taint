"""Internal structured microcode adapter. No public tools or native relifting.

Only extract_snapshot calls IDA. The remaining contracts/helpers are pure Python.
"""

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Callable
from typing import Literal, cast

from ida_pro_mcp.flow_core.contracts import (
    Block,
    CallInfo,
    Diagnostic,
    Environment,
    FunctionInput,
    Instruction,
    LocationSet,
    Operand,
    Snapshot,
    SnapshotIdentity,
)
from ida_pro_mcp.flow_core.profile_registry import (
    REGISTRY,
    REGISTRY_DIGEST,
    ProfileRegistry,
)
from ida_pro_mcp.flow_core.serialization import ContractError, Model, digest
from ida_pro_mcp.flow_core.states import ByteRange, StorageLocation, require

VERSION = "microcode-extractor/1"
RULES = {
    "version": 1,
    "input": "structured_microcode",
    "native_effects": "preserve_once",
    "void_width": None,
    "unsupported": "opaque_diagnostic",
    "registers": "sdk_byte_locations_no_native_rewrite",
}
POLICY = {
    "mode": "extraction_only",
    "source_origins": "observed_ea_union",
    "chain_scope": "not_serialized",
    "analysis": "not_implemented",
}
EMPTY_SUMMARIES = {"version": 1, "summaries": []}


@dataclass(frozen=True)
class CallObservation(Model):
    """One call operand tied to its exact native instruction origin."""

    block_index: int
    instruction_index: int
    instruction_ea: int
    call: CallInfo
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        require(
            self.block_index >= 0
            and self.instruction_index >= 0
            and self.instruction_ea >= 0,
            "Invalid call observation position",
        )


def _nested_calls(operand: Operand) -> tuple[CallInfo, ...]:
    if operand.call is not None:
        children = operand.call.arguments + operand.call.return_operands
        return (operand.call,) + tuple(
            call for child in children for call in _nested_calls(child)
        )
    return tuple(call for child in operand.children for call in _nested_calls(child))


@dataclass(frozen=True)
class ExtractedFunction(Model):
    snapshot: Snapshot
    image_base: int
    function_ea: int
    calls: tuple[CallObservation, ...]
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        require(
            0 <= self.image_base <= self.function_ea,
            "Function precedes image base",
        )
        keys = tuple(
            (call.block_index, call.instruction_index, call.instruction_ea)
            for call in self.calls
        )
        require(keys == tuple(sorted(set(keys))), "Calls must be sorted and unique")
        for call in self.calls:
            require(
                call.block_index < len(self.snapshot.function.blocks),
                "Missing call block",
            )
            instructions = self.snapshot.function.blocks[call.block_index].instructions
            require(
                call.instruction_index < len(instructions),
                "Missing call instruction",
            )
            instruction = instructions[call.instruction_index]
            require(
                call.instruction_ea in instruction.source_eas,
                "Call observation/native origin mismatch",
            )
            anchored = tuple(
                nested
                for operand in instruction.operands
                for nested in _nested_calls(operand)
            )
            require(
                anchored == (call.call,),
                "Call observation/structured instruction mismatch",
            )

    @property
    def function_rva(self) -> int:
        return self.function_ea - self.image_base


def anchor_profile(inventory, profile_id, abi, build_manifest):
    """Freeze selected inventory configuration, not an ISA support claim."""
    spec = REGISTRY.resolve_inventory_profile(inventory, profile_id)
    receipt = spec.measured_receipt
    if receipt is None:
        raise ContractError("Profile has no measured extraction receipt")
    if abi != receipt.abi:
        raise ContractError("ABI lacks anchor extraction evidence")
    row = next(r for r in inventory["profiles"] if r["profile_id"] == profile_id)
    builds = [
        b
        for b in build_manifest
        if b["abi_id"] == abi
        and b["format"] == receipt.format_id
        and b["binary_sha256"] in row["fixture_hashes"]
    ]
    if len(builds) != 1:
        raise ContractError("Anchor requires one matching Mach-O build receipt")
    build = builds[0]
    return {
        "format_id": receipt.format_id,
        "platform_tag": receipt.platform_tag,
        "abi_provenance": {
            "kind": "measured_anchor_build",
            "source_sha256": build["source_sha256"],
            "compiler": build["compiler"],
            "sdk_version": build["sdk_version"],
            "binary_sha256": build["binary_sha256"],
        },
        "profile_id": profile_id,
        "version": spec.profile_version,
        "mode": spec.mode,
        "abi": abi,
        "maturity": receipt.maturity,
        "bitness": spec.bitness,
        "data_endian": spec.data_endian,
        "instruction_endian": spec.instruction_endian,
        "processor": receipt.processor,
        "normal_status": spec.normal_status,
        "fallback_status": spec.fallback_status,
        "receipt_status": spec.receipt_status,
        "receipt_evidence": receipt.to_data(),
        "registry_digest": REGISTRY_DIGEST,
        "required_features": list(spec.required_features),
    }


def source_eas(operand):
    """Union observed nested origins; never reconstruct removed native origins."""
    eas = set(operand.source_eas)
    children = operand.children
    if operand.call is not None:
        children += operand.call.arguments + operand.call.return_operands
    for child in children:
        eas.update(source_eas(child))
    return tuple(sorted(eas))


def make_snapshot(
    function,
    environment,
    profile,
    namespace,
    binary_sha256,
    *,
    summary_digest=None,
):
    if not namespace.strip():
        raise ContractError("Explicit owner namespace required")
    if (environment.format_id, environment.platform_tag, environment.abi) != (
        profile["format_id"],
        profile["platform_tag"],
        profile["abi"],
    ):
        raise ContractError("Snapshot profile/format/platform mismatch")
    identity = SnapshotIdentity(
        namespace,
        "sha256-v1:" + binary_sha256,
        digest({"function": function.to_data(), "interpretation": RULES}),
        function.function_id,
        profile["maturity"],
        digest(profile),
        digest(RULES),
        digest(EMPTY_SUMMARIES) if summary_digest is None else summary_digest,
        digest(POLICY),
        digest(function),
        environment,
    )
    return Snapshot(identity, function, identity.snapshot_id)


def extract_snapshot(
    function_ea,
    *,
    namespace,
    function_key,
    profile,
    summary_digest=None,
    include_calls=False,
    deadline=None,
    cancelled=lambda: False,
    registry: ProfileRegistry = REGISTRY,
):
    """Main-thread SDK scope returning immutable, roundtrippable pure Snapshot.

    Deadlines poll before/after generation and during serialization; native
    generation is not forcibly preempted. Unsupported inputs remain diagnostic.
    """
    import ida_pro

    if not ida_pro.is_main_thread():
        raise RuntimeError("Microcode extraction requires the IDA main thread")
    import ida_funcs
    import ida_hexrays as hx
    import ida_ida
    import ida_idaapi
    import ida_kernwin
    import ida_nalt

    def check():
        if cancelled() or (deadline is not None and time.monotonic() >= deadline):
            raise InterruptedError("Cooperative extraction cancellation")

    check()
    if not namespace.strip() or not function_key.strip():
        raise ContractError("Explicit owner namespace and stable function key required")
    if profile.get("maturity") != "MMAT_CALLS":
        raise ContractError("Unmeasured maturity; no mixed-maturity extraction")
    if type(registry) is not ProfileRegistry:
        raise ContractError("Expected exact extraction profile registry")
    registry.validate_extraction_profile(profile)
    # Structured loader metadata, not processor names or display-text heuristics.
    loader_constants = {
        "FMT-MACHO": "f_MACHO",
        "FMT-ELF": "f_ELF",
        "FMT-PE": "f_PE",
        "FMT-RAW": "f_BIN",
    }
    expected_filetype = getattr(ida_ida, loader_constants[profile["format_id"]], None)
    if expected_filetype is None or ida_ida.inf_get_filetype() != expected_filetype:
        raise ContractError(
            "Binary format mismatch: expected measured " + profile["format_id"]
        )
    bits = 64 if ida_ida.inf_is_64bit() else 32
    endian = "big" if ida_ida.inf_is_be() else "little"
    if (ida_ida.inf_get_procname(), bits, endian) != (
        profile["processor"],
        profile["bitness"],
        profile["data_endian"],
    ):
        raise ContractError("Profile/environment mismatch")
    function = ida_funcs.get_func(function_ea)
    if function is None or function.start_ea != function_ea:
        raise ContractError("Select a function entry")
    if not hx.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays initialization unavailable")
    failure = hx.hexrays_failure_t()
    mba = hx.gen_microcode(
        hx.mba_ranges_t(function),
        failure,
        None,  # pyright: ignore[reportArgumentType] - IDAPython accepts null retlist.
        0,
        hx.MMAT_CALLS,
    )
    if mba is None:
        raise RuntimeError(
            f"gen_microcode failed: code={failure.code}, ea={failure.errea}"
        )
    if mba.maturity != hx.MMAT_CALLS:
        raise ContractError("Unexpected native maturity")
    check()
    diagnostics = [
        Diagnostic(
            "native_origins_incomplete",
            "Observed nested microcode EA union only; optimized-away native origins cannot be reconstructed",
            "information",
        ),
        Diagnostic(
            "chains_not_serialized",
            "SDK use-def/UD-DU availability measured in P0, not MemorySSA or serialized chains",
            "information",
        ),
    ]
    opcodes = {
        getattr(hx, name): name
        for name in dir(hx)
        if name.startswith("m_") and isinstance(getattr(hx, name), int)
    }
    kinds = {
        getattr(hx, name): name
        for name in dir(hx)
        if name.startswith("mop_") and isinstance(getattr(hx, name), int)
    }
    observed_calls = []
    get_imagebase = getattr(ida_nalt, "get_imagebase", None)
    if not callable(get_imagebase):
        raise RuntimeError("IDA image-base API unavailable")
    image_base = int(cast(Callable[[], int], get_imagebase)())

    def locations(value):
        last = int(value.reg.last()) if not value.reg.empty() else -1
        if last > 65535:
            raise ContractError("SDK register set exceeds extraction budget")
        registers = tuple(i for i in range(last + 1) if value.reg.has(i))
        all_memory = bool(value.mem.all_values())
        ranges = (
            ()
            if all_memory
            else tuple(
                ByteRange(int(value.mem.getivl(i).off), int(value.mem.getivl(i).end()))
                for i in range(value.mem.nivls())
            )
        )
        return LocationSet(registers, ranges, all_memory)

    def opaque(kind, bits, role, detail):
        diagnostic = Diagnostic("unsupported_operand", detail)
        diagnostics.append(diagnostic)
        return Operand(
            "unknown", bits, role=role, native_kind=kind, diagnostic=diagnostic
        )

    def operand(op, role, depth=0):
        check()
        kind = kinds.get(op.t, f"mop_code_{int(op.t)}")
        bits = int(op.size) * 8 if op.size > 0 else None
        if depth >= 64:
            return opaque(kind, bits, role, "Nested operand depth budget exceeded")
        common = {"role": role, "native_kind": kind}
        if op.t == hx.mop_z:
            return Operand("void", None, **common)
        if op.t == hx.mop_b:
            return Operand("block", None, block_index=int(op.b), **common)
        if op.t == hx.mop_v:
            # Preserve a native global location; the opcode determines read vs target.
            return Operand("global", bits, address=int(op.g), **common)
        if op.t == hx.mop_f:
            ci = op.f
            size = int(ci.return_type.get_size())
            unresolved = [
                "external_memory_effects_not_modeled",
                "return_type_code_and_size_only",
                "return_argloc_not_serialized",
            ]
            if size <= 0 or size >= (1 << 63):
                unresolved.append("return_width_unknown_or_void")
                return_width = None
            else:
                return_width = size * 8
            call = CallInfo(
                None if ci.callee == ida_idaapi.BADADDR else int(ci.callee),
                int(ci.cc),
                tuple(operand(a, "argument", depth + 1) for a in ci.args),
                tuple(operand(a, "return", depth + 1) for a in ci.retregs),
                return_width,
                locations(ci.return_regs),
                locations(ci.spoiled),
                int(ci.return_type.get_realtype()),
                bool(ci.return_type.is_void()),
                tuple(sorted(unresolved)),
            )
            diagnostics.append(
                Diagnostic(
                    "call_effects_unresolved",
                    "Call info is structural only; memory effects and full return type/argloc not normalized",
                )
            )
            return Operand("callinfo", None, call=call, **common)
        if bits is None:
            return opaque(kind, None, role, "Non-void value operand has no SDK width")
        if op.t == hx.mop_n:
            return Operand(
                "constant",
                bits,
                constant=int(op.nnn.value) & ((1 << bits) - 1),
                **common,
            )
        if op.t in (hx.mop_r, hx.mop_S):
            space = "microregister" if op.t == hx.mop_r else "stack"
            offset = int(op.r) if op.t == hx.mop_r else int(op.s.off)
            return Operand(
                "storage",
                bits,
                storage=StorageLocation(space, space, offset * 8, bits),
                **common,
            )
        if op.t == hx.mop_d:
            nested = instruction(op.d, 0, -1, depth + 1)
            return Operand(
                "expression",
                bits,
                operation=nested.opcode,
                children=nested.operands,
                source_eas=nested.source_eas,
                synthetic=nested.synthetic,
                **common,
            )
        return opaque(kind, bits, role, f"No structural normalization rule for {kind}")

    def nested_calls(value):
        found = []
        if value.call is not None:
            found.append(value.call)
            children = value.call.arguments + value.call.return_operands
        else:
            children = value.children
        for child in children:
            found.extend(nested_calls(child))
        return found

    def instruction(ins, index, block_index, depth=0):
        check()
        opcode = opcodes.get(ins.opcode, f"unknown_microcode_{int(ins.opcode)}")
        if opcode.startswith("unknown_") or opcode in ("m_ext", "m_und"):
            diagnostics.append(Diagnostic("opaque_microcode", opcode))
        operands = tuple(
            operand(o, role, depth)
            for o, role in zip((ins.l, ins.r, ins.d), ("left", "right", "destination"))
        )
        eas = set() if ins.ea == ida_idaapi.BADADDR else {int(ins.ea)}
        for op in operands:
            eas.update(source_eas(op))
        result = Instruction(
            index, opcode, operands, tuple(sorted(eas)), ins.ea == ida_idaapi.BADADDR
        )
        if depth == 0:
            calls = [call for value in operands for call in nested_calls(value)]
            if len(calls) == 1 and ins.ea != ida_idaapi.BADADDR:
                observed_calls.append((block_index, index, int(ins.ea), calls[0]))
            elif calls:
                diagnostics.append(
                    Diagnostic(
                        "call_origin_ambiguous",
                        "Call metadata lacks one exact native instruction origin",
                    )
                )
        return result

    blocks = []
    for index in range(mba.qty):
        check()
        block = mba.get_mblock(index)
        rows = []
        ins = block.head
        while ins is not None:
            rows.append(instruction(ins, len(rows), index))
            ins = ins.next
        blocks.append(
            Block(
                index,
                tuple(sorted(block.pred(i) for i in range(block.npred()))),
                tuple(rows),
                tuple(sorted(block.succ(i) for i in range(block.nsucc()))),
            )
        )
    # Caller supplies a stable structural key, independent of display names/EAs.
    pure = FunctionInput(
        function_key,
        0,
        tuple(blocks),
        tuple(sorted(set(diagnostics), key=lambda d: (d.code, d.detail, d.severity))),
    )
    env = Environment(
        ida_kernwin.get_kernel_version(),
        hx.get_hexrays_version(),
        ida_ida.inf_get_procname(),
        profile["abi"],
        bits,
        endian,
        profile["instruction_endian"],
        "ram",
        VERSION,
        profile["format_id"],
        profile["platform_tag"],
    )
    binary = hashlib.sha256(
        Path(ida_nalt.get_input_file_path()).read_bytes()
    ).hexdigest()
    snapshot = make_snapshot(
        pure,
        env,
        profile,
        namespace,
        binary,
        summary_digest=summary_digest,
    )
    snapshot = cast(
        Snapshot, Snapshot.from_data(json.loads(json.dumps(snapshot.to_data())))
    )
    if not include_calls:
        return snapshot
    calls = tuple(
        CallObservation(block, instruction_index, instruction_ea, call)
        for block, instruction_index, instruction_ea, call in sorted(
            observed_calls, key=lambda item: (item[0], item[1], item[2])
        )
    )
    return ExtractedFunction(snapshot, image_base, int(function_ea), calls)
