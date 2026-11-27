"""Exact data-only CFG witness export from one immutable SSA snapshot."""

from ida_pro_mcp.flow_core.serialization import ContractError, digest
from ida_pro_mcp.flow_core.ssa import SSAProgram


def build_cfg_witness(
    program: SSAProgram,
    *,
    image_base: int,
    exception_flow_complete: bool,
    alternate_entry_blocks: tuple[int, ...],
) -> dict:
    if type(program) is not SSAProgram:
        raise ContractError("cfg_witness_program_invalid")
    if type(image_base) is not int or image_base < 0:
        raise ContractError("cfg_witness_image_base_invalid")
    if type(exception_flow_complete) is not bool:
        raise ContractError("cfg_witness_exception_flow_invalid")
    if type(alternate_entry_blocks) is not tuple or any(
        type(value) is not int or value < 0
        for value in alternate_entry_blocks
    ):
        raise ContractError("cfg_witness_alternate_entries_invalid")
    function = program.graph.snapshot.function
    block_indexes = {block.index for block in function.blocks}
    if not set(alternate_entry_blocks) <= block_indexes:
        raise ContractError("cfg_witness_alternate_entry_missing")
    snapshot_id = program.graph.snapshot.snapshot_id

    def block_id(index: int) -> str:
        return f"flow-block:{snapshot_id}:{index}"

    owners: dict[int, int] = {}
    ambiguous_blocks: set[int] = set()
    block_instructions: dict[int, list[dict]] = {}
    native_eas: list[int] = []
    for block in function.blocks:
        values: dict[int, dict] = {}
        for instruction in block.instructions:
            for ea in instruction.source_eas:
                if ea < image_base:
                    ambiguous_blocks.add(block.index)
                    continue
                prior = owners.get(ea)
                if prior is not None and prior != block.index:
                    ambiguous_blocks.update((prior, block.index))
                owners.setdefault(ea, block.index)
                native_eas.append(ea)
                rva = ea - image_base
                values[rva] = {
                    "rva": _rva(rva),
                    "instruction_identity": f"instruction-rva:{rva:x}",
                    "supported": True,
                }
        block_instructions[block.index] = [values[key] for key in sorted(values)]
    diagnostics_complete = not any(
        diagnostic.severity == "unsupported"
        for diagnostic in function.diagnostics
    )
    # CFG completeness is owned by the immutable extracted FunctionInput.
    # Scalar/alias diagnostics can make the SSA graph partial without making
    # the recovered control-flow overapproximation partial.
    cfg_complete = diagnostics_complete and not ambiguous_blocks
    blocks = [
        {
            "block_index": block.index,
            "block_id": block_id(block.index),
            "instructions": block_instructions[block.index],
            "successors": [
                {"target_block_id": block_id(successor), "kind": "normal"}
                for successor in block.successors
            ],
            "has_unknown_successor": block.index in ambiguous_blocks,
        }
        for block in function.blocks
    ]
    entry_ea = _function_entry_ea(function.function_id, native_eas, image_base)
    if entry_ea is None or entry_ea < image_base:
        cfg_complete = False
        function_start_rva = None
    else:
        function_start_rva = _rva(entry_ea - image_base)
    generation = {
        "snapshot_id": snapshot_id,
        "graph_digest": program.graph.graph_digest,
        "binary_digest": program.graph.snapshot.identity.binary_digest,
        "semantic_digest": program.graph.snapshot.identity.semantic_digest,
        "profile_digest": program.graph.snapshot.identity.profile_digest,
        "rule_digest": program.graph.snapshot.identity.rule_digest,
        "summary_digest": program.graph.snapshot.identity.summary_digest,
        "policy_digest": program.graph.snapshot.identity.policy_digest,
        "input_digest": program.graph.snapshot.identity.input_digest,
    }
    return {
        "schema_version": "flow-cfg-witness/1",
        **generation,
        "analyzer_generation_digest": digest(generation),
        "image_base": image_base,
        "function_id": function.function_id,
        "function_start_rva": function_start_rva,
        "entry_block_id": block_id(function.entry_block),
        "block_count": len(blocks),
        "alternate_entry_block_ids": [
            block_id(value) for value in sorted(set(alternate_entry_blocks))
        ],
        "cfg_overapproximation_complete": cfg_complete,
        "exception_flow_complete": exception_flow_complete,
        "blocks": blocks,
        "target_executed": False,
        "no_auto_vulnerability_verdict": True,
    }


def _function_entry_ea(
    function_id: str, native_eas: list[int], image_base: int
) -> int | None:
    for prefix in ("function-entry:", "function-rva:"):
        if not function_id.startswith(prefix):
            continue
        raw = function_id.removeprefix(prefix)
        try:
            value = int(raw, 0)
        except ValueError:
            try:
                value = int(raw, 16)
            except ValueError:
                return None
        return value if prefix == "function-entry:" else image_base + value
    return min(native_eas) if native_eas else None


def _rva(value: int) -> str:
    return f"0x{value:x}"
