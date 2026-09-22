"""Independent RV32 lowering oracles and shared-contract regressions."""

from dataclasses import replace
import hashlib
import json
from pathlib import Path
from typing import Callable, Literal, cast

import pytest

from ida_pro_mcp.flow_core import ContractError, canonical_json, digest
from ida_pro_mcp.flow_core.analysis import Seed, analyze
from ida_pro_mcp.flow_core.contracts import (
    Block,
    Environment,
    Evidence,
    FunctionInput,
    Graph,
    Instruction,
    Node,
    NodeKey,
    Operand,
    ResultAxes,
    Site,
    Snapshot,
    SnapshotIdentity,
    StructuredEnvironment,
    StructuredSnapshot,
    StructuredSnapshotIdentity,
)
from ida_pro_mcp.flow_core.ssa import build_ssa
from ida_pro_mcp.flow_core.memory import MemoryPolicy
from ida_pro_mcp.flow_core.memory_graph import (
    RV32_FLAT_USERSPACE_ASSUMPTION,
    build_memory_graph,
)
from ida_pro_mcp.flow_core.rv32_capture import (
    CaptureBundle,
    InstructionCapture,
    ProcessReceipt,
)
from ida_pro_mcp.flow_core.rv32_lowering import (
    RV32LoweringPolicy,
    lower_bundle,
    lower_function,
)
from ida_pro_mcp.flow_core.states import BitValue, Labels, StorageLocation


ROOT = Path(__file__).resolve().parents[2]
CAPTURE_ROOT = ROOT / "tests/flow_fixtures/manifests/rv32_capture"
ORACLE_PATH = ROOT / "tests/flow_fixtures/oracles/rv32_lowering.json"
CAPTURE_DIGEST = (
    "sha256-v1:32268d0833ca8f4b235d289f99c301ee9e7313ccde9e05d6ffe0244a91514d27"
)


def _baseline_snapshot() -> Snapshot:
    function = FunctionInput(
        "f:entry",
        0,
        (
            Block(
                0,
                (),
                (
                    Instruction(
                        0, "mov", (Operand("constant", 8, constant=7),), (4096,)
                    ),
                ),
            ),
        ),
    )
    value_digest = "sha256-v1:" + "a" * 64
    identity = SnapshotIdentity(
        "database-owner-A",
        value_digest,
        value_digest,
        function.function_id,
        "MMAT_CALLS",
        value_digest,
        value_digest,
        value_digest,
        value_digest,
        digest(function),
        Environment(
            "9.3",
            "9.3",
            "metapc",
            "win64",
            64,
            "little",
            "little",
            "ram",
            "1",
            "FMT-PE",
            "windows",
        ),
    )
    return Snapshot(identity, function, identity.snapshot_id)


def _baseline_graph() -> Graph:
    snapshot = _baseline_snapshot()
    evidence = Evidence(
        snapshot.snapshot_id, "constant-v1", (Site(0, 0, (0,)),), (4096,)
    )
    node = Node(
        NodeKey(snapshot.snapshot_id, "f:entry", Site(0, 0, (0,))),
        "Constant",
        8,
        (evidence.evidence_id,),
        constant=7,
    )
    return Graph(snapshot, (node,), (), (evidence,), ResultAxes())


def _load_process_receipt(name: str) -> dict:
    return json.loads((CAPTURE_ROOT / name / "process-receipt.json").read_text())


def _capture(name: str = "fresh-1") -> CaptureBundle:
    receipt = cast(
        ProcessReceipt,
        ProcessReceipt.from_json(
            (CAPTURE_ROOT / name / "process-receipt.json").read_text()
        ),
    )
    return receipt.capture


def _replace_native(
    capture: CaptureBundle,
    function_index: int,
    block_index: int,
    instruction_index: int,
    update: Callable[[InstructionCapture], InstructionCapture],
) -> CaptureBundle:
    function = capture.functions[function_index]
    block = function.blocks[block_index]
    instructions = list(block.instructions)
    instructions[instruction_index] = update(instructions[instruction_index])
    blocks = list(function.blocks)
    blocks[block_index] = replace(block, instructions=tuple(instructions))
    functions = list(capture.functions)
    functions[function_index] = replace(function, blocks=tuple(blocks))
    return replace(capture, functions=tuple(functions))


def _entry(program, name):
    return next(item for item in program.entry_storage if item.storage.name == name)


def _fact_by_kind(program, result, kind):
    node = next(item for item in program.graph.nodes if item.kind == kind)
    return node, {item.node_id: item for item in result.facts}[node.node_id]


def _walk_json(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json(child)


def test_normal_snapshot_and_graph_canonical_bytes_remain_unchanged():
    snapshot = _baseline_snapshot()
    graph = _baseline_graph()
    snapshot_json = canonical_json(snapshot)
    graph_json = canonical_json(graph)

    assert len(snapshot_json.encode()) == 1579
    assert hashlib.sha256(snapshot_json.encode()).hexdigest() == (
        "c1ad43a5b076b3db72bb342975ae4b3089c7b945afafb38dd633a9f8040a62f9"
    )
    assert snapshot.snapshot_id == (
        "snapshot-v1:9f89b442db71ff0a2b8f86a4ada75e8b88c56d404a5aab6203e5de62423cdae4"
    )
    assert len(graph_json.encode()) == 2567
    assert hashlib.sha256(graph_json.encode()).hexdigest() == (
        "2b2f747befd40c3608f56fe8d28755b31f3774d806f35b564a4c8d00c008f2a1"
    )
    assert graph.graph_digest == (
        "sha256-v1:2b2f747befd40c3608f56fe8d28755b31f3774d806f35b564a4c8d00c008f2a1"
    )
    assert graph.nodes[0].node_id == (
        "node-v1:5ec14bc836ee3152dde8ab4c8d77c54b82245fb94c7bd76122eb856c19a4bb6d"
    )
    assert graph.evidence[0].evidence_id == (
        "evidence-v1:e80b212f12ac68d6e7c05c9ee41c545514af4525ca98904e147da2a718d5f73c"
    )
    assert Snapshot.from_json(snapshot_json) == snapshot
    assert Graph.from_json(graph_json) == graph


def _structured_snapshot() -> StructuredSnapshot:
    function = _baseline_snapshot().function
    value_digest = "sha256-v1:" + "b" * 64
    environment = StructuredEnvironment(
        ida_build="9.3",
        processor="riscv",
        abi="riscv-ilp32",
        bitness=32,
        data_endian="little",
        instruction_endian="little",
        address_space="ram",
        backend_id="ida-disasm-rv32",
        backend_version=1,
        extraction_stage="structured-disassembly",
        lowering_version="rv32-lowering/1",
        processor_adapter_digest=value_digest,
        format_id="FMT-ELF",
        platform_tag="linux",
    )
    identity = StructuredSnapshotIdentity(
        namespace="database-owner-A",
        binary_digest=value_digest,
        semantic_digest=value_digest,
        function_id=function.function_id,
        backend_digest=value_digest,
        profile_digest=value_digest,
        capture_digest=value_digest,
        lowering_rule_digest=value_digest,
        summary_digest=value_digest,
        policy_digest=value_digest,
        input_digest=digest(function),
        environment=environment,
    )
    return StructuredSnapshot(identity, function, identity.snapshot_id)


def test_structured_snapshot_is_distinct_strict_and_graph_roundtrips():
    normal = _baseline_snapshot()
    structured = _structured_snapshot()
    graph = Graph(structured, (), (), (), ResultAxes())

    assert structured.snapshot_id != normal.snapshot_id
    assert "maturity" not in structured.identity.to_data()
    assert "hexrays_build" not in structured.identity.environment.to_data()
    assert StructuredSnapshot.from_json(canonical_json(structured)) == structured
    roundtrip = cast(Graph, Graph.from_json(canonical_json(graph)))
    assert roundtrip == graph
    assert isinstance(roundtrip.snapshot, StructuredSnapshot)

    for path, value in (
        (("identity", "maturity"), "MMAT_CALLS"),
        (("identity", "environment", "hexrays_build"), "9.3"),
        (("identity", "environment", "extraction_stage"), "microcode"),
    ):
        data = structured.to_data()
        target = data
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        with pytest.raises(ContractError):
            StructuredSnapshot.from_data(data)


def test_every_structured_identity_input_changes_the_snapshot_id():
    snapshot = _structured_snapshot()
    identity = snapshot.identity
    for field in (
        "binary_digest",
        "semantic_digest",
        "backend_digest",
        "profile_digest",
        "capture_digest",
        "lowering_rule_digest",
        "summary_digest",
        "policy_digest",
    ):
        assert (
            replace(identity, **{field: digest(field)}).snapshot_id
            != snapshot.snapshot_id
        )
    assert (
        replace(
            identity,
            environment=replace(
                identity.environment,
                processor_adapter_digest=digest("other-adapter"),
            ),
        ).snapshot_id
        != snapshot.snapshot_id
    )


def test_hand_authored_oracle_is_bound_to_the_actual_repeatable_capture():
    oracle = json.loads(ORACLE_PATH.read_text())
    first = _load_process_receipt("fresh-1")
    second = _load_process_receipt("fresh-2")

    assert oracle["capture_digest"] == CAPTURE_DIGEST
    assert first["capture_digest"] == second["capture_digest"] == CAPTURE_DIGEST
    assert first["capture"] == second["capture"]
    assert first["target_executed"] is second["target_executed"] is False
    assert first["capture"]["target_executed"] is False

    functions = first["capture"]["functions"]
    expected_functions = oracle["functions"]
    assert [item["selector_ordinal"] for item in expected_functions] == list(range(6))
    assert [item["function_rva"] for item in expected_functions] == [
        item["function_rva"] for item in functions
    ]
    assert [item["instruction_count"] for item in expected_functions] == [
        sum(len(block["instructions"]) for block in function["blocks"])
        for function in functions
    ]

    instructions = [
        instruction
        for function in functions
        for block in function["blocks"]
        for instruction in block["instructions"]
    ]
    observed_itypes = {instruction["itype"] for instruction in instructions}
    assert observed_itypes == {item["itype"] for item in oracle["dispatch"]}
    for rule in oracle["dispatch"]:
        matches = [
            instruction
            for instruction in instructions
            if instruction["itype"] == rule["itype"]
            and instruction["canonical_feature_bits"] == rule["canonical_feature_bits"]
            and [operand["operand_type"] for operand in instruction["operands"]]
            == rule["operand_types"]
            and [operand["dtype"] for operand in instruction["operands"]]
            == rule["operand_dtypes"]
        ]
        assert matches, rule["semantic"]
        assert all(item["size"] in rule["reviewed_sizes"] for item in matches)

    forbidden_keys = {"disasm", "display_text", "mnemonic", "operand_text"}
    assert all(forbidden_keys.isdisjoint(item) for item in _walk_json(first["capture"]))


def test_actual_two_process_capture_lowers_all_six_functions_deterministically():
    first = lower_bundle(_capture("fresh-1"))
    second = lower_bundle(_capture("fresh-2"))

    assert first == second
    assert len(first) == 6
    assert len({snapshot.snapshot_id for snapshot in first}) == 6
    for snapshot in first:
        raw = canonical_json(snapshot)
        assert StructuredSnapshot.from_json(raw) == snapshot
        program = build_ssa(snapshot)
        assert Graph.from_json(canonical_json(program.graph)) == program.graph
        assert snapshot.identity.environment.backend_id == "ida-disasm-rv32"
        assert (
            snapshot.identity.environment.extraction_stage == "structured-disassembly"
        )
        assert "maturity" not in snapshot.identity.to_data()
        assert "hexrays_build" not in snapshot.identity.environment.to_data()


def test_actual_capture_exercises_the_exact_reviewed_dispatch_table():
    capture = _capture()
    lowered = lower_bundle(capture)
    expected = {
        1: {"m_mov"},
        13: {"m_mov", "m_ldx"},
        18: {"m_mov", "m_stx"},
        19: {"m_add"},
        22: {"m_xor"},
        28: {"m_add"},
        33: {"m_xor"},
        122: {"m_mov"},
        134: {"m_jz"},
        140: {"m_goto"},
        142: {"m_ret"},
        163: {"m_call"},
    }
    observed = {itype: set() for itype in expected}
    for native_function, snapshot in zip(capture.functions, lowered):
        for native_block, block in zip(
            native_function.blocks, snapshot.function.blocks
        ):
            assert len(native_block.instructions) == len(block.instructions)
            for native, instruction in zip(
                native_block.instructions, block.instructions
            ):
                observed[native.itype].add(instruction.opcode)
                assert instruction.source_eas == (capture.image_base + native.rva,)

    assert observed == expected


@pytest.mark.parametrize("itype", [1, 13, 18, 19, 22, 28, 33, 122, 134, 140, 142, 163])
def test_every_reviewed_dispatch_entry_rejects_feature_tampering(itype):
    capture = _capture()
    location = next(
        (function_index, block_index, instruction_index)
        for function_index, function in enumerate(capture.functions)
        for block_index, block in enumerate(function.blocks)
        for instruction_index, instruction in enumerate(block.instructions)
        if instruction.itype == itype
    )
    tampered = _replace_native(
        capture,
        *location,
        lambda instruction: replace(instruction, canonical_feature_bits=0),
    )
    if itype in {134, 140, 142, 163}:
        with pytest.raises(ContractError, match="control/effect layout"):
            lower_function(tampered, location[0])
    else:
        snapshot = lower_function(tampered, location[0])
        instruction = snapshot.function.blocks[location[1]].instructions[location[2]]
        assert instruction.opcode == "rv32_opaque"
        assert any(
            diagnostic.code == "rv32_opaque_instruction"
            for diagnostic in snapshot.function.diagnostics
        )


@pytest.mark.parametrize("itype", [28, 134], ids=["data", "control"])
def test_noncanonical_instruction_is_rejected_for_data_and_control(itype):
    capture = _capture()
    location = next(
        (function_index, block_index, instruction_index)
        for function_index, function in enumerate(capture.functions)
        for block_index, block in enumerate(function.blocks)
        for instruction_index, instruction in enumerate(block.instructions)
        if instruction.itype == itype
    )
    tampered = _replace_native(
        capture,
        *location,
        lambda instruction: replace(
            instruction,
            is_canon=False,
            canonical_feature_bits=None,
        ),
    )
    with pytest.raises(ContractError, match="control/effect layout"):
        lower_function(tampered, location[0])


@pytest.mark.parametrize(
    "update",
    [
        lambda instruction: replace(
            instruction,
            canonical_feature_bits=0,
        ),
        lambda instruction: replace(
            instruction,
            operands=(
                replace(instruction.operands[0], dtype=1),
                *instruction.operands[1:],
            ),
        ),
        lambda instruction: replace(
            instruction,
            operands=(
                replace(instruction.operands[0], operand_type=2),
                *instruction.operands[1:],
            ),
        ),
        lambda instruction: replace(
            instruction,
            operands=(
                replace(instruction.operands[0], specflag1=1),
                *instruction.operands[1:],
            ),
        ),
        lambda instruction: replace(instruction, is_macro=True, flags=1),
    ],
    ids=["feature", "dtype", "operand-type", "specflag", "macro-layout"],
)
def test_unreviewed_data_layouts_fail_closed_as_opaque(update):
    # isa_scalar block 0 instruction 8 is the reviewed add at RVA 0x1270.
    capture = _replace_native(_capture(), 0, 0, 8, update)
    snapshot = lower_function(capture, 0)
    instruction = snapshot.function.blocks[0].instructions[8]
    assert instruction.opcode == "rv32_opaque"
    assert snapshot.function.diagnostics[0].code == "rv32_opaque_instruction"


def test_unreviewed_control_layout_and_cfg_target_mismatch_are_rejected():
    # isa_branch block 0 instruction 7 is beqz at RVA 0x1298.
    wrong_feature = _replace_native(
        _capture(),
        1,
        0,
        7,
        lambda instruction: replace(
            instruction,
            canonical_feature_bits=(instruction.canonical_feature_bits or 0) ^ 1,
        ),
    )
    with pytest.raises(ContractError, match="control/effect layout"):
        lower_function(wrong_feature, 1)

    capture = _capture()
    wrong_target = capture.image_base + capture.functions[1].blocks[4].start_rva

    def retarget(instruction):
        return replace(
            instruction,
            operands=(
                instruction.operands[0],
                replace(instruction.operands[1], addr=wrong_target),
            ),
        )

    mismatched = _replace_native(capture, 1, 0, 7, retarget)
    with pytest.raises(ContractError, match="branch/CFG mismatch"):
        lower_function(mismatched, 1)


@pytest.mark.parametrize(
    "encoded,expected",
    [
        (0, 0),
        (0x7FFFFFFF, 0x7FFFFFFF),
        (0x80000000, 0x80000000),
        (0xFFFFFFFF, 0xFFFFFFFF),
        (0xFFFFFFFF80000000, 0x80000000),
        (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF),
    ],
)
def test_addi_immediate_uses_exact_rv32_twos_complement(encoded, expected):
    # isa_branch block 2 instruction 1 is addi a0, a0, 3.
    capture = _replace_native(
        _capture(),
        1,
        2,
        1,
        lambda instruction: replace(
            instruction,
            operands=(
                *instruction.operands[:2],
                replace(instruction.operands[2], value=encoded),
            ),
        ),
    )
    lowered = lower_function(capture, 1).function.blocks[2].instructions[1]
    assert lowered.opcode == "m_add"
    assert lowered.operands[1].constant == expected


def test_noncanonical_immediate_fails_closed_and_lui_shifts_by_twelve():
    noncanonical = _replace_native(
        _capture(),
        1,
        2,
        1,
        lambda instruction: replace(
            instruction,
            operands=(
                *instruction.operands[:2],
                replace(instruction.operands[2], value=0x100000000),
            ),
        ),
    )
    assert (
        lower_function(noncanonical, 1).function.blocks[2].instructions[1].opcode
        == "rv32_opaque"
    )

    entry = lower_function(_capture(), 5)
    lui = entry.function.blocks[0].instructions[18]
    assert lui.source_eas == (0x11370,)
    assert lui.opcode == "m_mov"
    assert lui.operands[0].constant == 18 << 12


def test_x0_reads_zero_and_writes_create_no_definition():
    capture = _capture()

    def write_x0(instruction):
        destination = replace(instruction.operands[0], reg=0, phrase=0)
        return replace(instruction, operands=(destination, instruction.operands[1]))

    no_write = _replace_native(capture, 0, 0, 9, write_x0)
    assert (
        lower_function(no_write, 0).function.blocks[0].instructions[9].opcode == "m_nop"
    )

    def read_x0(instruction):
        left = replace(instruction.operands[1], reg=0, phrase=0)
        return replace(
            instruction,
            operands=(instruction.operands[0], left, instruction.operands[2]),
        )

    zero_read = _replace_native(capture, 0, 0, 8, read_x0)
    lowered = lower_function(zero_read, 0).function.blocks[0].instructions[8]
    assert lowered.opcode == "m_add"
    assert lowered.operands[0].kind == "constant"
    assert lowered.operands[0].constant == 0


def test_affine_frame_slots_require_equal_join_state():
    capture = _capture()
    branch = lower_function(capture, 1)
    assert branch.function.blocks[4].instructions[0].opcode == "m_mov"
    assert branch.function.blocks[4].instructions[0].operands[
        0
    ].storage == StorageLocation("frame", "rv32:entry-sp:-12", 0, 32)

    def drift_s0(instruction):
        destination = replace(instruction.operands[0], reg=8, phrase=8)
        source = replace(instruction.operands[1], reg=8, phrase=8)
        return replace(
            instruction,
            operands=(destination, source, instruction.operands[2]),
        )

    unequal = _replace_native(capture, 1, 2, 1, drift_s0)
    lowered = lower_function(unequal, 1)
    assert lowered.function.blocks[4].instructions[0].opcode == "m_ldx"


def test_lowering_budgets_reject_oversized_work():
    capture = _capture()
    with pytest.raises(ContractError, match="block budget"):
        lower_function(capture, 1, policy=RV32LoweringPolicy(max_blocks=4))
    with pytest.raises(ContractError, match="instruction budget"):
        lower_function(capture, 0, policy=RV32LoweringPolicy(max_instructions=14))


def test_actual_scalar_ssa_has_only_explicit_argument_provenance():
    program = build_ssa(lower_function(_capture(), 0))
    return_node = next(node for node in program.graph.nodes if node.kind == "Return")

    for register in ("rv32:a0", "rv32:a1"):
        result = analyze(
            program.graph,
            (Seed(_entry(program, register).node_id, Labels((register,))),),
        )
        returned = {fact.node_id: fact for fact in result.facts}[return_node.node_id]
        assert returned.labels.explicit == (register,)

    unrelated = analyze(
        program.graph,
        (Seed(_entry(program, "rv32:ra").node_id, Labels(("UNRELATED",))),),
    )
    returned = {fact.node_id: fact for fact in unrelated.facts}[return_node.node_id]
    assert returned.labels.explicit == ()


def test_actual_branch_phi_is_deterministic_and_selector_stays_predicate_only():
    snapshot = lower_function(_capture(), 1)
    first = build_ssa(snapshot)
    second = build_ssa(snapshot)
    assert first == second
    phis = [node for node in first.graph.nodes if node.kind == "Phi"]
    assert phis
    assert all(
        tuple(item.predecessor for item in node.phi_inputs) == (2, 3) for node in phis
    )

    value_result = analyze(
        first.graph,
        (Seed(_entry(first, "rv32:a0").node_id, Labels(("VALUE",))),),
    )
    _, returned = _fact_by_kind(first, value_result, "Return")
    assert returned.labels.explicit == ("VALUE",)

    selector_result = analyze(
        first.graph,
        (Seed(_entry(first, "rv32:a1").node_id, Labels(("SELECTOR",))),),
    )
    branch_node = next(
        node for node in first.graph.nodes if node.kind == "Branch" and node.inputs
    )
    facts = {fact.node_id: fact for fact in selector_result.facts}
    assert facts[branch_node.inputs[0]].labels.explicit == ("SELECTOR",)
    _, returned = _fact_by_kind(first, selector_result, "Return")
    assert returned.labels.explicit == ()


@pytest.mark.parametrize(
    "function_index,node_kind",
    [(2, "Load"), (3, "Store")],
    ids=["isa_load", "isa_store"],
)
def test_actual_load_store_have_exact_four_byte_argument_memory(
    function_index, node_kind
):
    analysis = build_memory_graph(lower_function(_capture(), function_index))
    assert analysis.result.policy_digest == digest(
        MemoryPolicy(flat_segment_assumption=RV32_FLAT_USERSPACE_ASSUMPTION)
    )
    graph = analysis.graph
    node = next(item for item in graph.nodes if item.kind == node_kind)
    assert node.width_bits == 32
    assert node.memory is not None
    assert (node.memory.interval.start, node.memory.interval.end) == (0, 4)
    obj = next(
        item for item in graph.objects if item.object_id == node.memory.object_id
    )
    assert obj.kind == "argument"
    assert obj.address_space == "flat-rv32"


def test_isa_store_has_void_return_and_does_not_invent_a0_payload():
    snapshot = lower_function(_capture(), 3)
    native_return = snapshot.function.blocks[0].instructions[-1]
    assert native_return.opcode == "m_ret"
    assert native_return.operands == ()
    program = build_ssa(snapshot)
    return_node = next(node for node in program.graph.nodes if node.kind == "Return")
    assert return_node.inputs == ()
    assert return_node.width_bits is None


def _lowered_calls(snapshot):
    return [
        (
            instruction,
            next(operand.call for operand in instruction.operands if operand.call),
        )
        for block in snapshot.function.blocks
        for instruction in block.instructions
        if instruction.opcode == "m_call"
    ]


def test_calls_encode_target_specific_abi_and_remain_explicitly_partial():
    capture = _capture()

    def names(operands):
        return tuple(item.storage.name for item in operands)

    expected = {
        capture.image_base + capture.functions[0].function_rva: (
            ("rv32:a0", "rv32:a1"),
            ("rv32:a0",),
            False,
        ),
        capture.image_base + capture.functions[1].function_rva: (
            ("rv32:a0", "rv32:a1"),
            ("rv32:a0",),
            False,
        ),
        capture.image_base + capture.functions[2].function_rva: (
            ("rv32:a0",),
            ("rv32:a0",),
            False,
        ),
        capture.image_base + capture.functions[3].function_rva: (
            ("rv32:a0", "rv32:a1"),
            (),
            True,
        ),
        capture.image_base + capture.functions[4].function_rva: (
            ("rv32:a0",),
            ("rv32:a0",),
            False,
        ),
    }

    calls = _lowered_calls(lower_function(capture, 4))
    calls += _lowered_calls(lower_function(capture, 5))
    assert len(calls) == 5
    for instruction, call in calls:
        assert call.callee_ea is not None
        arguments, returns, is_void = expected[call.callee_ea]
        assert names(call.arguments) == arguments
        assert names(call.return_operands) == returns
        assert call.return_is_void is is_void
        assert call.unresolved == (
            "call_effects_partial",
            "memory_effects_unknown",
            "numeric_calling_convention_unavailable",
        )
        assert any(
            operand.kind == "global" and operand.address == call.callee_ea
            for operand in instruction.operands
        )
        assert any(operand.kind == "callinfo" for operand in instruction.operands)
        assert (len(instruction.operands) == 2) is is_void


OperandRole = Literal[
    "unspecified", "left", "right", "destination", "argument", "return"
]


def _storage(address_space: str, name: str, role: OperandRole = "left") -> Operand:
    return Operand(
        "storage",
        32,
        storage=StorageLocation(address_space, name, 0, 32),
        role=role,
    )


def _constant(value: int, role: OperandRole = "left") -> Operand:
    return Operand("constant", 32, constant=value, role=role)


def _normal_snapshot(instructions: tuple[Instruction, ...]) -> Snapshot:
    base = cast(
        Snapshot,
        Snapshot.from_data(
            json.loads(
                (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
            )["snapshot"]
        ),
    )
    function = FunctionInput(
        "rv32-store-havoc-regression", 0, (Block(0, (), instructions),)
    )
    identity = replace(
        base.identity,
        function_id=function.function_id,
        input_digest=digest(function),
    )
    return Snapshot(identity, function, identity.snapshot_id)


def _returned_value(snapshot: Snapshot) -> BitValue:
    program = build_ssa(snapshot)
    result = analyze(program.graph)
    facts = {fact.node_id: fact for fact in result.facts}
    returned = next(node for node in program.graph.nodes if node.kind == "Return")
    value = facts[returned.node_id].value
    assert value is not None
    return value


@pytest.mark.parametrize("address_space", ["microregister", "register"])
def test_normal_store_does_not_havoc_scalar_register_storage(address_space):
    snapshot = _normal_snapshot(
        (
            Instruction(
                0,
                "m_mov",
                (
                    _constant(7),
                    _storage(address_space, "rv32:a2", "destination"),
                ),
            ),
            Instruction(
                1,
                "m_stx",
                (
                    _constant(9),
                    _constant(0, "right"),
                    _storage("register", "rv32:a0", "destination"),
                ),
            ),
            Instruction(2, "m_ret", (_storage(address_space, "rv32:a2"),)),
        )
    )
    assert _returned_value(snapshot).value == 7


def test_normal_store_keeps_conservative_havoc_for_frame_storage():
    snapshot = _normal_snapshot(
        (
            Instruction(
                0,
                "m_mov",
                (_constant(7), _storage("frame", "entry-sp:-4", "destination")),
            ),
            Instruction(
                1,
                "m_stx",
                (
                    _constant(9),
                    _constant(0, "right"),
                    _storage("register", "rv32:a0", "destination"),
                ),
            ),
            Instruction(2, "m_ret", (_storage("frame", "entry-sp:-4"),)),
        )
    )
    assert _returned_value(snapshot).value is None
