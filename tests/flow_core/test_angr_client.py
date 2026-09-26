"""angr sidecar client: protocol, validation, and honest degradation.

Fake runners execute under the test interpreter; no angr install needed.
"""

import sys
from pathlib import Path

import pytest

from ida_pro_mcp.flow_core.angr_client import (
    AngrContext,
    AngrQuery,
    AngrSidecar,
    AngrSymbolicRegister,
    build_prefix_query,
    query,
    sidecar_from_environment,
)
from ida_pro_mcp.flow_core.contracts import (
    Block,
    Instruction,
    Operand,
    StorageLocation,
)
from ida_pro_mcp.flow_core.path_conditions import PathSelector, path_bindings
from ida_pro_mcp.flow_core.refine import RefinementSpec
from ida_pro_mcp.flow_core.serialization import ContractError
from ida_pro_mcp.flow_core.ssa import build_ssa
from test_ssa import const, ins, reg

DIGEST = "sha256-v1:" + "ab" * 32


def write_runner(path: Path, body: str) -> str:
    target = path / "fake_runner.py"
    target.write_text(body)
    return str(target)


OK_RUNNER = """
import json, sys
request = json.loads(open(sys.argv[1]).read())
assert request["schema_version"] == 1, request
assert request["find_eas"], request
json.dump({
    "status": "feasible",
    "witness": [{"name": "size", "width_bits": 64, "value_hex": "0x5"}],
    "engine": {"name": "angr-sidecar", "runner_version": "flow-angr-runner/1",
               "angr_version": "9.2.213", "z3_version": "4.13.0.0",
               "simprocedures": ["memset"], "loop_bound": 8,
               "exploration_steps": 12},
    "unresolved": [],
    "target_executed": False,
}, open(sys.argv[2], "w"))
"""

CRASH_RUNNER = "import sys; sys.exit(3)\n"
GARBAGE_RUNNER = "import sys; open(sys.argv[2], 'w').write('{not json}')\n"
SLOW_RUNNER = "import time; time.sleep(30)\n"


def make_query(**overrides):
    args = {
        "binary_path": "/tmp/probe.elf",
        "binary_sha256": DIGEST,
        "image_base": 0x400000,
        "entry_ea": 0x400000,
        "find_eas": (0x400010,),
        "avoid_eas": (0x400020,),
        "symbolic_registers": (AngrSymbolicRegister("rsi", 64),),
        "loop_bound": 8,
        "timeout_ms": 5000,
    }
    args.update(overrides)
    return AngrQuery(**args)


def test_refinement_spec_retired_solver_fields_rejected():
    old = {"symbolic_path": True, "symbolic_memory": False,
           "solver_timeout_ms": 5000, "schema_version": 1}
    with pytest.raises(ContractError):
        RefinementSpec.from_data(old)
    assert RefinementSpec(symbolic_angr=True).to_data()["symbolic_angr"] is True
    with pytest.raises(ContractError):
        RefinementSpec.from_data(
            {"symbolic_angr": 1, "solver_timeout_ms": 5000,
             "schema_version": 1}
        )


def test_happy_path_round_trip(tmp_path):
    runner = write_runner(tmp_path, OK_RUNNER)
    sidecar = AngrSidecar(interpreter=sys.executable, runner=runner)
    assert sidecar.probe() == "angr_configured_unverified"
    result = query(sidecar, make_query())
    assert result.status == "feasible"
    assert result.engine is not None
    assert result.engine.simprocedures == ("memset",)
    assert result.engine.angr_version == "9.2.213"
    (binding,) = result.witness
    assert (binding.name, binding.width_bits, binding.value_hex) == (
        "size", 64, "0x5")
    assert result.unresolved == ()
    assert result.target_executed is False


def test_missing_interpreter_and_runner_degrade(tmp_path):
    runner = write_runner(tmp_path, OK_RUNNER)
    missing = AngrSidecar(interpreter="/nonexistent/python", runner=runner)
    assert missing.probe() == "angr_unavailable"
    assert query(missing, make_query()).unresolved == ("angr_unavailable",)
    norunner = AngrSidecar(interpreter=sys.executable,
                            runner=str(tmp_path / "absent.py"))
    assert norunner.probe() == "angr_runner_missing"
    assert query(norunner, make_query()).unresolved == ("angr_runner_missing",)


def test_env_selects_interpreter(tmp_path, monkeypatch):
    runner = write_runner(tmp_path, OK_RUNNER)
    monkeypatch.setenv("IDA_MCP_ANGR_PYTHON", sys.executable)
    sidecar = sidecar_from_environment()
    assert sidecar.probe() == "angr_configured_unverified"  # vendored runner ships with the package
    sidecar = AngrSidecar(interpreter=sidecar.interpreter, runner=runner)
    assert query(sidecar, make_query()).status == "feasible"
    monkeypatch.delenv("IDA_MCP_ANGR_PYTHON")
    assert sidecar_from_environment().probe() == "angr_unavailable"


def test_runner_crash_and_garbage_degrade(tmp_path):
    crash = AngrSidecar(interpreter=sys.executable,
                        runner=write_runner(tmp_path, CRASH_RUNNER))
    assert query(crash, make_query()).unresolved == ("angr_runner_failed",)
    garbage = AngrSidecar(interpreter=sys.executable,
                           runner=write_runner(tmp_path, GARBAGE_RUNNER))
    assert query(garbage, make_query()).unresolved == ("angr_malformed_response",)


def test_timeout_and_cancel_degrade(tmp_path):
    slow = AngrSidecar(interpreter=sys.executable,
                       runner=write_runner(tmp_path, SLOW_RUNNER))
    quick = make_query(timeout_ms=100)
    assert query(slow, quick).unresolved == ("angr_timeout",)
    assert query(slow, make_query(timeout_ms=10000),
                 cancelled=lambda: True).unresolved == ("cancelled",)
    calls = {"n": 0}

    def flip():
        calls["n"] += 1
        return calls["n"] > 3

    assert query(slow, make_query(timeout_ms=10000),
                 cancelled=flip).unresolved == ("cancelled",)


def test_malformed_responses_rejected(tmp_path):
    bodies = {
        "range": '{"status": "feasible", "witness": [{"name": "x", "width_bits": 8, "value_hex": "0x100"}], "engine": {"name": "angr-sidecar", "runner_version": "r", "angr_version": "a", "z3_version": "z"}, "unresolved": [], "target_executed": false}',
        "executed": '{"status": "feasible", "witness": [], "engine": {"name": "angr-sidecar", "runner_version": "r", "angr_version": "a", "z3_version": "z"}, "unresolved": [], "target_executed": true}',
        "witnessed_unknown": '{"status": "unknown", "witness": [{"name": "x", "width_bits": 8, "value_hex": "0x1"}], "unresolved": ["x"], "target_executed": false}',
        "engineless": '{"status": "feasible", "witness": [], "unresolved": [], "target_executed": false}',
    }
    for name, payload in bodies.items():
        runner = write_runner(tmp_path, f"import sys; open(sys.argv[2], 'w').write({payload!r})\n")
        sidecar = AngrSidecar(interpreter=sys.executable, runner=runner)
        result = query(sidecar, make_query())
        assert result.unresolved == ("angr_malformed_response",), name
        assert result.status == "unknown"


def _context():
    return AngrContext(
        AngrSidecar(interpreter=sys.executable, runner="fake-runner.py"),
        "/fake/probe.elf",
        DIGEST,
        0x400000,
    )


BASE_EA = 0x500000
# Mirrors the captured prologue gap: the first microcode origin follows the
# native function entry, so execution must start at the native address.
NATIVE_ENTRY_EA = BASE_EA - 4


def arg_marker(index, ordinal, *, bit_offset=448, width_bits=32,
               native_kind="typed_argument_argloc"):
    """Exact extractor-shaped typed-argument metadata (addressless)."""
    return Instruction(
        index,
        "m_arg",
        (
            Operand("constant", 32, constant=ordinal, role="left"),
            Operand(
                "storage",
                width_bits,
                storage=StorageLocation(
                    "microregister", "microregister", bit_offset, width_bits
                ),
                role="argument",
                native_kind=native_kind,
                synthetic=True,
            ),
        ),
        (),
        True,
    )


def sparse_addressed(blocks, base=BASE_EA, *, entry_ea=None):
    """Attach EAs only to real instructions; markers stay addressless.

    The snapshot carries a canonical native function identity whose entry
    precedes the first microcode origin, mirroring the captured prologue gap.
    """
    from dataclasses import replace

    from test_ssa import snapshot

    if entry_ea is None:
        entry_ea = base - 4
    out = []
    ea = base
    for block in blocks:
        patched = []
        for instruction in block.instructions:
            if instruction.opcode == "m_arg":
                patched.append(instruction)
                continue
            patched.append(replace(instruction, source_eas=(ea,)))
            ea += 1
        out.append(Block(block.index, block.predecessors, tuple(patched)))
    return snapshot(tuple(out), function_id=f"function-entry:{entry_ea}")


def test_empty_blocks_follow_linear_successor_chain():
    graph = build_ssa(
        sparse_addressed(
            (
                Block(0, (), ()),
                Block(
                    1,
                    (0,),
                    (
                        ins(
                            0,
                            "m_jz",
                            reg(bits=8),
                            const(3, bits=8, role="right"),
                            Operand("block", None, block_index=2, role="destination"),
                        ),
                    ),
                ),
                Block(
                    2,
                    (1,),
                    (
                        ins(
                            0,
                            "m_mov",
                            reg(bits=8),
                            dest=reg(8, role="destination"),
                        ),
                    ),
                ),
                Block(
                    3,
                    (1,),
                    (
                        ins(
                            0,
                            "m_mov",
                            reg(bits=8),
                            dest=reg(8, role="destination"),
                        ),
                    ),
                ),
            ),
        )
    ).graph
    selector = PathSelector(path_bindings(graph), (0, 1, 2))
    built = build_prefix_query(graph, selector, _context(), timeout_ms=5000)
    # Execution starts at the native entry (prologue preserved); find/avoid
    # still use microcode origins.
    assert built.entry_ea == NATIVE_ENTRY_EA
    assert built.find_eas == (0x500001,)
    assert built.avoid_eas == (0x500002,)


def test_prefix_query_carries_image_base():
    graph = build_ssa(
        sparse_addressed(
            (
                Block(
                    0,
                    (),
                    (
                        ins(
                            0,
                            "m_jz",
                            reg(bits=8),
                            const(3, bits=8, role="right"),
                            Operand("block", None, block_index=1, role="destination"),
                        ),
                    ),
                ),
                Block(
                    1,
                    (0,),
                    (
                        ins(
                            0,
                            "m_mov",
                            reg(bits=8),
                            dest=reg(8, role="destination"),
                        ),
                    ),
                ),
                Block(
                    2,
                    (0,),
                    (
                        ins(
                            0,
                            "m_mov",
                            reg(bits=8),
                            dest=reg(8, role="destination"),
                        ),
                    ),
                ),
            ),
        )
    ).graph
    selector = PathSelector(path_bindings(graph), (0, 1))
    built = build_prefix_query(graph, selector, _context(), timeout_ms=5000)
    assert built.image_base == 0x400000
    with pytest.raises(ContractError, match="Invalid image_base"):
        make_query(image_base=-1)


def test_forked_empty_block_refuses():
    graph = build_ssa(
        sparse_addressed(
            (
                Block(0, (), ()),
                Block(
                    1,
                    (0,),
                    (
                        ins(
                            0,
                            "m_mov",
                            reg(bits=8),
                            dest=reg(8, role="destination"),
                        ),
                    ),
                ),
                Block(
                    2,
                    (0,),
                    (
                        ins(
                            0,
                            "m_mov",
                            reg(bits=8),
                            dest=reg(8, role="destination"),
                        ),
                    ),
                ),
            ),
        )
    ).graph
    # Block 0 is empty with two successors: no single entry address.
    assert graph.snapshot.function.blocks[0].successors == (1, 2)
    selector = PathSelector(path_bindings(graph), (0, 1))
    with pytest.raises(ContractError, match="angr_missing_block_addresses"):
        build_prefix_query(graph, selector, _context(), timeout_ms=5000)


def test_query_construction_rejects_programmer_errors():
    with pytest.raises(ContractError):
        make_query(find_eas=())
    with pytest.raises(ContractError):
        make_query(binary_sha256="nope")
    with pytest.raises(ContractError):
        make_query(timeout_ms=1)
    with pytest.raises(ContractError):
        query(AngrSidecar(interpreter=sys.executable, runner="x"), {"no": "model"})


def _prefix_graph(predecessors):
    return build_ssa(sparse_addressed(tuple(
        Block(index, incoming, (ins(0, "m_mov", reg(bits=8),
                                   dest=reg(8, role="destination")),))
        for index, incoming in enumerate(predecessors)
    ))).graph


@pytest.mark.parametrize(("predecessors", "path", "reason"), [
    (((), (0,), (1,)), (0, 2), "angr_prefix_nonedge"),
    (((), (0, 1), (1,)), (0, 1, 1, 2), "angr_prefix_repeated_block"),
    (((), (0,), (0, 1)), (0, 1, 2), "angr_prefix_order_unencodable"),
    (((), (0, 2), (1,), (2,)), (0, 1, 2, 3), "angr_prefix_order_unencodable"),
])
def test_prefix_rejects_paths_global_find_avoid_cannot_encode(predecessors, path, reason):
    graph = _prefix_graph(predecessors)
    with pytest.raises(ContractError, match=reason):
        build_prefix_query(graph, PathSelector(path_bindings(graph), path),
                           _context(), timeout_ms=5000)


def test_prefix_rejects_overlapping_native_addresses():
    from dataclasses import replace
    from test_ssa import snapshot

    original = _prefix_graph(((), (0,), (1,))).snapshot.function.blocks
    blocks = tuple(replace(block, instructions=tuple(
        replace(instruction, source_eas=(0x500000,))
        for instruction in block.instructions
    )) for block in original)
    graph = build_ssa(
        snapshot(blocks, function_id=f"function-entry:{NATIVE_ENTRY_EA}")
    ).graph
    with pytest.raises(ContractError, match="angr_block_address_overlap"):
        build_prefix_query(graph, PathSelector(path_bindings(graph), (0, 1, 2)),
                           _context(), timeout_ms=5000)


def test_configuration_probe_never_imports_or_launches_engine(monkeypatch):
    import ida_pro_mcp.flow_core.angr_client as client

    monkeypatch.setattr(client.subprocess, "Popen", lambda *a, **kw: pytest.fail(
        "configuration discovery must not start an engine"))
    assert AngrSidecar(sys.executable).probe() == "angr_configured_unverified"


def test_empty_tail_must_not_alias_an_already_visited_native_block():
    graph = build_ssa(sparse_addressed((
        Block(0, (), ()),
        Block(1, (0, 2), (ins(0, "m_mov", reg(bits=8),
                             dest=reg(8, role="destination")),)),
        Block(2, (1,), ()),
    ))).graph
    with pytest.raises(ContractError, match="angr_prefix_address_reentry"):
        build_prefix_query(graph, PathSelector(path_bindings(graph), (0, 1, 2)),
                           _context(), timeout_ms=5000)


def test_ambiguous_native_entry_addresses_are_rejected():
    from dataclasses import replace
    from test_ssa import snapshot

    blocks = _prefix_graph(((), (0,))).snapshot.function.blocks
    first = blocks[0]
    first = replace(first, instructions=(replace(first.instructions[0],
                                               source_eas=(0x500000, 0x500010)),))
    graph = build_ssa(
        snapshot((first, blocks[1]),
                 function_id=f"function-entry:{NATIVE_ENTRY_EA}")
    ).graph
    with pytest.raises(ContractError, match="angr_ambiguous_block_addresses"):
        build_prefix_query(graph, PathSelector(path_bindings(graph), (0, 1)),
                           _context(), timeout_ms=5000)


def test_linear_prefix_remains_encodable():
    graph = _prefix_graph(((), (0,), (1,)))
    built = build_prefix_query(graph, PathSelector(path_bindings(graph), (0, 1, 2)),
                               _context(), timeout_ms=5000)
    assert built.entry_ea == NATIVE_ENTRY_EA
    assert built.find_eas == (0x500002,)
    assert built.avoid_eas == ()


def test_configured_sidecar_missing_engine_dependencies_returns_unknown(tmp_path):
    runner = write_runner(tmp_path, "raise ModuleNotFoundError('angr')\n")
    sidecar = AngrSidecar(sys.executable, runner)
    assert sidecar.probe() == "angr_configured_unverified"
    result = query(sidecar, make_query())
    assert result.status == "unknown"
    assert result.unresolved == ("angr_runner_failed",)
    assert result.target_executed is False


@pytest.mark.parametrize("path", [(0, 1), (0, 1, 2)])
def test_nonempty_addressless_block_never_borrows_successor_entry(path):
    from dataclasses import replace
    from test_ssa import snapshot

    blocks = list(_prefix_graph(((), (0,), (1,))).snapshot.function.blocks)
    blocks[1] = replace(blocks[1], instructions=tuple(
        replace(instruction, source_eas=()) for instruction in blocks[1].instructions
    ))
    graph = build_ssa(
        snapshot(tuple(blocks), function_id=f"function-entry:{NATIVE_ENTRY_EA}")
    ).graph
    with pytest.raises(ContractError, match="angr_missing_block_addresses"):
        build_prefix_query(graph, PathSelector(path_bindings(graph), path),
                           _context(), timeout_ms=5000)


def _real_block(index, predecessors):
    return Block(
        index,
        predecessors,
        (ins(0, "m_mov", reg(bits=8), dest=reg(8, role="destination")),),
    )


def test_marker_only_entry_uses_native_entry_and_keeps_prologue():
    graph = build_ssa(
        sparse_addressed(
            (
                Block(0, (), (arg_marker(0, 0), arg_marker(1, 1, bit_offset=512))),
                _real_block(1, (0,)),
                _real_block(2, (1,)),
            ),
        )
    ).graph
    built = build_prefix_query(
        graph, PathSelector(path_bindings(graph), (0, 1, 2)),
        _context(), timeout_ms=5000,
    )
    assert built.entry_ea == NATIVE_ENTRY_EA
    assert built.find_eas == (BASE_EA + 1,)
    assert built.avoid_eas == ()


def test_marker_only_entry_allows_ordinal_gaps_and_pointer_kind():
    graph = build_ssa(
        sparse_addressed(
            (
                Block(0, (), (
                    arg_marker(0, 0),
                    arg_marker(1, 2, bit_offset=512,
                               native_kind="typed_pointer_argument_argloc"),
                )),
                _real_block(1, (0,)),
            ),
        )
    ).graph
    built = build_prefix_query(
        graph, PathSelector(path_bindings(graph), (0, 1)),
        _context(), timeout_ms=5000,
    )
    assert built.entry_ea == NATIVE_ENTRY_EA
    assert built.find_eas == (BASE_EA,)


def test_addressed_entry_with_trailing_markers_keeps_native_start():
    entry_real = ins(0, "m_mov", reg(bits=8), dest=reg(8, role="destination"))
    graph = build_ssa(
        sparse_addressed(
            (
                Block(0, (), (entry_real, arg_marker(1, 0))),
                _real_block(1, (0,)),
            ),
        )
    ).graph
    built = build_prefix_query(
        graph, PathSelector(path_bindings(graph), (0, 1)),
        _context(), timeout_ms=5000,
    )
    assert built.entry_ea == NATIVE_ENTRY_EA
    assert built.find_eas == (BASE_EA + 1,)


def test_entry_only_path_targets_native_entry():
    graph = build_ssa(
        sparse_addressed(
            (
                Block(0, (), (arg_marker(0, 0),)),
                _real_block(1, (0,)),
            ),
        )
    ).graph
    built = build_prefix_query(
        graph, PathSelector(path_bindings(graph), (0,)),
        _context(), timeout_ms=5000,
    )
    assert built.entry_ea == NATIVE_ENTRY_EA
    assert built.find_eas == (NATIVE_ENTRY_EA,)
    assert built.avoid_eas == ()


@pytest.mark.parametrize("function_id", [
    "scalar-test",
    "function-entry:",
    "function-entry:abc",
    "function-entry:-1",
    f"function-entry:{2 ** 64 - 1}",
    f"function-entry:{2 ** 64}",
    "function-entry:" + "1" * 21,
])
def test_invalid_native_function_identity_refused(function_id):
    from test_ssa import snapshot

    blocks = _prefix_graph(((), (0,))).snapshot.function.blocks
    graph = build_ssa(snapshot(blocks, function_id=function_id)).graph
    with pytest.raises(ContractError, match="angr_invalid_function_identity"):
        build_prefix_query(graph, PathSelector(path_bindings(graph), (0, 1)),
                           _context(), timeout_ms=5000)


def _malformed_marker_entries():
    from dataclasses import replace

    good = arg_marker(0, 0)
    ordinal, storage = good.operands
    real = ins(1, "m_mov", reg(bits=8), dest=reg(8, role="destination"))
    wide = replace(good, operands=(replace(ordinal, width_bits=64), storage))
    stacked = replace(storage, storage=StorageLocation("stack", "stack", 0, 32))
    wrong_kind = replace(storage, native_kind="typed_return_argloc")
    addressed_ordinal = replace(ordinal, source_eas=(BASE_EA + 100,))
    synthetic_ordinal = replace(ordinal, synthetic=True)
    return [
        ("wide_ordinal", (wide,)),
        ("non_register_storage",
         (replace(good, operands=(ordinal, stacked)),)),
        ("wrong_native_kind",
         (replace(good, operands=(ordinal, wrong_kind)),)),
        ("non_synthetic_instruction",
         (replace(good, synthetic=False),)),
        ("addressed_instruction",
         (replace(good, source_eas=(BASE_EA + 100,)),)),
        ("addressed_ordinal",
         (replace(good, operands=(addressed_ordinal, storage)),)),
        ("duplicate_ordinals",
         (arg_marker(0, 0), arg_marker(1, 0, bit_offset=512))),
        ("decreasing_ordinals",
         (arg_marker(0, 1), arg_marker(1, 0, bit_offset=512))),
        ("mixed_marker_first",
         (arg_marker(0, 0), real)),
        ("sub_byte_storage",
         (arg_marker(0, 0, bit_offset=4),)),
        ("synthetic_ordinal",
         (replace(good, operands=(synthetic_ordinal, storage)),)),
    ]


@pytest.mark.parametrize(
    ("entry_instructions", "reason"),
    [(entry, "angr_unexpected_argument_marker")
     for _, entry in _malformed_marker_entries()],
    ids=[name for name, _ in _malformed_marker_entries()],
)
def test_malformed_marker_only_entry_refused(entry_instructions, reason):
    graph = build_ssa(
        sparse_addressed(
            (
                Block(0, (), entry_instructions),
                _real_block(1, (0,)),
            ),
        )
    ).graph
    with pytest.raises(ContractError, match=reason):
        build_prefix_query(graph, PathSelector(path_bindings(graph), (0, 1)),
                           _context(), timeout_ms=5000)


def test_marker_only_entry_with_forked_successors_refused():
    graph = build_ssa(sparse_addressed((
        Block(0, (), (arg_marker(0, 0),)),
        _real_block(1, (0,)),
        _real_block(2, (0,)),
    ))).graph
    with pytest.raises(ContractError, match="angr_missing_block_addresses"):
        build_prefix_query(graph, PathSelector(path_bindings(graph), (0, 1)),
                           _context(), timeout_ms=5000)


def test_marker_only_entry_without_successor_refused():
    graph = build_ssa(sparse_addressed((
        Block(0, (), (arg_marker(0, 0),)),
    ))).graph
    with pytest.raises(ContractError, match="angr_missing_block_addresses"):
        build_prefix_query(graph, PathSelector(path_bindings(graph), (0,)),
                           _context(), timeout_ms=5000)


@pytest.mark.parametrize("shape", ["only", "trailing"])
def test_nonentry_argument_marker_refused(shape):
    real = ins(0, "m_mov", reg(bits=8), dest=reg(8, role="destination"))
    if shape == "only":
        block1 = Block(1, (0,), (arg_marker(0, 0),))
    else:
        block1 = Block(1, (0,), (real, arg_marker(1, 0)))
    graph = build_ssa(sparse_addressed((
        _real_block(0, ()),
        block1,
    ))).graph
    with pytest.raises(ContractError, match="angr_unexpected_argument_marker"):
        build_prefix_query(graph, PathSelector(path_bindings(graph), (0, 1)),
                           _context(), timeout_ms=5000)


def test_addressless_synthetic_nop_entry_still_refused():
    from dataclasses import replace

    from test_ssa import snapshot

    addressed = replace(
        ins(0, "m_mov", reg(bits=8), dest=reg(8, role="destination")),
        source_eas=(BASE_EA,),
    )
    graph = build_ssa(
        snapshot(
            (
                Block(0, (), (Instruction(0, "m_nop", (), (), True),)),
                Block(1, (0,), (addressed,)),
            ),
            function_id=f"function-entry:{NATIVE_ENTRY_EA}",
        )
    ).graph
    with pytest.raises(ContractError, match="angr_missing_block_addresses"):
        build_prefix_query(graph, PathSelector(path_bindings(graph), (0, 1)),
                           _context(), timeout_ms=5000)


def test_avoid_overlapping_native_entry_refused():
    from dataclasses import replace

    from test_ssa import snapshot

    addressed_blocks = sparse_addressed((
        Block(0, (), (arg_marker(0, 0),)),
        _real_block(1, (0,)),
        _real_block(2, (1,)),
        _real_block(3, (1,)),
    )).function.blocks
    patched = tuple(
        replace(block, instructions=(replace(
            block.instructions[0], source_eas=(NATIVE_ENTRY_EA,)),))
        if block.index == 3 else block
        for block in addressed_blocks
    )
    graph = build_ssa(
        snapshot(patched, function_id=f"function-entry:{NATIVE_ENTRY_EA}")
    ).graph
    with pytest.raises(ContractError, match="angr_find_avoid_overlap"):
        build_prefix_query(graph, PathSelector(path_bindings(graph), (0, 1, 2)),
                           _context(), timeout_ms=5000)
