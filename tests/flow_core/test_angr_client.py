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
from ida_pro_mcp.flow_core.contracts import Block, Operand
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
    assert sidecar.probe() is None
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
    assert sidecar.probe() is None  # vendored runner ships with the package
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


def sparse_addressed(blocks, base=0x500000):
    """Attach EAs only to blocks that already have instructions."""
    from dataclasses import replace

    from test_ssa import snapshot

    out = []
    ea = base
    for block in blocks:
        patched = []
        for instruction in block.instructions:
            patched.append(replace(instruction, source_eas=(ea,)))
            ea += 1
        out.append(Block(block.index, block.predecessors, tuple(patched)))
    return snapshot(tuple(out))


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
    # Block 0 is empty: the entry address is block 1's first instruction.
    assert built.entry_ea == 0x500000
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
