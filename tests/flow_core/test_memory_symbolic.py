"""Flat-array memory proofs: forwarding, overlap, endian, hostile."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from ida_pro_mcp.flow_core.contracts import Block, Instruction, Operand
from ida_pro_mcp.flow_core.memory import build_memory_plan
from ida_pro_mcp.flow_core.memory_symbolic import (
    prove_store_to_load,
    validate_memory_result,
)
from ida_pro_mcp.flow_core.path_conditions import PathSelector, path_bindings
from ida_pro_mcp.flow_core.path_symbolic import SymbolicPathQuery  # noqa: F401
from ida_pro_mcp.flow_core.serialization import digest
from ida_pro_mcp.flow_core.ssa import build_ssa
from ida_pro_mcp.flow_core.states import StorageLocation
from ida_pro_mcp.flow_core.symbolic import Z3Backend
from ida_pro_mcp.flow_core.contracts import FunctionInput, Snapshot

ROOT = Path(__file__).resolve().parents[2]

needs_z3 = pytest.mark.skipif(
    not Z3Backend().available, reason="z3-solver extra not installed"
)


def reg(offset=0, bits=64, role="left"):
    return Operand(
        "storage", bits,
        storage=StorageLocation("microregister", "bank", offset, bits),
        role=role,
    )


def const(value, bits=8, role="left"):
    return Operand("constant", bits, constant=value, role=role)


def load(index, out=128, bits=8, address=None):
    return Instruction(
        index, "m_ldx",
        (const(0, 16), address or reg(role="right"), reg(out, bits, "destination")),
    )


def store(index, data=None, address=None):
    return Instruction(
        index, "m_stx",
        (data or const(0), const(0, 16, "right"), address or reg(role="destination")),
    )


def plan(instructions, endian="little", blocks=None):
    original = Snapshot.from_data(
        json.loads(
            (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
        )["snapshot"]
    )
    blocks = blocks or (Block(0, (), tuple(instructions)),)
    blocks = tuple(
        replace(
            b, successors=tuple(c.index for c in blocks if b.index in c.predecessors)
        )
        for b in blocks
    )
    function = FunctionInput("memory-symbolic-fixture", 0, blocks)
    identity = replace(
        original.identity,
        function_id=function.function_id,
        input_digest=digest(function),
        environment=replace(original.identity.environment, data_endian=endian),
    )
    program = build_ssa(Snapshot(identity, function, identity.snapshot_id))
    return build_memory_plan(program), program.graph


def access_ids(memory_plan, graph):
    nodes = {n.node_id: n for n in graph.nodes}
    stores = [s.node_id for s in memory_plan.steps if nodes[s.node_id].kind == "Store"]
    loads = [s.node_id for s in memory_plan.steps if nodes[s.node_id].kind == "Load"]
    return stores, loads


def prove(memory_plan, graph, path, load_id, store_id, **kwargs):
    return prove_store_to_load(
        memory_plan, graph, PathSelector(path_bindings(graph), path),
        load_id, store_id, **kwargs
    )


@needs_z3
def test_const_spill_must_forward():
    memory_plan, graph = plan((
        store(0, const(0xAB), const(0x1000, 64, "destination")),
        load(1, bits=8, address=const(0x1000, 64, "right")),
    ))
    stores, loads = access_ids(memory_plan, graph)
    query, proof = prove(memory_plan, graph, (0,), loads[0], stores[0],
                         backend=Z3Backend())
    assert proof.status == "must_forward_value_bounded_v1"
    assert proof.overlap == "must_overlap"
    assert proof.value_forward
    validate_memory_result(query, proof)


@needs_z3
def test_const_disjoint_no_overlap():
    memory_plan, graph = plan((
        store(0, const(0xAB), const(0x1000, 64, "destination")),
        load(1, bits=8, address=const(0x2000, 64, "right")),
    ))
    stores, loads = access_ids(memory_plan, graph)
    query, proof = prove(memory_plan, graph, (0,), loads[0], stores[0],
                         backend=Z3Backend())
    assert proof.status == "no_overlap_bounded_v1"
    assert proof.overlap == "no_overlap"
    validate_memory_result(query, proof)


@needs_z3
def test_symbolic_same_slot_must_forward():
    memory_plan, graph = plan((
        store(0, reg(8, 8), reg(0, 64, "destination")),
        load(1, bits=8, address=reg(0, 64, "right")),
    ))
    stores, loads = access_ids(memory_plan, graph)
    query, proof = prove(memory_plan, graph, (0,), loads[0], stores[0],
                         backend=Z3Backend())
    assert proof.status == "must_forward_value_bounded_v1"
    validate_memory_result(query, proof)


@needs_z3
def test_partial_overlap_is_may_with_replaying_witness():
    # Wide load over a narrow store at the same base: bytes must overlap,
    # but no single store value determines the load.
    memory_plan, graph = plan((
        store(0, const(0xAB), reg(0, 64, "destination")),
        load(1, bits=32, address=reg(0, 64, "right")),
    ))
    stores, loads = access_ids(memory_plan, graph)
    query, proof = prove(memory_plan, graph, (0,), loads[0], stores[0],
                         backend=Z3Backend())
    assert proof.status == "may_overlap_example_v1"
    assert proof.overlap == "must_overlap"
    assert proof.witness
    validate_memory_result(query, proof)
    # Symbolically offset load: overlap genuinely uncertain.
    add = Instruction(
        1, "m_add",
        (reg(0, 64), reg(16, 64, "right"), reg(32, 64, "destination")),
    )
    memory_plan, graph = plan((
        store(0, const(0xAB), reg(0, 64, "destination")),
        add,
        load(2, bits=8, address=reg(32, 64, "right")),
    ))
    stores, loads = access_ids(memory_plan, graph)
    query, proof = prove(memory_plan, graph, (0,), loads[0], stores[0],
                         backend=Z3Backend())
    assert proof.status == "may_overlap_example_v1"
    assert proof.overlap == "may_overlap"
    validate_memory_result(query, proof)


@needs_z3
def test_intervening_clobber_selects_latest_store():
    memory_plan, graph = plan((
        store(0, const(0xAA), reg(0, 64, "destination")),
        store(1, const(0xBB), reg(0, 64, "destination")),
        load(2, bits=8, address=reg(0, 64, "right")),
    ))
    stores, loads = access_ids(memory_plan, graph)
    assert len(stores) == 2
    _, stale = prove(memory_plan, graph, (0,), loads[0], stores[0],
                     backend=Z3Backend())
    assert stale.status == "may_overlap_example_v1"
    assert stale.overlap == "must_overlap"
    assert not stale.value_forward
    _, fresh = prove(memory_plan, graph, (0,), loads[0], stores[1],
                     backend=Z3Backend())
    assert fresh.status == "must_forward_value_bounded_v1"


@needs_z3
def test_endianness_byte_order_ground_truth():
    from ida_pro_mcp.flow_core.memory_symbolic import _Encoder

    backend = Z3Backend()
    z3 = backend.require_module()
    for endian, low_first in (("little", True), ("big", False)):
        variables: dict = {}
        encoder = _Encoder(backend, variables, 64, endian, "ram")
        array = encoder.fresh_array("t")
        data = z3.BitVecVal(0xABCD, 16)
        array = encoder.store_bytes(array, z3.BitVecVal(0x1000, 64), data, 2)
        first = encoder.load_bytes(array, z3.BitVecVal(0x1000, 64), 1)
        solver = backend.new_solver()
        expected = 0xCD if low_first else 0xAB
        solver.add(first != expected)
        assert solver.check() == z3.unsat


@needs_z3
def test_narrow_load_from_wide_store_forwards():
    memory_plan, graph = plan((
        store(0, const(0xABCD, 16), const(0x1000, 64, "destination")),
        load(1, bits=8, address=const(0x1000, 64, "right")),
    ))
    stores, loads = access_ids(memory_plan, graph)
    _, proof = prove(memory_plan, graph, (0,), loads[0], stores[0],
                     backend=Z3Backend())
    assert proof.status == "must_forward_value_bounded_v1"


@needs_z3
def test_conditional_store_path_sensitive():
    taken = Block(
        0, (),
        (Instruction(
            0, "m_jz", (reg(16), const(0, 64, role="right"),
                        Operand("block", None, block_index=1, role="destination")),
        ),),
    )
    store_block = Block(1, (0,), (store(0, const(0xAB), const(0x1000, 64, "destination")),))
    skip_block = Block(2, (0,), ())
    join = Block(
        3, (1, 2),
        (load(0, bits=8, address=const(0x1000, 64, "right")),),
    )
    memory_plan, graph = plan((), blocks=(taken, store_block, skip_block, join))
    stores, loads = access_ids(memory_plan, graph)
    _, hit = prove(memory_plan, graph, (0, 1, 3), loads[0], stores[0],
                   backend=Z3Backend())
    assert hit.status == "must_forward_value_bounded_v1"
    _, miss = prove(memory_plan, graph, (0, 2, 3), loads[0], stores[0],
                    backend=Z3Backend())
    # The store never executes on this path: structural no-overlap.
    assert miss.status == "no_overlap_bounded_v1"
    assert miss.solver_stamp.startswith("memory-order-structural-v1")


@needs_z3
def test_auto_object_partition_never_overrides_addresses():
    from test_memory import obj, ptrseed, run

    memory_plan, graph = plan((
        store(0, reg(8, 8), reg(0, 64, "destination")),
        load(1, bits=8, address=reg(0, 64, "right")),
    ))
    stores, loads = access_ids(memory_plan, graph)
    first, second = obj(memory_plan, key="A"), obj(memory_plan, key="B")
    facts = run(memory_plan, (first, second),
                (ptrseed(memory_plan, first, register=0),))
    assert facts.dependencies, "v1 fixture must yield candidate objects"
    query, proof = prove(memory_plan, graph, (0,), loads[0], stores[0],
                         backend=Z3Backend(), memory_facts=facts)
    # v1 sees may-alias candidates across objects; identical addresses decide.
    assert proof.status == "must_forward_value_bounded_v1"
    assert proof.object_hints
    validate_memory_result(query, proof)


def test_store_after_load_is_structural_no_overlap():
    memory_plan, graph = plan((
        load(0, bits=8, address=const(0x1000, 64, "right")),
        store(1, const(0xAB), const(0x1000, 64, "destination")),
    ))
    stores, loads = access_ids(memory_plan, graph)
    query, proof = prove(memory_plan, graph, (0,), loads[0], stores[0],
                         backend=Z3Backend())
    assert proof.status == "no_overlap_bounded_v1"
    assert proof.solver_stamp.startswith("memory-order-structural-v1")
    assert proof.solver_version == ""
    validate_memory_result(query, proof)


def test_hostile_backend_states_are_unknown():
    from ida_pro_mcp.flow_core.path_symbolic import SymbolicCoverage  # noqa

    memory_plan, graph = plan((
        store(0, const(0xAB), const(0x1000, 64, "destination")),
        load(1, bits=8, address=const(0x1000, 64, "right")),
    ))
    stores, loads = access_ids(memory_plan, graph)
    _, proof = prove(memory_plan, graph, (0,), loads[0], stores[0], backend=None)
    assert proof.status == "unknown"
    assert "solver_unavailable" in proof.unresolved
    _, proof = prove(memory_plan, graph, (0,), loads[0], stores[0],
                     backend=Z3Backend(), cancelled=lambda: True)
    assert proof.status == "unknown"
    assert "cancelled" in proof.unresolved


def test_unknown_address_and_dependent_branch_are_unknown():
    # Address loaded from memory: address expression is a Load -> unresolved.
    memory_plan, graph = plan((
        load(0, bits=64, address=reg(0, 64, "right"), out=32),
        store(1, const(1), reg(32, 64, "destination")),
        load(2, bits=8, address=reg(0, 64, "right")),
    ))
    stores, loads = access_ids(memory_plan, graph)
    nodes = {n.node_id: n for n in graph.nodes}
    narrow = next(i for i in loads if nodes[i].width_bits == 8)
    _, proof = prove(memory_plan, graph, (0,), narrow, stores[0],
                     backend=Z3Backend())
    assert proof.status == "unknown"
    assert any("address_unresolved" in item for item in proof.unresolved)


def test_memory_dependent_branch_is_unknown():
    branch = Block(
        0, (),
        (store(0, const(1), const(0x1000, 64, "destination")),
         load(1, bits=8, address=const(0x1000, 64, "right"), out=32),
         Instruction(
             2, "m_jz", (reg(32, 8), const(0, 8, role="right"),
                         Operand("block", None, block_index=1, role="destination")),
         )),
    )
    memory_plan, graph = plan((), blocks=(branch, Block(1, (0,), ()), Block(2, (0,), ())))
    stores, loads = access_ids(memory_plan, graph)
    _, proof = prove(memory_plan, graph, (0, 1), loads[0], stores[0],
                     backend=Z3Backend())
    assert proof.status == "unknown"


@needs_z3
def test_validate_rejects_stale_and_forged_memory():
    from dataclasses import replace

    from ida_pro_mcp.flow_core.proof import StaleProofEvidenceError
    from ida_pro_mcp.flow_core import ContractError

    memory_plan, graph = plan((
        store(0, reg(8, 8), reg(0, 64, "destination")),
        load(1, bits=8, address=reg(0, 64, "right")),
    ))
    stores, loads = access_ids(memory_plan, graph)
    query, proof = prove(memory_plan, graph, (0,), loads[0], stores[0],
                         backend=Z3Backend())
    assert proof.status == "must_forward_value_bounded_v1"
    validate_memory_result(query, proof)
    with pytest.raises(StaleProofEvidenceError):
        validate_memory_result(query, replace(proof, query_digest=digest("x")))
    with pytest.raises(StaleProofEvidenceError):
        validate_memory_result(query, replace(proof, assumptions=()))
    with pytest.raises(StaleProofEvidenceError):
        validate_memory_result(query, replace(proof, path_blocks=(0, 1)))
    with pytest.raises(ContractError):
        validate_memory_result(query, replace(proof, solver_stamp=""))
