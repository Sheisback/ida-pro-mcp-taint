"""Bounded callee inline: return/pointer synthesis, rename robustness, bounds."""

import json
from dataclasses import replace
from pathlib import Path

import pytest

from ida_pro_mcp.flow_core.call_symbolic import (
    CalleeBody,
    InlineRequest,
    build_inline_fragments,
    callee_body_digest,
    inline_callee_body,
)
from ida_pro_mcp.flow_core.contracts import (
    Block,
    FunctionInput,
    Instruction,
    Operand,
    Snapshot,
)
from ida_pro_mcp.flow_core.memory import build_memory_plan
from ida_pro_mcp.flow_core.memory_symbolic import (
    prove_store_to_load,
    validate_memory_result,
)
from ida_pro_mcp.flow_core.path_conditions import PathSelector, path_bindings
from ida_pro_mcp.flow_core.path_symbolic import (
    FEASIBLE_SYMBOLIC,
    INFEASIBLE_SMT_BOUNDED,
    prove_symbolic_path,
    validate_symbolic_result,
)
from ida_pro_mcp.flow_core.serialization import digest
from ida_pro_mcp.flow_core.ssa import build_ssa
from ida_pro_mcp.flow_core.states import StorageLocation
from ida_pro_mcp.flow_core.symbolic import Z3Backend

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


def const(value, bits=64, role="left"):
    return Operand("constant", bits, constant=value, role=role)


def ins(index, opcode, left, right=None, dest=None):
    return Instruction(
        index, opcode, tuple(o for o in (left, right, dest) if o is not None)
    )


def branch(index, opcode, left, value, target, bits=64):
    return ins(
        index, opcode, left, const(value, bits, "right"),
        Operand("block", None, block_index=target, role="destination"),
    )


def snapshot(blocks, name):
    base = Snapshot.from_data(
        json.loads(
            (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
        )["snapshot"]
    )
    blocks = tuple(
        replace(
            b, successors=tuple(c.index for c in blocks if b.index in c.predecessors)
        )
        for b in blocks
    )
    function = FunctionInput(name, 0, blocks)
    identity = replace(
        base.identity,
        function_id=function.function_id,
        input_digest=digest(function),
    )
    return Snapshot(identity, function, identity.snapshot_id)


def program(blocks, name):
    return build_ssa(snapshot(blocks, name))


def nodes_of(graph):
    return {node.node_id: node for node in graph.nodes}


def reachable_inputs(nodes, *roots):
    """InputValue nodes transitively feeding the roots, sorted for stability."""
    seen, inputs, stack = set(), [], list(roots)
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        node = nodes[current]
        if node.kind == "InputValue":
            inputs.append(current)
        stack.extend(node.inputs)
    return tuple(sorted(inputs))


def nodes_of_kind(graph, kind, operation=None):
    return [
        node for node in graph.nodes
        if node.kind == kind and (operation is None or node.operation == operation)
    ]


def const_node(graph, value, bits):
    matches = [
        node for node in graph.nodes
        if node.kind == "Constant" and node.constant == value
        and node.width_bits == bits
    ]
    assert len(matches) >= 1, f"no const {value}:{bits}"
    return sorted(matches, key=lambda node: node.node_id)[0].node_id


def compare_unknown(nodes, graph, block_index):
    """The UnknownValue feeding the Compare of the branch in a block."""
    evidence = {item.evidence_id: item for item in graph.evidence}
    for node in graph.nodes:
        if node.kind != "Compare":
            continue
        sites = [
            site
            for eid in node.evidence_ids
            for site in evidence[eid].sites
        ]
        if not any(site.block_index == block_index for site in sites):
            continue
        for root in node.inputs:
            stack, seen = [root], set()
            while stack:
                current = stack.pop()
                if current in seen:
                    continue
                seen.add(current)
                candidate = nodes[current]
                if (
                    candidate.kind == "UnknownValue"
                    and candidate.operation == "unmodeled_memory_or_call_effect"
                ):
                    return current
                stack.extend(candidate.inputs)
    raise AssertionError(f"no post-call unknown feeding Compare in {block_index}")


def return_on_path(graph, block_index):
    evidence = {item.evidence_id: item for item in graph.evidence}
    matches = []
    for node in graph.nodes:
        if node.kind != "Return":
            continue
        sites = [
            site
            for eid in node.evidence_ids
            for site in evidence[eid].sites
        ]
        if any(site.block_index == block_index for site in sites):
            matches.append(node)
    assert len(matches) == 1, f"expected one Return in {block_index}"
    return matches[0].inputs[0]


def callee_body(graph, plan, entry_params, return_id):
    return CalleeBody(
        graph=graph,
        plan=plan,
        entry_params=entry_params,
        return_id=return_id,
        callee_digest=callee_body_digest(graph, entry_params, return_id),
    )


def mul2_callee():
    """Single-block callee: return p0 * 2."""
    callee = program(
        (
            Block(0, (), (
                ins(0, "m_mul", reg(0), const(2), reg(128, 64, "destination")),
                ins(1, "m_ret", reg(128)),
            )),
        ),
        "callee-mul2",
    )
    graph = callee.graph
    nodes = nodes_of(graph)
    ret = nodes_of_kind(graph, "Return")[0]
    (param,) = reachable_inputs(nodes, ret.inputs[0])
    return callee_body(
        graph, build_memory_plan(callee), (param,), ret.inputs[0]
    )


def mul2_caller(expected):
    """Caller: call; branch (result == expected)."""
    caller = program(
        (
            Block(0, (), (
                ins(0, "m_mov", const(4), None, reg(256, 64, "destination")),
                ins(1, "m_call", const(0x5000)),
                branch(2, "m_jz", reg(0), expected, 1),
            )),
            Block(1, (0,), ()),
            Block(2, (0,), ()),
        ),
        "caller-mul2",
    )
    graph = caller.graph
    nodes = nodes_of(graph)
    (call,) = nodes_of_kind(graph, "Call")
    return caller, call.node_id, compare_unknown(nodes, graph, 0)


@needs_z3
def test_inline_return_value_feasible():
    body = mul2_callee()
    caller, call_id, result_id = mul2_caller(8)
    graph = caller.graph
    request = InlineRequest(
        call_id, result_id, body, (0,), (const_node(graph, 4, 64),),
    )
    query, proof = prove_symbolic_path(
        graph,
        PathSelector(path_bindings(graph), (0, 1)),
        backend=Z3Backend(),
        inlines=(request,),
    )
    assert proof.status == FEASIBLE_SYMBOLIC
    # Closed term (4 * 2 == 8): empty witness is legitimate, replay decides.
    validate_symbolic_result(query, proof)
    summaries = [a for a in proof.assumptions if a.kind == "summary"]
    assert len(summaries) == 1
    record = json.loads(summaries[0].value)
    assert record["callee_digest"] == body.callee_digest
    assert record["depth"] == 0
    assert record["arguments_orchestrator_resolved"] is True


@needs_z3
def test_inline_return_value_infeasible_variant():
    # 4 * 2 == 9 never holds: the value genuinely flows, not just sat.
    body = mul2_callee()
    caller, call_id, result_id = mul2_caller(9)
    graph = caller.graph
    request = InlineRequest(
        call_id, result_id, body, (0,), (const_node(graph, 4, 64),),
    )
    query, proof = prove_symbolic_path(
        graph,
        PathSelector(path_bindings(graph), (0, 1)),
        backend=Z3Backend(),
        inlines=(request,),
    )
    assert proof.status == INFEASIBLE_SMT_BOUNDED
    validate_symbolic_result(query, proof)


def test_call_without_inline_stays_unknown():
    body = mul2_callee()
    caller, _call_id, _result_id = mul2_caller(8)
    graph = caller.graph
    assert body.callee_digest
    _query, proof = prove_symbolic_path(
        graph, PathSelector(path_bindings(graph), (0, 1)),
    )
    assert proof.status == "unknown"
    assert "unsupported_path_effect" in proof.unresolved


def branchy_callee():
    """Callee: if p0 == 0 return 10 else return 20."""
    callee = program(
        (
            Block(0, (), (
                branch(0, "m_jz", reg(0), 0, 1),
            )),
            Block(1, (0,), (
                ins(0, "m_mov", const(10), None, reg(128, 64, "destination")),
                ins(1, "m_ret", reg(128)),
            )),
            Block(2, (0,), (
                ins(0, "m_mov", const(20), None, reg(128, 64, "destination")),
                ins(1, "m_ret", reg(128)),
            )),
        ),
        "callee-branchy",
    )
    graph = callee.graph
    nodes = nodes_of(graph)
    compare = nodes_of_kind(graph, "Compare")[0]
    (param,) = reachable_inputs(nodes, *compare.inputs)
    return callee_body(
        graph, build_memory_plan(callee), (param,), return_on_path(graph, 1)
    )


@needs_z3
def test_branchy_callee_path_sensitive_feasible():
    body = branchy_callee()
    caller, call_id, result_id = mul2_caller(10)
    graph = caller.graph
    request = InlineRequest(
        call_id, result_id, body, (0, 1), (const_node(graph, 4, 64),),
    )
    # Wrong argument for this callee path: 4 != 0 contradicts p0 == 0.
    query, proof = prove_symbolic_path(
        graph,
        PathSelector(path_bindings(graph), (0, 1)),
        backend=Z3Backend(),
        inlines=(request,),
    )
    assert proof.status == INFEASIBLE_SMT_BOUNDED
    validate_symbolic_result(query, proof)
    assert any("inline-d0-" in item.constraint_id for item in query.predicates)


@needs_z3
def test_branchy_callee_matching_argument_feasible():
    body = branchy_callee()
    caller = program(
        (
            Block(0, (), (
                ins(0, "m_mov", const(0), None, reg(256, 64, "destination")),
                ins(1, "m_call", const(0x5000)),
                branch(2, "m_jz", reg(0), 10, 1),
            )),
            Block(1, (0,), ()),
            Block(2, (0,), ()),
        ),
        "caller-branchy-zero",
    )
    graph = caller.graph
    nodes = nodes_of(graph)
    (call,) = nodes_of_kind(graph, "Call")
    request = InlineRequest(
        call.node_id,
        compare_unknown(nodes, graph, 0),
        body,
        (0, 1),
        (const_node(graph, 0, 64),),
    )
    query, proof = prove_symbolic_path(
        graph,
        PathSelector(path_bindings(graph), (0, 1)),
        backend=Z3Backend(),
        inlines=(request,),
    )
    assert proof.status == FEASIBLE_SYMBOLIC
    validate_symbolic_result(query, proof)


def test_nested_call_result_use_refuses_fragment():
    """Callee branching on a nested call result cannot inline (v1)."""
    callee = program(
        (
            Block(0, (), (
                ins(0, "m_call", const(0x6000)),
                branch(1, "m_jz", reg(0), 0, 1),
            )),
            Block(1, (0,), (
                ins(0, "m_mov", const(42), None, reg(128, 64, "destination")),
                ins(1, "m_ret", reg(128)),
            )),
            Block(2, (0,), (
                ins(0, "m_mov", const(43), None, reg(128, 64, "destination")),
                ins(1, "m_ret", reg(128)),
            )),
        ),
        "callee-nested-use",
    )
    graph = callee.graph
    body = callee_body(graph, build_memory_plan(callee), (), return_on_path(graph, 1))
    caller, call_id, result_id = mul2_caller(42)
    caller_nodes = nodes_of(caller.graph)
    request = InlineRequest(call_id, result_id, body, (0, 1), ())
    fragment = inline_callee_body(request, caller_nodes)
    assert fragment.unknown == "inline_callee_unresolved"
    _query, proof = prove_symbolic_path(
        caller.graph,
        PathSelector(path_bindings(caller.graph), (0, 1)),
        inlines=(request,),
    )
    assert proof.status == "unknown"
    assert "inline_callee_unresolved" in proof.unresolved


def store_callee():
    """Void callee: store 8-bit data reg through 64-bit pointer reg."""
    callee = program(
        (
            Block(0, (), (
                Instruction(
                    0, "m_stx",
                    (
                        Operand(
                            "storage", 8,
                            storage=StorageLocation(
                                "microregister", "bank", 0, 8
                            ),
                            role="left",
                        ),
                        const(0, 16, "right"),
                        reg(128, 64, "destination"),
                    ),
                ),
                Instruction(1, "m_exit", ()),
            )),
        ),
        "callee-store",
    )
    graph = callee.graph
    nodes = nodes_of(graph)
    (store,) = nodes_of_kind(graph, "Store")
    assert store.memory_operands is not None
    (data,) = reachable_inputs(nodes, store.memory_operands.data)
    (ptr,) = reachable_inputs(nodes, store.memory_operands.address)
    body = callee_body(graph, build_memory_plan(callee), (data, ptr), None)
    return body, store.node_id


def store_caller():
    """Caller: call; load 8 bits from constant address 0x1000."""
    caller = program(
        (
            Block(0, (), (
                ins(
                    0, "m_mov", const(0x5A, 8), None,
                    Operand(
                        "storage", 8,
                        storage=StorageLocation(
                            "microregister", "bank", 512, 8
                        ),
                        role="destination",
                    ),
                ),
                ins(1, "m_call", const(0x5000)),
                Instruction(
                    2, "m_ldx",
                    (
                        const(0, 16),
                        const(0x1000, 64, "right"),
                        reg(1024, 8, "destination"),
                    ),
                ),
            )),
        ),
        "caller-store-load",
    )
    graph = caller.graph
    (call,) = nodes_of_kind(graph, "Call")
    (load,) = nodes_of_kind(graph, "Load")
    return caller, call.node_id, load.node_id


@needs_z3
def test_inline_pointer_store_forwards_to_caller_load():
    body, callee_store = store_callee()
    caller, call_id, load_id = store_caller()
    graph = caller.graph
    caller_nodes = nodes_of(graph)
    request = InlineRequest(
        call_id, None, body, (0,),
        (const_node(graph, 0x5A, 8), const_node(graph, 0x1000, 64)),
    )
    fragments, refused, _translated = build_inline_fragments(
        (request,), caller_nodes
    )
    assert not refused
    (fragment,) = fragments
    assert fragment.context is not None
    store_id = fragment.renamed[callee_store]
    query, proof = prove_store_to_load(
        build_memory_plan(caller),
        graph,
        PathSelector(path_bindings(graph), (0,)),
        load_id,
        store_id,
        backend=Z3Backend(),
        inlines=(request,),
    )
    assert proof.status == "must_forward_value_bounded_v1"
    validate_memory_result(query, proof)
    assert len(query.inlines) == 1
    context = query.inlines[0]
    assert context.callee_digest == body.callee_digest
    assert context.callee_blocks == (0,)
    assert context.depth == 0
    assert context.fragment_digest
    summaries = [a for a in proof.assumptions if a.kind == "summary"]
    assert len(summaries) == 1
    assert json.loads(summaries[0].value)["fragment_digest"]


def test_pointer_store_without_inline_stays_unknown():
    _body, _callee_store = store_callee()
    caller, _call_id, load_id = store_caller()
    graph = caller.graph
    (store,) = [
        node for node in graph.nodes if node.kind == "Store"
    ] if any(node.kind == "Store" for node in graph.nodes) else (None,)
    assert store is None  # the store lives only in the callee body
    _query, proof = prove_store_to_load(
        build_memory_plan(caller),
        graph,
        PathSelector(path_bindings(graph), (0,)),
        load_id,
        load_id,
    )
    assert proof.status == "unknown"


@needs_z3
def test_nullary_callee_nested_havoc_then_const_store():
    """Nullary callee: nested call havoc, then constant store survives."""
    callee = program(
        (
            Block(0, (), (
                ins(0, "m_call", const(0x6000)),
                Instruction(
                    1, "m_stx",
                    (
                        const(0x7E, 8),
                        const(0, 16, "right"),
                        const(0x2000, 64, "destination"),
                    ),
                ),
                Instruction(2, "m_exit", ()),
            )),
        ),
        "callee-const-store",
    )
    graph = callee.graph
    (store,) = nodes_of_kind(graph, "Store")
    body = callee_body(graph, build_memory_plan(callee), (), None)
    caller = program(
        (
            Block(0, (), (
                ins(0, "m_call", const(0x5000)),
                Instruction(
                    1, "m_ldx",
                    (
                        const(0, 16),
                        const(0x2000, 64, "right"),
                        reg(1024, 8, "destination"),
                    ),
                ),
            )),
        ),
        "caller-const-load",
    )
    caller_graph = caller.graph
    (call,) = nodes_of_kind(caller_graph, "Call")
    (load,) = nodes_of_kind(caller_graph, "Load")
    request = InlineRequest(call.node_id, None, body, (0,), ())
    fragments, refused, _translated = build_inline_fragments(
        (request,), nodes_of(caller_graph)
    )
    assert not refused
    (fragment,) = fragments
    assert [step.effect for step in fragment.steps] == ["havoc", "store"]
    query, proof = prove_store_to_load(
        build_memory_plan(caller),
        caller_graph,
        PathSelector(path_bindings(caller_graph), (0,)),
        load.node_id,
        fragment.renamed[store.node_id],
        backend=Z3Backend(),
        inlines=(request,),
    )
    assert proof.status == "must_forward_value_bounded_v1"
    validate_memory_result(query, proof)


@needs_z3
def test_two_calls_same_body_no_crosstalk():
    """Same body twice with different args: results stay independent."""
    body = mul2_callee()
    caller = program(
        (
            Block(0, (), (
                ins(0, "m_mov", const(4), None, reg(256, 64, "destination")),
                ins(1, "m_call", const(0x5000)),
                # r1 = 4 * 2 = 8, consumed before the second call.
                branch(2, "m_jz", reg(0), 10, 1),
            )),
            Block(1, (0,), (
                ins(0, "m_mov", const(5), None, reg(320, 64, "destination")),
                ins(1, "m_call", const(0x5000)),
                branch(2, "m_jz", reg(0), 10, 3),
            )),
            Block(2, (0,), ()),
            Block(3, (1,), ()),
            Block(4, (1,), ()),
        ),
        "caller-two-calls",
    )
    graph = caller.graph
    nodes = nodes_of(graph)
    calls = nodes_of_kind(graph, "Call")
    assert len(calls) == 2
    evidence = {item.evidence_id: item for item in graph.evidence}

    def block_of(node):
        sites = [
            site
            for eid in node.evidence_ids
            for site in evidence[eid].sites
        ]
        return sites[0].block_index

    by_block = {block_of(call): call.node_id for call in calls}
    first = InlineRequest(
        by_block[0],
        compare_unknown(nodes, graph, 0),
        body,
        (0,),
        (const_node(graph, 4, 64),),
    )
    second = InlineRequest(
        by_block[1],
        compare_unknown(nodes, graph, 1),
        body,
        (0,),
        (const_node(graph, 5, 64),),
    )
    # r1 is 8, so r1 == 10 is infeasible: no cross-talk from the 5 * 2 call.
    query, proof = prove_symbolic_path(
        graph,
        PathSelector(path_bindings(graph), (0, 1, 3)),
        backend=Z3Backend(),
        inlines=(first, second),
    )
    assert proof.status == INFEASIBLE_SMT_BOUNDED
    validate_symbolic_result(query, proof)
    summaries = [a for a in proof.assumptions if a.kind == "summary"]
    assert len(summaries) == 2
    tags = sorted(a.key for a in summaries)
    assert tags[0] != tags[1]
    assert len({item.constraint_id for item in query.predicates}) == len(
        query.predicates
    )


def test_inline_recursion_refused():
    body = mul2_callee()
    caller, call_id, result_id = mul2_caller(8)
    request = InlineRequest(
        call_id, result_id, body, (0,), (const_node(caller.graph, 4, 64),),
        context=(body.callee_digest,),
    )
    fragment = inline_callee_body(request, nodes_of(caller.graph))
    assert fragment.unknown == "inline_recursion_refused"
    _query, proof = prove_symbolic_path(
        caller.graph,
        PathSelector(path_bindings(caller.graph), (0, 1)),
        inlines=(request,),
    )
    assert proof.status == "unknown"
    assert "inline_recursion_refused" in proof.unresolved


def test_inline_depth_exceeded():
    body = mul2_callee()
    caller, call_id, result_id = mul2_caller(8)
    request = InlineRequest(
        call_id, result_id, body, (0,), (const_node(caller.graph, 4, 64),),
        context=("depth-a", "depth-b"),
        max_depth=2,
    )
    fragment = inline_callee_body(request, nodes_of(caller.graph))
    assert fragment.unknown == "inline_depth_exceeded"


def test_inline_argument_width_mismatch():
    body = mul2_callee()
    caller = program(
        (
            Block(0, (), (
                ins(
                    0, "m_mov", const(4, 32), None,
                    reg(256, 32, "destination"),
                ),
                ins(1, "m_call", const(0x5000)),
                branch(2, "m_jz", reg(0), 8, 1),
            )),
            Block(1, (0,), ()),
            Block(2, (0,), ()),
        ),
        "caller-width-mismatch",
    )
    graph = caller.graph
    nodes = nodes_of(graph)
    (call,) = nodes_of_kind(graph, "Call")
    request = InlineRequest(
        call.node_id,
        compare_unknown(nodes, graph, 0),
        body,
        (0,),
        (const_node(graph, 4, 32),),
    )
    fragment = inline_callee_body(request, nodes)
    assert fragment.unknown == "inline_argument_width_mismatch"


def test_inline_duplicate_call_site():
    body = mul2_callee()
    caller, call_id, result_id = mul2_caller(8)
    graph = caller.graph
    argument = (const_node(graph, 4, 64),)
    first = InlineRequest(call_id, result_id, body, (0,), argument)
    second = InlineRequest(call_id, result_id, body, (0,), argument)
    _query, proof = prove_symbolic_path(
        graph,
        PathSelector(path_bindings(graph), (0, 1)),
        inlines=(first, second),
    )
    assert proof.status == "unknown"
    assert "inline_duplicate_call" in proof.unresolved


@needs_z3
def test_nested_call_havoc_tolerated_when_unused():
    """Nested call before the branch predicate input still inlines."""
    callee = program(
        (
            Block(0, (), (
                branch(0, "m_jz", reg(0), 0, 1),
            )),
            Block(1, (0,), (
                ins(0, "m_call", const(0x6000)),
                ins(1, "m_mov", const(42), None, reg(128, 64, "destination")),
                ins(2, "m_ret", reg(128)),
            )),
            Block(2, (0,), (
                ins(0, "m_mov", const(43), None, reg(128, 64, "destination")),
                ins(1, "m_ret", reg(128)),
            )),
        ),
        "callee-nested-havoc",
    )
    graph = callee.graph
    nodes = nodes_of(graph)
    compare = nodes_of_kind(graph, "Compare")[0]
    (param,) = reachable_inputs(nodes, *compare.inputs)
    body = callee_body(
        graph, build_memory_plan(callee), (param,), return_on_path(graph, 1)
    )
    caller = program(
        (
            Block(0, (), (
                ins(0, "m_mov", const(0), None, reg(256, 64, "destination")),
                ins(1, "m_call", const(0x5000)),
                branch(2, "m_jz", reg(0), 42, 1),
            )),
            Block(1, (0,), ()),
            Block(2, (0,), ()),
        ),
        "caller-nested-havoc",
    )
    caller_graph = caller.graph
    caller_nodes = nodes_of(caller_graph)
    (call,) = nodes_of_kind(caller_graph, "Call")
    request = InlineRequest(
        call.node_id,
        compare_unknown(caller_nodes, caller_graph, 0),
        body,
        (0, 1),
        (const_node(caller_graph, 0, 64),),
    )
    query, proof = prove_symbolic_path(
        caller_graph,
        PathSelector(path_bindings(caller_graph), (0, 1)),
        backend=Z3Backend(),
        inlines=(request,),
    )
    assert proof.status == FEASIBLE_SYMBOLIC
    validate_symbolic_result(query, proof)
