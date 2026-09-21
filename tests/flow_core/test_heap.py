"""Explicit hand-authored heap IR. No allocator recognition or target execution."""

from dataclasses import fields, replace
from itertools import product
import json
from pathlib import Path

import pytest

from ida_pro_mcp.flow_core import ContractError, canonical_json, digest
from ida_pro_mcp.flow_core.cfg import dominance
from ida_pro_mcp.flow_core.contracts import (
    Block,
    Edge,
    Evidence,
    FunctionInput,
    Graph,
    Instruction,
    MemoryObject,
    MemoryOperands,
    MemoryVersion,
    Node,
    NodeKey,
    PhiInput,
    ResultAxes,
    Snapshot,
)
from ida_pro_mcp.flow_core.heap import (
    HeapPlan,
    HeapPolicy,
    HeapResult,
    HeapSeed,
    OneShotProof,
    build_heap_plan,
)
from ida_pro_mcp.flow_core.heap_analysis import (
    allocate_lifetime,
    analyze_heap,
    escape_lifetime,
    free_lifetime,
)
from ida_pro_mcp.flow_core.memory import PointerSeed
from ida_pro_mcp.flow_core.ssa import Definition, EntryStorage, SSAProgram
from ida_pro_mcp.flow_core.states import (
    ByteRange,
    Lifetime,
    MemoryReference,
    PointerCandidate,
    PointerValue,
    StorageLocation,
)

ROOT = Path(__file__).resolve().parents[2]
SUCCESS = HeapPolicy(allocation_nullable=False)


def fixture(rows, preds=None, proofs=(), context=(), bits=64):
    """Rows: (name, kind, input names, optional operation, optional constant).

    Phi inputs use (predecessor, name); all other roots retain operand order.
    """
    if preds is None:
        rows, preds = [rows], [()]
    base = Snapshot.from_data(
        json.loads(
            (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
        )["snapshot"]
    )
    blocks = tuple(
        Block(
            b,
            tuple(preds[b]),
            tuple(Instruction(i, "synthetic_heap", ()) for i, _ in enumerate(block)),
            tuple(c for c, ps in enumerate(preds) if b in ps),
        )
        for b, block in enumerate(rows)
    )
    function = FunctionInput("synthetic-heap", 0, blocks)
    identity = replace(
        base.identity,
        namespace="synthetic-heap-test",
        binary_digest=digest("synthetic-heap-fixture"),
        semantic_digest=digest(function),
        environment=replace(
            base.identity.environment, bitness=bits, abi="synthetic-test"
        ),
        function_id=function.function_id,
        input_digest=digest(function),
    )
    snapshot = Snapshot(identity, function, identity.snapshot_id)
    keys = {
        row[0]: NodeKey(snapshot.snapshot_id, function.function_id, synthetic=row[0])
        for block in rows
        for row in block
    }
    evidence = Evidence(
        snapshot.snapshot_id, "hand-authored-heap-ir-v1", synthetic=True
    )
    placeholder = MemoryObject(
        snapshot.snapshot_id, "synthetic-byte-reference", "ram", 8
    )
    version = MemoryVersion(snapshot.snapshot_id, "entry")
    memory = MemoryReference(
        placeholder.object_id, version.version_id, "ram", ByteRange(0, 1), "little"
    )
    nodes, definitions, entries = [], [], []
    for b, block in enumerate(rows):
        for i, row in enumerate(block):
            name, kind, roots = row[:3]
            op = row[3] if len(row) > 3 else None
            const = row[4] if len(row) > 4 else None
            width = (
                bits
                if kind
                in {
                    "Allocation",
                    "InputValue",
                    "Copy",
                    "Phi",
                    "Select",
                    "Constant",
                    "UnknownValue",
                }
                else (8 if kind in {"Load", "Store"} else None)
            )
            if len(row) > 5:
                width = row[5]
            args = {"operation": op, "constant": const}
            if kind == "Phi":
                args.update(
                    phi_block=b,
                    phi_inputs=tuple(
                        PhiInput(pred, keys[value].node_id) for pred, value in roots
                    ),
                )
            else:
                args["inputs"] = tuple(keys[r].node_id for r in roots)
            if kind in {"Load", "Store"}:
                args["memory"] = replace(memory, interval=ByteRange(0, width // 8))
                args["memory_operands"] = MemoryOperands(
                    keys[roots[-1]].node_id,
                    data=keys[roots[0]].node_id if kind == "Store" else None,
                )
            node = Node(keys[name], kind, width, (evidence.evidence_id,), **args)
            nodes.append(node)
            order = -2 if kind == "InputValue" else i
            definitions.append(Definition(node.node_id, b, order))
            if kind == "InputValue":
                entries.append(
                    EntryStorage(
                        StorageLocation(
                            "microregister", name, len(entries) * bits, bits
                        ),
                        node.node_id,
                    )
                )
    edges = []
    for n in nodes:
        for source in dict.fromkeys(n.inputs):
            edges.append(
                Edge(
                    source,
                    n.node_id,
                    "value_dependency",
                    n.evidence_ids,
                    ResultAxes(precision="exact"),
                )
            )
        for phi in n.phi_inputs:
            edges.append(
                Edge(
                    phi.node_id,
                    n.node_id,
                    "phi_input",
                    n.evidence_ids,
                    ResultAxes(precision="exact"),
                    predecessor=phi.predecessor,
                )
            )
    graph = Graph(
        snapshot,
        tuple(sorted(nodes, key=lambda n: n.node_id)),
        tuple(sorted(edges, key=lambda e: e.edge_id)),
        (evidence,),
        ResultAxes(precision="exact", analysis="complete_in_scope"),
        objects=(placeholder,) if any(n.memory for n in nodes) else (),
        versions=(version,) if any(n.memory for n in nodes) else (),
    )
    program = SSAProgram(
        graph,
        dominance(function),
        tuple(sorted(definitions, key=lambda d: d.node_id)),
        tuple(
            sorted(
                entries,
                key=lambda e: (
                    e.storage.address_space,
                    e.storage.name,
                    e.storage.bit_offset,
                    e.storage.width_bits,
                ),
            )
        ),
        (),
    )
    proof_rows = tuple(
        sorted(
            (
                OneShotProof(
                    keys[name].node_id,
                    "explicit single-invocation acyclic fixture",
                    "distinct synthetic allocation identity",
                )
                for name in proofs
            ),
            key=lambda p: p.allocation_node,
        )
    )
    return build_heap_plan(program, context, proof_rows), keys


def observation(result, keys, name):
    return next(o for o in result.observations if o.node_id == keys[name].node_id)


def site(plan, keys, name):
    return next(s.object for s in plan.sites if s.node_id == keys[name].node_id)


def test_h01_allocation_write_free_read_records_lifetime_without_verdict():
    plan, keys = fixture(
        [
            ("alloc", "Allocation", ()),
            ("value", "Constant", (), None, 7, 8),
            ("write", "Store", ("value", "alloc")),
            ("free", "Free", ("alloc",)),
            ("read", "Load", ("alloc",)),
        ],
        proofs=("alloc",),
    )
    result = analyze_heap(plan, policy=SUCCESS)
    assert observation(result, keys, "alloc").transitions[0].after == Lifetime(
        ("live",), "local"
    )
    assert observation(result, keys, "write").transitions[0].before.possible == (
        "live",
    )
    free = observation(result, keys, "free")
    assert (
        free.transitions[0].after.possible == ("freed",)
        and free.transitions[0].strong_update
    )
    read = observation(result, keys, "read")
    assert read.transitions[0].before.possible == ("freed",)
    assert read.transitions[0].after == read.transitions[0].before
    assert result.status == "partial"
    text = canonical_json(result).lower()
    assert not any(word in text for word in ("vulnerable", "safe", "cwe", "severity"))
    assert not any(
        word in {f.name for f in fields(HeapResult)}
        for word in ("vulnerable", "safe", "cwe", "severity")
    )
    assert HeapResult.from_json(canonical_json(result)) == result
    assert HeapPlan.from_json(canonical_json(plan)) == plan


def test_h02_summary_allocation_and_free_preserve_possible_instances():
    plan, keys = fixture([("alloc", "Allocation", ()), ("free", "Free", ("alloc",))])
    obj = site(plan, keys, "alloc")
    assert obj.kind == "heap" and not obj.singleton
    result = analyze_heap(
        plan,
        state_seeds=(HeapSeed(obj.object_id, Lifetime(("freed",), "local")),),
        policy=SUCCESS,
    )
    allocation = observation(result, keys, "alloc")
    assert set(allocation.transitions[0].after.possible) == {"live", "freed"}
    assert not allocation.transitions[0].strong_update
    assert {"live", "freed"} <= set(
        observation(result, keys, "free").transitions[0].after.possible
    )
    assert not any(t.strong_update for o in result.observations for t in o.transitions)


def test_h02_loop_one_site_is_static_and_not_singleton():
    rows = [
        [],
        [("alloc", "Allocation", ()), ("free", "Free", ("alloc",))],
        [("use", "OpaqueEffect", ("alloc",), "heap_use")],
    ]
    plan, keys = fixture(rows, [(), (0, 1), (1,)])
    result = analyze_heap(plan, policy=SUCCESS)
    assert len(plan.sites) == 1
    assert not plan.sites[0].object.singleton
    assert "freed" in observation(result, keys, "alloc").transitions[0].after.possible
    assert not result.frontier and result.iterations < 100
    assert analyze_heap(plan, policy=SUCCESS) == result
    with pytest.raises(ContractError, match="Cyclic"):
        fixture(rows, [(), (0, 1), (1,)], proofs=("alloc",))


def test_h03_escape_is_independent_then_opaque_effect_widens():
    plan, keys = fixture(
        [
            ("alloc", "Allocation", ()),
            ("escape", "OpaqueEffect", ("alloc",), "heap_escape"),
            ("opaque", "OpaqueEffect", (), "external_unknown"),
        ],
        proofs=("alloc",),
    )
    result = analyze_heap(plan, policy=SUCCESS)
    escaped = observation(result, keys, "escape").transitions[0]
    assert escaped.before.possible == escaped.after.possible == ("live",)
    assert escaped.after.escape == "escaped"
    opaque = observation(result, keys, "opaque").transitions[0]
    assert {"live", "freed"} <= set(opaque.after.possible)
    assert opaque.after.escape == "unknown" and result.status == "partial"


def test_h04_live_escaped_branch_may_free_join():
    rows = [
        [
            ("alloc", "Allocation", ()),
            ("escape", "OpaqueEffect", ("alloc",), "heap_escape"),
        ],
        [("free", "Free", ("alloc",))],
        [],
        [("use", "OpaqueEffect", ("alloc",), "heap_use")],
    ]
    plan, keys = fixture(rows, [(), (0,), (0,), (1, 2)], proofs=("alloc",))
    result = analyze_heap(plan, policy=SUCCESS)
    joined = observation(result, keys, "use").transitions[0].before
    assert joined == Lifetime(("freed", "live"), "escaped")
    assert next(p for p in plan.phis if p.block == 3).predecessors == (1, 2)
    assert result.states[0].lifetime == joined


def test_address_disjointness_does_not_prove_unreachability():
    plan, keys = fixture(
        [
            ("a", "Allocation", ()),
            ("b", "Allocation", ()),
            ("opaque", "OpaqueEffect", ("b",), "heap_opaque_reachable"),
        ],
        proofs=("a", "b"),
    )
    result = analyze_heap(plan, policy=SUCCESS)
    a, b = site(plan, keys, "a"), site(plan, keys, "b")
    event = observation(result, keys, "opaque")
    assert {t.object_id for t in event.transitions} == {a.object_id, b.object_id}
    assert (
        next(s for s in result.states if s.object_id == a.object_id).lifetime.escape
        == "unknown"
    )
    # Without disjoint/local proof a differently named object is not excluded.
    no_proofs = build_heap_plan(plan.program)
    broad = analyze_heap(no_proofs, policy=SUCCESS)
    assert len(observation(broad, keys, "opaque").transitions) == 2


def test_already_escaped_object_remains_reachable_by_opaque_effect():
    plan, keys = fixture(
        [
            ("a", "Allocation", ()),
            ("b", "Allocation", ()),
            ("escape", "OpaqueEffect", ("a",), "heap_escape"),
            ("opaque", "OpaqueEffect", ("b",), "heap_opaque_reachable"),
        ],
        proofs=("a", "b"),
    )
    result = analyze_heap(plan, policy=SUCCESS)
    assert len(observation(result, keys, "opaque").transitions) == 2


def test_null_free_is_recorded_and_conservative():
    plan, keys = fixture(
        [
            ("alloc", "Allocation", ()),
            ("null", "Constant", (), None, 0),
            ("free", "Free", ("null",)),
        ],
        proofs=("alloc",),
    )
    result = analyze_heap(plan, policy=SUCCESS)
    free = observation(result, keys, "free")
    assert free.pointer.may_be_null and not free.pointer.candidates
    assert (
        free.unresolved and free.transitions and not free.transitions[0].strong_update
    )
    assert (
        "live" in free.transitions[0].after.possible
        and "freed" in free.transitions[0].after.possible
    )
    assert result.status == "partial"


def test_nullable_allocation_and_free_keep_possibilities():
    plan, keys = fixture(
        [("alloc", "Allocation", ()), ("free", "Free", ("alloc",))], proofs=("alloc",)
    )
    result = analyze_heap(plan)
    assert set(observation(result, keys, "alloc").transitions[0].after.possible) == {
        "not_allocated",
        "live",
    }
    free = observation(result, keys, "free")
    assert free.unresolved and not free.transitions[0].strong_update
    assert set(free.transitions[0].after.possible) == {"not_allocated", "live", "freed"}


def test_double_free_relation_is_not_a_vulnerability_verdict():
    plan, keys = fixture(
        [
            ("alloc", "Allocation", ()),
            ("first", "Free", ("alloc",)),
            ("second", "Free", ("alloc",)),
        ],
        proofs=("alloc",),
    )
    result = analyze_heap(plan, policy=SUCCESS)
    second = observation(result, keys, "second")
    assert second.transitions[0].before.possible == ("freed",)
    assert "freed" in second.transitions[0].after.possible and second.unresolved
    assert "nonlive_free_boundary" in result.diagnostics


def test_free_before_allocation_does_not_become_definitely_live():
    plan, keys = fixture(
        [
            ("input", "InputValue", ()),
            ("free", "Free", ("input",)),
            ("alloc", "Allocation", ()),
        ]
    )
    obj = site(plan, keys, "alloc")
    seed = PointerSeed(
        keys["input"].node_id,
        PointerValue("ram", 64, (PointerCandidate(obj.object_id, 0),)),
    )
    result = analyze_heap(plan, (seed,), policy=SUCCESS)
    assert observation(result, keys, "free").transitions[0].before.possible == (
        "not_allocated",
    )
    assert "freed" in observation(result, keys, "alloc").transitions[0].after.possible
    assert result.status == "partial"


def test_select_ab_free_updates_both_weakly():
    plan, keys = fixture(
        [
            ("condition", "InputValue", ()),
            ("a", "Allocation", ()),
            ("b", "Allocation", ()),
            ("select", "Select", ("condition", "a", "b")),
            ("free", "Free", ("select",)),
        ],
        proofs=("a", "b"),
    )
    result = analyze_heap(plan, policy=SUCCESS)
    free = observation(result, keys, "free")
    assert len(free.pointer.candidates) == 2
    assert all(
        t.after.possible == ("freed", "live") and not t.strong_update
        for t in free.transitions
    )


def test_context_identity_is_bounded_static_and_ordered():
    rows = [("alloc", "Allocation", ())]
    first, _ = fixture(rows, context=("caller-a", "callee"))
    repeat, _ = fixture(rows, context=("caller-a", "callee"))
    other, _ = fixture(rows, context=("caller-b", "callee"))
    assert (
        first.sites == repeat.sites
        and first.sites[0].object.object_id != other.sites[0].object.object_id
    )
    assert first.plan_digest != other.plan_digest
    with pytest.raises(ContractError, match="context"):
        fixture(rows, context=("recursive",) * 9)


def test_heap_budgets_leave_unknown_frontier_not_empty_results():
    plan, keys = fixture(
        [("alloc", "Allocation", ()), ("free", "Free", ("alloc",))], proofs=("alloc",)
    )
    for policy in (
        replace(SUCCESS, max_iterations=1),
        replace(SUCCESS, max_event_visits=1),
        replace(SUCCESS, max_state_updates=1),
    ):
        result = analyze_heap(plan, policy=policy)
        assert result.status == "partial" and result.frontier
        assert set(result.states[0].lifetime.possible) == {
            "not_allocated",
            "live",
            "freed",
        }
        assert result.states[0].lifetime.escape == "unknown"
        assert all(
            f.pointer.any_compatible_location and f.pointer.may_be_null
            for f in result.pointers
        )
        assert all(
            not t.strong_update for o in result.observations for t in o.transitions
        )
    with pytest.raises(ContractError, match="budget"):
        build_heap_plan(plan.program, max_events=1)


def test_candidate_budget_preserves_all_possible_free_targets():
    plan, keys = fixture(
        [
            ("condition", "InputValue", ()),
            ("a", "Allocation", ()),
            ("b", "Allocation", ()),
            ("select", "Select", ("condition", "a", "b")),
            ("free", "Free", ("select",)),
        ],
        proofs=("a", "b"),
    )
    result = analyze_heap(plan, policy=replace(SUCCESS, max_candidates=1))
    assert observation(result, keys, "free").pointer.any_compatible_location
    assert len(observation(result, keys, "free").transitions) == 2
    assert result.status == "partial"


def test_seed_and_policy_cache_identities_are_independent():
    plan, keys = fixture(
        [
            ("input", "InputValue", ()),
            ("alloc", "Allocation", ()),
            ("use", "OpaqueEffect", ("input",), "heap_use"),
        ]
    )
    obj = site(plan, keys, "alloc")
    seed = PointerSeed(
        keys["input"].node_id,
        PointerValue("ram", 64, (PointerCandidate(obj.object_id, 0),)),
    )
    a = analyze_heap(plan, policy=SUCCESS)
    b = analyze_heap(plan, (seed,), policy=SUCCESS)
    c = analyze_heap(
        plan,
        (seed,),
        (HeapSeed(obj.object_id, Lifetime(("freed",), "escaped")),),
        policy=SUCCESS,
    )
    d = analyze_heap(plan, (seed,), policy=HeapPolicy())
    assert len({r.cache_key for r in (a, b, c, d)}) == 4
    assert len({r.plan_digest for r in (a, b, c, d)}) == 1


def test_singleton_proof_and_event_contracts_fail_closed():
    plan, keys = fixture([("alloc", "Allocation", ()), ("free", "Free", ("alloc",))])
    site_record = plan.sites[0]
    forged = replace(
        site_record,
        object=replace(
            site_record.object, singleton=True, singleton_evidence="not plan proof"
        ),
    )
    with pytest.raises(ContractError, match="proof"):
        replace(plan, sites=(forged,))
    with pytest.raises(ContractError, match="coverage"):
        replace(plan, events=())
    with pytest.raises(ContractError, match="scope|payload"):
        replace(
            plan,
            events=tuple(
                replace(e, scope="all") if e.kind == "free" else e for e in plan.events
            ),
        )
    exact, _ = fixture([("alloc", "Allocation", ())], proofs=("alloc",))
    with pytest.raises(ContractError, match="not_allocated"):
        analyze_heap(
            exact,
            state_seeds=(
                HeapSeed(exact.sites[0].object.object_id, Lifetime(("live",), "local")),
            ),
        )
    with pytest.raises(ContractError, match="exactly one"):
        fixture([("escape", "OpaqueEffect", (), "heap_escape")])
    with pytest.raises(ContractError, match="positive"):
        fixture([("size", "Constant", (), None, 0), ("alloc", "Allocation", ("size",))])


def test_call_named_malloc_is_not_an_allocation_model():
    plan, _ = fixture([("call", "Call", (), "malloc")])
    assert plan.sites == ()
    result = analyze_heap(plan, policy=SUCCESS)
    assert result.observations[0].kind == "opaque" and result.status == "partial"


def test_independent_lifetime_transition_truth_tables():
    possible = [
        tuple(
            x
            for i, x in enumerate(("freed", "live", "not_allocated"))
            if mask & (1 << i)
        )
        for mask in range(1, 8)
    ]
    for states, escape, singleton, nullable in product(
        possible, ("local", "escaped", "unknown"), (False, True), (False, True)
    ):
        before = Lifetime(states, escape)
        after, strong = allocate_lifetime(
            before, singleton=singleton, nullable=nullable
        )
        expected = {"live"} | ({"not_allocated"} if nullable else set())
        fresh = singleton and states == ("not_allocated",)
        if not fresh:
            expected.update(states)
        assert set(after.possible) == expected and after.escape == escape
        assert strong == (fresh and not nullable)
        escaped = escape_lifetime(before, definite=singleton)
        assert escaped.possible == states
        assert escaped.escape == (
            "escaped" if singleton or escape == "escaped" else "unknown"
        )
        freed, strong, unresolved = free_lifetime(before, definite=singleton)
        if singleton and states == ("live",):
            assert freed == Lifetime(("freed",), escape) and strong and not unresolved
        elif states == ("live",):
            assert freed == Lifetime(("freed", "live"), escape) and not strong
        else:
            assert (
                set(freed.possible) == {"not_allocated", "live", "freed"}
                and unresolved
                and not strong
            )


@pytest.mark.parametrize("bits", (32, 64))
def test_pointer_profile_width_is_not_cpu_specific(bits):
    plan, keys = fixture(
        [
            ("alloc", "Allocation", ()),
            ("copy", "Copy", ("alloc",)),
            ("free", "Free", ("copy",)),
        ],
        proofs=("alloc",),
        bits=bits,
    )
    result = analyze_heap(plan, policy=SUCCESS)
    assert observation(result, keys, "free").pointer.width_bits == bits
    assert observation(result, keys, "free").transitions[0].after.possible == ("freed",)


def test_pointer_phi_from_two_allocation_branches_is_not_strong_free():
    rows = [
        [],
        [("a", "Allocation", ())],
        [("b", "Allocation", ())],
        [("phi", "Phi", ((1, "a"), (2, "b"))), ("free", "Free", ("phi",))],
    ]
    plan, keys = fixture(rows, [(), (0,), (0,), (1, 2)], proofs=("a", "b"))
    result = analyze_heap(plan, policy=SUCCESS)
    free = observation(result, keys, "free")
    assert len(free.pointer.candidates) == 2
    assert all(
        not t.strong_update and {"live", "freed"} <= set(t.after.possible)
        for t in free.transitions
    )


@pytest.mark.parametrize("offset", (1, -1, None))
def test_interior_or_unknown_free_is_an_unresolved_relation(offset):
    plan, keys = fixture(
        [
            ("input", "InputValue", ()),
            ("alloc", "Allocation", ()),
            ("free", "Free", ("input",)),
        ],
        proofs=("alloc",),
    )
    obj = site(plan, keys, "alloc")
    pointer = PointerValue("ram", 64, (PointerCandidate(obj.object_id, offset),))
    result = analyze_heap(
        plan, (PointerSeed(keys["input"].node_id, pointer),), policy=SUCCESS
    )
    event = observation(result, keys, "free")
    assert event.unresolved and not any(t.strong_update for t in event.transitions)
    assert {"live", "freed"} <= set(event.transitions[0].after.possible)


def test_unknown_free_pointer_affects_all_compatible_heap_sites():
    plan, keys = fixture(
        [
            ("input", "InputValue", ()),
            ("a", "Allocation", ()),
            ("b", "Allocation", ()),
            ("free", "Free", ("input",)),
        ],
        proofs=("a", "b"),
    )
    result = analyze_heap(plan, policy=SUCCESS)
    event = observation(result, keys, "free")
    assert event.pointer.any_compatible_location and event.unresolved
    assert len(event.transitions) == 2
    assert all(t.after.possible == ("freed", "live") for t in event.transitions)


def test_context_and_plan_contracts_reject_forged_refs_and_order():
    plan, keys = fixture(
        [
            ("input", "InputValue", ()),
            ("a", "Allocation", ()),
            ("b", "Allocation", ()),
            ("free", "Free", ("a",)),
        ]
    )
    with pytest.raises(ContractError, match="sorted"):
        replace(plan, sites=tuple(reversed(plan.sites)))
    with pytest.raises(ContractError, match="identity"):
        replace(plan, context=("other-context",))
    with pytest.raises(ContractError, match="coverage"):
        replace(plan, sites=plan.sites[:1])
    result = analyze_heap(plan, policy=SUCCESS)
    with pytest.raises(ContractError, match="coverage"):
        replace(result, observations=()).validate_plan(plan)
    with pytest.raises(ContractError, match="Stale"):
        replace(result, plan_digest=digest("other")).validate_plan(plan)
    data = result.to_data()
    data["schema_version"] = 2
    with pytest.raises(ContractError):
        HeapResult.from_data(data)
    bad_pointer = PointerValue(
        "ram", 64, (PointerCandidate("object-v1:" + "0" * 64, 0),)
    )
    with pytest.raises(ContractError, match="Dangling"):
        analyze_heap(plan, (PointerSeed(keys["input"].node_id, bad_pointer),))


def test_escape_and_use_observation_schema_cannot_rewrite_liveness():
    plan, keys = fixture(
        [
            ("alloc", "Allocation", ()),
            ("escape", "OpaqueEffect", ("alloc",), "heap_escape"),
            ("use", "OpaqueEffect", ("alloc",), "heap_use"),
        ],
        proofs=("alloc",),
    )
    result = analyze_heap(plan, policy=SUCCESS)
    for name in ("escape", "use"):
        obs = observation(result, keys, name)
        bad = replace(
            obs.transitions[0],
            after=Lifetime(("freed",), "unknown"),
            strong_update=False,
        )
        with pytest.raises(ContractError, match="liveness|lifetime"):
            replace(obs, transitions=(bad,))
    assert observation(result, keys, "use").transitions[0].before == Lifetime(
        ("live",), "escaped"
    )


def test_plan_object_can_be_shared_with_memory_core_without_lifetime_mutation():
    from ida_pro_mcp.flow_core.memory import alias_relation
    from ida_pro_mcp.flow_core.states import ByteRange

    plan, keys = fixture([("alloc", "Allocation", ()), ("free", "Free", ("alloc",))])
    original = canonical_json(plan)
    obj = site(plan, keys, "alloc")
    assert MemoryObject.from_json(canonical_json(obj)) == obj
    assert alias_relation(obj, ByteRange(0, 1), obj, ByteRange(0, 1)) == "may_alias"
    analyze_heap(plan, policy=SUCCESS)
    assert canonical_json(plan) == original


def test_loop_target_growth_does_not_invent_historical_exact_state():
    rows = [
        [("a", "Allocation", ())],
        [
            ("pointer", "Phi", ((0, "a"), (2, "b"))),
            ("use", "OpaqueEffect", ("pointer",), "heap_use"),
        ],
        [("b", "Allocation", ())],
        [],
    ]
    plan, keys = fixture(rows, [(), (0, 2), (1,), (1,)], proofs=("a",))
    result = analyze_heap(plan, policy=SUCCESS)
    use = observation(result, keys, "use")
    assert len(use.pointer.candidates) == 2
    assert use.unresolved and use.precision == "opaque"
    assert "heap_target_set_widened" in result.diagnostics
    b = site(plan, keys, "b")
    b_transition = next(t for t in use.transitions if t.object_id == b.object_id)
    assert set(b_transition.before.possible) == {"not_allocated", "live", "freed"}


def test_allocation_size_and_phi_budget_are_explicit_contracts():
    plan, keys = fixture(
        [("size", "Constant", (), None, 16), ("alloc", "Allocation", ("size",))]
    )
    assert site(plan, keys, "alloc").size_bytes == 16
    with pytest.raises(ContractError, match="at most one"):
        fixture(
            [
                ("size", "Constant", (), None, 16),
                ("alloc", "Allocation", ("size", "size")),
            ]
        )
    branching, _ = fixture(
        [[], [], [], [("alloc", "Allocation", ())]], [(), (0,), (0,), (1, 2)]
    )
    with pytest.raises(ContractError, match="phi-input budget"):
        build_heap_plan(branching.program, max_phi_inputs=1)


@pytest.mark.parametrize(
    "operation", ("unsupported_opcode:m_unmodeled", "unknown_memory_width")
)
def test_builder_unknown_side_effect_encoding_is_opaque_heap_event(operation):
    from ida_pro_mcp.flow_core.memory import build_memory_plan

    plan, keys = fixture(
        [
            ("alloc", "Allocation", ()),
            ("effect", "UnknownValue", (), operation),
            ("use", "OpaqueEffect", ("alloc",), "heap_use"),
        ],
        proofs=("alloc",),
    )
    event = next(e for e in plan.events if e.node_id == keys["effect"].node_id)
    assert event.kind == "opaque" and event.scope == "all"
    # The established byte-memory plan classifies the same encoding as havoc.
    byte_plan = build_memory_plan(plan.program)
    assert (
        next(s for s in byte_plan.steps if s.node_id == keys["effect"].node_id).effect
        == "havoc"
    )
    result = analyze_heap(plan, policy=SUCCESS)
    used = observation(result, keys, "use").transitions[0].before
    assert set(used.possible) == {"not_allocated", "live", "freed"}
    assert used.escape == "unknown" and result.status == "partial"


@pytest.mark.parametrize(
    "operation",
    (
        "unmodeled_operand:global",
        "destination_width_mismatch",
        "unmodeled_memory_or_call_effect",
        "unsupported_value:synthetic",
    ),
)
def test_value_only_unknown_does_not_invent_heap_mutation(operation):
    plan, keys = fixture(
        [
            ("alloc", "Allocation", ()),
            ("value", "UnknownValue", (), operation),
            ("use", "OpaqueEffect", ("alloc",), "heap_use"),
        ],
        proofs=("alloc",),
    )
    assert keys["value"].node_id not in {e.node_id for e in plan.events}
    result = analyze_heap(plan, policy=SUCCESS)
    assert observation(result, keys, "use").transitions[0].before == Lifetime(
        ("live",), "local"
    )


def test_root_object_can_contain_pointer_to_disjoint_local_heap_object():
    plan, keys = fixture(
        [
            ("a", "Allocation", ()),
            ("b", "Allocation", ()),
            ("write_pointer", "Store", ("b", "a"), None, None, 64),
            ("opaque", "OpaqueEffect", ("a",), "heap_opaque_reachable"),
            ("use_b", "OpaqueEffect", ("b",), "heap_use"),
        ],
        proofs=("a", "b"),
    )
    a, b = site(plan, keys, "a"), site(plan, keys, "b")
    assert a.disjoint and b.disjoint
    write = next(
        n
        for n in plan.program.graph.nodes
        if n.node_id == keys["write_pointer"].node_id
    )
    assert write.width_bits == 64 and write.memory_operands.data == keys["b"].node_id
    assert write.memory_operands.address == keys["a"].node_id
    result = analyze_heap(plan, policy=SUCCESS)
    opaque = observation(result, keys, "opaque")
    assert {t.object_id for t in opaque.transitions} == {a.object_id, b.object_id}
    used = observation(result, keys, "use_b").transitions[0].before
    assert used.escape == "unknown" and "freed" in used.possible
    assert result.status == "partial"
    assert keys["write_pointer"].node_id not in {f.node_id for f in result.pointers}


def test_v2_heap_policy_and_rule_versions_invalidate_old_results():
    policy = HeapPolicy()
    assert policy.ruleset == "synthetic-heap-v2"
    old = policy.to_data() | {"ruleset": "synthetic-heap-v1"}
    assert digest(policy) != digest(old)
    with pytest.raises(ContractError):
        HeapPolicy.from_data(old)
    plan, keys = fixture([("alloc", "Allocation", ())], proofs=("alloc",))
    assert {e.rule_id for e in plan.events} == {"explicit-heap-events-v2"}
    result = analyze_heap(plan, policy=SUCCESS)
    assert {o.rule_id for o in result.observations} == {
        "synthetic-lifetime-transfer-v2"
    }
    assert result.policy_digest == digest(SUCCESS)
    assert HeapPlan.from_json(canonical_json(plan)) == plan
    assert HeapResult.from_json(canonical_json(result)) == result
