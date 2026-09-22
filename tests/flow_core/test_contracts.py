"""Hand-authored schema examples, not extraction receipts or engine goldens."""

from dataclasses import replace
import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import sys

import pytest

from ida_pro_mcp.flow_core import ContractError, canonical_json, digest, stable_id
from ida_pro_mcp.flow_core.contracts import (
    Block,
    Edge,
    Environment,
    Evidence,
    FunctionInput,
    Graph,
    Instruction,
    MemoryObject,
    MemoryOperands,
    MemorySource,
    MemoryVersion,
    Node,
    NodeKey,
    Operand,
    PhiInput,
    ResultAxes,
    Site,
    Snapshot,
    SnapshotIdentity,
    ValueSource,
)
from ida_pro_mcp.flow_core.states import (
    BitValue,
    ByteRange,
    Labels,
    Lifetime,
    MemoryCell,
    MemoryReference,
    MemoryState,
    PointerCandidate,
    PointerValue,
    StorageLocation,
)

ROOT = Path(__file__).resolve().parents[2]


def sample_snapshot():
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
    d = "sha256-v1:" + "a" * 64
    identity = SnapshotIdentity(
        "database-owner-A",
        d,
        d,
        function.function_id,
        "MMAT_CALLS",
        d,
        d,
        d,
        d,
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


def sample_graph():
    snapshot = sample_snapshot()
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


def test_canonical_known_answer():
    # Literal byte string and independent standard-library hash, not a production golden.
    expected = '{"a":[true,null,3],"z":"한"}'
    value = {"z": "한", "a": [True, None, 3]}
    assert canonical_json(value) == expected
    assert digest(value) == "sha256-v1:" + hashlib.sha256(expected.encode()).hexdigest()
    assert (
        digest({})
        == "sha256-v1:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    )
    assert canonical_json(BitValue(8, 7)) == '{"value":7,"width_bits":8}'


@pytest.mark.parametrize(
    "value",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        object(),
        {1: "x"},
        (1,),
        {"a": object()},
    ],
)
def test_non_json_rejected(value):
    with pytest.raises(ContractError):
        canonical_json(value)


def test_json_duplicate_keys_nonfinite_and_schema_versions():
    for raw in (
        '{"value":0,"value":1,"width_bits":8}',
        '{"value":NaN,"width_bits":8}',
        '{"value":1e999,"width_bits":8}',
        "[]",
        "{}",
    ):
        with pytest.raises(ContractError):
            BitValue.from_json(raw)
    graph = sample_graph()
    for target in ((), ("snapshot",), ("snapshot", "identity")):
        data = graph.to_data()
        part = data
        for key in target:
            part = part[key]
        part["schema_version"] = 2
        with pytest.raises(ContractError):
            Graph.from_data(data)
    data = graph.to_data()
    data["extra"] = 1
    with pytest.raises(ContractError):
        Graph.from_data(data)


def test_roundtrip_identity_and_known_snapshot_hash():
    graph = sample_graph()
    assert Graph.from_json(canonical_json(graph)) == graph
    assert Graph.from_json(canonical_json(graph)).graph_digest == graph.graph_digest
    # Identity input is explicitly ID-free; node ID depends on structural path, not EA.
    payload = json.dumps(
        {"domain": "snapshot", "value": graph.snapshot.identity.to_data()},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    assert (
        graph.snapshot.snapshot_id
        == "snapshot-v1:" + hashlib.sha256(payload.encode()).hexdigest()
    )
    key = graph.nodes[0].key
    assert replace(key, site=Site(0, 0)).node_id != key.node_id
    assert (
        replace(graph.snapshot.identity, namespace="other-db").snapshot_id
        != graph.snapshot.snapshot_id
    )
    assert (
        replace(graph.snapshot.identity, maturity="MMAT_GLBOPT3").snapshot_id
        != graph.snapshot.snapshot_id
    )
    for field in (
        "profile_digest",
        "rule_digest",
        "summary_digest",
        "policy_digest",
        "semantic_digest",
    ):
        assert (
            replace(graph.snapshot.identity, **{field: digest(field)}).snapshot_id
            != graph.snapshot.snapshot_id
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["snapshot"].update(snapshot_id="bad"),
        lambda d: d["snapshot"]["identity"].update(input_digest=digest("other")),
        lambda d: d["snapshot"]["identity"].update(maturity="MMAT_LOCOPT"),
        lambda d: d["snapshot"]["function"].update(function_id="other"),
        lambda d: d["nodes"].append(d["nodes"][0]),
        lambda d: d["evidence"].append(d["evidence"][0]),
        lambda d: d["nodes"][0]["key"]["site"].update(operand_path=[9]),
        lambda d: d["nodes"][0].update(width_bits=True),
        lambda d: d["nodes"][0].update(constant=256),
        lambda d: d["nodes"][0].update(inputs=[stable_id("node", "absent")]),
        lambda d: d["nodes"][0].update(evidence_ids=[stable_id("evidence", "absent")]),
        lambda d: d["axes"].update(proof="safe"),
        lambda d: d["axes"].update(alias="exact"),
    ],
)
def test_invalid_graphs_rejected(mutate):
    data = sample_graph().to_data()
    mutate(data)
    with pytest.raises(ContractError):
        Graph.from_data(data)


def test_evidence_and_edges():
    graph = sample_graph()
    node = graph.nodes[0]
    ev = Evidence(
        graph.snapshot.snapshot_id, "copy-v1", synthetic=True, origins=(node.node_id,)
    )
    copy = Node(
        NodeKey(graph.snapshot.snapshot_id, "f:entry", synthetic="copy:0"),
        "Copy",
        8,
        (ev.evidence_id,),
        inputs=(node.node_id,),
    )
    edge = Edge(
        node.node_id,
        copy.node_id,
        "value_dependency",
        (ev.evidence_id,),
        ResultAxes(precision="exact"),
        8,
    )
    valid = replace(
        graph,
        nodes=tuple(sorted((node, copy), key=lambda n: n.node_id)),
        evidence=tuple(sorted(graph.evidence + (ev,), key=lambda e: e.evidence_id)),
        edges=(edge,),
    )
    assert Graph.from_json(canonical_json(valid)) == valid
    for changes in (
        {"edges": (edge, edge)},
        {"edges": (replace(edge, source=stable_id("node", "missing")),)},
        {"edges": (replace(edge, evidence_ids=(stable_id("evidence", "missing"),)),)},
        {
            "evidence": graph.evidence
            + (replace(ev, origins=(stable_id("node", "missing"),)),)
        },
        {"nodes": (replace(node, key=replace(node.key, function_id="wrong")),)},
    ):
        with pytest.raises(ContractError):
            replace(valid, **changes)


def phi_graph():
    old = sample_snapshot()
    function = FunctionInput(
        "f:entry",
        0,
        tuple(
            Block(
                i,
                () if i < 2 else (0, 1),
                (Instruction(0, "nop", ()),),
                (2,) if i < 2 else (),
            )
            for i in range(3)
        ),
    )
    identity = replace(old.identity, input_digest=digest(function))
    snap = Snapshot(identity, function, identity.snapshot_id)
    ev = Evidence(snap.snapshot_id, "phi-v1", synthetic=True)
    inputs = tuple(
        Node(
            NodeKey(snap.snapshot_id, "f:entry", Site(i, 0)),
            "InputValue",
            8,
            (ev.evidence_id,),
        )
        for i in range(2)
    )
    phi = Node(
        NodeKey(snap.snapshot_id, "f:entry", synthetic="phi:b2:r0"),
        "Phi",
        8,
        (ev.evidence_id,),
        phi_inputs=tuple(PhiInput(i, n.node_id) for i, n in enumerate(inputs)),
        phi_block=2,
    )
    edges = tuple(
        Edge(
            n.node_id,
            phi.node_id,
            "phi_input",
            (ev.evidence_id,),
            ResultAxes(),
            predecessor=i,
        )
        for i, n in enumerate(inputs)
    )
    return Graph(
        snap,
        tuple(sorted(inputs + (phi,), key=lambda n: n.node_id)),
        tuple(sorted(edges, key=lambda e: e.edge_id)),
        (ev,),
        ResultAxes(),
    )


def test_phi_predecessor_contract():
    graph = phi_graph()
    assert Graph.from_json(canonical_json(graph)) == graph
    phi = next(n for n in graph.nodes if n.kind == "Phi")
    for bad in (
        (PhiInput(0, graph.nodes[0].node_id),),
        (PhiInput(0, graph.nodes[0].node_id), PhiInput(9, graph.nodes[1].node_id)),
        (PhiInput(0, stable_id("node", "absent")), PhiInput(1, graph.nodes[1].node_id)),
    ):
        with pytest.raises(ContractError):
            replace(graph, nodes=graph.nodes[:-1] + (replace(phi, phi_inputs=bad),))
    with pytest.raises(ContractError):
        replace(graph, edges=(replace(graph.edges[0], predecessor=1),))


def test_all_result_axes_are_independent():
    axes = ResultAxes(
        "architecture_rule",
        "may_alias",
        "partial",
        "frontier_exhausted",
        "unknown",
        "no_alias",
    )
    assert ResultAxes.from_data(axes.to_data()) == axes
    assert axes.analysis == "partial" and axes.alias == "no_alias"
    for field in axes.to_data():
        with pytest.raises(ContractError):
            replace(axes, **{field: "unexpected"})


def test_bitvalue_join_exhaustive_small_domain():
    values = [BitValue(2, i) for i in range(4)] + [BitValue(2)]
    meanings = [{i} for i in range(4)] + [set(range(4))]
    for (a, sa), (b, sb) in itertools.product(zip(values, meanings), repeat=2):
        union = sa | sb
        expected = next(iter(union)) if len(union) == 1 else None
        assert a.join(b) == BitValue(2, expected)
    for args in ((0, None), (2, -1), (2, 4), (True, 0)):
        with pytest.raises(ContractError):
            BitValue(*args)
    with pytest.raises(ContractError):
        BitValue(2).join(BitValue(8))


def test_labels_keep_unknown_and_control_separate():
    a = Labels(("X",), (), False)
    b = Labels((), ("C",), True, True)
    assert a.join(b) == Labels(("X",), ("C",), True, True)
    assert Labels(unknown_provenance=True) != Labels()
    for flag_a, flag_b in itertools.product((False, True), repeat=2):
        result = Labels(unknown_provenance=flag_a).join(
            Labels(unknown_provenance=flag_b)
        )
        assert result.unknown_provenance == bool(flag_a + flag_b)
    with pytest.raises(ContractError):
        Labels(("X", "X"))


def test_lifetime_product_finite_truth_table():
    domain = ("freed", "live", "not_allocated")
    sets = [
        tuple(v for i, v in enumerate(domain) if mask & (1 << i))
        for mask in range(1, 8)
    ]
    for a, b, ea, eb in itertools.product(
        sets, sets, ("local", "escaped", "unknown"), ("local", "escaped", "unknown")
    ):
        out = Lifetime(a, ea).join(Lifetime(b, eb))
        assert set(out.possible) == set(a) | set(b)
        assert out.escape == (ea if ea == eb else "unknown")
    assert Lifetime(("live",), "escaped").possible == ("live",)


def test_pointer_union_and_top():
    a = PointerCandidate(stable_id("object", "a"), -4)
    b = PointerCandidate(stable_id("object", "b"), 0)
    pa, pb = PointerValue("ram", 64, (a,)), PointerValue("ram", 64, (b,))
    assert set(pa.join(pb).candidates) == {a, b}
    assert pa.join(
        PointerValue("ram", 64, any_compatible_location=True)
    ).any_compatible_location
    with pytest.raises(ContractError):
        pa.join(PointerValue("io", 64, (a,)))
    with pytest.raises(ContractError):
        PointerValue("ram", 64)


def test_memory_contract_and_sources():
    graph = sample_graph()
    obj = MemoryObject(graph.snapshot.snapshot_id, "arg0", "ram", 12)
    version = MemoryVersion(graph.snapshot.snapshot_id, "entry")
    ref = MemoryReference(
        obj.object_id, version.version_id, "ram", ByteRange(0, 4), "little"
    )
    graph = replace(graph, objects=(obj,), versions=(version,))
    graph.validate_source(MemorySource(graph.snapshot.snapshot_id, ref))
    graph.validate_source(
        ValueSource(graph.snapshot.snapshot_id, graph.nodes[0].node_id)
    )
    cell = MemoryCell(ref, BitValue(32), Labels(("X",)))
    assert MemoryState.from_json(canonical_json(MemoryState((cell,)))) == MemoryState(
        (cell,)
    )
    with pytest.raises(ContractError):
        MemoryState((cell, cell))
    for change in (
        {"endian": "big"},
        {"interval": ByteRange(0, 13)},
        {"address_space": "io"},
        {"version_id": stable_id("memory", "missing")},
        {"object_id": stable_id("object", "missing")},
    ):
        with pytest.raises(ContractError):
            graph.validate_memory(replace(ref, **change))
    for interval in ((-1, 1), (1, 1), (2, 1)):
        with pytest.raises(ContractError):
            ByteRange(*interval)
    with pytest.raises(ContractError):
        replace(cell, value=BitValue(8))


def test_g003_oracle_layout_structural_bridge_only():
    oracle = json.loads(
        (ROOT / "tests/flow_fixtures/oracles/sum_point.json").read_text()
    )
    # Hand-authored memory expectations from G003; no claim an analysis ran.
    fields = {
        key: ByteRange(*value) for key, value in oracle["layout"]["fields"].items()
    }
    assert fields == {
        "x": ByteRange(0, 4),
        "y": ByteRange(4, 8),
        "tag": ByteRange(8, 9),
    }
    assert oracle["seeds"] == {"arg0.memory[0,4)": "X"}
    assert fields["x"].end <= fields["y"].start
    assert fields["y"].end <= fields["tag"].start


def test_core_import_isolation():
    # Block attempted imports, not just successful imports, including lazy submodules.
    script = """
import importlib.abc, sys
class RejectIDA(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith(("ida_", "idapro")) and not fullname.startswith(("ida_pro_mcp",)):
            raise AssertionError(fullname)
        if fullname.startswith("ida_pro_mcp.ida_mcp"):
            raise AssertionError(fullname)
sys.meta_path.insert(0, RejectIDA())
import ida_pro_mcp.flow_core.contracts
import ida_pro_mcp.flow_core.states
import ida_pro_mcp.flow_core.serialization
import ida_pro_mcp.flow_core.cfg
import ida_pro_mcp.flow_core.ssa
import ida_pro_mcp.flow_core.analysis
import ida_pro_mcp.flow_core.memory
import ida_pro_mcp.flow_core.memory_analysis
import ida_pro_mcp.flow_core.heap
import ida_pro_mcp.flow_core.heap_analysis
import ida_pro_mcp.flow_core.runtime_contracts
import ida_pro_mcp.flow_core.persistence
import ida_pro_mcp.flow_core.runtime
"""
    subprocess.run([sys.executable, "-c", script], check=True, cwd=ROOT)


def test_operand_constraints():
    loc = StorageLocation("register", "r0", 0, 8)
    assert Operand("storage", 8, storage=loc).storage == loc
    for make in (
        lambda: Operand("constant", 8),
        lambda: Operand("unknown", 8, constant=1),
        lambda: Operand("storage", 16, storage=loc),
        lambda: Site(0, 0, (-1,)),
        lambda: Block(0, (3,), ()),
    ):
        # A Block alone may refer to not-yet-created blocks; FunctionInput checks closure.
        with pytest.raises(ContractError):
            value = make()
            if isinstance(value, Block):
                FunctionInput("f", 0, (value,))


def test_snapshot_input_canonical_hand_authored_contract():
    expected = (
        '{"blocks":[{"index":0,"instructions":[{"index":0,"opcode":"mov",'
        '"operands":[{"address":null,"block_index":null,"call":null,"children":[],"constant":7,'
        '"diagnostic":null,"kind":"constant","native_kind":null,"operation":null,'
        '"role":"unspecified","source_eas":[],"storage":null,"synthetic":false,"width_bits":8}],"source_eas":[4096],"synthetic":false}],'
        '"predecessors":[],"successors":[]}],"diagnostics":[],"entry_block":0,"function_id":"f:entry"}'
    )
    snapshot = sample_snapshot()
    assert canonical_json(snapshot.function) == expected
    assert (
        snapshot.identity.input_digest
        == "sha256-v1:" + hashlib.sha256(expected.encode()).hexdigest()
    )
    assert FunctionInput.from_json(expected) == snapshot.function


@pytest.mark.parametrize("field", ["explicit", "control"])
def test_label_join_finite_sets(field):
    universe = ("A", "B")
    subsets = [
        tuple(x for i, x in enumerate(universe) if mask & (1 << i)) for mask in range(4)
    ]
    for a, b in itertools.product(subsets, repeat=2):
        result = Labels(**{field: a}).join(Labels(**{field: b}))
        assert set(getattr(result, field)) == set(a) | set(b)
        assert not getattr(result, "control" if field == "explicit" else "explicit")


def test_range_nonoverlap_finite_intervals():
    ref = MemoryReference(
        stable_id("object", "a"),
        stable_id("memory", "v0"),
        "ram",
        ByteRange(0, 1),
        "little",
    )
    ranges = [
        ByteRange(start, end) for start in range(4) for end in range(start + 1, 5)
    ]
    for a, b in itertools.product(ranges, repeat=2):
        cells = tuple(
            MemoryCell(
                replace(ref, interval=r), BitValue(8 * (r.end - r.start)), Labels()
            )
            for r in (a, b)
        )
        disjoint = not (set(range(a.start, a.end)) & set(range(b.start, b.end)))
        if disjoint:
            assert (
                len(
                    MemoryState(
                        tuple(sorted(cells, key=lambda c: c.reference.interval.start))
                    ).cells
                )
                == 2
            )
        else:
            with pytest.raises(ContractError):
                MemoryState(cells)


def test_versioned_identity_and_native_objects_fail_closed():
    snapshot = sample_snapshot()
    for value in ("SHA256:" + "a" * 64, "sha256-v1:" + "A" * 64, "sha256-v1:a"):
        with pytest.raises(ContractError):
            replace(snapshot.identity, semantic_digest=value)
    for value in (True, 1.0, "1", 0):
        with pytest.raises(ContractError):
            replace(snapshot, schema_version=value)
    with pytest.raises(ContractError):
        replace(snapshot.identity, environment=object())
    with pytest.raises(ContractError):
        replace(snapshot, function=snapshot.function.to_data())
    cyclic = []
    cyclic.append(cyclic)
    with pytest.raises(ContractError):
        canonical_json(cyclic)


def test_cross_snapshot_evidence_and_memory_rejected():
    graph = sample_graph()
    other = replace(graph.snapshot.identity, namespace="B").snapshot_id
    with pytest.raises(ContractError):
        replace(graph, evidence=(replace(graph.evidence[0], snapshot_id=other),))
    with pytest.raises(ContractError):
        replace(graph, objects=(MemoryObject(other, "arg0", "ram", 4),))
    with pytest.raises(ContractError):
        replace(graph, versions=(MemoryVersion(other, "entry"),))
    with pytest.raises(ContractError):
        graph.validate_source(ValueSource(other, graph.nodes[0].node_id))
    with pytest.raises(ContractError):
        graph.validate_source(
            ValueSource(graph.snapshot.snapshot_id, stable_id("node", "missing"))
        )
    with pytest.raises(ContractError):
        Evidence(graph.snapshot.snapshot_id, "r")
    with pytest.raises(ContractError):
        replace(graph, evidence=(replace(graph.evidence[0], source_eas=(4097,)),))


def test_fork_ci_surface_does_not_require_licensed_runner():
    workflow = (ROOT / ".github/workflows/flow-core-tests.yml").read_text()
    assert "  pull_request:" in workflow
    assert "pull_request_target" not in workflow and "secrets." not in workflow
    assert "tests/flow_core" in workflow and "check_wheel.py" in workflow
    assert "uvx ruff@" in workflow and "uv run ruff check" not in workflow
    assert (
        "- name: Import core from wheel without application dependencies\n"
        "        env:\n"
        "          PYTHONPATH: src\n"
    ) in workflow
    assert "github.repository ==" not in workflow


def test_value_width_and_unicode_constraints():
    with pytest.raises(ContractError):
        canonical_json("\ud800")
    with pytest.raises(ContractError):
        BitValue.from_json('{"width_bits":8,"value":"\\ud800"}')
    graph = sample_graph()
    with pytest.raises(ContractError):
        replace(graph.nodes[0], width_bits=None)
    with pytest.raises(ContractError):
        replace(graph.nodes[0], inputs=(graph.nodes[0].node_id,))
    with pytest.raises(ContractError):
        replace(graph.nodes[0], kind="Binary", constant=None)
    phi = phi_graph()
    with pytest.raises(ContractError):
        replace(phi, nodes=(replace(phi.nodes[0], width_bits=16),) + phi.nodes[1:])


def test_set_collections_have_one_canonical_order():
    graph = phi_graph()
    for field in ("nodes", "edges"):
        assert len(getattr(graph, field)) > 1
        with pytest.raises(ContractError, match="sorted unique"):
            replace(graph, **{field: tuple(reversed(getattr(graph, field)))})
    evidence = tuple(
        sorted(
            graph.evidence
            + (Evidence(graph.snapshot.snapshot_id, "another-rule", synthetic=True),),
            key=lambda e: e.evidence_id,
        )
    )
    objects = tuple(
        sorted(
            (MemoryObject(graph.snapshot.snapshot_id, k, "ram") for k in ("a", "b")),
            key=lambda o: o.object_id,
        )
    )
    versions = tuple(
        sorted(
            (MemoryVersion(graph.snapshot.snapshot_id, k) for k in ("a", "b")),
            key=lambda v: v.version_id,
        )
    )
    graph = replace(graph, evidence=evidence, objects=objects, versions=versions)
    for field in ("evidence", "objects", "versions"):
        with pytest.raises(ContractError, match="sorted unique"):
            replace(graph, **{field: tuple(reversed(getattr(graph, field)))})
    assert Graph.from_json(canonical_json(graph)).graph_digest == graph.graph_digest
    for permutation in itertools.permutations(graph.nodes):
        reordered = tuple(sorted(permutation, key=lambda n: n.node_id))
        assert replace(graph, nodes=reordered).graph_digest == graph.graph_digest


def test_nested_set_order_is_required():
    graph = phi_graph()
    sid = graph.snapshot.snapshot_id
    ids = tuple(sorted(n.node_id for n in graph.nodes))
    evidence = Evidence(
        sid, "r", (Site(0, 0), Site(1, 0)), origins=ids, assumptions=("a", "b")
    )
    for field in ("sites", "origins", "assumptions"):
        for bad in (
            tuple(reversed(getattr(evidence, field))),
            getattr(evidence, field) * 2,
        ):
            with pytest.raises(ContractError, match="sorted unique"):
                replace(evidence, **{field: bad})
    eids = tuple(sorted((evidence.evidence_id, graph.evidence[0].evidence_id)))
    node = replace(graph.nodes[0], evidence_ids=eids)
    edge = replace(graph.edges[0], evidence_ids=eids)
    for item in (node, edge):
        with pytest.raises(ContractError, match="sorted unique"):
            replace(item, evidence_ids=tuple(reversed(eids)))
    phi = next(n for n in graph.nodes if n.kind == "Phi")
    with pytest.raises(ContractError, match="sorted unique"):
        replace(phi, phi_inputs=tuple(reversed(phi.phi_inputs)))


def test_memory_sets_and_ordered_inputs_are_distinct():
    graph = sample_graph()
    ref = MemoryReference(
        stable_id("object", "a"),
        stable_id("memory", "v0"),
        "ram",
        ByteRange(0, 1),
        "little",
    )
    ids = tuple(sorted((graph.nodes[0].node_id, stable_id("node", "other"))))
    cell = MemoryCell(ref, BitValue(8), Labels(), ids)
    with pytest.raises(ContractError, match="sorted unique"):
        replace(cell, reaching_definitions=tuple(reversed(ids)))
    next_cell = replace(cell, reference=replace(ref, interval=ByteRange(1, 2)))
    state = MemoryState((cell, next_cell))
    with pytest.raises(ContractError, match="sorted unique"):
        MemoryState((next_cell, cell))
    assert MemoryState.from_json(canonical_json(state)) == state
    # Input order is semantic: subtraction operands must not be sorted.
    binary = replace(
        graph.nodes[0], kind="Binary", constant=None, operation="sub", inputs=ids
    )
    swapped = replace(binary, inputs=tuple(reversed(ids)))
    assert digest(binary) != digest(swapped)


@pytest.mark.parametrize(
    "left_null,right_null", itertools.product((False, True), repeat=2)
)
def test_pointer_null_join_with_candidates_and_top(left_null, right_null):
    candidate = PointerCandidate(stable_id("object", "a"), 0)
    left = PointerValue("ram", 64, (candidate,), may_be_null=left_null)
    right = PointerValue(
        "ram", 64, any_compatible_location=True, may_be_null=right_null
    )
    result = left.join(right)
    assert result.any_compatible_location and not result.candidates
    assert result.may_be_null == (left_null or right_null)
    assert PointerValue.from_json(canonical_json(result)) == result


def test_exact_null_domain_and_invalid_empty_pointer():
    null = PointerValue("ram", 64, may_be_null=True)
    candidate = PointerCandidate(stable_id("object", "a"), -1)
    pointer = PointerValue("ram", 64, (candidate,))
    assert null.join(null) == null
    assert null.join(pointer) == PointerValue("ram", 64, (candidate,), may_be_null=True)
    assert pointer.join(null) == null.join(pointer)
    assert null.join(
        PointerValue("ram", 64, any_compatible_location=True)
    ) == PointerValue("ram", 64, any_compatible_location=True, may_be_null=True)
    assert (
        canonical_json(null)
        == '{"address_space":"ram","any_compatible_location":false,"candidates":[],"may_be_null":true,"width_bits":64}'
    )
    assert PointerValue.from_json(canonical_json(null)) == null
    with pytest.raises(ContractError):
        PointerValue("ram", 64)
    with pytest.raises(ContractError):
        PointerValue("ram", 64, (candidate,), True, True)
    with pytest.raises(ContractError):
        replace(null, may_be_null=1)


def test_phi_edges_exactly_mirror_node_mappings():
    graph = phi_graph()
    phi = next(n for n in graph.nodes if n.kind == "Phi")
    with pytest.raises(ContractError, match="completeness"):
        replace(graph, edges=())
    with pytest.raises(ContractError, match="completeness"):
        replace(graph, edges=graph.edges[:1])
    # Distinct edge IDs for the same mapping must still be rejected.
    duplicate = replace(
        graph.edges[0], axes=replace(graph.edges[0].axes, precision="exact")
    )
    with pytest.raises(ContractError, match="Duplicate"):
        replace(
            graph,
            edges=tuple(sorted(graph.edges + (duplicate,), key=lambda e: e.edge_id)),
        )
    for bad in (
        replace(graph.edges[0], predecessor=9),
        replace(graph.edges[0], target=graph.edges[0].source),
        replace(graph.edges[0], source=phi.node_id),
    ):
        with pytest.raises(ContractError, match="completeness"):
            replace(
                graph,
                edges=tuple(sorted((bad,) + graph.edges[1:], key=lambda e: e.edge_id)),
            )
    assert len(graph.edges) == len(phi.phi_inputs)
    assert Graph.from_json(canonical_json(graph)) == graph


@pytest.mark.parametrize(
    "kind,valid_counts,operation",
    [
        ("Constant", (0,), None),
        ("InputValue", (0,), None),
        ("Copy", (1,), None),
        ("Unary", (1,), "neg"),
        ("Binary", (2,), "add"),
        ("Compare", (2,), "eq"),
        ("Select", (3,), None),
        ("Free", (1,), None),
        ("Return", (0, 1), None),
        ("Branch", (0, 1), None),
    ],
)
def test_node_arity_truth_table(kind, valid_counts, operation):
    base = sample_graph().nodes[0]
    for count in range(5):
        kwargs = dict(
            kind=kind,
            inputs=(base.node_id,) * count,
            operation=operation,
            constant=7 if kind == "Constant" else None,
        )
        if count in valid_counts:
            node = replace(base, **kwargs)
            assert Node.from_json(canonical_json(node)) == node
        else:
            with pytest.raises(ContractError, match="arity"):
                replace(base, **kwargs)


def test_memory_node_payload_and_width_contracts():
    base = sample_graph().nodes[0]
    ref = MemoryReference(
        stable_id("object", "a"),
        stable_id("memory", "v"),
        "ram",
        ByteRange(0, 4),
        "little",
    )
    for kind in ("InputMemory", "Load", "Store"):
        kwargs = dict(
            kind=kind,
            constant=None,
            width_bits=32,
            inputs=(base.node_id, base.node_id)
            if kind == "Store"
            else ((base.node_id,) if kind == "Load" else ()),
            memory_operands=MemoryOperands(
                base.node_id, data=base.node_id if kind == "Store" else None
            )
            if kind != "InputMemory"
            else None,
        )
        node = replace(base, memory=ref, **kwargs)
        assert Node.from_json(canonical_json(node)) == node
        with pytest.raises(ContractError, match="payload"):
            replace(base, **kwargs)
        with pytest.raises(ContractError, match="width/range"):
            replace(node, width_bits=8)
    with pytest.raises(ContractError, match="value input"):
        replace(base, kind="Store", constant=None, memory=ref, width_bits=32)
    with pytest.raises(ContractError, match="payload"):
        replace(base, memory=ref)
    for kind in ("Call", "Allocation", "UnknownValue", "OpaqueEffect"):
        node = replace(base, kind=kind, constant=None, inputs=(base.node_id,) * 5)
        assert Node.from_json(canonical_json(node)) == node


def test_direct_from_data_cycle_and_depth_are_contract_errors():
    operand = Operand("expression", 8, operation="nested").to_data()
    operand["children"].append(operand)
    with pytest.raises(ContractError, match="Cyclic|deep"):
        Operand.from_data(operand)
    operand = Operand("expression", 8, operation="nested").to_data()
    operand["children"].append(operand["children"])
    with pytest.raises(ContractError, match="Cyclic|deep"):
        Operand.from_data(operand)
    operand = Operand("constant", 8, constant=0).to_data()
    for _ in range(1500):
        outer = Operand("expression", 8, operation="nested").to_data()
        outer["children"].append(operand)
        operand = outer
    with pytest.raises(ContractError, match="Cyclic|deep"):
        Operand.from_data(operand)
