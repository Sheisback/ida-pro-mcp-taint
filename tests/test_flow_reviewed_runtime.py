"""Public reviewed-call runtime regression; recorded inputs are static only."""

import json
from importlib import import_module
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import test_flow_capabilities as capabilities_tests
from ida_pro_mcp.flow_core import ContractError, digest
from ida_pro_mcp.flow_core.profile_routing import (
    OpenDatabaseEvidence,
    resolve_open_database_profile,
)

flow = capabilities_tests.flow

ROOT = Path(__file__).resolve().parents[1]


def receipt(arch):
    return json.loads(
        (
            ROOT / f"tests/flow_fixtures/manifests/calls/extraction_{arch}.json"
        ).read_text()
    )


@pytest.mark.parametrize("arch", ["x86_64", "arm64"])
def test_shipped_owned_catalog_routes_and_pins_every_component(flow, arch):
    module, _ = flow
    service = module._service()
    data = receipt(arch)
    profile = data["profile"]
    env = data["functions"][0]["baseline"]["snapshot"]["identity"]["environment"]
    observed = OpenDatabaseEvidence(
        "sha256-v1:" + data["binary"]["sha256"],
        profile["processor"],
        profile["bitness"],
        profile["data_endian"],
        profile["format_id"],
        env["ida_build"],
        env["hexrays_build"],
    )
    route = resolve_open_database_profile(observed)
    assert route.profile == profile
    info = dict(
        binary=observed.binary_digest,
        profile=route.profile,
        ida=observed.ida_build,
        hexrays=observed.hexrays_build,
    )
    catalog = service.reviewed_catalog(info)
    assert catalog.to_data() == data["catalog"]
    assert {s.kind for s in catalog.summaries} >= {
        "identity",
        "output",
        "alloc",
        "free",
    }
    for altered in (
        dict(info, binary=digest("foreign-binary")),
        dict(info, profile={**profile, "version": 999}),
        dict(info, ida="foreign-build"),
        dict(info, hexrays="foreign-build"),
    ):
        assert service.reviewed_catalog(altered).summaries == ()
    with pytest.raises(ContractError):
        resolve_open_database_profile(replace(observed, ida_build="foreign"))


def install_recorded_extractor(service, monkeypatch, data):
    records = {r["rva"]: r for r in data["functions"]}
    visited = []

    def extract(ea, *, namespace, function_key, profile, summary_digest, **kwargs):
        rva = ea - data["binary"]["image_base"]
        visited.append(rva)
        baseline = service.extractor.ExtractedFunction.from_data(
            records[rva]["baseline"]
        )
        function = replace(baseline.snapshot.function, function_id=function_key)
        snapshot = service.extractor.make_snapshot(
            function,
            baseline.snapshot.identity.environment,
            profile,
            namespace,
            data["binary"]["sha256"],
            summary_digest=summary_digest,
        )
        return replace(baseline, snapshot=snapshot)

    monkeypatch.setattr(service.extractor, "extract_snapshot", extract)
    return records, visited


@pytest.mark.parametrize("arch", ["x86_64", "arm64"])
@pytest.mark.parametrize(
    "name,kinds",
    [
        ("call_context_left", {"identity"}),
        ("call_heap_h01", {"alloc", "free"}),
        ("call_heap_h03", {"alloc"}),
        ("call_recursive", {"identity"}),
        ("call_indirect", set()),
        ("call_output_user", {"output"}),
    ],
)
def test_public_runtime_composes_reviewed_calls_and_retains_remainders(
    flow,
    monkeypatch,
    arch,
    name,
    kinds,
):
    module, _ = flow
    service = module._service()
    data = receipt(arch)
    records, visited = install_recorded_extractor(service, monkeypatch, data)
    selected = next(r for r in records.values() if r["name"] == name)
    profile = data["profile"]
    baseline = selected["baseline"]["snapshot"]["identity"]
    from ida_pro_mcp.flow_core.profile_registry import REGISTRY

    info = dict(
        dbpath="/tmp/owned-call.i64",
        binary=baseline["binary_digest"],
        profile=profile,
        registry=REGISTRY,
        count=0,
        ida=baseline["environment"]["ida_build"],
        hexrays=baseline["environment"]["hexrays_build"],
    )
    monkeypatch.setattr(service, "_context_for_request", lambda *a, **kw: info)
    catalog = service.reviewed_catalog(info)
    scope = service._runtime_scope(info, "runtime-owner")
    artifacts = {}

    def put(kind, value):
        key = f"{kind}-{len(artifacts)}"
        artifacts[key] = value.to_data() if hasattr(value, "to_data") else value
        return key

    engine = SimpleNamespace(store=SimpleNamespace(scope=scope, put_artifact=put))
    monkeypatch.setattr(service, "get_runtime", lambda *_: engine)
    request = dict(
        ea=selected["baseline"]["function_ea"],
        profile=profile,
        namespace="runtime-owner",
        function_key="public-entry",
        fingerprint=service._fingerprint(info),
        summary_digest=catalog.catalog_digest,
    )
    ctx = SimpleNamespace(
        deadline=None, cancel=SimpleNamespace(is_set=lambda: False), check=lambda: None
    )
    result = service._analyze(ctx, service._extract(ctx, request))
    raw = artifacts[result["call_composition_artifact"]]
    items, metadata = service._interprocedural_page(raw)
    found = {
        b["summary"]["kind"] for i in items for b in i["binding"]["plan"]["branches"]
    }
    assert found == kinds
    observations = [o for i in items for o in i["composition"]["heap_observations"]]
    if name == "call_heap_h01":
        assert {o["kind"] for o in observations} >= {"allocate", "free"}
        allocation = next(o for o in observations if o["kind"] == "allocate")
        freed = next(o for o in observations if o["kind"] == "free")
        assert allocation["transitions"] and freed["transitions"]
        assert (
            allocation["transitions"][0]["object_id"]
            == freed["transitions"][0]["object_id"]
        )
        assert freed["pointer"]["candidates"] == allocation["pointer"]["candidates"]
        assert "live" in freed["transitions"][0]["before"]["possible"]
        assert "freed" in freed["transitions"][0]["after"]["possible"]

    if name == "call_heap_h03":
        opaque = next(o for o in observations if o["kind"] == "opaque")
        assert opaque["transitions"]
        assert opaque["transitions"][0]["before"]["escape"] != "local"
        assert opaque["transitions"][0]["after"] == {
            "possible": ["freed", "live", "not_allocated"],
            "escape": "unknown",
        }
    if name == "call_output_user":
        assert [
            o["operation"]
            for i in items
            for o in i["composition"]["memory_observations"]
        ] == ["output"]
        assert all(i["composition"]["return_value"] is None for i in items)
        output = items[0]["composition"]
        assert output["memory_observations"][0]["targets"]
        assert len(output["state"]["memory"]) == 4
        assert all(byte["labels"]["explicit"] for byte in output["state"]["memory"])

    assert result["target_executed"] is False
    assert result["summary_digest"] == data["catalog_digest"]
    assert len(visited) <= 64
    assert len(visited) == len(set(visited))
    if name in {"call_recursive", "call_indirect", "call_heap_h03"}:
        assert metadata["unknown_remainder_count"] > 0
        assert metadata["status"] == "partial"
    for item in items:
        assert item["composition"]["plan_digest"]
    assert result["callee_closure"]["max_functions"] == 64


@pytest.mark.parametrize("arch", ["x86_64", "arm64"])
@pytest.mark.parametrize("limit", ["depth", "functions", "stale"])
def test_callee_closure_fails_closed_at_budgets_and_changed_body(
    flow, monkeypatch, arch, limit
):
    module, _ = flow
    service = module._service()
    data = receipt(arch)
    records, visited = install_recorded_extractor(service, monkeypatch, data)
    selected = next(r for r in records.values() if r["name"] == "call_context_left")
    root = service.extractor.ExtractedFunction.from_data(selected["runtime"])
    identity = root.snapshot.identity
    from ida_pro_mcp.flow_core.profile_registry import REGISTRY

    info = dict(
        binary=identity.binary_digest,
        profile=data["profile"],
        registry=REGISTRY,
        ida=identity.environment.ida_build,
        hexrays=identity.environment.hexrays_build,
    )
    ctx = SimpleNamespace(
        deadline=None, cancel=SimpleNamespace(is_set=lambda: False), check=lambda: None
    )
    kwargs = {}
    if limit == "depth":
        kwargs["max_depth"] = 0
    elif limit == "functions":
        kwargs["max_functions"] = 1
    else:
        original = service.extractor.extract_snapshot

        def stale(*args, **kwargs):
            result = original(*args, **kwargs)
            function = replace(
                result.snapshot.function, function_id="changed-body-identity"
            )
            snapshot = service.extractor.make_snapshot(
                function,
                result.snapshot.identity.environment,
                data["profile"],
                result.snapshot.identity.namespace,
                data["binary"]["sha256"],
                summary_digest=result.snapshot.identity.summary_digest,
            )
            return replace(result, snapshot=snapshot)

        monkeypatch.setattr(service.extractor, "extract_snapshot", stale)
    callees, closure = service.extract_callee_closure(ctx, root, info, **kwargs)
    assert callees == {}
    assert [b["reason"] for b in closure["boundaries"]] == [
        {
            "depth": "depth_limit",
            "functions": "function_limit",
            "stale": "stale_callee_snapshot",
        }[limit]
    ]
    binding = import_module(service.__package__ + ".summary_catalog").bind_call(
        root, root.calls[0], service.reviewed_catalog(info), callees
    )
    assert not binding.plan.branches
    assert binding.plan.unknown_remainder is not None


@pytest.mark.parametrize("field", ["RULES", "POLICY"])
def test_reviewed_catalog_rules_and_policy_fence(flow, monkeypatch, field):
    module, _ = flow
    service = module._service()
    data = receipt("x86_64")
    info = dict(
        binary="sha256-v1:" + data["binary"]["sha256"],
        profile=data["profile"],
        ida="9.3",
        hexrays="9.3.0.260213",
    )
    assert service.reviewed_catalog(info).summaries
    monkeypatch.setattr(service.extractor, field, {"version": "changed"})
    assert not service.reviewed_catalog(info).summaries


def test_capabilities_only_offer_reviewed_semantics_for_packaged_catalog(
    flow, monkeypatch
):
    module, _ = flow
    assert (
        module.flow_get_capabilities()["features"]["interprocedural"]["status"]
        == "unavailable"
    )
    data = receipt("x86_64")
    monkeypatch.setattr(
        module.ida_nalt,
        "retrieve_input_file_sha256",
        lambda: bytes.fromhex(data["binary"]["sha256"]),
    )
    result = module.flow_get_capabilities()
    assert result["features"]["interprocedural"]["status"] == "available"


def test_closure_cancellation_prevents_callee_extraction(flow, monkeypatch):
    module, _ = flow
    service = module._service()
    data = receipt("x86_64")
    records, visited = install_recorded_extractor(service, monkeypatch, data)
    selected = next(r for r in records.values() if r["name"] == "call_context_left")
    root = service.extractor.ExtractedFunction.from_data(selected["runtime"])
    identity = root.snapshot.identity
    info = dict(
        binary=identity.binary_digest,
        profile=data["profile"],
        ida=identity.environment.ida_build,
        hexrays=identity.environment.hexrays_build,
    )

    def cancelled():
        raise InterruptedError("cancelled")

    ctx = SimpleNamespace(check=cancelled)
    with pytest.raises(InterruptedError, match="cancelled"):
        service.extract_callee_closure(ctx, root, info)
    assert visited == []


def program_call_fixture(flow, arch, name):
    from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
    from ida_pro_mcp.flow_core.summaries import SummaryCatalog

    module, _ = flow
    service = module._service()
    data = receipt(arch)
    functions = {
        row["name"]: service.extractor.ExtractedFunction.from_data(row["runtime"])
        for row in data["functions"]
    }
    function = functions[name]
    callees = {
        row["rva"]: service.extractor.ExtractedFunction.from_data(
            row["baseline"]
        ).snapshot
        for row in data["functions"]
    }
    return (
        service,
        function,
        build_memory_graph(function.snapshot).program,
        SummaryCatalog.from_data(data["catalog"]),
        callees,
    )


@pytest.mark.parametrize("arch", ["x86_64", "arm64"])
def test_unknown_pointer_transform_does_not_reconstruct_allocator_identity(flow, arch):
    service, function, program, catalog, callees = program_call_fixture(
        flow, arch, "call_heap_h01"
    )
    nodes = {node.node_id: node for node in program.graph.nodes}
    copies = [
        node
        for node in nodes.values()
        if node.kind == "Copy" and any(nodes[i].kind == "Call" for i in node.inputs)
    ]
    assert len(copies) == 1
    changed = replace(
        copies[0], kind="UnknownValue", operation="unsupported_pointer_transform"
    )
    graph = replace(
        program.graph,
        nodes=tuple(
            changed if n.node_id == changed.node_id else n for n in program.graph.nodes
        ),
    )
    rows = service.compose_program_calls(
        function, replace(program, graph=graph), catalog, callees, lambda: None
    )
    freed = next(
        o
        for row in rows
        for o in row["composition"]["heap_observations"]
        if o["kind"] == "free"
    )
    assert freed["pointer"] is None
    assert freed["unresolved"] is True
    assert not any(t["strong_update"] for t in freed["transitions"])


@pytest.mark.parametrize("arch", ["x86_64", "arm64"])
def test_loop_call_state_never_invents_one_iteration_order(flow, arch):
    from ida_pro_mcp.flow_core.memory_graph import build_memory_graph

    service, function, _, catalog, callees = program_call_fixture(
        flow, arch, "call_context_left"
    )
    block_index = function.calls[0].block_index
    original = function.snapshot.function.blocks[block_index]
    loop = replace(
        original,
        predecessors=tuple(sorted(set(original.predecessors) | {block_index})),
        successors=tuple(sorted(set(original.successors) | {block_index})),
    )
    body = replace(
        function.snapshot.function,
        blocks=tuple(
            loop if b.index == block_index else b
            for b in function.snapshot.function.blocks
        ),
    )
    data = receipt(arch)
    snapshot = service.extractor.make_snapshot(
        body,
        function.snapshot.identity.environment,
        data["profile"],
        function.snapshot.identity.namespace,
        data["binary"]["sha256"],
        summary_digest=catalog.catalog_digest,
    )
    function = replace(function, snapshot=snapshot)
    rows = service.compose_program_calls(
        function, build_memory_graph(snapshot).program, catalog, callees, lambda: None
    )
    assert rows
    assert all(
        row["composition"]["status"] == "partial"
        and "call_state_loop_or_order_unknown" in row["composition"]["diagnostics"]
        for row in rows
    )


def test_stateful_composition_checks_graph_ownership_and_cancellation(flow):
    service, function, program, catalog, callees = program_call_fixture(
        flow, "x86_64", "call_heap_h01"
    )
    _, foreign, _, _, _ = program_call_fixture(flow, "x86_64", "call_output_user")
    with pytest.raises(ContractError, match="not owned"):
        service.compose_program_calls(foreign, program, catalog, callees, lambda: None)

    def cancelled():
        raise InterruptedError("cancelled state composition")

    with pytest.raises(InterruptedError, match="cancelled state"):
        service.compose_program_calls(function, program, catalog, callees, cancelled)


@pytest.mark.parametrize("arch", ["x86_64", "arm64"])
def test_call_state_uses_cfg_order_not_numeric_block_or_observation_order(flow, arch):
    from ida_pro_mcp.flow_core.memory_graph import build_memory_graph

    service, function, _, catalog, callees = program_call_fixture(
        flow, arch, "call_heap_h01"
    )
    body = function.snapshot.function
    count = len(body.blocks)
    mapping = {b.index: count - 1 - b.index for b in body.blocks}

    def operand(op):
        return replace(
            op,
            block_index=None if op.block_index is None else mapping[op.block_index],
            children=tuple(operand(child) for child in op.children),
        )

    blocks = tuple(
        sorted(
            (
                replace(
                    b,
                    index=mapping[b.index],
                    predecessors=tuple(sorted(mapping[p] for p in b.predecessors)),
                    successors=tuple(sorted(mapping[s] for s in b.successors)),
                    instructions=tuple(
                        replace(i, operands=tuple(operand(o) for o in i.operands))
                        for i in b.instructions
                    ),
                )
                for b in body.blocks
            ),
            key=lambda b: b.index,
        )
    )
    body = replace(body, blocks=blocks, entry_block=mapping[body.entry_block])
    data = receipt(arch)
    snapshot = service.extractor.make_snapshot(
        body,
        function.snapshot.identity.environment,
        data["profile"],
        function.snapshot.identity.namespace,
        data["binary"]["sha256"],
        summary_digest=catalog.catalog_digest,
    )
    calls = tuple(
        sorted(
            (
                replace(call, block_index=mapping[call.block_index])
                for call in function.calls
            ),
            key=lambda call: (
                call.block_index,
                call.instruction_index,
                call.instruction_ea,
            ),
        )
    )
    function = replace(function, snapshot=snapshot, calls=calls)
    rows = service.compose_program_calls(
        function, build_memory_graph(snapshot).program, catalog, callees, lambda: None
    )
    events = [o for row in rows for o in row["composition"]["heap_observations"]]
    assert [o["kind"] for o in events] == ["allocate", "free"]
    assert events[0]["pointer"]["candidates"] == events[1]["pointer"]["candidates"]
    assert events[1]["transitions"]


@pytest.mark.parametrize("arch", ["x86_64", "arm64"])
@pytest.mark.parametrize(
    "operation", ["unsupported_opcode:m_unknown", "unknown_memory_width"]
)
def test_canonical_unknown_memory_effect_invalidates_spills_and_heap(
    flow, arch, operation
):
    service, function, program, catalog, callees = program_call_fixture(
        flow, arch, "call_heap_h01"
    )
    nodes = {n.node_id: n for n in program.graph.nodes}
    copied_return = next(
        n
        for n in nodes.values()
        if n.kind == "Copy" and any(nodes[i].kind == "Call" for i in n.inputs)
    )
    effect = replace(copied_return, kind="UnknownValue", operation=operation)
    graph = replace(
        program.graph,
        nodes=tuple(
            effect if n.node_id == effect.node_id else n for n in program.graph.nodes
        ),
    )
    rows = service.compose_program_calls(
        function, replace(program, graph=graph), catalog, callees, lambda: None
    )
    free_row = next(
        row
        for row in rows
        if any(o["kind"] == "free" for o in row["composition"]["heap_observations"])
    )
    free = next(
        o for o in free_row["composition"]["heap_observations"] if o["kind"] == "free"
    )
    assert free["pointer"] is None
    assert free["transitions"][0]["before"] == {
        "possible": ["freed", "live", "not_allocated"],
        "escape": "unknown",
    }
    assert (
        "opaque_program_effect_call_state_havoc"
        in free_row["composition"]["diagnostics"]
    )


@pytest.mark.parametrize("arch", ["x86_64", "arm64"])
def test_lost_pointer_unknown_call_havocs_existing_local_heap_and_bytes(
    flow, monkeypatch, arch
):
    from ida_pro_mcp.flow_core.call_composition import CallMemoryByte
    from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
    from ida_pro_mcp.flow_core.states import BitValue, Labels
    from ida_pro_mcp.flow_core.summaries import SummaryCatalog

    service, function, _, catalog, callees = program_call_fixture(
        flow, arch, "call_heap_h01"
    )
    catalog = SummaryCatalog(tuple(s for s in catalog.summaries if s.kind != "free"))
    data = receipt(arch)
    snapshot = service.extractor.make_snapshot(
        function.snapshot.function,
        function.snapshot.identity.environment,
        data["profile"],
        function.snapshot.identity.namespace,
        data["binary"]["sha256"],
        summary_digest=catalog.catalog_digest,
    )
    function = replace(function, snapshot=snapshot)
    program = build_memory_graph(snapshot).program
    nodes = {n.node_id: n for n in program.graph.nodes}
    copied_return = next(
        n
        for n in nodes.values()
        if n.kind == "Copy" and any(nodes[i].kind == "Call" for i in n.inputs)
    )

    def change(n):
        if n.node_id == copied_return.node_id:
            return replace(
                n, kind="UnknownValue", operation="unsupported_pointer_transform"
            )
        # Keep the materialized test byte untouched until the unknown call.
        if (
            n.kind == "Store"
            and nodes[n.memory_operands.address].operation != "stack_address"
        ):
            return replace(
                n,
                kind="OpaqueEffect",
                operation="nop",
                memory=None,
                memory_operands=None,
                inputs=(),
            )
        return n

    graph = replace(program.graph, nodes=tuple(change(n) for n in program.graph.nodes))
    adapter = import_module(service.__package__ + ".call_state")
    original = adapter.compose_binding

    def with_initial_byte(*args, **kwargs):
        result = original(*args, **kwargs)
        if any(o.kind == "allocate" for o in result.heap_observations):
            oid = result.heap_observations[0].transitions[0].object_id
            result = replace(
                result,
                state=replace(
                    result.state,
                    memory=(
                        CallMemoryByte(
                            oid, 0, BitValue(8, 42), Labels(explicit=("initial-byte",))
                        ),
                    ),
                ),
            )
        return result

    monkeypatch.setattr(adapter, "compose_binding", with_initial_byte)
    rows = service.compose_program_calls(
        function, replace(program, graph=graph), catalog, callees, lambda: None
    )
    opaque_row = next(
        row for row in rows if row["binding"]["plan"]["unknown_remainder"] is not None
    )
    result = opaque_row["composition"]
    heap = next(o for o in result["heap_observations"] if o["kind"] == "opaque")
    assert heap["transitions"]
    assert heap["transitions"][0]["before"]["escape"] == "local"
    assert heap["transitions"][0]["after"] == {
        "possible": ["freed", "live", "not_allocated"],
        "escape": "unknown",
    }
    assert result["memory_observations"][0]["targets"]
    assert result["state"]["memory"][0]["value"]["value"] is None
    assert result["state"]["memory"][0]["labels"]["unknown_provenance"] is True


def test_unknown_call_proven_narrow_scalar_does_not_expose_local_heap(
    flow, monkeypatch
):
    from ida_pro_mcp.flow_core.call_composition import CallMemoryByte, CallState
    from ida_pro_mcp.flow_core.contracts import MemoryObject
    from ida_pro_mcp.flow_core.heap import HeapObjectState
    from ida_pro_mcp.flow_core.states import BitValue, Lifetime
    from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
    from ida_pro_mcp.flow_core.summaries import SummaryCatalog

    service, function, program, catalog, callees = program_call_fixture(
        flow, "x86_64", "call_context_left"
    )
    catalog = SummaryCatalog(
        tuple(s for s in catalog.summaries if s.kind != "identity")
    )
    data = receipt("x86_64")
    snapshot = service.extractor.make_snapshot(
        function.snapshot.function,
        function.snapshot.identity.environment,
        data["profile"],
        function.snapshot.identity.namespace,
        data["binary"]["sha256"],
        summary_digest=catalog.catalog_digest,
    )
    function = replace(function, snapshot=snapshot)
    program = build_memory_graph(snapshot).program
    obj = MemoryObject(
        function.snapshot.snapshot_id, "local-test-allocation", "ram", 1, "heap"
    )
    state = CallState(
        objects=(obj,),
        memory=(CallMemoryByte(obj.object_id, 0, BitValue(8, 42)),),
        heap=(HeapObjectState(obj.object_id, Lifetime(("live",), "local")),),
    )
    adapter = import_module(service.__package__ + ".call_state")
    original = adapter.compose_binding

    def with_local_state(*args, **kwargs):
        inputs = kwargs["inputs"]
        assert all(
            a.value.width_bits == 32 and a.pointer is None for a in inputs.arguments
        )
        return original(*args, **{**kwargs, "inputs": replace(inputs, state=state)})

    monkeypatch.setattr(adapter, "compose_binding", with_local_state)
    rows = service.compose_program_calls(
        function, program, catalog, callees, lambda: None
    )
    for row in rows:
        result = row["composition"]
        assert result["heap_observations"][0]["transitions"] == []
        assert result["state"]["heap"][0]["lifetime"] == {
            "possible": ["live"],
            "escape": "local",
        }
        assert result["state"]["memory"][0]["value"]["value"] == 42


@pytest.mark.parametrize("arch", ["x86_64", "arm64"])
@pytest.mark.parametrize("missing_free", [False, True])
def test_loop_remainder_retains_and_widens_reachable_allocation_prefix(
    flow, monkeypatch, arch, missing_free
):
    from ida_pro_mcp.flow_core.call_composition import CallMemoryByte
    from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
    from ida_pro_mcp.flow_core.states import BitValue
    from ida_pro_mcp.flow_core.summaries import SummaryCatalog

    service, function, _, catalog, callees = program_call_fixture(
        flow, arch, "call_heap_h01"
    )
    if missing_free:
        catalog = SummaryCatalog(
            tuple(s for s in catalog.summaries if s.kind != "free")
        )
    free_block = function.calls[-1].block_index
    block = function.snapshot.function.blocks[free_block]
    loop = replace(
        block,
        predecessors=tuple(sorted(set(block.predecessors) | {free_block})),
        successors=tuple(sorted(set(block.successors) | {free_block})),
    )
    body = replace(
        function.snapshot.function,
        blocks=tuple(
            loop if b.index == free_block else b
            for b in function.snapshot.function.blocks
        ),
    )
    data = receipt(arch)
    snapshot = service.extractor.make_snapshot(
        body,
        function.snapshot.identity.environment,
        data["profile"],
        function.snapshot.identity.namespace,
        data["binary"]["sha256"],
        summary_digest=catalog.catalog_digest,
    )
    function = replace(function, snapshot=snapshot)
    adapter = import_module(service.__package__ + ".call_state")
    original = adapter.compose_binding

    def with_prefix_byte(*args, **kwargs):
        result = original(*args, **kwargs)
        allocations = [o for o in result.heap_observations if o.kind == "allocate"]
        if allocations:
            oid = allocations[0].transitions[0].object_id
            result = replace(
                result,
                state=replace(
                    result.state, memory=(CallMemoryByte(oid, 0, BitValue(8, 42)),)
                ),
            )
        return result

    monkeypatch.setattr(adapter, "compose_binding", with_prefix_byte)
    rows = service.compose_program_calls(
        function, build_memory_graph(snapshot).program, catalog, callees, lambda: None
    )
    prefix = next(
        row
        for row in rows
        if any(o["kind"] == "allocate" for o in row["composition"]["heap_observations"])
    )
    oid = prefix["composition"]["state"]["heap"][0]["object_id"]
    remainder = next(
        row["composition"]
        for row in rows
        if "call_state_loop_or_order_unknown" in row["composition"]["diagnostics"]
    )
    assert remainder["status"] == "partial"
    assert remainder["state"]["heap"] == [
        {
            "object_id": oid,
            "lifetime": {
                "possible": ["freed", "live", "not_allocated"],
                "escape": "unknown",
            },
        }
    ]
    assert remainder["state"]["memory"][0]["object_id"] == oid
    assert remainder["state"]["memory"][0]["value"]["value"] is None
    assert oid in remainder["state"]["havoced_objects"]
    assert any(
        "call_state_loop_or_order_unknown" in e["reasons"]
        for e in remainder["evidence"]
    )


@pytest.mark.parametrize("arch", ["x86_64", "arm64"])
def test_unreachable_call_never_imports_reachable_prefix_heap(flow, arch):
    from ida_pro_mcp.flow_core.memory_graph import build_memory_graph

    service, function, _, catalog, callees = program_call_fixture(
        flow, arch, "call_heap_h01"
    )
    free_block = function.calls[-1].block_index
    # Remove incoming edges to the free arm. Its outgoing edges are retained;
    # unreachable predecessors do not authorize state import at a CFG join.
    body = function.snapshot.function
    changed = []
    for block in body.blocks:
        if block.index == free_block:
            block = replace(block, predecessors=())
        elif free_block in block.successors:
            block = replace(
                block,
                successors=tuple(s for s in block.successors if s != free_block),
                instructions=block.instructions[:-1],
            )
        changed.append(block)
    body = replace(body, blocks=tuple(changed))
    data = receipt(arch)
    snapshot = service.extractor.make_snapshot(
        body,
        function.snapshot.identity.environment,
        data["profile"],
        function.snapshot.identity.namespace,
        data["binary"]["sha256"],
        summary_digest=catalog.catalog_digest,
    )
    function = replace(function, snapshot=snapshot)
    rows = service.compose_program_calls(
        function, build_memory_graph(snapshot).program, catalog, callees, lambda: None
    )
    assert any(row["composition"]["state"]["heap"] for row in rows)
    unreachable = next(
        row["composition"]
        for row in rows
        if "call_state_unreachable_cfg" in row["composition"]["diagnostics"]
    )
    assert unreachable["state"]["objects"] == []
    assert unreachable["state"]["heap"] == []
    assert unreachable["branches"] == []
    assert unreachable["heap_observations"] == []
