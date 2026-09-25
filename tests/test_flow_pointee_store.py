"""SDK-free public-handler integration; synthetic IR is never executed."""

import copy
import json
import types
from dataclasses import replace

import pytest

from ida_pro_mcp.flow_core.analysis import Seed
from ida_pro_mcp.flow_core.contracts import (
    Block,
    FunctionInput,
    Instruction,
    Operand,
    Snapshot,
)
from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
from ida_pro_mcp.flow_core.persistence import Store
from ida_pro_mcp.flow_core.pointee import PointeeSeed
from ida_pro_mcp.flow_core.runtime_contracts import RuntimeScope
from ida_pro_mcp.flow_core.serialization import ContractError, digest, to_wire_v2
from ida_pro_mcp.flow_core.states import ByteRange, Labels, StorageLocation
from test_flow_capabilities import ROOT, flow as flow_fixture  # noqa: F401


def reg(offset=0, bits=64, role="left"):
    return Operand(
        "storage",
        bits,
        storage=StorageLocation("microregister", "bank", offset, bits),
        role=role,
    )


def const(value, bits=64, role="left"):
    return Operand("constant", bits, constant=value, role=role)


def memory_fixture(callback=False, v2=False):
    original = Snapshot.from_data(
        json.loads(
            (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
        )["snapshot"]
    )
    if callback:
        instructions = (
            Instruction(
                0,
                "m_add",
                (reg(), const(112, role="right"), reg(64, role="destination")),
            ),
            Instruction(
                1,
                "m_stx",
                (const(0x12345678), const(0, 16, "right"), reg(64, role="destination")),
            ),
        )
    else:
        instructions = (
            Instruction(
                0,
                "m_stx",
                (const(0, 32), const(0, 16, "right"), reg(role="destination")),
            ),
            Instruction(
                1,
                "m_ldx",
                (const(0, 16), reg(role="right"), reg(128, role="destination")),
            ),
            Instruction(2, "m_ret", (reg(128),)),
        )
    function = FunctionInput("public-memory-fixture", 0, (Block(0, (), instructions),))
    identity = replace(
        original.identity,
        function_id=function.function_id,
        input_digest=digest(function),
        wire_version="flow-wire/2" if v2 else "flow-wire/1",
    )
    memory = build_memory_graph(Snapshot(identity, function, identity.snapshot_id))
    pointer = next(
        e.node_id for e in memory.program.entry_storage if e.storage.bit_offset == 0
    )
    return memory, pointer


@pytest.fixture
def harness(flow_fixture, monkeypatch, tmp_path):  # noqa: F811
    module, server = flow_fixture
    service = module._service()
    memory, _ = memory_fixture()
    identity = memory.graph.snapshot.identity
    scope = RuntimeScope(
        identity.namespace,
        identity.semantic_digest,
        identity.binary_digest,
        identity.profile_digest,
        identity.rule_digest,
        identity.summary_digest,
        identity.policy_digest,
    )
    store = Store(
        tmp_path / "public-store", scope, "public-integration-owner-secret-000001"
    )
    submissions = []

    def submit(kind, request, key, **kwargs):
        submissions.append((kind, request, key))
        return "submitted-job"

    runtime = types.SimpleNamespace(store=store, submit=submit)
    monkeypatch.setattr(service, "get_runtime", lambda *args: runtime)
    monkeypatch.setattr(service, "_request_runtime", lambda *args: runtime)
    monkeypatch.setattr(service, "context", lambda: {"routing": {}})
    monkeypatch.setattr(service, "_context_for_request", lambda *args, **kwargs: {})
    yield module, service, store, submissions, server
    store.close()


def run_implicit(harness, *, mixed=False, legacy=False, v2=False, label="user"):
    module, service, store, submitted, _ = harness
    memory, pointer = memory_fixture(v2=v2)
    source_id = store.put_artifact("analysis", memory.program.to_data())
    seeds = (
        []
        if legacy
        else [
            PointeeSeed(
                pointer, ByteRange(0, 8), Labels((label,)), "analyst_assumed_exact"
            ).to_data()
        ]
    )
    if mixed or legacy:
        seeds.append(Seed(pointer, Labels(("address",))).to_data())
    request_seeds = to_wire_v2(seeds) if v2 else seeds
    assert (
        module.flow_create_implicit_analysis(
            source_id, request_seeds, "implicit-request"
        )["job_id"]
        == "submitted-job"
    )
    ctx = types.SimpleNamespace(check=lambda: None)
    extracted = service._extract_implicit(ctx, submitted[-1][1])
    return memory, pointer, service._analyze_implicit(ctx, extracted)


def pages(call, artifact):
    result, cursor = [], None
    while True:
        page = call(artifact, cursor=cursor, limit=1)
        assert "items" in page, page
        result.extend(page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            return result, page["metadata"]


@pytest.mark.parametrize("mixed", [False, True])
def test_pointee_handler_persists_exact_tail_and_replayable_certificate(harness, mixed):
    module, _, store, _, _ = harness
    memory, pointer, result = run_implicit(harness, mixed=mixed)
    raw = store.artifact(result["implicit_artifact"])
    assert raw["schema_version"] == "flow-implicit-artifact/3"
    facts, metadata = pages(
        module.flow_get_implicit_analysis, result["implicit_artifact"]
    )
    load_id = next(n.node_id for n in memory.graph.nodes if n.kind == "Load")
    fact = next(
        item for item in facts if item["type"] == "fact" and item["node_id"] == load_id
    )
    assert fact["explicit_bit_ranges"] == [
        {"label": "user", "bit_offset": 32, "width_bits": 32}
    ]
    pointer_fact = next(
        item for item in facts if item["type"] == "fact" and item["node_id"] == pointer
    )
    assert pointer_fact["labels"]["explicit"] == (["address"] if mixed else [])
    certificate, meta = pages(
        module.flow_get_pointee_evidence, result["pointee_certificate_artifact"]
    )
    assert {item["type"] for item in certificate} >= {
        "source",
        "binding",
        "content_seed",
        "evidence",
    }
    assert "not_os_input_proof" in meta["scope"]
    assert metadata["target_executed"] is False
    explanation = module.flow_explain_implicit_analysis(
        result["implicit_artifact"], load_id
    )
    assert "items" in explanation, explanation


def test_old_whole_value_seed_retains_v2_artifact(harness):
    module, _, store, _, _ = harness
    _, _, result = run_implicit(harness, legacy=True)
    assert (
        store.artifact(result["implicit_artifact"])["schema_version"]
        == "flow-implicit-artifact/2"
    )
    assert "pointee_certificate_artifact" not in result
    assert "items" in module.flow_get_implicit_analysis(result["implicit_artifact"])


def test_v2_pointee_wire_round_trip(harness):
    module, _, _, _, _ = harness
    _, _, result = run_implicit(harness, v2=True)
    items, metadata = pages(
        module.flow_get_implicit_analysis, result["implicit_artifact"]
    )
    assert metadata["wire_version"] == "flow-wire/2"
    assert any(
        item.get("explicit_bit_ranges")
        == [
            {
                "label": "user",
                "bit_offset": {"$int": "32"},
                "width_bits": {"$int": "32"},
            }
        ]
        for item in items
    )


def test_pointee_certificate_tamper_rejected_by_public_replay(harness):
    module, _, store, _, _ = harness
    _, _, result = run_implicit(harness)
    certificate = store.artifact(result["pointee_certificate_artifact"])
    certificate["sources"][0]["interval"]["end"] = 7
    tampered = store.put_artifact("analysis", certificate)
    assert (
        module.flow_get_pointee_evidence(tampered)["schema_version"] == "flow-error/1"
    )


def run_store(harness, monkeypatch, layout, *, observed=True, v2=False):
    module, service, store, submitted, _ = harness
    memory, base = memory_fixture(callback=True, v2=v2)
    source = store.put_artifact("analysis", memory.program.to_data())
    node = next(n.node_id for n in memory.graph.nodes if n.kind == "Store")
    response = module.flow_check_store(
        source,
        node,
        base,
        {"$int": "112"} if v2 else 112,
        "Callback",
        "store-request",
        ["slots", 14] if layout["status"] != "not_requested" else [],
    )
    assert response["job_id"] == "submitted-job", response
    import importlib

    observation_module = importlib.import_module(
        service.__package__ + ".store_observation"
    )
    observation = {
        "function_observation": {
            "status": "observed",
            "target_ea": 0x12345678,
            "name": "Callback",
            "exact_entry": True,
        }
        if observed
        else {"status": "unknown", "reason": "missing_function"},
        "layout_observation": layout,
        "assumptions": ["current_idb_type_correctness"],
        "target_executed": False,
    }
    monkeypatch.setattr(
        observation_module,
        "capture_store_observation",
        lambda *args: copy.deepcopy(observation),
    )
    ctx = types.SimpleNamespace(check=lambda: None)
    return service._analyze_store_proof(
        ctx, service._extract_store_proof(ctx, submitted[-1][1])
    )


@pytest.mark.parametrize(
    "layout,observed,expected",
    [
        ({"status": "not_requested"}, True, "proven_in_scope"),
        (
            {"status": "observed", "byte_offset": 112, "width_bits": 64},
            True,
            "proven_in_scope",
        ),
        (
            {"status": "observed", "byte_offset": 120, "width_bits": 64},
            True,
            "mismatch",
        ),
        (
            {"status": "observed", "byte_offset": 112, "width_bits": 32},
            True,
            "mismatch",
        ),
        ({"status": "unknown"}, True, "unknown"),
        ({"status": "not_requested"}, False, "unknown"),
    ],
)
def test_store_handler_combines_observation_numeric_proof_and_replay(
    harness, monkeypatch, layout, observed, expected
):
    module = harness[0]
    result = run_store(harness, monkeypatch, layout, observed=observed)
    assert result["status"] == expected
    items, metadata = pages(
        lambda artifact, **kwargs: module.flow_check_store(
            artifact_id=artifact, **kwargs
        ),
        result["store_evidence_artifact"],
    )
    assert metadata["status"] == expected
    assert "not_final_registration" in metadata["scope"]
    assert any(item["type"] == "proof" for item in items) == observed
    assert metadata["target_executed"] is False


def test_store_v2_tagged_offset_and_result(harness, monkeypatch):
    result = run_store(harness, monkeypatch, {"status": "not_requested"}, v2=True)
    page = harness[0].flow_check_store(artifact_id=result["store_evidence_artifact"])
    assert page["metadata"]["wire_version"] == "flow-wire/2"
    proof = next(item for item in page["items"] if item["type"] == "proof")
    assert proof["byte_offset"] == {"$int": "112"}


def test_store_replay_rejects_modified_proof(harness, monkeypatch):
    result = run_store(harness, monkeypatch, {"status": "not_requested"})
    module, _, store, _, _ = harness
    raw = store.artifact(result["store_evidence_artifact"])
    raw["proof"]["target_ea"] += 1
    artifact = store.put_artifact("analysis", raw)
    assert (
        module.flow_check_store(artifact_id=artifact)["schema_version"]
        == "flow-error/1"
    )


def test_store_mixed_submission_and_paging_rejected(harness):
    assert (
        harness[0].flow_check_store(artifact_id="bad", target_function="Callback")[
            "schema_version"
        ]
        == "flow-error/1"
    )
    assert harness[0].flow_check_store()["schema_version"] == "flow-error/1"


def test_public_new_tools_are_readonly_and_schemas_accept_pointee_and_store(
    harness, monkeypatch
):
    from jsonschema import Draft202012Validator

    module, _, _, submitted, server = harness
    schemas = {tool["name"]: tool for tool in server._mcp_tools_list()["tools"]}
    readonly = (ROOT / "profiles/flow-readonly.txt").read_text().splitlines()
    for name in ("flow_get_pointee_evidence", "flow_check_store"):
        assert name in readonly
        assert "database" not in schemas[name]["inputSchema"]["properties"]
    _, _, result = run_implicit(harness)
    request = submitted[-1][1]
    Draft202012Validator(
        schemas["flow_create_implicit_analysis"]["inputSchema"]
    ).validate(
        {
            "ssa_artifact": request["ssa_artifact"],
            "seeds": request["seeds"],
            "request_key": "schema-request",
        }
    )
    page = module.flow_get_pointee_evidence(result["pointee_certificate_artifact"])
    Draft202012Validator(schemas["flow_get_pointee_evidence"]["outputSchema"]).validate(
        page
    )
    result = run_store(harness, monkeypatch, {"status": "not_requested"})
    page = module.flow_check_store(artifact_id=result["store_evidence_artifact"])
    Draft202012Validator(schemas["flow_check_store"]["outputSchema"]).validate(page)


def test_foreign_database_cannot_page_pointee_or_store_artifacts(
    harness, monkeypatch, tmp_path
):
    module, service, store, _, _ = harness
    _, _, implicit = run_implicit(harness)
    proof = run_store(harness, monkeypatch, {"status": "not_requested"})
    foreign = Store(
        tmp_path / "foreign",
        replace(store.scope, namespace="foreign-db"),
        "foreign-public-owner-secret-00000001",
    )
    try:
        monkeypatch.setattr(
            service, "get_runtime", lambda *args: types.SimpleNamespace(store=foreign)
        )
        assert (
            module.flow_get_pointee_evidence(implicit["pointee_certificate_artifact"])[
                "schema_version"
            ]
            == "flow-error/1"
        )
        assert (
            module.flow_check_store(artifact_id=proof["store_evidence_artifact"])[
                "schema_version"
            ]
            == "flow-error/1"
        )
    finally:
        foreign.close()


@pytest.mark.parametrize("stage", ["implicit", "store"])
def test_stale_context_prevents_analysis_artifact_publication(
    harness, monkeypatch, stage
):
    _, service, store, _, _ = harness
    memory, pointer = memory_fixture(callback=stage == "store")
    source = store.put_artifact("analysis", memory.program.to_data())
    request = {
        "ssa_artifact": source,
        "store_node_id": next(
            (n.node_id for n in memory.graph.nodes if n.kind == "Store")
        ),
        "base_node_id": pointer,
        "byte_offset": 112,
    }

    def stale(*args):
        raise ContractError("stale_database")

    monkeypatch.setattr(service, "_request_runtime", stale)
    ctx = types.SimpleNamespace(check=lambda: None)
    if stage == "implicit":
        from ida_pro_mcp.flow_core.implicit_analysis import ImplicitPolicy

        extracted = (
            memory.program,
            (
                PointeeSeed(
                    pointer, ByteRange(0, 8), Labels(("user",)), "analyst_assumed_exact"
                ),
            ),
            ImplicitPolicy(),
            request,
        )
        handler = service._analyze_implicit
    else:
        observation = {
            "function_observation": {"status": "observed", "target_ea": 0x12345678},
            "layout_observation": {"status": "not_requested"},
        }
        extracted = (memory.program, observation, request)
        handler = service._analyze_store_proof
    writes = []
    monkeypatch.setattr(store, "put_artifact", lambda *args: writes.append(args))
    with pytest.raises(ContractError, match="stale_database"):
        handler(ctx, extracted)
    assert writes == []


def test_pointee_certificate_rejects_modified_source_labels(harness):
    module, _, store, _, _ = harness
    _, _, result = run_implicit(harness)
    certificate = store.artifact(result["pointee_certificate_artifact"])
    certificate["sources"][0]["labels"]["explicit"] = ["other"]
    tampered = store.put_artifact("analysis", certificate)
    response = module.flow_get_pointee_evidence(tampered)
    assert response["schema_version"] == "flow-error/1"
    assert response["error"]["code"] == "pointee_source_digest_mismatch"


@pytest.mark.parametrize("endpoint", ["page", "explain"])
def test_implicit_rejects_valid_certificate_from_differently_labeled_job(
    harness, endpoint
):
    module, _, store, _, _ = harness
    memory, _, original = run_implicit(harness, label="user")
    _, _, other = run_implicit(harness, label="other")
    # Both certificates are individually genuine, with the same label-independent graph.
    for result in (original, other):
        assert "items" in module.flow_get_pointee_evidence(
            result["pointee_certificate_artifact"]
        )
        assert "items" in module.flow_get_implicit_analysis(result["implicit_artifact"])
    first = store.artifact(original["pointee_certificate_artifact"])
    second = store.artifact(other["pointee_certificate_artifact"])
    assert first["graph_digest"] == second["graph_digest"]
    assert store.artifact(first["bound_ssa_artifact"]) == store.artifact(
        second["bound_ssa_artifact"]
    )
    assert first["implicit_source_digest"] != second["implicit_source_digest"]
    raw = store.artifact(original["implicit_artifact"])
    raw["pointee_certificate_artifact"] = other["pointee_certificate_artifact"]
    # Match artifact references too: only the label/source digest distinguishes jobs.
    raw["source_artifact"] = second["bound_ssa_artifact"]
    raw["base_source_artifact"] = second["base_ssa_artifact"]
    mixed = store.put_artifact("analysis", raw)
    if endpoint == "page":
        response = module.flow_get_implicit_analysis(mixed)
    else:
        load = next(n.node_id for n in memory.graph.nodes if n.kind == "Load")
        response = module.flow_explain_implicit_analysis(mixed, load)
    assert response["schema_version"] == "flow-error/1"
    assert response["error"]["code"] == "implicit_pointee_source_mismatch"
