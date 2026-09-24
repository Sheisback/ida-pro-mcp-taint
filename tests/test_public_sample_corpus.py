"""G015 public-corpus provenance, oracle, build, and static-receipt gates."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from collections import Counter
from pathlib import Path
from typing import Any, cast

import pytest

from ida_pro_mcp.flow_core import digest
from ida_pro_mcp.flow_core.analysis import Seed, analyze
from ida_pro_mcp.flow_core.contracts import Snapshot
from ida_pro_mcp.flow_core.memory import build_memory_plan
from ida_pro_mcp.flow_core.memory_analysis import analyze_memory
from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
from ida_pro_mcp.flow_core.ssa import build_ssa
from ida_pro_mcp.flow_core.states import Labels

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "tests/flow_fixtures"
PUBLIC = BASE / "public_samples"
MANIFESTS = BASE / "manifests/public_samples"
STATIC = MANIFESTS / "static"


def read(path: Path) -> Any:
    return json.loads(path.read_text())


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def builder_module():
    path = ROOT / "scripts/build_public_sample_corpus.py"
    spec = importlib.util.spec_from_file_location("public_sample_builder_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def test_authoritative_provenance_and_license_boundaries():
    provenance = read(PUBLIC / "provenance.json")
    builder = builder_module()
    assert builder.load_and_validate_provenance() == provenance
    assert provenance["svf"]["commit"] == builder.SVF_COMMIT
    assert provenance["svf"]["license"] == {
        "status": "unproven",
        "spdx": None,
        "repository_license_file": None,
        "github_api_license": None,
        "redistribution": False,
        "handling": (
            "Selected sources are fetched into an isolated build root, "
            "hash-verified, and not committed or redistributed. This is a named "
            "evidence limitation, not an inferred license grant."
        ),
    }
    assert provenance["juliet"]["license"]["spdx"] == "CC0-1.0"
    assert provenance["juliet"]["archive_sha256"] == builder.JULIET_SHA256
    assert provenance["juliet"]["published_hash_matches"] is True
    assert provenance["target_executed"] is False
    assert all(path.suffix == ".json" for path in PUBLIC.rglob("*") if path.is_file())


@pytest.mark.parametrize(
    ("section", "field", "replacement"),
    [
        ("svf", "upstream_url", "https://example.invalid/substitute.git"),
        ("svf", "commit", "0" * 40),
        ("juliet", "archive_url", "https://example.invalid/substitute.zip"),
        ("juliet", "archive_sha256", "0" * 64),
    ],
)
def test_sc01_manifest_substitution_fails_closed(
    tmp_path: Path, section: str, field: str, replacement: str
):
    manifest = copy.deepcopy(read(PUBLIC / "provenance.json"))
    manifest[section][field] = replacement
    path = tmp_path / "provenance.json"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="mismatch"):
        builder_module().load_and_validate_provenance(path)


def test_archive_or_selected_file_hash_mismatch_fails_closed(tmp_path: Path):
    builder = builder_module()
    corrupt = tmp_path / "juliet.zip"
    corrupt.write_bytes(b"not the allowlisted archive")
    with pytest.raises(ValueError, match="archive size mismatch"):
        builder.verify_juliet(corrupt)
    manifest = copy.deepcopy(read(PUBLIC / "provenance.json"))
    first = next(iter(manifest["svf"]["selected_files"]))
    manifest["svf"]["selected_files"][first] = "0" * 64
    path = tmp_path / "provenance.json"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="selected hashes mismatch"):
        builder.load_and_validate_provenance(path)


def test_svf_oracles_are_independent_native_relations_sc05():
    oracle = read(PUBLIC / "oracles/svf.json")
    assert oracle["upstream_annotations_authoritative"] is False
    assert oracle["native_mismatch_policy"].startswith("exclude_or_modify_fixture")
    assert oracle["automatic_vulnerability_verdict"] is False
    assert {case["semantic"] for case in oracle["cases"]} == {
        "pointer_copy",
        "pointer_store_load",
        "field_sensitivity",
        "cross_function_context",
    }
    for case in oracle["cases"]:
        assert case["expected_relations"] and case["forbidden_relations"]
        assert not any(
            "MAYALIAS(" in relation for relation in case["expected_relations"]
        )


def test_juliet_good_label_does_not_remove_external_provenance_sc04():
    oracle = read(PUBLIC / "oracles/juliet.json")
    assert oracle["automatic_vulnerability_verdict"] is False
    assert oracle["cwe_metadata_is_analysis_truth"] is False
    assert {case["flow_variant"] for case in oracle["cases"]} == {31, 32, 33, 34, 41}
    for case in oracle["cases"]:
        good = case["goodB2G"]
        assert good["juliet_label"] == "good"
        assert good["provenance_at_sink"] == ["external_stdin"]
        assert "data < 100" in good["sanitization"]
        assert case["bad"]["provenance_at_sink"] == ["external_stdin"]
    assert all("verdict" not in node for node in walk(oracle))


def test_reproducible_build_manifest_is_bound_to_pinned_inputs():
    provenance = read(PUBLIC / "provenance.json")
    rows = read(MANIFESTS / "build.json")
    assert len(rows) == 9
    assert {row["case_id"] for row in rows} == {
        "svf-pointer-copy",
        "svf-pointer-store-load",
        "svf-field-sensitivity",
        "svf-context-call",
        "juliet-cwe789-31",
        "juliet-cwe789-32",
        "juliet-cwe789-33",
        "juliet-cwe789-34",
        "juliet-cwe789-41",
    }
    expected_sources = {
        **provenance["svf"]["selected_files"],
        **provenance["juliet"]["selected_files"],
    }
    for row in rows:
        assert row["source_sha256"] == expected_sources[row["upstream_source"]]
        assert row["format"] == "FMT-MACHO"
        assert row["architecture"] == "x86_64"
        assert row["reproducibility"] == {
            "fresh_builds": 2,
            "binary_sha256_equal": True,
        }
        assert row["object_mtime"] == 0
        assert row["environment"] == {"SOURCE_DATE_EPOCH": "0"}
        assert row["target_executed"] is False
        assert row["ida_receipt_recorded"] is False
        assert row["builder_sha256"] == sha256(
            ROOT / "scripts/build_public_sample_corpus.py"
        )


def test_actual_ida_receipts_are_fresh_repeatable_and_input_preserving():
    rows = {row["case_id"]: row for row in read(MANIFESTS / "build.json")}
    matrix = read(STATIC / "matrix.json")
    assert matrix["build_manifest_sha256"] == sha256(MANIFESTS / "build.json")
    assert matrix["target_executed"] is False
    assert matrix["input_preserved"] is True
    assert {entry["case_id"] for entry in matrix["receipts"]} == set(rows)
    for entry in matrix["receipts"]:
        path = STATIC / entry["path"]
        receipt = read(path)
        row = rows[entry["case_id"]]
        assert entry["sha256"] == sha256(path)
        assert entry["binary_sha256"] == row["binary_sha256"]
        assert entry["target_executed"] is False
        assert entry["input_preserved"] is True
        assert receipt["schema_version"] == "flow-public-sample-static/1"
        assert receipt["binary_sha256"] == row["binary_sha256"]
        assert receipt["source_sha256"] == row["source_sha256"]
        assert receipt["environment"]["ida_version"] == "9.3"
        assert receipt["target_executed"] is False
        assert receipt["input_preserved"] is True
        assert receipt["generator_sha256"] == sha256(
            ROOT / "scripts/flow_public_sample_extract.py"
        )
        assert receipt["recorder_sha256"] == sha256(
            ROOT / "scripts/record_public_sample_receipts.py"
        )
        assert receipt["extractor_sha256"] == sha256(
            ROOT / "src/ida_pro_mcp/ida_mcp/flow/extractor.py"
        )
        assert receipt["profile"]["abi_provenance"]["case_id"] == entry["case_id"]
        assert (
            receipt["profile"]["abi_provenance"]["binary_sha256"]
            == row["binary_sha256"]
        )
        assert len(receipt["functions"]) == entry["function_count"]
        for function in receipt["functions"]:
            assert function["repeat_equal"] is True
            assert function["roundtrip_equal"] is True
            assert function["image_base"] > 0
            assert function["function_rva"] >= 0
            snapshot = Snapshot.from_data(function["snapshot"])
            assert function["canonical_digest"] == digest(snapshot)
    assert rows["svf-context-call"]["case_id"] in {
        entry["case_id"] for entry in matrix["receipts"]
    }
    assert (
        next(
            entry
            for entry in matrix["receipts"]
            if entry["case_id"] == "juliet-cwe789-41"
        )["function_count"]
        == 3
    )


def _svf_main(case_id):
    receipt = read(STATIC / f"{case_id}.json")
    function = next(
        row for row in receipt["functions"] if row["function_key"].endswith("main")
    )
    snapshot = cast(Snapshot, Snapshot.from_data(function["snapshot"]))
    program = build_ssa(snapshot, storage_model="memory")
    return function, program, analyze(program.graph), build_memory_graph(snapshot)


def _relation_signature(program):
    return Counter(node.kind for node in program.graph.nodes), Counter(
        edge.kind for edge in program.graph.edges
    )


def _assert_memory_operand_edges(program):
    for node in program.graph.nodes:
        if node.kind not in {"Load", "Store"}:
            continue
        assert node.memory_operands is not None
        incoming = [edge for edge in program.graph.edges if edge.target == node.node_id]
        assert any(
            edge.source == node.memory_operands.address
            and edge.kind == "address_dependency"
            for edge in incoming
        )
        if node.kind == "Store":
            assert node.memory_operands.data is not None
            assert any(
                edge.source == node.memory_operands.data
                and edge.kind == "memory_data_dependency"
                for edge in incoming
            )
            assert not any(
                edge.source == node.memory_operands.address
                and edge.kind == "memory_data_dependency"
                for edge in incoming
            )
            assert not any(
                edge.source == node.memory_operands.data
                and edge.kind == "address_dependency"
                for edge in incoming
            )


def test_svf_receipts_replay_through_memory_core_with_partial_boundaries():
    oracle = {
        case["case_id"]: case for case in read(PUBLIC / "oracles/svf.json")["cases"]
    }
    for case_id, case in oracle.items():
        receipt = read(STATIC / f"{case_id}.json")
        outcomes = []
        for function in receipt["functions"]:
            snapshot = cast(Snapshot, Snapshot.from_data(function["snapshot"]))
            program = build_ssa(snapshot, storage_model="memory")
            result = analyze(program.graph)
            outcomes.append((function, program, result))
            assert program.graph.snapshot == snapshot
            assert result.status == "partial"
            assert "partial_input_graph" in result.diagnostics
            assert program.graph.axes.analysis == "partial"
            if any(node.kind in {"Load", "Store"} for node in program.graph.nodes):
                memory = analyze_memory(build_memory_plan(program), ())
                assert memory.status == "partial"
                assert set(memory.diagnostics) & {
                    "unknown_address",
                    "unknown_call_or_write",
                    "unresolved_scalar_effect",
                }
        assert case["expected_relations"] and case["forbidden_relations"]
        assert any(
            set(program.diagnostics)
            & {
                "call_effects_unresolved",
                "memory_load_boundary",
                "memory_store_boundary",
                "unmodeled_memory_or_call_effect",
            }
            for _, program, _ in outcomes
        )


def test_svf_pointer_copy_has_verified_memory_signature_without_pointee_claim():
    _, program, _, memory = _svf_main("svf-pointer-copy")
    nodes, edges = _relation_signature(program)
    assert (nodes["Load"], nodes["Store"]) == (7, 4)
    # Fresh IDA extraction includes the typed entry and normal Return; the
    # address/data roles and exact memory ranges remain independently checked.
    assert nodes["Return"] == 1
    assert (
        edges["value_dependency"],
        edges["address_dependency"],
        edges["memory_data_dependency"],
    ) == (46, 12, 4)
    _assert_memory_operand_edges(program)
    assert memory.result.status == "partial"
    assert "load_range_widened" in memory.result.diagnostics
    unresolved = [access for access in memory.result.accesses if access.unresolved]
    assert len(unresolved) == 1
    assert unresolved[0].alias == "unknown"
    assert unresolved[0].precision == "range_widened"
    assert {
        (dependency.interval.start, dependency.interval.end)
        for dependency in memory.result.dependencies
        if dependency.precision == "exact" and dependency.interval is not None
    } == {(offset, offset + 1) for offset in range(16, 24)}


def test_svf_pointer_store_load_keeps_address_and_memory_data_roles_distinct():
    _, program, _, memory = _svf_main("svf-pointer-store-load")
    nodes, edges = _relation_signature(program)
    assert (nodes["Load"], nodes["Store"]) == (2, 6)
    assert nodes["Return"] == 1
    assert (
        edges["value_dependency"],
        edges["address_dependency"],
        edges["memory_data_dependency"],
    ) == (42, 8, 6)
    _assert_memory_operand_edges(program)
    assert memory.result.status == "partial"
    assert not any(access.unresolved for access in memory.result.accesses)


def test_svf_field_sensitivity_keeps_nine_exact_disjoint_stack_accesses():
    _, program, _, memory = _svf_main("svf-field-sensitivity")
    nodes, edges = _relation_signature(program)
    assert (nodes["Load"], nodes["Store"]) == (3, 6)
    assert nodes["Return"] == 1
    assert (
        edges["value_dependency"],
        edges["address_dependency"],
        edges["memory_data_dependency"],
    ) == (58, 9, 6)
    _assert_memory_operand_edges(program)
    intervals = Counter(
        (candidate.interval.start, candidate.interval.end)
        for access in memory.result.accesses
        for candidate in access.candidates
        if candidate.interval is not None
    )
    assert intervals == Counter(
        {
            (8, 16): 3,
            (16, 24): 1,
            (24, 32): 3,
            (32, 40): 1,
            (44, 48): 1,
        }
    )
    assert all(
        access.alias == "must_alias"
        and access.precision == "exact"
        and len(access.candidates) == 1
        for access in memory.result.accesses
    )
    assert (8, 40) not in intervals and (8, 48) not in intervals


def _call_node_for_observation(program, observation):
    evidence = {item.evidence_id: item for item in program.graph.evidence}
    site = (observation["block_index"], observation["instruction_index"])
    matches = []
    for node in program.graph.nodes:
        if node.kind != "Call":
            continue
        for evidence_id in node.evidence_ids:
            for observed_site in evidence[evidence_id].sites:
                if (observed_site.block_index, observed_site.instruction_index) == site:
                    matches.append(node)
    assert len(matches) == 1
    return matches[0]


def _call_observation_named(function, name):
    matches = [
        observation
        for observation in function["calls"]
        if observation["callee_name"] is not None
        and observation["callee_name"].lstrip("_") == name
    ]
    assert len(matches) == 1
    return matches[0]


def test_svf_context_calls_resolve_to_one_foo_without_merging_caller_facts():
    receipt = read(STATIC / "svf-context-call.json")
    main = next(
        row for row in receipt["functions"] if row["function_key"].endswith("main")
    )
    callee = next(
        row for row in receipt["functions"] if row["function_key"].endswith("callee")
    )
    observations = [
        observation
        for observation in main["calls"]
        if observation["callee_name"] == "_foo"
    ]
    assert len(observations) == 2
    assert {
        observation["call"]["callee_ea"] - main["image_base"]
        for observation in observations
    } == {callee["function_rva"]}
    snapshot = cast(Snapshot, Snapshot.from_data(main["snapshot"]))
    program = build_ssa(snapshot, storage_model="memory")
    call_nodes = [
        _call_node_for_observation(program, observation) for observation in observations
    ]
    assert call_nodes[0].node_id != call_nodes[1].node_id
    assert "call_effects_unresolved" in program.diagnostics
    for selected, other in ((0, 1), (1, 0)):
        label = f"caller-context-{selected}"
        result = analyze(
            program.graph,
            (Seed(call_nodes[selected].node_id, Labels((label,))),),
        )
        facts = {fact.node_id: fact for fact in result.facts}
        assert result.status == "partial"
        assert "unresolved_boundary" in result.diagnostics
        assert facts[call_nodes[selected].node_id].labels.explicit == (label,)
        assert facts[call_nodes[selected].node_id].labels.unknown_provenance is True
        assert facts[call_nodes[other].node_id].labels.explicit == ()
        assert facts[call_nodes[other].node_id].labels.unknown_provenance is True


def test_juliet_good_paths_keep_named_external_source_and_conservative_sink():
    oracle = {
        case["case_id"]: case for case in read(PUBLIC / "oracles/juliet.json")["cases"]
    }
    for case_id, case in oracle.items():
        receipt = read(STATIC / f"{case_id}.json")
        function = next(
            row
            for row in receipt["functions"]
            if "good-bad-source" in row["function_key"]
        )
        snapshot = cast(Snapshot, Snapshot.from_data(function["snapshot"]))
        program = build_ssa(snapshot)
        assert len(
            [node for node in program.graph.nodes if node.kind == "Call"]
        ) == len(function["calls"])
        source_observation = _call_observation_named(function, "fgets")
        conversion_observation = _call_observation_named(function, "strtoul")
        source = _call_node_for_observation(program, source_observation)
        result = analyze(
            program.graph,
            (Seed(source.node_id, Labels(("external_stdin",))),),
        )
        fact = next(item for item in result.facts if item.node_id == source.node_id)
        assert fact.labels.explicit == ("external_stdin",)
        assert fact.labels.unknown_provenance is True
        assert result.status == "partial"
        assert "unresolved_boundary" in result.diagnostics
        assert "call_effects_unresolved" in program.diagnostics
        memory = analyze_memory(build_memory_plan(program), ())
        assert memory.status == "partial"
        assert "unknown_call_or_write" in memory.diagnostics
        for observation in (source_observation, conversion_observation):
            assert (
                "external_memory_effects_not_modeled"
                in observation["call"]["unresolved"]
            )
            unresolved = _call_node_for_observation(program, observation)
            assert (
                next(
                    item for item in result.facts if item.node_id == unresolved.node_id
                ).labels.unknown_provenance
                is True
            )
        assert case["goodB2G"]["juliet_label"] == "good"
        assert case["goodB2G"]["provenance_at_sink"] == ["external_stdin"]
        if case["flow_variant"] == 41:
            sink = next(
                row
                for row in receipt["functions"]
                if row["function_key"] == "juliet-41-good-sink-callee"
            )
            selected = _call_observation_named(function, "goodB2GSink")
            assert (
                selected["call"]["callee_ea"] - function["image_base"]
                == sink["function_rva"]
            )
            sink_snapshot = cast(Snapshot, Snapshot.from_data(sink["snapshot"]))
            sink_program = build_ssa(sink_snapshot)
            sink_result = analyze(sink_program.graph)
            sink_observation = _call_observation_named(sink, "malloc")
        else:
            sink_program = program
            sink_result = result
            sink_observation = _call_observation_named(function, "malloc")
        sink_node = _call_node_for_observation(sink_program, sink_observation)
        sink_fact = next(
            item for item in sink_result.facts if item.node_id == sink_node.node_id
        )
        assert (
            "external_stdin" in sink_fact.labels.explicit
            or sink_fact.labels.unknown_provenance
            or sink_fact.labels.any_explicit_source
        )


def test_static_command_audit_allows_only_compilers_and_ida_sc06():
    commands = []
    for row in read(MANIFESTS / "build.json"):
        commands.extend(
            row[key]
            for key in ("compile_command", "link_command", "support_compile_command")
            if key in row
        )
    matrix = read(STATIC / "matrix.json")
    commands.extend(
        read(STATIC / row["path"])["invocation"] for row in matrix["receipts"]
    )
    assert {command[0] for command in commands} <= {"clang", "clang++", "idat"}
    for command in commands:
        joined = " ".join(command).lower()
        assert not any(
            forbidden in joined
            for forbidden in ("lldb", "gdb", "qemu", "debugserver", "frida", "poc")
        )
        if command[0] == "idat":
            assert "-A" in command and "-c" in command
            assert command[-1] == "$BINARY"
        else:
            assert "-arch" in command and "x86_64" in command


def test_receipt_hash_tampering_is_detected():
    matrix = read(STATIC / "matrix.json")
    entry = matrix["receipts"][0]
    assert entry["sha256"] == sha256(STATIC / entry["path"])
    altered = (STATIC / entry["path"]).read_bytes() + b"\n"
    assert hashlib.sha256(altered).hexdigest() != entry["sha256"]
