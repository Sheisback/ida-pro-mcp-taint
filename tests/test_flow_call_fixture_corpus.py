"""Independent G011 call/heap oracle and build-only corpus checks."""

import hashlib
import importlib.util
import json
import re
from pathlib import Path

from ida_pro_mcp.flow_core import digest
from ida_pro_mcp.flow_core.call_composition import CallCompositionResult
from ida_pro_mcp.flow_core.contracts import Snapshot
from ida_pro_mcp.flow_core.interproc import CallPlan
from ida_pro_mcp.flow_core.summaries import SummaryCatalog

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "tests/flow_fixtures"
SOURCE = BASE / "call_heap_anchor.c"
ORACLE = BASE / "oracles/calls.json"
MANIFESTS = BASE / "manifests/calls"
BUILDER = ROOT / "scripts/build_flow_call_anchors.py"
EXTRACTOR = ROOT / "src/ida_pro_mcp/ida_mcp/flow/extractor.py"
CATALOG = ROOT / "src/ida_pro_mcp/ida_mcp/flow/summary_catalog.py"
CALL_EXTRACTOR = ROOT / "scripts/flow_call_extract.py"
CALL_REPLAY = ROOT / "tests/flow_core/record_call_receipts.py"

SUMMARY_FUNCTIONS = {
    "call_identity",
    "call_copy",
    "call_fill",
    "call_output",
    "call_global",
    "call_alloc",
    "call_free",
}
SUPPORT_FUNCTIONS = {
    "call_output_user",
    "call_context_left",
    "call_context_right",
    "call_recursive",
    "call_candidate_increment",
    "call_indirect",
}
HEAP_HELPERS = {f"call_heap_h0{index}" for index in range(1, 5)}


def read(path):
    return json.loads(path.read_text())


def test_source_and_oracle_cover_phase_a_cases():
    oracle = read(ORACLE)
    assert oracle["schema_version"] == "flow-call-heap-oracles/1"
    assert "hand-authored" in oracle["oracle_origin"]
    assert set(oracle["reviewed_summary_functions"]) == SUMMARY_FUNCTIONS
    assert set(oracle["support_functions"]) == SUPPORT_FUNCTIONS
    assert set(oracle["observation_helpers"]) == HEAP_HELPERS
    assert set(oracle["summary_identity_fields"]) == {
        "binary_sha256",
        "callee_rva",
        "callee_snapshot_id",
        "profile_digest",
        "calling_convention",
        "signature_digest",
    }
    assert "target_must_never_execute" in oracle["status"]
    assert "no_automatic_vulnerability_verdict" in oracle["status"]
    cases = oracle["cases"]
    assert {case["oracle_id"] for case in cases} == {
        "C01",
        "C02",
        "C03",
        "C04",
        "H01",
        "H02",
        "H03",
        "H04",
    }
    for case in cases:
        for key in (
            "entrypoints",
            "seeds",
            "observations",
            "expected_relations",
            "forbidden_relations",
            "preconditions",
            "widths",
            "comparison",
        ):
            assert case[key]

    defined = set()
    for line in SOURCE.read_text().splitlines():
        if line.startswith("KEEP "):
            match = re.search(r"\b(call_[a-z0-9_]+)\s*\(", line)
            assert match, line
            defined.add(match.group(1))
    assert defined == SUMMARY_FUNCTIONS | SUPPORT_FUNCTIONS | HEAP_HELPERS
    referenced = {function for case in cases for function in case["entrypoints"]}
    assert referenced == defined


def test_oracle_preserves_effect_context_and_unknown_boundaries():
    cases = {case["oracle_id"]: case for case in read(ORACLE)["cases"]}
    c01 = cases["C01"]["observations"]
    assert c01["return_effects"] and c01["memory_effects"]
    assert any("output.memory" in effect for effect in c01["memory_effects"])
    assert not any("call_output" in effect for effect in c01["return_effects"])

    c02 = cases["C02"]["observations"]
    assert c02["shared_callee"] == "call_identity"
    assert len(c02["contexts"]) == 2 and len(c02["returns"]) == 2

    c03 = cases["C03"]["observations"]
    assert "explicit unresolved" in c03["boundary"]

    c04 = cases["C04"]["observations"]
    assert set(c04["known_candidates"]) == {
        "call_identity",
        "call_candidate_increment",
    }
    assert c04["unknown_remainder"] is True

    assert cases["H01"]["observations"]["read_lifetime_before"] == ["freed"]
    assert cases["H02"]["observations"]["after_left_free"] == {
        "left": ["freed"],
        "right": ["live"],
    }
    assert set(cases["H03"]["observations"]["post_call_lifetime"]) == {
        "live",
        "freed",
    }
    assert set(cases["H04"]["observations"]["join_lifetime"]) == {
        "live",
        "freed",
    }


def test_build_only_manifests_pin_two_reproducible_architectures():
    assert {path.name for path in MANIFESTS.iterdir()} == {
        "build.json",
        "extraction_x86_64.json",
        "extraction_arm64.json",
        "x86_64_analysis.json",
        "arm64_analysis.json",
        "public_runtime.json",
    }
    builds = read(MANIFESTS / "build.json")
    assert {build["arch"] for build in builds} == {"x86_64", "arm64"}
    all_functions = SUMMARY_FUNCTIONS | SUPPORT_FUNCTIONS | HEAP_HELPERS
    for build in builds:
        assert build["manifest_kind"] == "build_only"
        assert build["source"] == "tests/flow_fixtures/call_heap_anchor.c"
        assert build["source_sha256"] == hashlib.sha256(SOURCE.read_bytes()).hexdigest()
        assert (
            build["builder_sha256"] == hashlib.sha256(BUILDER.read_bytes()).hexdigest()
        )
        assert set(build["functions"]) == all_functions
        assert build["reproducibility"] == {
            "fresh_builds": 2,
            "binary_sha256_equal": True,
            "dwarf_sha256_equal": True,
        }
        assert build["environment"] == {"SOURCE_DATE_EPOCH": "0"}
        assert build["object_mtime"] == 0
        assert build["target_executed"] is False
        assert build["ida_receipt_recorded"] is False
        assert build["compile_command"][0] == "clang"
        assert "-fno-builtin" in build["compile_command"]
        assert build["link_command"][0] == "clang"
        assert "-Wl,-no_uuid" in build["link_command"]
        assert build["dsym_command"][0] == "dsymutil"
        assert build["companion_artifacts"] == [
            {
                "path": (
                    build["binary"]
                    + ".dSYM/Contents/Resources/DWARF/"
                    + build["binary"]
                ),
                "bundle": build["binary"] + ".dSYM",
                "placement": "sibling_of_binary",
                "sha256": build["companion_artifacts"][0]["sha256"],
                "required": True,
                "purpose": "function/source mapping",
            }
        ]


def test_public_reviewed_runtime_receipt_matches_actual_owned_call_evidence():
    receipt = read(MANIFESTS / "public_runtime.json")
    assert receipt["schema_version"] == "flow-reviewed-public-smoke/1"
    assert receipt["target_executed"] is False
    assert receipt["output_helper_native_caller"] is True
    assert receipt["limitations"] == [
        "Reviewed output memory effects retain unresolved pointer uncertainty; no definite memory write or vulnerability verdict is inferred."
    ]
    builds = {row["arch"]: row for row in read(MANIFESTS / "build.json")}
    assert len(receipt["fixtures"]) == 2
    assert {row["arch"] for row in receipt["fixtures"]} == set(builds)
    expected = {
        "call_context_left": (["identity"], [], False),
        "call_output_user": (["output"], [], False),
        "call_heap_h01": (["alloc", "free"], ["allocate", "free"], False),
        "call_heap_h03": (["alloc"], ["allocate", "opaque"], True),
        "call_recursive": (["identity"], ["opaque"], True),
        "call_indirect": ([], ["opaque"], True),
    }
    for fixture in receipt["fixtures"]:
        arch = fixture["arch"]
        extraction = read(MANIFESTS / f"extraction_{arch}.json")
        catalog = SummaryCatalog.from_data(extraction["catalog"])
        assert fixture["binary_sha256"] == builds[arch]["binary_sha256"]
        assert fixture["target_executed"] is False
        assert len(fixture["cases"]) == len(expected)
        assert {case["function"] for case in fixture["cases"]} == set(expected)
        assert {
            "flow_get_capabilities",
            "flow_create_snapshot",
            "flow_get_job",
            "flow_cancel_job",
            "flow_get_call_compositions",
        } == set(fixture["tool_calls"])
        assert fixture["tool_calls"].count("flow_get_call_compositions") == 2 * sum(
            case["page_count"] for case in fixture["cases"]
        )
        functions = {row["name"]: row for row in extraction["functions"]}
        for case in fixture["cases"]:
            kinds, effects, unknown = expected[case["function"]]
            assert case["reviewed_kinds"] == kinds
            assert case["heap_effects"] == effects
            assert case["memory_effects"] == (
                ["reachable_havoc"]
                if unknown
                else ["output"]
                if case["function"] == "call_output_user"
                else []
            )
            assert case["target_executed"] is False
            metadata = case["metadata"]
            assert metadata["catalog_digest"] == catalog.catalog_digest
            assert metadata["target_executed"] is False
            assert metadata["no_auto_vulnerability_verdict"] is True
            assert metadata["call_count"] == len(
                functions[case["function"]]["baseline"]["calls"]
            )
            assert (metadata["unknown_remainder_count"] > 0) is unknown
            assert metadata["status"] == (
                "complete_in_scope"
                if case["function"] == "call_context_left"
                else "partial"
            )
            assert type(case["page_count"]) is int
            assert case["page_count"] >= metadata["call_count"] > 0
            closure = case["closure"]
            assert closure["max_depth"] == 8 and closure["max_functions"] == 64
            assert len(closure["visited_rvas"]) <= closure["max_functions"]
            reasons = {boundary["reason"] for boundary in closure["boundaries"]}
            if case["function"] == "call_recursive":
                assert "recursive_boundary" in reasons
            if case["function"] == "call_indirect":
                assert "unresolved_indirect" in reasons
            if case["function"] == "call_heap_h01":
                assert case["page_count"] > 1
                assert "external_or_unreviewed_callee" in reasons
                state = case["state_evidence"]
                allocated, freed = state["allocation"], state["free"]
                assert allocated["transitions"] and freed["transitions"]
                oid = allocated["transitions"][0]["object_id"]
                assert freed["pointer"]["candidates"] == [
                    {"object_id": oid, "offset": 0}
                ]
                assert freed["transitions"][0]["object_id"] == oid
                assert "live" in freed["transitions"][0]["before"]["possible"]
                assert "freed" in freed["transitions"][0]["after"]["possible"]
                assert freed["transitions"][0]["strong_update"] is False
            if case["function"] == "call_heap_h03":
                state = case["state_evidence"]
                allocated, opaque = state["allocation"], state["opaque"]
                assert opaque["transitions"]
                assert (
                    opaque["transitions"][0]["object_id"]
                    == allocated["transitions"][0]["object_id"]
                )
                assert opaque["transitions"][0]["before"]["escape"] != "local"
                assert opaque["transitions"][0]["after"] == {
                    "possible": ["freed", "live", "not_allocated"],
                    "escape": "unknown",
                }
            if case["function"] == "call_output_user":
                state = case["state_evidence"]
                assert len(state["output_targets"]) == 1
                target = state["output_targets"][0]
                assert target["interval"] == {"start": 0, "end": 4}
                assert len(state["output_bytes"]) == 4
                assert [byte["offset"] for byte in state["output_bytes"]] == [
                    0,
                    1,
                    2,
                    3,
                ]
                assert all(
                    byte["object_id"] == target["object_id"]
                    and byte["labels"]["explicit"]
                    for byte in state["output_bytes"]
                )


def test_public_reviewed_runtime_receipt_is_current():
    from ida_pro_mcp.flow_core.build_identity import BUILD_ID

    receipt = read(MANIFESTS / "public_runtime.json")
    assert receipt["build_id"] == BUILD_ID
    producer = ROOT / "tests/flow_core/native_reviewed_runtime_smoke.py"
    assert (
        receipt["producer_sha256"] == hashlib.sha256(producer.read_bytes()).hexdigest()
    )
    for fixture in receipt["fixtures"]:
        assert fixture["worker_build_id"] == BUILD_ID


def test_static_ida_call_receipts_pin_catalog_runtime_and_replay():
    builds = {build["arch"]: build for build in read(MANIFESTS / "build.json")}
    extractor_hash = hashlib.sha256(EXTRACTOR.read_bytes()).hexdigest()
    catalog_hash = hashlib.sha256(CATALOG.read_bytes()).hexdigest()
    script_hash = hashlib.sha256(CALL_EXTRACTOR.read_bytes()).hexdigest()
    replay_hash = hashlib.sha256(CALL_REPLAY.read_bytes()).hexdigest()
    expected_functions = SUMMARY_FUNCTIONS | SUPPORT_FUNCTIONS | HEAP_HELPERS
    for arch in ("x86_64", "arm64"):
        extraction_path = MANIFESTS / f"extraction_{arch}.json"
        extraction = read(extraction_path)
        assert extraction["schema_version"] == "flow-call-extraction/1"
        assert extraction["arch"] == arch
        assert extraction["binary"]["sha256"] == builds[arch]["binary_sha256"]
        assert extraction["extractor_sha256"] == extractor_hash
        assert extraction["catalog_module_sha256"] == catalog_hash
        assert extraction["script_sha256"] == script_hash
        assert extraction["target_executed"] is False
        assert extraction["fresh_static_ida_extraction"] is True
        assert extraction["repeat_equal"] and extraction["roundtrip_equal"]
        catalog = SummaryCatalog.from_data(extraction["catalog"])
        assert catalog.catalog_digest == extraction["catalog_digest"]
        assert {
            summary.display_name for summary in catalog.summaries
        } == SUMMARY_FUNCTIONS
        assert {
            record["name"] for record in extraction["functions"]
        } == expected_functions
        for record in extraction["functions"]:
            baseline = record["baseline"]
            runtime = record["runtime"]
            assert (
                baseline["snapshot"]["identity"]["summary_digest"]
                == extraction["baseline_summary_digest"]
            )
            assert (
                runtime["snapshot"]["identity"]["summary_digest"]
                == catalog.catalog_digest
            )
            assert digest(Snapshot.from_data(runtime["snapshot"])) == digest(
                runtime["snapshot"]
            )
            for binding in record["bindings"]:
                plan = CallPlan.from_data(binding["plan"])
                assert plan.catalog_digest == catalog.catalog_digest
                assert plan.site.instruction_rva == binding["site"]["instruction_rva"]
            assert len(record["bindings"]) == len(record["compositions"])
            for binding, composition in zip(record["bindings"], record["compositions"]):
                result = CallCompositionResult.from_data(composition)
                assert (
                    result.plan_digest
                    == CallPlan.from_data(binding["plan"]).plan_digest
                )
                assert digest(result) == digest(composition)
        assert (
            extraction["closure"]["visited_rvas"] == extraction["closure"]["root_rvas"]
        )
        assert extraction["closure"]["boundaries"]

        replay = read(MANIFESTS / f"{arch}_analysis.json")
        assert replay["schema_version"] == "flow-call-replay/2"
        assert replay["generator_sha256"] == replay_hash
        assert (
            replay["extraction_file_sha256"]
            == hashlib.sha256(extraction_path.read_bytes()).hexdigest()
        )
        assert replay["catalog_digest"] == catalog.catalog_digest
        assert replay["c02_contexts"]["distinct"] is True
        assert "missing_reviewed_summary" in replay["c03_remainder_reasons"]
        assert replay["c04_reviewed_branches"] == []
        assert replay["c04_unknown_remainder"] is True
        assert replay["actual_composition_count"] == replay["call_plan_count"]
        assert (
            len(replay["actual_composition_digests"])
            == replay["actual_composition_count"]
        )
        cases = replay["semantic_cases"]
        assert cases["C01"]["identity_return_labels"] == ["X"]
        assert cases["C01"]["copy_destination_values"] == [0, 1, 2, 3]
        assert cases["C01"]["fill_destination_values"] == [0x5A] * 4
        assert cases["C01"]["output_values"] == [0x11, 0x22, 0x33, 0x44]
        assert cases["C01"]["output_return"] is None
        assert cases["C01"]["global_return_value"] == 7
        assert cases["C01"]["global_memory_operation"] == "global_write"
        assert cases["C02"]["left_context"] != cases["C02"]["right_context"]
        assert cases["C02"]["left_return_labels"] == ["LEFT"]
        assert cases["C02"]["right_return_labels"] == ["RIGHT"]
        assert cases["C03"]["recursive_status"] == "partial"
        assert cases["C03"]["recursive_unknown_provenance"] is True
        assert "missing_reviewed_summary" in cases["C03"]["recursive_diagnostics"]
        assert cases["C04"]["reviewed_branches"] == []
        assert cases["C04"]["status"] == "partial"
        assert cases["C04"]["return_labels"] == []
        assert cases["C04"]["unknown_provenance"] is True
        assert cases["H01"]["post_free_lifetime"] == ["freed"]
        assert cases["H02"]["after_left_free"] == {
            "left": ["freed"],
            "right": ["live"],
        }
        h02_proof = cases["H02"]["selected_free_site"]
        assert (
            h02_proof["selection"]
            == "two_allocations_dominate_and_cleanup_path_excluded"
        )
        assert len(h02_proof["allocation_instruction_rvas"]) == 2
        assert (
            h02_proof["cleanup_first_free_instruction_rva"]
            < h02_proof["selected_left_free_instruction_rva"]
            < h02_proof["later_right_free_instruction_rva"]
        )
        assert {"live", "freed"} <= set(cases["H03"]["post_call_lifetime"])
        assert cases["H03"]["post_call_escape"] == "unknown"
        assert cases["H03"]["status"] == "partial"
        assert set(cases["H04"]["join_lifetime"]) == {"live", "freed"}
        assert replay["target_executed"] is False

        spec = importlib.util.spec_from_file_location(
            "g011_fresh_replay_" + arch, CALL_REPLAY
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert module.receipt(arch) == replay


def test_builder_performs_two_fresh_builds_without_target_execution(
    monkeypatch, tmp_path
):
    import sys

    spec = importlib.util.spec_from_file_location("call_anchor_builder", BUILDER)
    assert spec is not None and spec.loader is not None
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    commands = []

    def check_output(command, **kwargs):
        assert kwargs == {"text": True}
        if command == ["clang", "--version"]:
            return "mock Apple clang"
        assert command == ["xcrun", "--show-sdk-version"]
        return "mock sdk"

    def run(command, **kwargs):
        assert kwargs["cwd"] == ROOT
        assert kwargs["check"] is True
        assert kwargs["env"]["SOURCE_DATE_EPOCH"] == "0"
        assert command[0] in {"clang", "dsymutil"}
        commands.append(command)
        if command[0] == "clang":
            path = Path(command[command.index("-o") + 1])
            path.write_bytes(("mock-" + command[2]).encode())
            return
        binary = Path(command[-1])
        dwarf = (
            binary.parent
            / (binary.name + ".dSYM")
            / "Contents/Resources/DWARF"
            / binary.name
        )
        dwarf.parent.mkdir(parents=True)
        dwarf.write_bytes(("mock-dwarf-" + binary.name).encode())

    monkeypatch.setattr(builder.subprocess, "check_output", check_output)
    monkeypatch.setattr(builder.subprocess, "run", run)
    monkeypatch.setattr(sys, "argv", ["builder", str(tmp_path / "output")])
    builder.main()

    assert len(commands) == 12
    assert [command[0] for command in commands].count("clang") == 8
    assert [command[0] for command in commands].count("dsymutil") == 4
    assert not any(command[0].startswith("call_heap_") for command in commands)
    builds = read(tmp_path / "output/build.json")
    assert len(builds) == 2
    assert all(build["reproducibility"]["fresh_builds"] == 2 for build in builds)
    assert all(build["target_executed"] is False for build in builds)
