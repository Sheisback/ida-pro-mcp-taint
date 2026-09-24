"""Build debug-typed owned C and check actual Return taint in static IDA 9.3.

PYTHONPATH=src:. uv run python tests/flow_core/native_typed_macho_smoke.py OUTPUT
Never executes a target. IDB types are an explicit analyst assumption.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from ida_pro_mcp import idalib_supervisor as sm
from ida_pro_mcp.flow_core.build_identity import BUILD_ID
from native_taint_scenarios import Client

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/flow_fixtures/taint_scenarios.c"
HELPER_SOURCE = ROOT / "tests/flow_fixtures/taint_helper_cases.c"
LABEL = {
    "explicit": ["argument-0"],
    "control": [],
    "unknown_provenance": False,
    "any_explicit_source": False,
    "any_control_source": False,
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build(directory, arch, optimization):
    directory.mkdir(parents=True)
    obj = directory / "taint_scenarios.o"
    helper_obj = directory / "taint_helper_cases.o"
    binary = directory / "taint_scenarios"
    flags = [
        "-arch",
        arch,
        "-" + optimization,
        "-g",
        "-fno-builtin",
        "-fno-stack-protector",
        "-fdebug-compilation-dir=.",
        f"-ffile-prefix-map={ROOT}=.",
    ]
    subprocess.run(["clang", *flags, "-c", str(SOURCE), "-o", str(obj)], check=True)
    os.utime(obj, (0, 0))  # Keep ld's N_OSO timestamp reproducible.
    subprocess.run(
        ["clang", *flags, "-c", str(HELPER_SOURCE), "-o", str(helper_obj)],
        check=True,
    )
    os.utime(helper_obj, (0, 0))
    subprocess.run(
        [
            "clang",
            "-arch",
            arch,
            "-g",
            "-Wl,-no_uuid",
            f"-Wl,-oso_prefix,{directory}/",
            str(obj),
            str(helper_obj),
            "-o",
            str(binary),
        ],
        check=True,
    )
    subprocess.run(
        ["dsymutil", "--oso-prepend-path", str(directory), str(binary)], check=True
    )
    dwarf = directory / (binary.name + ".dSYM/Contents/Resources/DWARF/" + binary.name)
    assert dwarf.is_file(), "required debug companion unavailable"
    return binary, dwarf, flags


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--arch", choices=("x86_64", "arm64"), action="append")
    parser.add_argument("--optimization", choices=("O0", "O1"), action="append")
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix="flow-typed-macho-", dir="/private/tmp"))
    os.environ["IDA_MCP_FLOW_STATE_ROOT"] = str(work / "state")
    supervisor = sm.IdalibSupervisor(
        sm.mcp,
        max_workers=1,
        worker_args=["--profile", str(ROOT / "profiles/flow-readonly.txt")],
    )
    sm.supervisor = supervisor
    receipt = {
        "schema_version": "flow-typed-macho-smoke/1",
        "target_executed": False,
        "source_sha256": sha(SOURCE),
        "helper_source_sha256": sha(HELPER_SOURCE),
        "runner_sha256": sha(__file__),
        "build_id": BUILD_ID,
        "compiler": subprocess.check_output(["clang", "--version"], text=True).strip(),
        "sdk_version": subprocess.check_output(
            ["xcrun", "--show-sdk-version"], text=True
        ).strip(),
        "work_directory": str(work),
        "runs": [],
        "limitations": [
            "IDB debug type correctness is an analyst assumption",
            "Unknown direct/indirect calls remain partial and are not promoted to reviewed summaries",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        for arch in args.arch or ["x86_64", "arm64"]:
            profile, abi = (
                ("X64-LE", "darwin-x86_64-sysv-derived")
                if arch == "x86_64"
                else ("A64-LE", "darwin-aarch64")
            )
            for optimization in args.optimization or ["O0", "O1"]:
                built, dwarf, flags = build(
                    work / arch / optimization, arch, optimization
                )
                analysis_dir = work / "analysis" / arch / optimization
                analysis_dir.mkdir(parents=True)
                binary = analysis_dir / built.name
                shutil.copy2(built, binary)
                shutil.copytree(str(built) + ".dSYM", str(binary) + ".dSYM")
                session = supervisor.open_session(str(binary), mode="force_headless")
                client = Client(sm, session.session_id, 0)
                row = {
                    "arch": arch,
                    "optimization": optimization,
                    "profile": profile,
                    "abi": abi,
                    "format": "FMT-MACHO",
                    "compiler_flags": flags,
                    "binary_sha256": sha(built),
                    "dwarf_sha256": sha(dwarf),
                    "functions": [],
                }
                receipt["runs"].append(row)
                try:
                    capabilities = client.call("flow_get_capabilities")
                    assert capabilities["build_id"] == BUILD_ID
                    assert capabilities["environment"]["ida_version"] == "9.3"
                    row["environment"] = capabilities["environment"]
                    for function in (
                        "taint_identity",
                        "taint_independent",
                        "taint_call_identity",
                        "taint_call_static_seven",
                        "taint_call_static_seven_preserve",
                        "taint_call_indirect",
                        "taint_pointer_only",
                        "taint_load_before_store",
                        "taint_store_then_load",
                    ):
                        result = client.wait(
                            client.call(
                                "flow_create_snapshot",
                                function=function,
                                profile=profile,
                                abi=abi,
                                routing_mode="analyst_selected",
                                request_key=function,
                            )
                        )
                        assert result["target_executed"] is False
                        nodes, metadata = client.pages(
                            "flow_get_function_ssa", artifact_id=result["ssa_artifact"]
                        )
                        returns = [n for n in nodes if n["kind"] == "Return"]
                        assert len(returns) == 1 and returns[0]["width_bits"] == 32
                        bindings = metadata["argument_bindings"]
                        first = next(b for b in bindings if b["argument_index"] == 0)
                        assert first["storage"]["width_bits"] == (
                            64 if function == "taint_pointer_only" else 32
                        )
                        assert first["idb_pointer_type_assumption"] is (
                            function == "taint_pointer_only"
                        )
                        assert first["entry_node_ids"]
                        seed_labels = (
                            {**LABEL, "explicit": ["PTR"]}
                            if function == "taint_pointer_only"
                            else LABEL
                        )
                        seeds = [
                            {"node_id": nid, "labels": seed_labels}
                            for nid in first["entry_node_ids"]
                        ]
                        analysis = client.wait(
                            client.call(
                                "flow_create_implicit_analysis",
                                ssa_artifact=result["ssa_artifact"],
                                seeds=seeds,
                                request_key="typed-" + function,
                            )
                        )
                        facts, implicit_metadata = client.pages(
                            "flow_get_implicit_analysis",
                            artifact_id=analysis["implicit_artifact"],
                        )
                        labels = {
                            item["node_id"]: item["labels"]
                            for item in facts
                            if item["type"] == "fact"
                        }
                        observed = labels[returns[0]["node_id"]]
                        classification = "expected_unknown"
                        derived_metadata = None
                        explanation_metadata = None
                        explanation_items = None
                        if function == "taint_identity":
                            classification = (
                                "match"
                                if implicit_metadata["status"] == "complete_in_scope"
                                and observed["explicit"] == ["argument-0"]
                                and observed["unknown_provenance"] is False
                                else "return_provenance_incomplete"
                            )
                        if function == "taint_independent":
                            classification = (
                                "extra_label"
                                if "argument-0" in observed["explicit"]
                                else "match"
                                if implicit_metadata["status"] == "complete_in_scope"
                                and observed["unknown_provenance"] is False
                                else "return_provenance_incomplete"
                            )
                        if function == "taint_call_identity":
                            proofs = result["derived_call_evidence"]
                            assert (
                                len(proofs) == len(result["derived_call_returns"]) == 1
                            )
                            derived_items, derived_metadata = client.pages(
                                "flow_get_derived_call_evidence",
                                artifact_id=proofs[0]["artifact_id"],
                            )
                            assert (
                                derived_metadata["provenance"]
                                == "derived_static_unreviewed"
                            )
                            assert (
                                derived_metadata["proof_digest"]
                                == proofs[0]["proof_digest"]
                            )
                            assert derived_metadata["memory_effects"] == "unknown"
                            assert {item["type"] for item in derived_items} == {
                                "derived_return_effect",
                                "callee_snapshot",
                            }
                            global_writes = [
                                item for item in result["derived_call_memory_writes"]
                                if "global_address" in item
                            ]
                            if global_writes:
                                assert len(global_writes) == 1
                                evidence = result["derived_call_memory_evidence"]
                                assert len(evidence) == 1
                                _, memory_metadata = client.pages(
                                    "flow_get_derived_call_evidence",
                                    artifact_id=evidence[0]["artifact_id"],
                                )
                                assert memory_metadata["memory_effects"] == (
                                    "single_fixed_global_write"
                                )
                                assert memory_metadata["proof_digest"] == (
                                    global_writes[0]["proof_digest"]
                                )
                                assert "unknown_call_or_write" not in result[
                                    "memory_diagnostics"
                                ]
                            else:
                                assert "unknown_call_or_write" in result[
                                    "memory_diagnostics"
                                ]
                            classification = (
                                "derived_return_and_global_write_scalar_partial"
                                if global_writes
                                and "argument-0" in observed["explicit"]
                                and observed["unknown_provenance"] is False
                                and implicit_metadata["status"] == "partial"
                                else "derived_return_but_effects_partial"
                                if result["derived_call_returns"]
                                and "argument-0" in observed["explicit"]
                                and observed["unknown_provenance"] is False
                                and implicit_metadata["status"] == "partial"
                                else "direct_return_unresolved"
                            )
                        if function == "taint_call_static_seven":
                            proofs = result["derived_call_evidence"]
                            classification = "constant_return_unresolved"
                            if len(proofs) == len(result["derived_call_returns"]) == 1:
                                derived_items, derived_metadata = client.pages(
                                    "flow_get_derived_call_evidence",
                                    artifact_id=proofs[0]["artifact_id"],
                                )
                                assert (
                                    derived_metadata["proof_digest"]
                                    == proofs[0]["proof_digest"]
                                )
                                assert derived_metadata["memory_effects"] == "none"
                                assert (
                                    "unknown_call_or_write"
                                    not in result["memory_diagnostics"]
                                )
                                assert {item["type"] for item in derived_items} == {
                                    "derived_return_effect",
                                    "callee_snapshot",
                                }
                                if (
                                    result["derived_call_returns"][0][
                                        "argument_indices"
                                    ]
                                    == []
                                    and not observed["explicit"]
                                    and observed["unknown_provenance"] is False
                                    and implicit_metadata["status"] == "partial"
                                ):
                                    classification = (
                                        "derived_constant_return_effects_partial"
                                    )
                            elif (
                                not proofs
                                and not result["derived_call_returns"]
                                and not any(node["kind"] == "Call" for node in nodes)
                                and implicit_metadata["status"] == "complete_in_scope"
                                and not observed["explicit"]
                                and observed["unknown_provenance"] is False
                            ):
                                # Optimizer eliminated the helper call. This
                                # validates only the optimized return, not P6.
                                classification = "optimized_constant_no_call"
                        if function == "taint_call_static_seven_preserve":
                            proofs = result["derived_call_evidence"]
                            classification = "memory_preservation_unresolved"
                            if len(proofs) == len(result["derived_call_returns"]) == 1:
                                derived_items, derived_metadata = client.pages(
                                    "flow_get_derived_call_evidence",
                                    artifact_id=proofs[0]["artifact_id"],
                                )
                                assert {item["type"] for item in derived_items} == {
                                    "derived_return_effect",
                                    "callee_snapshot",
                                }
                                if (
                                    derived_metadata["memory_effects"] == "none"
                                    and "unknown_call_or_write"
                                    not in result["memory_diagnostics"]
                                    and observed["explicit"] == ["argument-0"]
                                    and observed["unknown_provenance"] is False
                                    and implicit_metadata["status"] == "partial"
                                    and any(node["kind"] == "Load" for node in nodes)
                                ):
                                    classification = "memory_preserved_scalar_partial"
                            elif (
                                not proofs
                                and not result["derived_call_returns"]
                                and not any(node["kind"] == "Call" for node in nodes)
                                and observed["explicit"] == ["argument-0"]
                                and observed["unknown_provenance"] is False
                            ):
                                classification = "optimized_preserved_no_call"
                        if function == "taint_call_indirect":
                            assert not result["derived_call_returns"]
                            assert not result["derived_call_evidence"]
                            explanation_items, explanation_metadata = client.pages(
                                "flow_explain_implicit_analysis",
                                artifact_id=analysis["implicit_artifact"],
                                observation_node_id=returns[0]["node_id"],
                            )
                            assert (
                                explanation_metadata["observation_labels"] == observed
                            )
                            assert explanation_metadata["local_cause_count"] > 0
                            assert any(
                                item["type"] == "cause" for item in explanation_items
                            )
                            assert (
                                implicit_metadata["status"] == "partial"
                                or observed["unknown_provenance"]
                            ), "Unreviewed call cannot be declared complete and clean"
                        if function in {
                            "taint_pointer_only", "taint_load_before_store"
                        }:
                            explanation_items, explanation_metadata = client.pages(
                                "flow_explain_implicit_analysis",
                                artifact_id=analysis["implicit_artifact"],
                                observation_node_id=returns[0]["node_id"],
                            )
                            reasons = {
                                item.get("reason_code") for item in explanation_items
                                if item["type"] == "cause"
                            }
                            classification = (
                                "typed_pointee_unknown_no_source_taint"
                                if not observed["explicit"]
                                and observed["unknown_provenance"] is True
                                and implicit_metadata["status"] == "complete_in_scope"
                                and explanation_metadata["truncated"] is False
                                and "possible_uninitialized_memory" in reasons
                                else "typed_alias_regression"
                            )
                        if function == "taint_store_then_load":
                            classification = (
                                "typed_store_then_load_exact"
                                if observed["explicit"] == ["argument-0"]
                                and observed["unknown_provenance"] is False
                                and implicit_metadata["status"] == "complete_in_scope"
                                else "typed_store_then_load_regression"
                            )
                        row["functions"].append(
                            {
                                "name": function,
                                "classification": classification,
                                "snapshot_result": result,
                                "derived_evidence_metadata": derived_metadata,
                                "explanation_metadata": explanation_metadata,
                                "explanation_items": explanation_items,
                                "argument_bindings": bindings,
                                "return_node": returns[0],
                                "return_labels": observed,
                                "implicit_metadata": implicit_metadata,
                                "ssa_diagnostics": metadata["diagnostics"],
                            }
                        )
                        print(
                            arch,
                            optimization,
                            function,
                            classification,
                            implicit_metadata["status"],
                            observed,
                            flush=True,
                        )
                finally:
                    supervisor.close_session(session.session_id, save=False)
                    row["closed_save_false"] = True
                    row["input_preserved"] = sha(binary) == sha(built)
                    assert row["input_preserved"]
    finally:
        for database in list(supervisor.sessions):
            supervisor.close_session(database, save=False)
        supervisor.shutdown()
        args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    if any(
        function["classification"]
        not in {
            "match",
            "expected_unknown",
            "derived_return_but_effects_partial",
            "derived_return_and_global_write_scalar_partial",
            "derived_constant_return_effects_partial",
            "optimized_constant_no_call",
            "memory_preserved_scalar_partial",
            "optimized_preserved_no_call",
            "typed_pointee_unknown_no_source_taint",
            "typed_store_then_load_exact",
        }
        for run in receipt["runs"]
        for function in run["functions"]
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
