"""Probe typed output-pointer calls with disposable, static IDA 9.3 sessions.

PYTHONPATH=src:. uv run python tests/flow_core/native_output_pointer_probe.py OUTPUT
Never executes a target binary or marks support as verified.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from ida_pro_mcp import idalib_supervisor as sm
from ida_pro_mcp.flow_core.build_identity import BUILD_ID
from native_taint_scenarios import Client
from native_typed_macho_smoke import HELPER_SOURCE, ROOT, SOURCE, build, sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--arch", choices=("x86_64", "arm64"), action="append")
    parser.add_argument("--optimization", choices=("O0", "O1"), action="append")
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix="flow-output-probe-", dir="/private/tmp"))
    os.environ["IDA_MCP_FLOW_STATE_ROOT"] = str(work / "state")
    supervisor = sm.IdalibSupervisor(
        sm.mcp,
        max_workers=1,
        worker_args=["--profile", str(ROOT / "profiles/flow-readonly.txt")],
    )
    sm.supervisor = supervisor
    report = {
        "schema_version": "flow-output-probe/1",
        "target_executed": False,
        "build_id": BUILD_ID,
        "source_sha256": sha(SOURCE),
        "helper_source_sha256": sha(HELPER_SOURCE),
        "runner_sha256": sha(__file__),
        "builder_sha256": sha(Path(__file__).with_name("native_typed_macho_smoke.py")),
        "compiler": subprocess.check_output(["clang", "--version"], text=True).strip(),
        "sdk_version": subprocess.check_output(
            ["xcrun", "--show-sdk-version"], text=True
        ).strip(),
        "work_directory": str(work),
        "runs": [],
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
                    "binary_sha256": sha(built),
                    "dwarf_sha256": sha(dwarf),
                    "compiler_flags": flags,
                    "functions": [],
                }
                report["runs"].append(row)
                try:
                    capabilities = client.call("flow_get_capabilities")
                    assert capabilities["build_id"] == BUILD_ID
                    assert capabilities["environment"]["ida_version"] == "9.3"
                    row["worker_build_id"] = capabilities["build_id"]
                    row["environment"] = capabilities["environment"]
                    for function in ("taint_write_output", "taint_call_write_output"):
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
                        memory, memory_metadata = client.pages(
                            "flow_get_memory_analysis",
                            artifact_id=result["memory_result_artifact"],
                        )
                        observation = None
                        memory_evidence = None
                        if function == "taint_call_write_output":
                            first = next(
                                item
                                for item in metadata["argument_bindings"]
                                if item["argument_index"] == 0
                            )
                            assert first["storage"]["width_bits"] == 32
                            seeds = [
                                {
                                    "node_id": node_id,
                                    "labels": {
                                        "explicit": ["argument-0"],
                                        "control": [],
                                        "unknown_provenance": False,
                                        "any_explicit_source": False,
                                        "any_control_source": False,
                                    },
                                }
                                for node_id in first["entry_node_ids"]
                            ]
                            analysis = client.wait(
                                client.call(
                                    "flow_create_implicit_analysis",
                                    ssa_artifact=result["ssa_artifact"],
                                    seeds=seeds,
                                    request_key="output-" + function,
                                )
                            )
                            facts, implicit_metadata = client.pages(
                                "flow_get_implicit_analysis",
                                artifact_id=analysis["implicit_artifact"],
                            )
                            returns = [
                                node for node in nodes if node["kind"] == "Return"
                            ]
                            assert len(returns) == 1
                            observed = next(
                                item["labels"]
                                for item in facts
                                if item["type"] == "fact"
                                and item["node_id"] == returns[0]["node_id"]
                            )
                            explanation_items, explanation_metadata = client.pages(
                                "flow_explain_implicit_analysis",
                                artifact_id=analysis["implicit_artifact"],
                                observation_node_id=returns[0]["node_id"],
                            )
                            assert (
                                explanation_metadata["analysis_status"]
                                == (implicit_metadata["status"])
                            )
                            assert (
                                explanation_metadata["observation_labels"] == observed
                            )
                            assert explanation_metadata["local_cause_count"] == 0
                            assert explanation_metadata["truncated"] is False
                            assert any(
                                item["type"] == "global_diagnostic"
                                for item in explanation_items
                            )
                            observation = {
                                "return_node": returns[0],
                                "return_labels": observed,
                                "implicit_metadata": implicit_metadata,
                                "explanation_metadata": explanation_metadata,
                                "explanation_items": explanation_items,
                            }
                            if result["derived_call_memory_evidence"]:
                                proof = result["derived_call_memory_evidence"][0]
                                evidence_items, evidence_metadata = client.pages(
                                    "flow_get_derived_call_evidence",
                                    artifact_id=proof["artifact_id"],
                                )
                                assert (
                                    evidence_metadata["proof_digest"]
                                    == proof["proof_digest"]
                                )
                                assert evidence_metadata["memory_effects"] == (
                                    "single_typed_output_write"
                                )
                                assert any(
                                    item["type"] == "derived_memory_write_effect"
                                    for item in evidence_items
                                )
                                memory_evidence = evidence_metadata
                            assert len(result["derived_call_memory_writes"]) == 1
                            assert result["derived_call_returns"] == []
                            assert (
                                "unknown_call_or_write"
                                not in result["memory_diagnostics"]
                            )
                            assert observed["explicit"] == ["argument-0"]
                            assert observed["unknown_provenance"] is False
                            assert implicit_metadata["status"] == "partial"
                        row["functions"].append(
                            {
                                "name": function,
                                "result": result,
                                "nodes": nodes,
                                "ssa_metadata": metadata,
                                "memory_items": memory,
                                "memory_metadata": memory_metadata,
                                "observation": observation,
                                "derived_memory_evidence_metadata": memory_evidence,
                            }
                        )
                        print(
                            arch,
                            optimization,
                            function,
                            result["callee_closure"],
                            result["memory_diagnostics"],
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
        args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
