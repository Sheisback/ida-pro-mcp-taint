"""Static IDA 9.3 check of low/high source bits through volatile byte memory.

PYTHONPATH=src:. uv run python tests/flow_core/native_bit_memory_probe.py OUTPUT
Never executes target binaries; IDB types are an analyst assumption.
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
from native_taint_scenarios import Client, entry_range
from native_typed_macho_smoke import HELPER_SOURCE, ROOT, SOURCE, build, sha


LABEL = {
    "explicit": ["LOW32"],
    "control": [],
    "unknown_provenance": False,
    "any_explicit_source": False,
    "any_control_source": False,
}


def selected_seed(nodes, binding):
    start = binding["storage"]["bit_offset"]
    atoms = [
        (node, entry_range(node))
        for node in nodes
        if node["kind"] == "InputValue" and node["node_id"] in binding["entry_node_ids"]
    ]
    covering = [
        (node, location)
        for node, location in atoms
        if location is not None
        and location[0] <= start
        and start + 32 <= location[0] + location[1]
    ]
    assert len(covering) == 1, "No exact type-backed lower-half input atom"
    node, location = covering[0]
    if location[1] == 32:
        return {"node_id": node["node_id"], "labels": LABEL}, "whole_atom"
    return (
        {
            "kind": "bit_range",
            "schema_version": 1,
            "node_id": node["node_id"],
            "labels": LABEL,
            "bit_offset": start - location[0],
            "width_bits": 32,
        },
        "bit_range",
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--arch", choices=("x86_64", "arm64"), action="append")
    parser.add_argument("--optimization", choices=("O0", "O1"), action="append")
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix="flow-bit-memory-", dir="/private/tmp"))
    os.environ["IDA_MCP_FLOW_STATE_ROOT"] = str(work / "state")
    supervisor = sm.IdalibSupervisor(
        sm.mcp,
        max_workers=1,
        worker_args=["--profile", str(ROOT / "profiles/flow-readonly.txt")],
    )
    sm.supervisor = supervisor
    report = {
        "schema_version": "flow-bit-memory-probe/1",
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
                    for function, expected, expected_status, require_load in (
                        (
                            "taint_low32_roundtrip",
                            ["LOW32"],
                            "complete_in_scope",
                            False,
                        ),
                        ("taint_high32_roundtrip", [], "complete_in_scope", False),
                        ("taint_bit_output_low", ["LOW32"], "partial", True),
                        ("taint_bit_output_high", [], "partial", True),
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
                        binding = next(
                            item
                            for item in metadata["argument_bindings"]
                            if item["argument_index"] == 0
                        )
                        assert binding["storage"]["width_bits"] == 64
                        seed, mode = selected_seed(nodes, binding)
                        analysis = client.wait(
                            client.call(
                                "flow_create_implicit_analysis",
                                ssa_artifact=result["ssa_artifact"],
                                seeds=[seed],
                                request_key="bit-memory-" + function,
                            )
                        )
                        facts, implicit_metadata = client.pages(
                            "flow_get_implicit_analysis",
                            artifact_id=analysis["implicit_artifact"],
                        )
                        returns = [node for node in nodes if node["kind"] == "Return"]
                        assert len(returns) == 1 and returns[0]["width_bits"] == 32
                        observed = next(
                            item["labels"]
                            for item in facts
                            if item["type"] == "fact"
                            and item["node_id"] == returns[0]["node_id"]
                        )
                        memory, memory_metadata = client.pages(
                            "flow_get_memory_analysis",
                            artifact_id=result["memory_result_artifact"],
                        )
                        row["functions"].append(
                            {
                                "name": function,
                                "nodes": nodes,
                                "ssa_metadata": metadata,
                                "source_mode": mode,
                                "seed": seed,
                                "return_labels": observed,
                                "implicit_metadata": implicit_metadata,
                                "implicit_items": facts,
                                "memory_metadata": memory_metadata,
                                "memory_items": memory,
                                "snapshot_result": result,
                                "load_count": sum(
                                    node["kind"] == "Load" for node in nodes
                                ),
                                "store_count": sum(
                                    node["kind"] == "Store" for node in nodes
                                ),
                            }
                        )
                        assert any(item["kind"] == "Store" for item in nodes)
                        assert observed["explicit"] == expected
                        assert observed["unknown_provenance"] is False
                        assert (
                            "bit_seed_byte_store_widened"
                            not in implicit_metadata["diagnostics"]
                        )
                        assert implicit_metadata["status"] == expected_status
                        if require_load:
                            assert row["functions"][-1]["load_count"] >= 1
                            assert len(result["derived_call_memory_writes"]) == 1
                            assert (
                                "unknown_call_or_write"
                                not in result["memory_diagnostics"]
                            )
                        print(
                            arch,
                            optimization,
                            function,
                            mode,
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
        args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
