"""Static IDA 9.3 two-target call proof; never execute owned target binaries.

PYTHONPATH=src:tests/flow_core:. uv run python \
  tests/flow_core/native_finite_indirect_smoke.py OUTPUT_JSON
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from ida_pro_mcp import idalib_supervisor as sm
from ida_pro_mcp.flow_core.build_identity import BUILD_ID
from native_taint_scenarios import Client, entry_range

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/flow_fixtures/taint_finite_indirect.c"
LABEL = {
    "explicit": ["X"],
    "control": [],
    "unknown_provenance": False,
    "any_explicit_source": False,
    "any_control_source": False,
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build(directory, arch):
    directory.mkdir(parents=True)
    obj = directory / "finite.o"
    binary = directory / "finite"
    flags = [
        "-arch", arch, "-O1", "-g", "-fno-builtin", "-fno-stack-protector",
        "-fdebug-compilation-dir=.", f"-ffile-prefix-map={ROOT}=.",
    ]
    subprocess.run(["clang", *flags, "-c", str(SOURCE), "-o", str(obj)], check=True)
    os.utime(obj, (0, 0))  # Mach-O N_OSO otherwise embeds this mtime.
    subprocess.run(
        [
            "clang", "-arch", arch, "-g", "-Wl,-no_uuid",
            f"-Wl,-oso_prefix,{directory}/", str(obj), "-o", str(binary),
        ],
        check=True,
    )
    subprocess.run(
        ["dsymutil", "--oso-prepend-path", str(directory), str(binary)], check=True
    )
    dwarf = directory / "finite.dSYM/Contents/Resources/DWARF/finite"
    assert dwarf.is_file()
    return binary, dwarf, flags


def main(output):
    work = Path(tempfile.mkdtemp(prefix="flow-finite-indirect-", dir="/private/tmp"))
    os.environ["IDA_MCP_FLOW_STATE_ROOT"] = str(work / "state")
    supervisor = sm.IdalibSupervisor(
        sm.mcp,
        max_workers=1,
        worker_args=["--profile", str(ROOT / "profiles/flow-readonly.txt")],
    )
    sm.supervisor = supervisor
    receipt = {
        "schema_version": "flow-finite-indirect-smoke/1",
        "source_sha256": sha(SOURCE),
        "runner_sha256": sha(__file__),
        "build_id": BUILD_ID,
        "compiler": subprocess.check_output(["clang", "--version"], text=True).strip(),
        "sdk_version": subprocess.check_output(
            ["xcrun", "--show-sdk-version"], text=True
        ).strip(),
        "target_executed": False,
        "work_directory": str(work),
        "runs": [],
        "support_promoted": False,
        "vulnerability_verdict": False,
    }
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        for arch, profile, abi in (
            ("x86_64", "X64-LE", "darwin-x86_64-sysv-derived"),
            ("arm64", "A64-LE", "darwin-aarch64"),
        ):
            built, dwarf, flags = build(work / arch / "build", arch)
            second, second_dwarf, _ = build(work / arch / "rebuild", arch)
            assert sha(built) == sha(second), "nonreproducible_binary_build"
            assert sha(dwarf) == sha(second_dwarf), "nonreproducible_dwarf_build"
            analysis = work / arch / "analysis"
            analysis.mkdir()
            binary = analysis / built.name
            shutil.copy2(built, binary)
            shutil.copytree(str(built) + ".dSYM", str(binary) + ".dSYM")
            session = supervisor.open_session(str(binary), mode="force_headless")
            client = Client(sm, session.session_id, 0)
            run = {
                "arch": arch,
                "profile": profile,
                "abi": abi,
                "flags": flags,
                "binary_sha256": sha(built),
                "dwarf_sha256": sha(dwarf),
                "fresh_builds": 2,
                "binary_sha256_equal": True,
                "dwarf_sha256_equal": True,
                "cases": [],
            }
            receipt["runs"].append(run)
            try:
                capabilities = client.call("flow_get_capabilities")
                assert capabilities["build_id"] == BUILD_ID
                assert capabilities["environment"]["ida_version"] == "9.3"
                run["environment"] = capabilities["environment"]
                for name in (
                    "finite_choose",
                    "finite_choose_constants",
                    "finite_choose_unknown",
                ):
                    result = client.wait(
                        client.call(
                            "flow_create_snapshot",
                            function=name,
                            profile=profile,
                            abi=abi,
                            routing_mode="analyst_selected",
                            request_key=name,
                        )
                    )
                    assert result["target_executed"] is False
                    print(
                        arch,
                        name,
                        "closure",
                        json.dumps(result["callee_closure"]),
                        "indirect_effects",
                        len(result.get("derived_indirect_returns", [])),
                        flush=True,
                    )
                    nodes, metadata = client.pages(
                        "flow_get_function_ssa", artifact_id=result["ssa_artifact"]
                    )
                    returns = [node for node in nodes if node["kind"] == "Return"]
                    assert len(returns) == 1 and returns[0]["width_bits"] == 32
                    first = next(
                        row for row in metadata["argument_bindings"]
                        if row["argument_index"] == 0
                    )
                    assert first["storage"]["width_bits"] == 32
                    seeds = [
                        {"node_id": identifier, "labels": LABEL}
                        for identifier in first["entry_node_ids"]
                    ]
                    implicit = client.wait(
                        client.call(
                            "flow_create_implicit_analysis",
                            ssa_artifact=result["ssa_artifact"],
                            seeds=seeds,
                            request_key="finite-" + name,
                        )
                    )
                    facts, implicit_metadata = client.pages(
                        "flow_get_implicit_analysis",
                        artifact_id=implicit["implicit_artifact"],
                    )
                    labels = next(
                        item["labels"] for item in facts
                        if item["type"] == "fact"
                        and item["node_id"] == returns[0]["node_id"]
                    )
                    evidence_metadata = []
                    evidence_kinds = []
                    high_only_labels = None
                    selector_labels = None
                    proofs = result.get("derived_indirect_returns", [])
                    evidence = result.get("derived_indirect_evidence", [])
                    if name == "finite_choose":
                        assert len(proofs) == len(evidence) >= 1
                        assert len({ea for proof in proofs for ea in proof["target_eas"]}) == 2
                        assert all(proof["argument_indices"] == [0] for proof in proofs)
                        assert labels["explicit"] == ["X"]
                        assert labels["unknown_provenance"] is False
                        for proof, reference in zip(proofs, evidence, strict=True):
                            items, one_metadata = client.pages(
                                "flow_get_derived_call_evidence",
                                artifact_id=reference["artifact_id"],
                            )
                            evidence_metadata.append(one_metadata)
                            evidence_kinds.extend(item["type"] for item in items)
                            assert one_metadata["provenance"] == (
                                "derived_static_finite_indirect"
                            )
                            assert one_metadata["proof_digest"] == reference[
                                "proof_digest"
                            ]
                            assert one_metadata["candidate_count"] == len(
                                proof["target_eas"]
                            )
                        assert evidence_kinds.count("callee_snapshot") == 2
                        high_entries = [
                            node for node in nodes
                            if node["kind"] == "InputValue"
                            and entry_range(node)
                            == (first["storage"]["bit_offset"] + 32, 32)
                        ]
                        assert len(high_entries) == 1
                        high_seed = {
                            "node_id": high_entries[0]["node_id"],
                            "labels": {**LABEL, "explicit": ["HIGH_ONLY"]},
                        }
                        high_job = client.wait(
                            client.call(
                                "flow_create_implicit_analysis",
                                ssa_artifact=result["ssa_artifact"],
                                seeds=[high_seed],
                                request_key="finite-high-" + name,
                            )
                        )
                        high_facts, _ = client.pages(
                            "flow_get_implicit_analysis",
                            artifact_id=high_job["implicit_artifact"],
                        )
                        high_only_labels = next(
                            item["labels"] for item in high_facts
                            if item["type"] == "fact"
                            and item["node_id"] == returns[0]["node_id"]
                        )
                        assert "HIGH_ONLY" not in high_only_labels["explicit"]
                        assert high_only_labels["unknown_provenance"] is False
                    elif name == "finite_choose_unknown":
                        assert len(proofs) == len(evidence)
                        assert any(
                            row["reason"] in {
                                "finite_target_set_incomplete", "unresolved_indirect"
                            }
                            for row in result["callee_closure"]["boundaries"]
                        )
                        assert labels["unknown_provenance"] is True
                    else:
                        if proofs:
                            assert len(proofs) == len(evidence)
                            assert len({ea for proof in proofs for ea in proof["target_eas"]}) == 2
                            assert all(proof["argument_indices"] == [] for proof in proofs)
                            assert "X" not in labels["explicit"]
                            assert labels["unknown_provenance"] is False
                        else:
                            # A compiler-proven constant without an indirect
                            # call is not counted as an interprocedural proof.
                            assert not any(node["kind"] == "Call" for node in nodes)
                            assert "X" not in labels["explicit"]
                        second = next(
                            row for row in metadata["argument_bindings"]
                            if row["argument_index"] == 1
                        )
                        selector_seeds = [
                            {
                                "node_id": identifier,
                                "labels": {**LABEL, "explicit": ["SELECTOR"]},
                            }
                            for identifier in second["entry_node_ids"]
                        ]
                        selector_job = client.wait(
                            client.call(
                                "flow_create_implicit_analysis",
                                ssa_artifact=result["ssa_artifact"],
                                seeds=selector_seeds,
                                request_key="finite-selector-" + name,
                            )
                        )
                        selector_facts, _ = client.pages(
                            "flow_get_implicit_analysis",
                            artifact_id=selector_job["implicit_artifact"],
                        )
                        selector_labels = next(
                            item["labels"] for item in selector_facts
                            if item["type"] == "fact"
                            and item["node_id"] == returns[0]["node_id"]
                        )
                        assert "SELECTOR" in selector_labels["control"]
                        assert selector_labels["unknown_provenance"] is False
                    run["cases"].append(
                        {
                            "name": name,
                            "snapshot_result": result,
                            "return_labels": labels,
                            "implicit_status": implicit_metadata["status"],
                            "evidence_metadata": evidence_metadata,
                            "evidence_kinds": evidence_kinds,
                            "high_only_labels": high_only_labels,
                            "selector_labels": selector_labels,
                        }
                    )
                    print(arch, name, labels, flush=True)
                    output.write_text(json.dumps(receipt, indent=2) + "\n")
            finally:
                supervisor.close_session(session.session_id, save=False)
                run["closed_save_false"] = True
                run["input_preserved"] = sha(binary) == sha(built)
                output.write_text(json.dumps(receipt, indent=2) + "\n")
    finally:
        for database in list(supervisor.sessions):
            supervisor.close_session(database, save=False)
        supervisor.shutdown()
    assert all(run["closed_save_false"] and run["input_preserved"] for run in receipt["runs"])
    output.write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main(sys.argv[1])
