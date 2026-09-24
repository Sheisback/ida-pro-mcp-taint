"""Licensed IDA 9.3 static Return/argloc matrix over disposable Mach-O copies.

PYTHONPATH=src:tests/flow_core:. uv run python \
  tests/flow_core/native_return_matrix_smoke.py OUTPUT_JSON
Never execute the linked target binaries.
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
from native_taint_scenarios import Client

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/flow_fixtures/taint_return_matrix.c"

# Source-level expectations, not copied from an engine result.
CASES = {
    "return_u8": (8, 8, True),
    "return_u16": (16, 16, True),
    "return_u32": (32, 32, True),
    "return_u64": (64, 64, True),
    "return_constant": (32, 32, False),
    "return_sign_extend": (32, 8, True),
    "return_zero_extend": (32, 8, True),
    "return_multi": (32, 32, True),
    "return_unused": (32, 32, False),
    "return_pointer": (64, 64, True),
    "return_void": (None, 64, None),
    "return_noreturn": (None, None, None),
    "return_stack_ninth": (32, 32, None),
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build(directory, arch, optimization):
    directory.mkdir(parents=True)
    obj = directory / "returns.o"
    binary = directory / "returns"
    flags = [
        "-arch", arch, "-" + optimization, "-g", "-fno-builtin",
        "-fno-stack-protector", "-fdebug-compilation-dir=.",
        f"-ffile-prefix-map={ROOT}=.",
    ]
    subprocess.run(["clang", *flags, "-c", str(SOURCE), "-o", str(obj)], check=True)
    # ld records the input object's mtime in Mach-O N_OSO; pin it so two
    # genuinely independent builds remain byte-identical across seconds.
    os.utime(obj, (0, 0))
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
    dwarf = directory / "returns.dSYM/Contents/Resources/DWARF/returns"
    assert dwarf.is_file()
    return binary, dwarf, flags


def seed(name, binding):
    labels = {
        "explicit": [name],
        "control": [],
        "unknown_provenance": False,
        "any_explicit_source": False,
        "any_control_source": False,
    }
    return [
        {"node_id": identifier, "labels": labels}
        for identifier in binding["entry_node_ids"]
    ]


def return_labels(client, snapshot_result, returned, binding, name, request_key):
    queued = client.call(
        "flow_create_implicit_analysis",
        ssa_artifact=snapshot_result["ssa_artifact"],
        seeds=seed(name, binding),
        request_key=request_key,
    )
    result = client.wait(queued)
    facts, metadata = client.pages(
        "flow_get_implicit_analysis", artifact_id=result["implicit_artifact"]
    )
    labels = next(
        row["labels"] for row in facts
        if row["type"] == "fact" and row["node_id"] == returned["node_id"]
    )
    return labels, metadata["status"]


def observe(client, name, expected, profile, abi, arch):
    return_width, first_width, first_depends = expected
    snapshot = client.wait(
        client.call(
            "flow_create_snapshot",
            function=name,
            profile=profile,
            abi=abi,
            routing_mode="analyst_selected",
            request_key="return-" + name,
        )
    )
    assert snapshot["target_executed"] is False
    nodes, metadata = client.pages(
        "flow_get_function_ssa", artifact_id=snapshot["ssa_artifact"]
    )
    returns = [node for node in nodes if node["kind"] == "Return"]
    exits = [node for node in nodes if node["kind"] == "Exit"]
    diagnostics = {item["code"] for item in metadata["diagnostics"]}
    bindings = metadata["argument_bindings"]
    row = {
        "name": name,
        "snapshot_id": snapshot["snapshot_id"],
        "return_widths": [item["width_bits"] for item in returns],
        "exit_count": len(exits),
        "argument_bindings": [
            {
                "index": item["argument_index"],
                "width_bits": item["storage"]["width_bits"],
                "entry_node_ids": item["entry_node_ids"],
                "idb_pointer_type_assumption": item[
                    "idb_pointer_type_assumption"
                ],
            }
            for item in bindings
        ],
        "diagnostic_codes": sorted(diagnostics),
        "target_executed": False,
    }
    if name == "return_noreturn":
        assert not returns and not exits and not bindings
        assert "typed_noreturn" in diagnostics
        assert snapshot["analysis"] == "partial"
        return row
    first = next(item for item in bindings if item["argument_index"] == 0)
    assert first["storage"]["width_bits"] == first_width
    assert first["entry_node_ids"]
    if name == "return_void":
        assert not returns and len(exits) == 1
        assert "typed_void_return" in diagnostics
        assert [item["width_bits"] for item in row["argument_bindings"]] == [64, 32]
        assert [item["idb_pointer_type_assumption"] for item in row["argument_bindings"]] == [True, False]
        return row
    assert len(returns) == 1 and not exits
    returned = returns[0]
    assert returned["width_bits"] == return_width
    assert first["idb_pointer_type_assumption"] is (name == "return_pointer")
    assert "typed_return_location" in diagnostics
    evidence, _ = client.pages(
        "flow_get_evidence",
        artifact_id=snapshot["graph_artifact"],
        evidence_ids=returned["evidence_ids"],
    )
    assert evidence and all(
        item.get("synthetic") and not item.get("source_eas") for item in evidence
    )
    observed, status = return_labels(
        client, snapshot, returned, first, "X", "first-" + name
    )
    assert status == "complete_in_scope"
    row["first_argument_labels"] = observed
    row["implicit_status"] = status
    if name == "return_stack_ninth":
        expected_indices = list(range(6 if arch == "x86_64" else 8))
        assert [item["index"] for item in row["argument_bindings"]] == expected_indices
        assert "typed_argument_unmapped" in diagnostics
        assert observed["explicit"] == [] and observed["unknown_provenance"] is True
        return row
    assert observed["explicit"] == (["X"] if first_depends else [])
    assert observed["unknown_provenance"] is False
    if name == "return_multi":
        assert any(node["kind"] == "Branch" for node in nodes)
        second = next(item for item in bindings if item["argument_index"] == 1)
        selector, selector_status = return_labels(
            client, snapshot, returned, second, "FLAG", "selector-" + name
        )
        assert selector_status == "complete_in_scope"
        assert selector["explicit"] == []
        assert selector["control"] == ["FLAG"]
        assert selector["unknown_provenance"] is False
        row["selector_labels"] = selector
    if name == "return_unused":
        second = next(item for item in bindings if item["argument_index"] == 1)
        used, used_status = return_labels(
            client, snapshot, returned, second, "USED", "used-" + name
        )
        assert used_status == "complete_in_scope"
        assert used["explicit"] == ["USED"] and not used["unknown_provenance"]
        row["second_argument_labels"] = used
    return row


def main(output):
    work = Path(tempfile.mkdtemp(prefix="flow-return-matrix-", dir="/private/tmp"))
    os.environ["IDA_MCP_FLOW_STATE_ROOT"] = str(work / "state")
    supervisor = sm.IdalibSupervisor(
        sm.mcp, max_workers=1,
        worker_args=["--profile", str(ROOT / "profiles/flow-readonly.txt")],
    )
    sm.supervisor = supervisor
    receipt = {
        "schema_version": "flow-return-matrix-smoke/1",
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
            for optimization in ("O0", "O1"):
                built, dwarf, flags = build(work / arch / optimization / "build", arch, optimization)
                second, second_dwarf, _ = build(
                    work / arch / optimization / "rebuild", arch, optimization
                )
                assert sha(built) == sha(second), "nonreproducible_binary_build"
                assert sha(dwarf) == sha(second_dwarf), "nonreproducible_dwarf_build"
                analysis = work / arch / optimization / "analysis"
                analysis.mkdir()
                binary = analysis / built.name
                shutil.copy2(built, binary)
                shutil.copytree(str(built) + ".dSYM", str(binary) + ".dSYM")
                session = supervisor.open_session(str(binary), mode="force_headless")
                client = Client(sm, session.session_id, 0)
                run = {
                    "arch": arch,
                    "optimization": optimization,
                    "profile": profile,
                    "abi": abi,
                    "format": "FMT-MACHO",
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
                    for name, expected in CASES.items():
                        row = observe(client, name, expected, profile, abi, arch)
                        run["cases"].append(row)
                        print(arch, optimization, name, row["return_widths"], flush=True)
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
