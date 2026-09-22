"""Build twice and statically check owned byte-branch paths through public tools.

Usage: uv run python tests/flow_core/native_path_smoke.py OUTPUT_JSON
Requires the licensed local IDA runtime and Apple clang. Never executes targets.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path("tests/flow_fixtures/path_anchor.c")
SCRIPT = Path("tests/flow_core/native_path_smoke.py")
COMPILER_VERSION = "Apple clang version 21.0.0 (clang-2100.0.123.102)"
SDK_VERSION = "26.4"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def implementation_hashes():
    paths = [
        ROOT / "src/ida_pro_mcp/ida_mcp/api_flow.py",
        ROOT / "src/ida_pro_mcp/ida_mcp/zeromcp/mcp.py",
        ROOT / "src/ida_pro_mcp/ida_mcp.py",
        ROOT / "src/ida_pro_mcp/idalib_server.py",
        ROOT / "src/ida_pro_mcp/idalib_supervisor.py",
        ROOT / "src/ida_pro_mcp/installer.py",
        ROOT / "profiles/flow-readonly.txt",
        *sorted((ROOT / "src/ida_pro_mcp/flow_core").glob("*.py")),
        *sorted((ROOT / "src/ida_pro_mcp/ida_mcp/flow").glob("*.py")),
    ]
    return {str(path.relative_to(ROOT)): sha(path) for path in paths}


def main(output):
    # Import only in the explicit licensed execution path, not pure receipt tests.
    from ida_pro_mcp import idalib_supervisor as sm
    from ida_pro_mcp.flow_core.build_identity import BUILD_ID

    work = Path(tempfile.mkdtemp(prefix="flow-native-path-", dir="/private/tmp"))
    print("Disposable build and IDB directory:", work, flush=True)
    environment = dict(os.environ, SOURCE_DATE_EPOCH="0")
    compiler = subprocess.check_output(["clang", "--version"], text=True).strip()
    sdk = subprocess.check_output(["xcrun", "--show-sdk-version"], text=True).strip()
    assert compiler.splitlines()[0] == COMPILER_VERSION, "compiler_version_mismatch"
    assert sdk == SDK_VERSION, "sdk_version_mismatch"
    os.environ["IDA_MCP_FLOW_STATE_ROOT"] = str(work / "state")
    supervisor = sm.IdalibSupervisor(
        sm.mcp,
        max_workers=1,
        worker_args=["--profile", str(ROOT / "profiles/flow-readonly.txt")],
    )
    sm.supervisor = supervisor
    anchors = []
    try:
        for arch, profile, abi in (
            ("x86_64", "X64-LE", "darwin-x86_64-sysv-derived"),
            ("arm64", "A64-LE", "darwin-aarch64"),
        ):
            binaries = []
            flags = [
                "-arch",
                arch,
                "-O1",
                "-fomit-frame-pointer",
                "-fno-stack-protector",
                "-Wl,-no_uuid",
            ]
            for index in range(2):
                directory = work / arch / str(index)
                directory.mkdir(parents=True)
                binary = directory / "path_anchor"
                subprocess.run(
                    ["clang", *flags, str(SOURCE), "-o", str(binary)],
                    cwd=ROOT,
                    env=environment,
                    check=True,
                )
                binaries.append(binary)
            hashes = [sha(binary) for binary in binaries]
            assert hashes[0] == hashes[1], ("non_reproducible_build", arch, hashes)
            binary = work / ("path_" + arch)
            shutil.copy2(binaries[0], binary)
            assert sha(binary) == hashes[0]
            session = supervisor.open_session(str(binary), mode="force_headless")
            database = session.session_id
            calls = []

            def call(name, **arguments):
                response = sm._handle_tools_call(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": name,
                            "arguments": {"database": database, **arguments},
                        },
                    }
                )
                assert response is not None
                assert not response.get("error"), response
                result = response["result"]
                assert not result.get("isError"), response
                data = result["structuredContent"]
                assert "_truncated" not in data and "_download_url" not in data
                size = len(json.dumps(data))
                assert size < 40000
                assert not data.get("error"), data
                calls.append({"tool": name, "response_chars": size, "truncated": False})
                print(arch, name, json.dumps(data)[:350], flush=True)
                return data

            def wait_job(submitted):
                for _ in range(600):
                    job = call("flow_get_job", job_id=submitted["job_id"])
                    if job["state"] in {
                        "complete",
                        "failed",
                        "cancelled",
                        "stale",
                        "interrupted",
                    }:
                        assert job["state"] == "complete", job
                        return job["result"]
                    time.sleep(0.05)
                raise AssertionError("job_timeout")

            def pages(name, **arguments):
                page = call(name, **arguments)
                items = list(page["items"])
                while page["next_cursor"]:
                    page = call(name, **arguments, cursor=page["next_cursor"])
                    items.extend(page["items"])
                return items, page["metadata"]

            tools = supervisor._worker_rpc(
                session, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            )["result"]["tools"]
            tool_names = sorted(tool["name"] for tool in tools)
            assert "flow_check_path" in tool_names
            assert not {"flow_create_path_proof", "flow_get_path_proof"} & set(
                tool_names
            )
            capabilities = call("flow_get_capabilities")
            assert capabilities["build_id"] == BUILD_ID
            result = wait_job(
                call(
                    "flow_create_snapshot",
                    function="_path_anchor",
                    profile=profile,
                    abi=abi,
                    routing_mode="analyst_selected",
                    request_key="snapshot",
                )
            )
            cfg, metadata = pages("flow_get_cfg", artifact_id=result["ssa_artifact"])
            graph, graph_metadata = pages(
                "flow_get_graph", artifact_id=result["graph_artifact"]
            )
            entry = next(block for block in cfg if not block["predecessors"])
            # Entry stubs may precede the first conditional block. Every step is
            # selected from public CFG successors, never private host analysis.
            prefix = [entry["block"]]
            by_block = {block["block"]: block for block in cfg}
            while len(by_block[prefix[-1]]["successors"]) == 1:
                successor = by_block[prefix[-1]]["successors"][0]
                assert successor not in prefix, "unanticipated_loop"
                prefix.append(successor)
            successors = by_block[prefix[-1]]["successors"]
            assert len(successors) == 2, cfg
            proofs = []
            for target in successors:
                selector = {
                    "schema_version": 1,
                    "blocks": prefix + [target],
                    "bindings": {
                        "snapshot_id": metadata["snapshot_id"],
                        "graph_digest": metadata["graph_digest"],
                        "profile_digest": metadata["profile_digest"],
                        "ruleset_digest": metadata["rule_digest"],
                        "summary_digests": [metadata["summary_digest"]],
                    },
                }
                proof_result = wait_job(
                    call(
                        "flow_check_path",
                        graph_artifact=result["graph_artifact"],
                        path=selector,
                        request_key="path-" + str(target),
                    )
                )
                proof_items, proof_metadata = pages(
                    "flow_check_path",
                    artifact_id=proof_result["path_proof_artifact"],
                    limit=2,
                )
                proofs.append(
                    {
                        "selector": selector,
                        "result": proof_result,
                        "metadata": proof_metadata,
                        "items": proof_items,
                    }
                )
            anchor = {
                "arch": arch,
                "profile": profile,
                "abi": abi,
                "compiler": compiler,
                "sdk_version": sdk,
                "flags": flags,
                "fresh_builds": 2,
                "binary_sha256": hashes,
                "copied_binary_sha256": sha(binary),
                "build_id": capabilities["build_id"],
                "environment": capabilities["environment"],
                "registered_tools": tool_names,
                "cfg": cfg,
                "graph_metadata": graph_metadata,
                "graph": graph,
                "proofs": proofs,
                "calls": calls,
                "target_executed": False,
            }
            # Keep diagnostic evidence outside the repository on failure.
            (work / (arch + "-observed.json")).write_text(
                json.dumps(anchor, indent=2) + "\n"
            )
            assert any(
                p["metadata"]["status"] == "feasible"
                and p["metadata"]["model_kind"] == "exact"
                and p["metadata"]["witness_valid"] is True
                for p in proofs
            ), anchor["proofs"]
            anchors.append(anchor)
            supervisor.close_session(database, save=False)
    finally:
        for database in list(supervisor.sessions):
            supervisor.close_session(database, save=False)
        supervisor.shutdown()
    receipt = {
        "schema_version": "flow-path-public-smoke/1",
        "target_executed": False,
        "build_id": BUILD_ID,
        "source": str(SOURCE),
        "source_sha256": sha(ROOT / SOURCE),
        "script": str(SCRIPT),
        "script_sha256": sha(ROOT / SCRIPT),
        "implementation_sha256": implementation_hashes(),
        "anchors": anchors,
    }
    Path(output).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main(*sys.argv[1:])
