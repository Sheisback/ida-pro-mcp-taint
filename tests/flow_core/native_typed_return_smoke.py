"""Verify an uninstrumented typed return in disposable IDA 9.3 static analysis.

PYTHONPATH=src:. uv run python tests/flow_core/native_typed_return_smoke.py OUTPUT
Never executes the fixture. This is an exact local observation, not ISA support.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

from ida_pro_mcp import idalib_supervisor as sm
from ida_pro_mcp.flow_core.build_identity import BUILD_ID

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tests/typed_fixture.elf"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main(output):
    work = Path(tempfile.mkdtemp(prefix="flow-typed-return-", dir="/private/tmp"))
    binary = work / SOURCE.name
    shutil.copy2(SOURCE, binary)
    os.environ["IDA_MCP_FLOW_STATE_ROOT"] = str(work / "state")
    supervisor = sm.IdalibSupervisor(
        sm.mcp,
        max_workers=1,
        worker_args=["--profile", str(ROOT / "profiles/flow-readonly.txt")],
    )
    sm.supervisor = supervisor
    session = None
    try:
        session = supervisor.open_session(str(binary), mode="force_headless")

        def call(name, **arguments):
            response = sm._handle_tools_call(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": name,
                        "arguments": {"database": session.session_id, **arguments},
                    },
                }
            )
            assert response is not None and not response.get("error"), response
            result = response["result"]
            assert not result.get("isError"), response
            data = result["structuredContent"]
            assert not data.get("error"), data
            assert "_truncated" not in data and "_download_url" not in data
            return data

        capabilities = call("flow_get_capabilities")
        assert capabilities["environment"]["ida_version"] == "9.3"
        assert capabilities["build_id"] == BUILD_ID
        submitted = call(
            "flow_create_snapshot",
            function="sum_point",
            profile="X64-LE",
            abi="sysv-amd64",
            routing_mode="analyst_selected",
            request_key="typed-sum-point",
        )
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            job = call("flow_get_job", job_id=submitted["job_id"])
            if job["state"] in {
                "complete",
                "failed",
                "stale",
                "cancelled",
                "interrupted",
            }:
                break
            time.sleep(0.05)
        assert job["state"] == "complete", job
        result = job["result"]
        assert result["target_executed"] is False

        def pages(name, **arguments):
            items, cursor = [], None
            while True:
                page = call(name, **arguments, cursor=cursor, limit=200)
                items.extend(page["items"])
                cursor = page["next_cursor"]
                if cursor is None:
                    return items, page["metadata"]

        nodes, metadata = pages(
            "flow_get_function_ssa", artifact_id=result["ssa_artifact"]
        )
        returns = [node for node in nodes if node["kind"] == "Return"]
        assert len(returns) == 1 and returns[0]["width_bits"] == 32
        assert len(returns[0]["inputs"]) == 1
        assert any(node["node_id"] == returns[0]["inputs"][0] for node in nodes)
        assert not any(node["kind"] == "Exit" for node in nodes)
        assert "typed_return_location" in {d["code"] for d in metadata["diagnostics"]}
        assert "typed_argument_location" in {d["code"] for d in metadata["diagnostics"]}
        bindings = metadata["argument_bindings"]
        assert len(bindings) == 1 and bindings[0]["argument_index"] == 0
        assert bindings[0]["storage"]["width_bits"] == 64
        assert len(bindings[0]["entry_node_ids"]) >= 1
        assert set(bindings[0]["entry_node_ids"]) <= {
            node["node_id"] for node in nodes if node["kind"] == "InputValue"
        }
        evidence, _ = pages(
            "flow_get_evidence",
            artifact_id=result["graph_artifact"],
            evidence_ids=returns[0]["evidence_ids"],
        )
        assert all(
            item.get("synthetic") and not item.get("source_eas") for item in evidence
        )
        receipt = {
            "schema_version": "flow-typed-return-smoke/1",
            "target_executed": False,
            "source": str(SOURCE.relative_to(ROOT)),
            "source_sha256": sha(SOURCE),
            "copied_sha256": sha(binary),
            "build_id": BUILD_ID,
            "environment": capabilities["environment"],
            "profile": "X64-LE",
            "abi": "sysv-amd64",
            "format": "FMT-ELF",
            "routing_mode": "analyst_selected",
            "function": "sum_point",
            "result": result,
            "return_node": returns[0],
            "return_evidence": evidence,
            "argument_bindings": bindings,
            "runner_sha256": sha(__file__),
            "limitations": [
                "Current IDB function type is an analyst assumption, not an inferred ABI proof",
                "This proves a value-bearing Return node; pointer-pointee taint and broad support remain unverified",
            ],
        }
        assert receipt["copied_sha256"] == receipt["source_sha256"]
        Path(output).write_text(json.dumps(receipt, indent=2) + "\n")
    finally:
        if session is not None:
            supervisor.close_session(session.session_id, save=False)
        supervisor.shutdown()


if __name__ == "__main__":
    main(*sys.argv[1:])
