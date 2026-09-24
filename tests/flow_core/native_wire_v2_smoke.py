"""Static IDA 9.3 flow-wire/2 smoke on an owned disposable fixture copy.

Run with ``PYTHONPATH=src:. uv run python tests/flow_core/native_wire_v2_smoke.py``.
The target binary is never executed, and the headless IDB closes with save=False.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import time

from ida_pro_mcp import idalib_supervisor as sm


ROOT = Path(__file__).resolve().parents[2]


def main() -> None:
    with tempfile.TemporaryDirectory(
        prefix="flow-wire-v2-", dir="/private/tmp"
    ) as directory:
        work = Path(directory)
        binary = work / "typed_fixture.elf"
        shutil.copy2(ROOT / "tests/typed_fixture.elf", binary)
        os.environ["IDA_MCP_FLOW_STATE_ROOT"] = str(work / "state")
        supervisor = sm.IdalibSupervisor(
            sm.mcp,
            max_workers=1,
            worker_args=["--profile", str(ROOT / "profiles/flow-readonly.txt")],
        )
        sm.supervisor = supervisor
        session = None

        def call(name: str, **arguments):
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
            if response.get("error") or response["result"].get("isError"):
                raise AssertionError(f"{name}: {response}")
            result = response["result"]["structuredContent"]
            if result.get("schema_version") == "flow-error/1":
                raise AssertionError(f"{name}: {result}")
            return result

        try:
            session = supervisor.open_session(str(binary), mode="force_headless")
            submitted = call(
                "flow_create_snapshot",
                function="sum_point",
                profile="X64-LE",
                abi="sysv-amd64",
                routing_mode="analyst_selected",
                request_key="native-wire-v2-smoke",
                wire_version="flow-wire/2",
            )
            deadline = time.monotonic() + 90
            while True:
                job = call("flow_get_job", job_id=submitted["job_id"])
                assert job["wire_version"] == "flow-wire/2"
                assert set(job["revision"]) == {"$int"}
                if job["state"] in {
                    "complete",
                    "failed",
                    "stale",
                    "interrupted",
                    "cancelled",
                }:
                    break
                assert time.monotonic() < deadline, "snapshot job timeout"
                time.sleep(0.2)
            assert job["state"] == "complete", job
            result = job["result"]
            assert result["snapshot_id"].startswith("snapshot-v2:")
            artifact = result["graph_artifact"]
            chunks = []
            cursor = None
            offset = 0
            while True:
                page = call(
                    "flow_get_graph_digest_bytes", artifact_id=artifact, cursor=cursor
                )
                assert page["identity_version"] == 2
                assert page["offset"] == offset
                chunk = base64.urlsafe_b64decode(page["chunk_base64url"] + "===")
                assert len(chunk) == page["byte_count"]
                chunks.append(chunk)
                offset += len(chunk)
                cursor = page["next_cursor"]
                if cursor is None:
                    break
            payload = b"".join(chunks)
            assert len(payload) == page["total_bytes"]
            assert page["graph_digest"] == (
                "sha256-v2:" + hashlib.sha256(payload).hexdigest()
            )
            wrapper = json.loads(payload)
            assert wrapper["domain"] == "graph"
            assert wrapper["identity_version"] == 2
            view = call("flow_get_graph", artifact_id=artifact, limit=1)
            assert view["metadata"]["wire_version"] == "flow-wire/2"
            assert view["metadata"]["environment"]["bitness"] == {"$int": "64"}
            cursor = None
            edge = None
            while edge is None:
                graph_page = call(
                    "flow_get_graph", artifact_id=artifact, cursor=cursor, limit=200
                )
                edge = next(
                    (item for item in graph_page["items"] if item["type"] == "edge"),
                    None,
                )
                cursor = graph_page["next_cursor"]
                assert edge is not None or cursor is not None
            trace = call(
                "flow_trace_backward",
                snapshot_artifact=result["snapshot_artifact"],
                graph_artifact=artifact,
                source={"kind": "value", "node_id": edge["target"]},
                edge_kinds=[edge["kind"]],
                request_key="native-wire-v2-trace",
                limit=1,
            )
            assert trace["revision"] == {"$int": "1"}
            continued = call(
                "flow_continue_trace",
                trace_id=trace["trace_id"],
                expected_revision=trace["revision"],
                cursor=trace["cursor"],
                request_key="native-wire-v2-trace-next",
                limit=1,
            )
            assert continued["revision"] == {"$int": "2"}
            print(
                json.dumps(
                    {
                        "snapshot_id": result["snapshot_id"],
                        "graph_digest": page["graph_digest"],
                        "total_bytes": len(payload),
                        "target_executed": False,
                        "database_saved": False,
                    }
                )
            )
        finally:
            if session is not None:
                supervisor.close_session(session.session_id, save=False)
            supervisor.shutdown()


if __name__ == "__main__":
    main()
