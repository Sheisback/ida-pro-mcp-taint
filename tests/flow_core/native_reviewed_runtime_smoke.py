"""Build owned fixtures and exercise public reviewed calls through static IDA.

Usage: uv run python tests/flow_core/native_reviewed_runtime_smoke.py OUTPUT
Requires the pinned Apple toolchain and licensed IDA; never executes targets.
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

from ida_pro_mcp import idalib_supervisor as sm
from ida_pro_mcp.flow_core.build_identity import BUILD_ID

ROOT = Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(output):
    work = Path(tempfile.mkdtemp(prefix="g022-reviewed-", dir="/private/tmp"))
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/build_flow_call_anchors.py"),
            str(work / "build"),
        ],
        check=True,
        cwd=ROOT,
    )
    expected = json.loads(
        (ROOT / "tests/flow_fixtures/manifests/calls/build.json").read_text()
    )
    os.environ["IDA_MCP_FLOW_STATE_ROOT"] = str(work / "state")
    supervisor = sm.IdalibSupervisor(
        sm.mcp,
        max_workers=1,
        worker_args=["--profile", str(ROOT / "profiles/flow-readonly.txt")],
    )
    sm.supervisor = supervisor
    results = []
    try:
        for manifest in expected:
            arch = manifest["arch"]
            build = work / "build/fresh-1" / arch
            source = build / manifest["binary"]
            assert sha(source) == manifest["binary_sha256"]
            assert sha(ROOT / manifest["source"]) == manifest["source_sha256"]
            binary = work / source.name
            shutil.copy2(source, binary)
            for companion in manifest["companion_artifacts"]:
                assert sha(build / companion["path"]) == companion["sha256"]
                shutil.copytree(build / companion["bundle"], work / companion["bundle"])
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
                result = response.get("result")
                assert isinstance(result, dict), response
                assert not result.get("isError"), response
                data = result["structuredContent"]
                assert not data.get("error"), data
                assert "_truncated" not in data and "_download_url" not in data
                assert len(json.dumps(data)) < 40000
                calls.append(name)
                return data

            capabilities = call("flow_get_capabilities")
            assert capabilities["build_id"] == BUILD_ID, capabilities
            assert (
                capabilities["features"]["interprocedural"]["status"] == "available"
            ), capabilities
            extraction = json.loads(
                (
                    ROOT / f"tests/flow_fixtures/manifests/calls/extraction_{arch}.json"
                ).read_text()
            )
            selectors = {
                r["name"]: hex(r["baseline"]["function_ea"])
                for r in extraction["functions"]
            }
            cases = []
            for function, expected_kinds, expect_unknown in (
                ("call_context_left", {"identity"}, False),
                ("call_output_user", {"output"}, False),
                ("call_heap_h01", {"alloc", "free"}, False),
                ("call_heap_h03", {"alloc"}, True),
                ("call_recursive", {"identity"}, True),
                ("call_indirect", set(), True),
            ):
                request = dict(
                    function=selectors[function],
                    profile=capabilities["supported_profiles"][0],
                    request_key=function,
                )
                queued = call("flow_create_snapshot", **request)
                deadline = time.monotonic() + 120
                job = None
                while time.monotonic() < deadline:
                    job = call("flow_get_job", job_id=queued["job_id"])
                    if job["state"] in {
                        "complete",
                        "failed",
                        "stale",
                        "cancelled",
                        "interrupted",
                    }:
                        break
                    time.sleep(0.05)
                assert job is not None
                assert job["state"] == "complete", job
                assert (
                    call("flow_create_snapshot", **request)["job_id"]
                    == queued["job_id"]
                )
                assert (
                    call("flow_cancel_job", job_id=queued["job_id"])["state"]
                    == "complete"
                )
                result = job["result"]
                assert result["target_executed"] is False
                items = []
                cursor = None
                page_count = 0
                while True:
                    page = call(
                        "flow_get_call_compositions",
                        artifact_id=result["call_composition_artifact"],
                        cursor=cursor,
                        limit=1,
                    )
                    replay = call(
                        "flow_get_call_compositions",
                        artifact_id=result["call_composition_artifact"],
                        cursor=cursor,
                        limit=1,
                    )
                    assert replay == page
                    items.extend(page["items"])
                    page_count += 1
                    cursor = page["next_cursor"]
                    if cursor is None:
                        break
                chunks = {}
                complete = []
                for item in items:
                    if item["type"] != "canonical_json_chunk":
                        complete.append(item)
                    else:
                        text = chunks.setdefault(item["item_id"], "")
                        assert item["offset"] == len(text)
                        assert item["length"] == len(item["text"])
                        chunks[item["item_id"]] += item["text"]
                        if len(chunks[item["item_id"]]) == item["total_length"]:
                            complete.append(json.loads(chunks.pop(item["item_id"])))
                assert not chunks
                items = complete
                kinds = {
                    b["summary"]["kind"]
                    for i in items
                    for b in i["binding"]["plan"]["branches"]
                }
                assert kinds == expected_kinds, (function, result, items)
                heap_effects = {
                    o["kind"]
                    for i in items
                    for o in i["composition"]["heap_observations"]
                }
                memory_effects = {
                    o["operation"]
                    for i in items
                    for o in i["composition"]["memory_observations"]
                }
                state_evidence = {}
                if function == "call_output_user":
                    assert memory_effects == {"output"}
                    composed = items[0]["composition"]
                    targets = composed["memory_observations"][0]["targets"]
                    written = composed["state"]["memory"]
                    assert len(targets) == 1 and targets[0]["interval"] == {
                        "start": 0,
                        "end": 4,
                    }
                    assert len(written) == 4
                    assert [b["offset"] for b in written] == [0, 1, 2, 3]
                    assert all(
                        b["object_id"] == targets[0]["object_id"]
                        and b["labels"]["explicit"]
                        for b in written
                    )
                    state_evidence = {
                        "output_targets": targets,
                        "output_bytes": written,
                    }
                    assert all(i["composition"]["return_value"] is None for i in items)
                if function == "call_heap_h01":
                    assert heap_effects >= {"allocate", "free"}
                    heap = [
                        o for i in items for o in i["composition"]["heap_observations"]
                    ]
                    allocated = next(o for o in heap if o["kind"] == "allocate")
                    freed = next(o for o in heap if o["kind"] == "free")
                    assert allocated["transitions"] and freed["transitions"]
                    oid = allocated["transitions"][0]["object_id"]
                    assert freed["pointer"]["candidates"] == [
                        {"object_id": oid, "offset": 0}
                    ]
                    assert freed["transitions"][0]["object_id"] == oid
                    assert "live" in freed["transitions"][0]["before"]["possible"]
                    assert "freed" in freed["transitions"][0]["after"]["possible"]
                    state_evidence = {"allocation": allocated, "free": freed}
                if function == "call_heap_h03":
                    heap = [
                        o for i in items for o in i["composition"]["heap_observations"]
                    ]
                    allocated = next(o for o in heap if o["kind"] == "allocate")
                    opaque = next(o for o in heap if o["kind"] == "opaque")
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
                    state_evidence = {"allocation": allocated, "opaque": opaque}
                if function == "call_context_left":
                    assert any(
                        i["composition"]["return_value"] is not None for i in items
                    )
                assert (
                    page["metadata"]["unknown_remainder_count"] > 0
                ) == expect_unknown
                cases.append(
                    {
                        "function": function,
                        "reviewed_kinds": sorted(kinds),
                        "page_count": page_count,
                        "metadata": page["metadata"],
                        "heap_effects": sorted(heap_effects),
                        "memory_effects": sorted(memory_effects),
                        "state_evidence": state_evidence,
                        "closure": result["callee_closure"],
                        "target_executed": False,
                    }
                )
            results.append(
                {
                    "arch": arch,
                    "binary_sha256": sha(binary),
                    "worker_build_id": capabilities["build_id"],
                    "cases": cases,
                    "tool_calls": calls,
                    "target_executed": False,
                }
            )
            supervisor.close_session(database, save=False)
            assert sha(binary) == manifest["binary_sha256"]
    finally:
        supervisor.shutdown()
    Path(output).write_text(
        json.dumps(
            {
                "schema_version": "flow-reviewed-public-smoke/1",
                "build_id": BUILD_ID,
                "producer_sha256": sha(Path(__file__)),
                "fixtures": results,
                "target_executed": False,
                "output_helper_native_caller": True,
                "limitations": [
                    "Reviewed output memory effects retain unresolved pointer uncertainty; no definite memory write or vulnerability verdict is inferred."
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


if __name__ == "__main__":
    main(sys.argv[1])
