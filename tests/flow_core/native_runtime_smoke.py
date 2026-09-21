"""IDA startup smoke: ROOT STORE_ROOT RECEIPT. Owned copy only; never run target."""

import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import sys
import threading

import ida_auto
import ida_kernwin
import ida_nalt
import ida_pro
import idc


def main():
    root, storage, output = idc.ARGV[1:]
    root = Path(root)
    sys.path.insert(0, str(root / "src"))
    from ida_pro_mcp.flow_core.runtime import Handler
    from ida_pro_mcp.flow_core.runtime_contracts import RuntimeScope
    from ida_pro_mcp.worker_lifecycle import WorkerLifecycle

    sample = json.loads(
        (
            root / "tests/flow_fixtures/manifests/memory/x86_64_memory_alias.json"
        ).read_text()
    )
    identity = sample["snapshot"]["identity"]
    ida_auto.auto_wait()
    assert (
        "sha256-v1:" + bytes(ida_nalt.retrieve_input_file_sha256()).hex()
        == identity["binary_digest"]
    )
    scope = RuntimeScope(
        "g009-native-smoke",
        identity["semantic_digest"],
        identity["binary_digest"],
        identity["profile_digest"],
        identity["rule_digest"],
        identity["summary_digest"],
        identity["policy_digest"],
    )
    path = root / "src/ida_pro_mcp/ida_mcp/flow/runtime.py"
    spec = importlib.util.spec_from_file_location("g009_native_factory", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    entered, release = threading.Event(), threading.Event()

    def extract(ctx, value):
        # Pure callback: an SDK extraction handler would need a host pump wrapper.
        entered.set()
        assert release.wait(10)
        ctx.check()
        ctx.report({"phase": "extract"}, {"checkpoint": True})
        return value

    runtime = module.configure_runtime(
        Path(storage).resolve(),
        scope,
        secrets.token_hex(32),
        {
            "reference": Handler(
                extract, lambda ctx, value: {"answer": value["input"] + 1}
            )
        },
    )
    job = runtime.submit("reference", {"input": 4}, "native-request")
    assert entered.wait(10)
    life = WorkerLifecycle(idle_ttl_sec=1)
    life._last_request_at = 0
    life.set_busy_probe(lambda: module.active_job_count() > 0)
    assert module.active_job_count() == 1 and life.check_shutdown_reason() is None
    from ida_pro_mcp.flow_core.persistence import PersistenceError

    try:
        with module.database_switch():
            raise AssertionError("switch admitted during active job")
    except PersistenceError as exc:
        assert "internal flow jobs are active" in str(exc)
    release.set()
    assert runtime.wait(job, 10)
    record = runtime.store.job(job)
    assert record["state"] == "complete" and record["result"] == {"answer": 5}
    assert runtime.submit("reference", {"input": 4}, "native-request") == job
    assert module.active_job_count() == 0
    with module.database_switch():
        pass
    assert runtime.store.integrity_check()
    module.shutdown(1)
    receipt = {
        "schema_version": "flow-runtime-native-smoke/1",
        "ida_version": ida_kernwin.get_kernel_version(),
        "binary_digest": identity["binary_digest"],
        "busy_guard_passed": True,
        "admission_blocks_active_job": True,
        "empty_switch_passed": True,
        "job_terminal": "complete",
        "result": {"answer": 5},
        "idempotent_replay": True,
        "integrity_passed": True,
        "target_executed": False,
        "scope": "native IDA process + private runtime factory; supervisor lifecycle separately covered by fakes",
        "implementation_sha256": {
            name: hashlib.sha256((root / name).read_bytes()).hexdigest()
            for name in (
                "src/ida_pro_mcp/flow_core/runtime_contracts.py",
                "tests/flow_core/native_runtime_smoke.py",
                "src/ida_pro_mcp/flow_core/persistence.py",
                "src/ida_pro_mcp/flow_core/runtime.py",
                "src/ida_pro_mcp/ida_mcp/flow/runtime.py",
                "src/ida_pro_mcp/idalib_server.py",
            )
        },
    }
    Path(output).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback

        traceback.print_exc()
        ida_pro.qexit(1)
    ida_pro.qexit(0)
