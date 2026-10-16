"""Job-level failure taxonomy: C1/C2 reasons plus extract instrumentation.

Combines the fake-SDK extractor pattern with Runtime+Handler job mapping and
asserts at the durable job error/progress level. No target binary is executed.
Every failure asserts that native EAs, host paths, and arbitrary messages stay
off the durable job boundary.
"""

import importlib.util
import json
import sys
import threading
import time
import types
from pathlib import Path

import pytest

from ida_pro_mcp.flow_core import ContractError, digest
from ida_pro_mcp.flow_core.persistence import Store
from ida_pro_mcp.flow_core.runtime import Handler, JobContext, Runtime
from ida_pro_mcp.flow_core.runtime_contracts import RuntimeScope
from test_flow_extractor import adapter, fake_sdk

ROOT = Path(__file__).resolve().parents[1]
FLOW_DIR = ROOT / "src/ida_pro_mcp/ida_mcp/flow"
OWNER = "owner-secret-not-a-binary-hash-0002"
SECRET_PATH = "/Users/private/secret.i64"
SECRET_EA = "0x401000"


def make_runtime(tmp_path, handlers):
    token = digest("taxonomy-scope")
    scope = RuntimeScope("taxonomy", token, token, token, token, token, token)
    store = Store(tmp_path / "store", scope, OWNER)
    return store, Runtime(store, handlers)


def run_job(store, runtime, handler_name, request_key):
    identifier = runtime.submit(handler_name, {}, request_key)
    assert runtime.wait(identifier)
    return store.job(identifier)


def finish(runtime, store):
    runtime.shutdown()
    store.close()


def assert_boundary_clean(row):
    blob = json.dumps({"error": row["error"], "progress": row.get("progress")})
    assert SECRET_PATH not in blob
    assert SECRET_EA not in blob
    assert "401000" not in blob
    assert "/Users" not in blob


def ida_shape(name, module, bases=(Exception,)):
    return type(name, bases, {"__module__": module})


def load_flow_module(name):
    package = "tflow_taxonomy_pkg"
    if package not in sys.modules:
        module = types.ModuleType(package)
        module.__path__ = [str(FLOW_DIR)]
        sys.modules[package] = module
    full = package + "." + name
    hit = sys.modules.get(full)
    if hit is not None:
        return hit
    spec = importlib.util.spec_from_file_location(full, FLOW_DIR / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[full] = module
    spec.loader.exec_module(module)
    return module


def live_context():
    return JobContext(
        threading.Event(), time.monotonic() + 60.0, time.monotonic,
        lambda progress, checkpoint: None,
    )


def test_extractor_cancel_maps_to_cancelled_job(monkeypatch, tmp_path):
    profile = fake_sdk(monkeypatch, tmp_path)

    def extract(ctx, value):
        return adapter.extract_snapshot(
            0x100,
            namespace="owner",
            function_key="fixture-0",
            profile=profile,
            cancelled=lambda: True,
            report_stage=ctx.note_extract_stage,
        )

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", "cancel-key")
    finally:
        finish(runtime, store)
    assert row["state"] == "cancelled"
    assert row["error"] == {
        "code": "cancelled",
        "phase": "extract",
        "reason": "cancelled",
    }
    assert row["progress"]["extract_stage"] == "preflight"
    assert row["progress"]["extract_elapsed_ms"] >= 0
    assert_boundary_clean(row)


def test_extractor_deadline_maps_to_interrupted_job(monkeypatch, tmp_path):
    profile = fake_sdk(monkeypatch, tmp_path)

    def extract(ctx, value):
        return adapter.extract_snapshot(
            0x100,
            namespace="owner",
            function_key="fixture-0",
            profile=profile,
            deadline=0.0,
            report_stage=ctx.note_extract_stage,
        )

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", "deadline-key")
    finally:
        finish(runtime, store)
    assert row["state"] == "interrupted"
    assert row["error"] == {
        "code": "lease_expired",
        "phase": "extract",
        "reason": "deadline_exceeded",
    }
    assert row["progress"]["extract_stage"] == "preflight"
    assert row["progress"]["extract_elapsed_ms"] >= 0
    assert_boundary_clean(row)


def test_residual_interrupted_error_is_typed_cancel(tmp_path):
    def extract(ctx, value):
        raise InterruptedError("Cooperative extraction cancellation")

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", "interrupted-key")
    finally:
        finish(runtime, store)
    assert row["state"] == "failed"
    assert row["error"] == {
        "code": "handler_failed",
        "phase": "extract",
        "reason": "extraction_cancelled",
        "type": "InternalError",
    }
    assert_boundary_clean(row)


def test_contract_subclass_is_typed(tmp_path):
    class SpecificContract(ContractError):
        pass

    def extract(ctx, value):
        raise SpecificContract(f"unlisted {SECRET_EA} {SECRET_PATH}")

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", "subclass-key")
    finally:
        finish(runtime, store)
    assert row["state"] == "failed"
    assert row["error"] == {
        "code": "handler_failed",
        "phase": "extract",
        "reason": "contract_subclass",
        "type": "ContractError",
    }
    assert_boundary_clean(row)


def test_timeout_subclass_keeps_handler_timeout(tmp_path):
    class SpecificTimeout(TimeoutError):
        pass

    def extract(ctx, value):
        raise SpecificTimeout(f"slow {SECRET_PATH}")

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", "timeout-key")
    finally:
        finish(runtime, store)
    assert row["error"] == {
        "code": "handler_failed",
        "phase": "extract",
        "reason": "handler_timeout",
        "type": "TimeoutError",
    }
    assert_boundary_clean(row)


def test_recursion_error_keeps_runtime_boundary(tmp_path):
    def extract(ctx, value):
        raise RecursionError("maximum recursion depth exceeded")

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", "recursion-key")
    finally:
        finish(runtime, store)
    assert row["error"] == {
        "code": "handler_failed",
        "phase": "extract",
        "reason": "runtime_boundary",
        "type": "RuntimeError",
    }
    assert_boundary_clean(row)


def test_exact_value_error_keeps_handler_value_reason(tmp_path):
    def extract(ctx, value):
        raise ValueError("bad handler value")

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", "value-key")
    finally:
        finish(runtime, store)
    assert row["error"] == {
        "code": "handler_failed",
        "phase": "extract",
        "reason": "invalid_handler_value",
        "type": "ValueError",
    }
    assert_boundary_clean(row)


@pytest.mark.parametrize(
    "stage, reason",
    (
        (None, "invalid_handler_value"),
        ("preflight", "invalid_handler_value"),
        ("gen_microcode", "invalid_handler_value"),
        ("microcode_walk", "invalid_handler_value"),
        ("typed_argloc", "invalid_handler_value"),
        ("input_digest", "invalid_handler_value"),
        ("snapshot_serialize", "snapshot_serialization_failed"),
        ("callee_closure", "derived_closure_failed"),
        ("derived_closure", "derived_closure_failed"),
    ),
)
def test_value_error_subclass_stays_typed_in_any_extract_stage(
    tmp_path, stage, reason
):
    class SpecificValue(ValueError):
        pass

    def extract(ctx, value):
        if stage is not None:
            ctx.note_extract_stage(stage)
        raise SpecificValue(f"bad {SECRET_EA} {SECRET_PATH}")

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", f"value-subclass-{stage}")
    finally:
        finish(runtime, store)
    assert row["error"] == {
        "code": "handler_failed",
        "phase": "extract",
        "reason": reason,
        "type": "ValueError",
    }
    if stage is not None:
        assert row["progress"]["extract_stage"] == stage
    assert_boundary_clean(row)


def test_snapshot_stage_routes_decode_failure(tmp_path):
    def extract(ctx, value):
        ctx.note_extract_stage("snapshot_serialize")
        raise json.JSONDecodeError("corrupt", "doc", 0)

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", "snapshot-key")
    finally:
        finish(runtime, store)
    assert row["error"] == {
        "code": "handler_failed",
        "phase": "extract",
        "reason": "snapshot_serialization_failed",
        "type": "ValueError",
    }
    assert row["progress"]["extract_stage"] == "snapshot_serialize"
    assert_boundary_clean(row)


def test_walk_stage_routes_sdk_shape_failure(tmp_path):
    def extract(ctx, value):
        ctx.note_extract_stage("microcode_walk")
        raise AttributeError(f"missing SDK field {SECRET_EA}")

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", "sdk-key")
    finally:
        finish(runtime, store)
    assert row["error"] == {
        "code": "handler_failed",
        "phase": "extract",
        "reason": "sdk_shape_mismatch",
        "type": "InternalError",
    }
    assert row["progress"]["extract_stage"] == "microcode_walk"
    assert_boundary_clean(row)


def test_digest_stage_routes_input_failure(tmp_path):
    def extract(ctx, value):
        ctx.note_extract_stage("input_digest")
        raise OSError(f"{SECRET_PATH}: missing input")

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", "digest-key")
    finally:
        finish(runtime, store)
    assert row["error"] == {
        "code": "handler_failed",
        "phase": "extract",
        "reason": "input_digest_unavailable",
        "type": "InternalError",
    }
    assert row["progress"]["extract_stage"] == "input_digest"
    assert_boundary_clean(row)


def test_closure_stage_routes_derived_failure(tmp_path):
    def extract(ctx, value):
        ctx.note_extract_stage("derived_closure")
        raise KeyError("finite-target proof gap")

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", "closure-key")
    finally:
        finish(runtime, store)
    assert row["error"] == {
        "code": "handler_failed",
        "phase": "extract",
        "reason": "derived_closure_failed",
        "type": "InternalError",
    }
    assert row["progress"]["extract_stage"] == "derived_closure"
    assert_boundary_clean(row)


def test_specific_reason_wins_over_stage(tmp_path):
    def extract(ctx, value):
        ctx.note_extract_stage("microcode_walk")
        raise RuntimeError(f"gen_microcode failed: code=1, ea={SECRET_EA}")

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", "specific-key")
    finally:
        finish(runtime, store)
    assert row["error"] == {
        "code": "handler_failed",
        "phase": "extract",
        "reason": "microcode_generation_failed",
        "type": "RuntimeError",
    }
    assert row["progress"]["extract_stage"] == "microcode_walk"
    assert row["progress"]["extract_elapsed_ms"] >= 0
    assert_boundary_clean(row)


def test_stale_stage_does_not_route_analyze_failure(tmp_path):
    def extract(ctx, value):
        ctx.note_extract_stage("snapshot_serialize")
        return value

    class SpecificContract(ContractError):
        pass

    def analyze(ctx, value):
        raise SpecificContract("unlisted analyze contract")

    store, runtime = make_runtime(tmp_path, {"probe": Handler(extract, analyze)})
    try:
        row = run_job(store, runtime, "probe", "analyze-key")
    finally:
        finish(runtime, store)
    assert row["error"] == {
        "code": "handler_failed",
        "phase": "analyze",
        "reason": "contract_subclass",
        "type": "ContractError",
    }
    assert_boundary_clean(row)


def test_unknown_stage_is_dropped_without_failure(tmp_path):
    def extract(ctx, value):
        ctx.note_extract_stage("bogus_stage")
        raise ValueError("bad handler value")

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", "unknown-stage-key")
    finally:
        finish(runtime, store)
    assert row["error"]["reason"] == "invalid_handler_value"
    assert "extract_stage" not in row["progress"]
    assert row["progress"]["extract_elapsed_ms"] >= 0
    assert_boundary_clean(row)


def test_ida_tool_timeout_is_typed(tmp_path):
    timeout_shape = ida_shape("IDASyncError", "ida_pro_mcp.ida_mcp.sync")

    def extract(ctx, value):
        raise timeout_shape("Tool timed out after 60.00s")

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", "timeout-shape-key")
    finally:
        finish(runtime, store)
    assert row["error"] == {
        "code": "handler_failed",
        "phase": "extract",
        "reason": "ida_tool_timeout",
        "type": "InternalError",
    }
    assert_boundary_clean(row)


def test_non_timeout_ida_sync_error_stays_internal(tmp_path):
    timeout_shape = ida_shape("IDASyncError", "ida_pro_mcp.ida_mcp.sync")

    def extract(ctx, value):
        raise timeout_shape("Call stack is not empty while calling x")

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", "sync-shape-key")
    finally:
        finish(runtime, store)
    assert row["error"]["reason"] == "internal_error"
    assert_boundary_clean(row)


@pytest.mark.parametrize(
    "name, module",
    (
        ("CancelledError", "ida_pro_mcp.ida_mcp.sync"),
        ("RequestCancelledError", "ida_pro_mcp.ida_mcp.zeromcp.jsonrpc"),
    ),
)
def test_ida_request_cancel_is_typed(tmp_path, name, module):
    shape = ida_shape(name, module)

    def extract(ctx, value):
        raise shape("Request was cancelled")

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", f"cancel-shape-{name}")
    finally:
        finish(runtime, store)
    assert row["error"] == {
        "code": "handler_failed",
        "phase": "extract",
        "reason": "ida_request_cancelled",
        "type": "InternalError",
    }
    assert_boundary_clean(row)


def test_pump_busy_is_typed(tmp_path):
    shape = ida_shape(
        "PumpBusyError", "ida_pro_mcp.ida_mcp.mainthread", bases=(RuntimeError,)
    )

    def extract(ctx, value):
        raise shape("worker did not run 'x' within 90.0s; busy")

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", "pump-key")
    finally:
        finish(runtime, store)
    assert row["error"] == {
        "code": "handler_failed",
        "phase": "extract",
        "reason": "ida_pump_busy",
        "type": "RuntimeError",
    }
    assert_boundary_clean(row)


def test_pump_busy_tool_error_is_typed(tmp_path):
    shape = ida_shape("IDAError", "ida_pro_mcp.ida_mcp.sync")

    def extract(ctx, value):
        raise shape("worker did not run 'x'; the IDA main thread is busy")

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", "pump-tool-key")
    finally:
        finish(runtime, store)
    assert row["error"] == {
        "code": "handler_failed",
        "phase": "extract",
        "reason": "ida_pump_busy",
        "type": "InternalError",
    }
    assert_boundary_clean(row)


def test_other_tool_error_stays_internal(tmp_path):
    shape = ida_shape("IDAError", "ida_pro_mcp.ida_mcp.sync")

    def extract(ctx, value):
        raise shape(f"No function found at address {SECRET_EA}")

    store, runtime = make_runtime(
        tmp_path, {"probe": Handler(extract, lambda ctx, value: value)}
    )
    try:
        row = run_job(store, runtime, "probe", "tool-key")
    finally:
        finish(runtime, store)
    assert row["error"]["reason"] == "internal_error"
    assert_boundary_clean(row)


def test_reviewed_closure_notes_stage():
    reviewed = load_flow_module("reviewed_runtime")
    ctx = live_context()
    snapshots, _ = reviewed.extract_callee_closure(ctx, types.SimpleNamespace(), None)
    assert snapshots == {}
    assert ctx._extract_stage == "callee_closure"


def test_derived_closure_notes_stage(monkeypatch):
    monkeypatch.setitem(
        sys.modules, "ida_funcs", types.SimpleNamespace(get_func=lambda ea: None)
    )
    derived = load_flow_module("derived_runtime")
    ctx = live_context()
    root = types.SimpleNamespace(function_rva=0, calls=())
    snapshots, result = derived.extract_local_direct_callees(ctx, root, None)
    assert snapshots == {}
    assert result["visited_rvas"] == [0]
    assert ctx._extract_stage == "derived_closure"
