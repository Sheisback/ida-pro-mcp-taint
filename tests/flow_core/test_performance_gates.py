"""Deterministic structural and fail-closed tests for B01-B03 benchmarking."""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

from scripts import run_flow_benchmarks as benchmark
from scripts import run_ida_flow_benchmark as ida_benchmark

from performance_workloads import run_b01, run_b02, run_b03

ROOT = Path(__file__).resolve().parents[2]
LIMITS_PATH = ROOT / "tests/flow_fixtures/manifests/benchmark-limits.json"
IDA_RECEIPT_PATH = ROOT / "tests/flow_fixtures/manifests/benchmark-ida-x64.json"


def limits():
    return json.loads(LIMITS_PATH.read_text())


def passing_measurement(result, name):
    measured = {
        "name": name,
        "warmups": 5,
        "measurements": 30,
        "wall_time_ms": {key: 1 for key in benchmark.STATS},
        "peak_rss_bytes": 1,
        "result": result,
    }
    if name == "b02":
        measured["cancellation_latency_ms"] = {key: 1 for key in benchmark.STATS}
    if name == "b03":
        measured["page_latency_ms"] = {key: 1 for key in benchmark.STATS}
        measured["page_latency_samples"] = 30
    return measured


def test_limits_are_numeric_frozen_and_implementation_bound():
    frozen = limits()
    benchmark.validate_limits(frozen)
    assert frozen["sampling"] == {
        "warmups": 5,
        "measurements": 30,
        "statistics": list(benchmark.STATS),
        "p95_method": "nearest-rank",
    }
    assert frozen["threshold_policy"]["frozen"] is True
    assert frozen["threshold_policy"]["wall_clock_only_pass_forbidden"] is True
    assert set(frozen["stages"]) == {"ida_extract", "core_compute", "page"}
    assert frozen["implementation_sha256"] == benchmark.implementation_sha256()
    assert frozen["calibration"]["status"] == "pure_static_and_licensed_ida_measured"
    assert frozen["calibration"]["warmups"] == 5
    assert frozen["calibration"]["measurements"] == 30
    assert set(frozen["calibration"]["workloads"]) == {"b01", "b02", "b03"}
    assert frozen["calibration"]["ida_extract"]["status"] == "measured"
    assert frozen["calibration"]["target_executed"] is False
    assert frozen["calibration"]["input_preserved"] is True


def test_b01_scalar_sizes_and_static_anchors_keep_semantic_oracles():
    receipt = run_b01()
    assert [item["size"] for item in receipt["synthetic"]] == [8, 64, 256]
    assert {item["anchor"] for item in receipt["anchors"]} == {"x64", "a64"}
    assert all(item["provenance_preserved"] for item in receipt["synthetic"])
    assert all(
        item["required_kinds"] == ["Load", "Phi", "Store"]
        for item in receipt["anchors"]
    )
    assert receipt["target_executed"] is False
    assert receipt["input_preserved"] is True


def test_b02_budget_alias_loop_and_cancellation_remain_partial_unknown():
    receipt = run_b02()
    assert receipt["alias"]["status"] == "partial"
    assert receipt["alias"]["unknown_preserved"] is True
    assert receipt["alias"]["labels"] == ["A", "B"]
    assert receipt["loop"]["status"] == "partial"
    assert receipt["loop"]["frontier_count"] > 0
    assert receipt["loop"]["unknown_preserved"] is True
    assert receipt["scalar_budget"]["status"] == "partial"
    assert receipt["scalar_budget"]["unknown_preserved"] is True
    assert receipt["cancellation"]["budget_status"] == "budget_exceeded"
    assert receipt["cancellation"]["cancel_status"] == "cancelled"
    assert receipt["cancellation"]["cancel_replay_equal"] is True


def test_b03_pages_concurrency_and_restart_preserve_exact_replay():
    receipt = run_b03()
    assert receipt["terminal_status"] == "frontier_exhausted"
    assert receipt["unique_nodes"] == receipt["reachable_nodes"]
    assert receipt["max_json_chars"] <= 40000
    assert receipt["concurrent_clients"] == 2
    assert receipt["concurrent_replay_equal"] is True
    assert receipt["restart_replay_equal"] is True


def test_evaluator_requires_semantics_and_structural_budgets_not_timing_alone():
    frozen = limits()
    workloads = [
        passing_measurement(run_b01(), "b01"),
        passing_measurement(run_b02(), "b02"),
        passing_measurement(run_b03(), "b03"),
    ]
    evaluated = benchmark.evaluate_pure({"workloads": workloads}, frozen)
    assert evaluated["status"] == "pass"

    semantic_failure = deepcopy(workloads)
    semantic_failure[0]["result"]["semantics_passed"] = False
    assert (
        benchmark.evaluate_pure({"workloads": semantic_failure}, frozen)["status"]
        == "fail"
    )

    timing_failure = deepcopy(workloads)
    timing_failure[2]["page_latency_ms"]["p95_ms"] = (
        frozen["workloads"]["b03"]["page_latency_ms"]["p95_ms"] + 1
    )
    assert (
        benchmark.evaluate_pure({"workloads": timing_failure}, frozen)["status"]
        == "fail"
    )


def test_licensed_ida_metrics_are_separate_and_fail_closed():
    frozen = limits()
    absent = benchmark.evaluate_ida(None, frozen)
    assert absent == {
        "status": "not_measured",
        "reason": "protected licensed IDA runner metrics were not supplied",
    }
    safe = {
        "schema_version": "flow-ida-benchmark/1",
        "ida_build": "9.3",
        "hardware_id": "protected-darwin-arm64",
        "commit": "a" * 40,
        "fixture_sha256": "b" * 64,
        "profile": "X64-LE",
        "warmups": 5,
        "measurements": 30,
        "wall_time_ms": {key: 1 for key in benchmark.STATS},
        "peak_rss_bytes": 1,
        "target_executed": False,
        "input_preserved": True,
    }
    assert benchmark.evaluate_ida(safe, frozen)["status"] == "pass"
    unsafe = safe | {"target_executed": True}
    assert benchmark.evaluate_ida(unsafe, frozen)["status"] == "fail"

    measured = json.loads(IDA_RECEIPT_PATH.read_text())
    assert benchmark.evaluate_ida(measured, frozen)["status"] == "pass"
    assert measured["warmups"] == 5 and measured["measurements"] == 30
    assert measured["fixture_sha256"] == (
        "015c684b75facbf3e1f8f5928adee695de44d927f2a4b93c5be10261af72350c"
    )
    assert measured["target_executed"] is False
    assert measured["input_preserved"] is True


def test_bsd_time_parser_keeps_wall_time_and_peak_rss_separate():
    wall_ms, peak_rss = ida_benchmark.parse_bsd_time(
        "        0.91 real         0.74 user         0.09 sys\n"
        "           206979072  maximum resident set size\n"
    )
    assert wall_ms == 910
    assert peak_rss == 206979072
