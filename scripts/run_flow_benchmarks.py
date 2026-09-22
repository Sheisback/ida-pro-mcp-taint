#!/usr/bin/env python3
"""Measure and evaluate the static B01-B03 flow workloads.

The default command measures pure-core/page work only. Licensed IDA extraction
metrics are accepted as a separate, protected-runner JSON input; their absence
is reported as partial release evidence rather than silently treated as a pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import platform
import re
import resource
import runpy
import statistics
import subprocess
import sys
import time
from typing import Any, Callable, cast

ROOT = Path(__file__).resolve().parents[1]
WORKLOAD_PATH = ROOT / "tests/flow_core/performance_workloads.py"
IDA_BENCHMARK_PATH = ROOT / "scripts/run_ida_flow_benchmark.py"
IDA_EXTRACTION_ENTRY = ROOT / "scripts/flow_benchmark_extract.py"
DEFAULT_LIMITS = ROOT / "tests/flow_fixtures/manifests/benchmark-limits.json"
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests/flow_core")]

Json = dict[str, Any]
WORKLOADS = cast(
    dict[str, Callable[[], Json]], runpy.run_path(str(WORKLOAD_PATH))["WORKLOADS"]
)
STATS = ("median_ms", "p95_ms", "max_ms")
VOLATILE_KEYS = frozenset({"page_latencies_ms", "cancellation_latency_ms"})
COMMIT = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256-v1:[0-9a-f]{64}")
BUILD_ID = re.compile(r"flow-build-sha256-v1:[0-9a-f]{64}")


def _sha256(path: Path) -> str:
    return "sha256-v1:" + hashlib.sha256(path.read_bytes()).hexdigest()


def implementation_sha256() -> str:
    hasher = hashlib.sha256()
    for path in (
        Path(__file__).resolve(),
        IDA_BENCHMARK_PATH,
        IDA_EXTRACTION_ENTRY,
        WORKLOAD_PATH,
    ):
        hasher.update(path.name.encode())
        hasher.update(b"\0")
        hasher.update(path.read_bytes())
        hasher.update(b"\0")
    return "sha256-v1:" + hasher.hexdigest()


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def statistics_ms(values: list[float]) -> Json:
    if not values:
        raise ValueError("at least one timing sample is required")
    return {
        "median_ms": statistics.median(values),
        "p95_ms": _percentile(values, 0.95),
        "max_ms": max(values),
    }


def _rss_bytes() -> int:
    maximum = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(maximum if sys.platform == "darwin" else maximum * 1024)


def _stable(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _stable(item)
            for key, item in sorted(value.items())
            if key not in VOLATILE_KEYS
        }
    if isinstance(value, list):
        return [_stable(item) for item in value]
    return value


def measure_workload(
    name: str,
    workload: Callable[[], Json],
    *,
    warmups: int,
    measurements: int,
) -> Json:
    if warmups < 0 or measurements <= 0:
        raise ValueError("invalid benchmark sample counts")
    for _ in range(warmups):
        workload()
    elapsed: list[float] = []
    page_latencies: list[float] = []
    cancellation_latencies: list[float] = []
    stable_result: Any = None
    last_result: Json | None = None
    for _ in range(measurements):
        started = time.perf_counter_ns()
        result = workload()
        elapsed.append((time.perf_counter_ns() - started) / 1_000_000)
        candidate = _stable(result)
        if stable_result is None:
            stable_result = candidate
        elif candidate != stable_result:
            raise AssertionError(
                f"{name} structural/semantic output was nondeterministic"
            )
        page_latencies.extend(result.get("page_latencies_ms", []))
        cancellation = result.get("cancellation")
        if isinstance(cancellation, dict):
            latency = cancellation.get("cancellation_latency_ms")
            if isinstance(latency, (int, float)) and not isinstance(latency, bool):
                cancellation_latencies.append(float(latency))
        last_result = result
    if last_result is None:
        raise AssertionError("benchmark produced no result")
    report: Json = {
        "name": name,
        "warmups": warmups,
        "measurements": measurements,
        "wall_time_ms": statistics_ms(elapsed),
        "peak_rss_bytes": _rss_bytes(),
        "result": stable_result,
    }
    if page_latencies:
        report["page_latency_ms"] = statistics_ms(page_latencies)
        report["page_latency_samples"] = len(page_latencies)
    if cancellation_latencies:
        report["cancellation_latency_ms"] = statistics_ms(cancellation_latencies)
    return report


def _numeric(value: Any, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{path} must be numeric")
    if not math.isfinite(float(value)) or value <= 0:
        raise ValueError(f"{path} must be finite and positive")
    return float(value)


def _positive_int(value: Any, path: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{path} must be a positive integer")
    return value


def _nonnegative_int(value: Any, path: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{path} must be a non-negative integer")
    return value


def _statistics(value: Any, path: str) -> Json:
    if not isinstance(value, dict) or set(value) != set(STATS):
        raise ValueError(f"{path} must contain exact timing statistics")
    result = {key: _numeric(value[key], f"{path}.{key}") for key in STATS}
    if not result["median_ms"] <= result["p95_ms"] <= result["max_ms"]:
        raise ValueError(f"{path} statistics must be monotonic")
    return result


def _string(value: Any, path: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{path} must be a non-empty string")
    return value


def _expectations(
    limits: Json,
    *,
    commit: str,
    build_id: str,
    limits_digest: str,
    ida_executable_sha256: str,
) -> Json:
    expected = limits["stages"]["ida_extract"]["expectations"]
    return {
        "commit": commit,
        "build_id": build_id,
        "limits_digest": limits_digest,
        "ida_executable_sha256": ida_executable_sha256,
        **expected,
    }


def validate_limits(limits: Json) -> None:
    if limits.get("schema_version") != "flow-benchmark-limits/1":
        raise ValueError("unsupported benchmark limits schema")
    sampling = limits.get("sampling")
    if sampling != {
        "warmups": 5,
        "measurements": 30,
        "statistics": list(STATS),
        "p95_method": "nearest-rank",
    }:
        raise ValueError(
            "benchmark sampling contract must remain 5 warmups/30 measurements"
        )
    expected_hash = limits.get("implementation_sha256")
    if expected_hash != implementation_sha256():
        raise ValueError("benchmark implementation hash is stale")
    workloads = limits.get("workloads")
    if not isinstance(workloads, dict) or set(workloads) != {"b01", "b02", "b03"}:
        raise ValueError("benchmark limits must define B01-B03")
    for name, entry in workloads.items():
        if not isinstance(entry, dict):
            raise ValueError(f"workloads.{name} must be an object")
        for statistic in STATS:
            _numeric(
                entry["wall_time_ms"][statistic], f"{name}.wall_time_ms.{statistic}"
            )
        _numeric(entry["peak_rss_bytes"], f"{name}.peak_rss_bytes")
        structural = entry.get("structural")
        if not isinstance(structural, dict) or not structural:
            raise ValueError(f"{name}.structural must contain numeric budgets")
        for key, value in structural.items():
            _numeric(value, f"{name}.structural.{key}")
    for stage in ("ida_extract", "core_compute", "page"):
        if stage not in limits.get("stages", {}):
            raise ValueError(f"missing separately budgeted {stage} stage")
    ida = limits["stages"]["ida_extract"]
    for statistic in STATS:
        _numeric(ida["wall_time_ms"][statistic], f"ida_extract.{statistic}")
    _numeric(ida["peak_rss_bytes"], "ida_extract.peak_rss_bytes")
    expected = ida.get("expectations")
    if not isinstance(expected, dict) or set(expected) != {
        "fixture_sha256",
        "profile",
        "ida_build",
        "hexrays_build",
        "hardware_class",
    }:
        raise ValueError("licensed IDA expectations are incomplete")
    if re.fullmatch(r"[0-9a-f]{64}", str(expected["fixture_sha256"])) is None:
        raise ValueError("invalid expected fixture digest")
    for field in ("profile", "ida_build", "hexrays_build", "hardware_class"):
        _string(expected[field], f"ida_extract.expectations.{field}")
    if re.fullmatch(r"[A-Z0-9]+(?:-[A-Z0-9]+)+", expected["profile"]) is None:
        raise ValueError("invalid expected profile")
    if re.fullmatch(r"\d+\.\d+(?:\.\d+)*", expected["ida_build"]) is None:
        raise ValueError("invalid expected IDA build")
    if re.fullmatch(r"\d+\.\d+(?:\.\d+)*", expected["hexrays_build"]) is None:
        raise ValueError("invalid expected Hex-Rays build")
    if re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,127}", expected["hardware_class"]) is None:
        raise ValueError("invalid expected hardware class")


def _within_stats(
    measured: Json, frozen: Json, prefix: str, failures: list[str]
) -> None:
    for statistic in STATS:
        actual = _numeric(measured[statistic], f"measured.{prefix}.{statistic}")
        limit = _numeric(frozen[statistic], f"limit.{prefix}.{statistic}")
        if actual > limit:
            failures.append(f"{prefix}.{statistic}: {actual:.3f} > {limit:.3f}")


def _result_number(result: Json, *path: str) -> float:
    value: Any = result
    for key in path:
        value = value[key]
    return _numeric(value, ".".join(path))


def evaluate_pure(report: Json, limits: Json) -> Json:
    failures: list[str] = []
    rows = report.get("workloads")
    if (
        type(rows) is not list
        or len(rows) != 3
        or not all(type(item) is dict for item in rows)
    ):
        failures.append("pure report must contain B01-B03 exactly once")
        return {"status": "fail", "failures": failures}
    names = [item.get("name") for item in rows]
    if len(set(names)) != 3 or set(names) != {"b01", "b02", "b03"}:
        failures.append("pure report must contain B01-B03 exactly once")
        return {"status": "fail", "failures": failures}
    by_name = {item["name"]: item for item in rows}
    for name, measured in by_name.items():
        try:
            if set(measured) - {
                "name",
                "warmups",
                "measurements",
                "wall_time_ms",
                "peak_rss_bytes",
                "result",
                "cancellation_latency_ms",
                "page_latency_ms",
                "page_latency_samples",
            }:
                raise ValueError(f"{name} contains unknown measurement fields")
            if (
                type(measured.get("warmups")) is not int
                or type(measured.get("measurements")) is not int
                or measured.get("warmups") != 5
                or measured.get("measurements") != 30
            ):
                raise ValueError(f"{name} must use 5 warmups/30 measurements")
            _statistics(measured.get("wall_time_ms"), f"{name}.wall_time_ms")
            _positive_int(measured.get("peak_rss_bytes"), f"{name}.peak_rss_bytes")
            if type(measured.get("result")) is not dict:
                raise ValueError(f"{name}.result must be an object")
            if name == "b02":
                _statistics(
                    measured.get("cancellation_latency_ms"),
                    "b02.cancellation_latency_ms",
                )
            if name == "b03":
                _statistics(measured.get("page_latency_ms"), "b03.page_latency_ms")
                _positive_int(
                    measured.get("page_latency_samples"), "b03.page_latency_samples"
                )
        except (KeyError, TypeError, ValueError) as exc:
            failures.append(str(exc))
    if failures:
        return {"status": "fail", "failures": failures}
    for name, measured in by_name.items():
        frozen = limits["workloads"][name]
        _within_stats(
            measured["wall_time_ms"], frozen["wall_time_ms"], f"{name}.wall", failures
        )
        if _positive_int(
            measured["peak_rss_bytes"], f"{name}.peak_rss_bytes"
        ) > _numeric(frozen["peak_rss_bytes"], f"limit.{name}.peak_rss_bytes"):
            failures.append(
                f"{name}.peak_rss_bytes: {measured['peak_rss_bytes']} > {frozen['peak_rss_bytes']}"
            )
        result = measured["result"]
        if result.get("semantics_passed") is not True:
            failures.append(f"{name}: semantic oracle failed")
        if (
            result.get("target_executed") is not False
            or result.get("input_preserved") is not True
        ):
            failures.append(f"{name}: static safety evidence failed")

    b01 = by_name["b01"]["result"]
    if type(b01.get("synthetic")) is not list or not b01["synthetic"]:
        failures.append("b01.synthetic must contain measured graphs")
        return {"status": "fail", "failures": failures}
    if type(b01.get("anchors")) is not list or len(b01["anchors"]) != 2:
        failures.append("b01 must contain both committed static anchors")
        return {"status": "fail", "failures": failures}
    graphs = b01["synthetic"] + b01["anchors"]
    try:
        for ordinal, item in enumerate(graphs):
            if type(item) is not dict:
                raise ValueError(f"b01.graphs.{ordinal} must be an object")
            for field in ("nodes", "edges", "evaluations"):
                _positive_int(item.get(field), f"b01.graphs.{ordinal}.{field}")
    except ValueError as exc:
        return {"status": "fail", "failures": [str(exc)]}
    b01_structural = {
        "max_nodes": max(item["nodes"] for item in graphs),
        "max_edges": max(item["edges"] for item in graphs),
        "max_evaluations": max(item["evaluations"] for item in graphs),
        "anchor_count": len(b01["anchors"]),
    }
    b02 = by_name["b02"]["result"]
    try:
        _positive_int(b02["alias"]["candidate_count"], "b02.alias.candidate_count")
        _nonnegative_int(b02["alias"]["interval_count"], "b02.alias.interval_count")
        _positive_int(b02["alias"]["iterations"], "b02.alias.iterations")
        _positive_int(b02["loop"]["iterations"], "b02.loop.iterations")
        _positive_int(b02["loop"]["frontier_count"], "b02.loop.frontier_count")
        _positive_int(
            b02["scalar_budget"]["frontier_count"],
            "b02.scalar_budget.frontier_count",
        )
    except (KeyError, TypeError, ValueError) as exc:
        return {"status": "fail", "failures": [str(exc)]}
    b02_structural = {
        "max_alias_candidates": b02["alias"]["candidate_count"],
        "max_intervals": b02["alias"]["interval_count"],
        "max_iterations": max(b02["alias"]["iterations"], b02["loop"]["iterations"]),
        "min_frontier": min(
            b02["loop"]["frontier_count"], b02["scalar_budget"]["frontier_count"]
        ),
    }
    b03 = by_name["b03"]["result"]
    try:
        for field in (
            "page_count",
            "reachable_nodes",
            "max_json_chars",
            "concurrent_clients",
        ):
            _positive_int(b03.get(field), f"b03.{field}")
    except ValueError as exc:
        return {"status": "fail", "failures": [str(exc)]}
    b03_structural = {
        "max_pages": b03["page_count"],
        "max_reachable_nodes": b03["reachable_nodes"],
        "max_json_chars": b03["max_json_chars"],
        "concurrent_clients": b03["concurrent_clients"],
    }
    observed = {"b01": b01_structural, "b02": b02_structural, "b03": b03_structural}
    for name, fields in observed.items():
        frozen = limits["workloads"][name]["structural"]
        for key, actual in fields.items():
            limit = frozen[key]
            if key in {"anchor_count", "concurrent_clients"}:
                if actual != limit:
                    failures.append(f"{name}.{key}: {actual} != {limit}")
            elif key == "min_frontier":
                if actual < limit:
                    failures.append(f"{name}.{key}: {actual} < {limit}")
            elif actual > limit:
                failures.append(f"{name}.{key}: {actual} > {limit}")

    _within_stats(
        by_name["b02"]["cancellation_latency_ms"],
        limits["workloads"]["b02"]["cancellation_latency_ms"],
        "b02.cancellation",
        failures,
    )
    _within_stats(
        by_name["b03"]["page_latency_ms"],
        limits["workloads"]["b03"]["page_latency_ms"],
        "b03.page",
        failures,
    )
    return {
        "status": "fail" if failures else "pass",
        "failures": failures,
        "observed": observed,
    }


def evaluate_ida(
    metrics: Json | None, limits: Json, expected: Json | None = None
) -> Json:
    if metrics is None:
        return {
            "status": "not_measured",
            "reason": "protected licensed IDA runner metrics were not supplied",
        }
    failures: list[str] = []
    required = {
        "schema_version",
        "ida_build",
        "ida_executable_sha256",
        "hexrays_build",
        "hardware_class",
        "commit",
        "build_id",
        "limits_digest",
        "fixture_sha256",
        "profile",
        "warmups",
        "measurements",
        "wall_time_ms",
        "peak_rss_bytes",
        "target_executed",
        "input_preserved",
    }
    if set(metrics) != required:
        failures.append("licensed IDA metrics fields do not match the v1 contract")
    if metrics.get("schema_version") != "flow-ida-benchmark/2":
        failures.append("unsupported licensed IDA benchmark schema")
    if (
        type(metrics.get("warmups")) is not int
        or type(metrics.get("measurements")) is not int
        or metrics.get("warmups") != 5
        or metrics.get("measurements") != 30
    ):
        failures.append("licensed IDA benchmark must use 5 warmups/30 measurements")
    if (
        metrics.get("target_executed") is not False
        or metrics.get("input_preserved") is not True
    ):
        failures.append("licensed IDA benchmark violated static-only safety evidence")
    try:
        if COMMIT.fullmatch(str(metrics.get("commit"))) is None:
            raise ValueError("licensed IDA benchmark commit is invalid")
        if BUILD_ID.fullmatch(str(metrics.get("build_id"))) is None:
            raise ValueError("licensed IDA benchmark build ID is invalid")
        if DIGEST.fullmatch(str(metrics.get("limits_digest"))) is None:
            raise ValueError("licensed IDA benchmark limits digest is invalid")
        if (
            type(metrics.get("ida_executable_sha256")) is not str
            or re.fullmatch(r"[0-9a-f]{64}", metrics["ida_executable_sha256"]) is None
        ):
            raise ValueError("licensed IDA benchmark executable digest is invalid")
        if re.fullmatch(r"[0-9a-f]{64}", str(metrics.get("fixture_sha256"))) is None:
            raise ValueError("licensed IDA benchmark fixture digest is invalid")
        for field in ("profile", "ida_build", "hexrays_build", "hardware_class"):
            _string(metrics.get(field), f"licensed_ida.{field}")
        if re.fullmatch(r"[A-Z0-9]+(?:-[A-Z0-9]+)+", metrics["profile"]) is None:
            raise ValueError("licensed IDA benchmark profile is invalid")
        if re.fullmatch(r"\d+\.\d+(?:\.\d+)*", metrics["ida_build"]) is None:
            raise ValueError("licensed IDA benchmark IDA build is invalid")
        if re.fullmatch(r"\d+\.\d+(?:\.\d+)*", metrics["hexrays_build"]) is None:
            raise ValueError("licensed IDA benchmark Hex-Rays build is invalid")
        if (
            re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,127}", metrics["hardware_class"])
            is None
        ):
            raise ValueError("licensed IDA benchmark hardware class is invalid")
        _statistics(metrics.get("wall_time_ms"), "licensed_ida.wall_time_ms")
        _positive_int(metrics.get("peak_rss_bytes"), "licensed_ida.peak_rss_bytes")
        if expected is not None:
            for field, value in expected.items():
                if metrics.get(field) != value:
                    raise ValueError(f"licensed IDA benchmark {field} mismatch")
    except (TypeError, ValueError) as exc:
        failures.append(str(exc))
    if not failures:
        frozen = limits["stages"]["ida_extract"]
        _within_stats(
            metrics["wall_time_ms"], frozen["wall_time_ms"], "ida_extract", failures
        )
        if metrics["peak_rss_bytes"] > frozen["peak_rss_bytes"]:
            failures.append("ida_extract.peak_rss_bytes exceeded the frozen limit")
    return {"status": "fail" if failures else "pass", "failures": failures}


def build_report(
    workloads: list[Json],
    limits: Json,
    ida_metrics: Json | None,
    *,
    limits_digest: str | None = None,
    commit: str | None = None,
    build_id: str | None = None,
    expected_ida_executable_sha256: str | None = None,
) -> Json:
    if limits_digest is None:
        limits_digest = _sha256(DEFAULT_LIMITS)
    if commit is None:
        commit = git_commit()
    if build_id is None:
        from ida_pro_mcp.flow_core.build_identity import BUILD_ID as build_id
    report: Json = {
        "schema_version": "flow-benchmark-report/2",
        "commit": commit,
        "build_id": build_id,
        "expected_ida_executable_sha256": expected_ida_executable_sha256,
        "implementation_sha256": implementation_sha256(),
        "limits_sha256": limits_digest,
        "environment": {
            "system": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "sampling": limits["sampling"],
        "workloads": workloads,
        "ida_metrics": ida_metrics,
        "target_executed": False,
        "input_preserved": True,
    }
    pure = evaluate_pure(report, limits)
    expected = None
    if expected_ida_executable_sha256 is not None:
        expected = _expectations(
            limits,
            commit=commit,
            build_id=build_id,
            limits_digest=limits_digest,
            ida_executable_sha256=expected_ida_executable_sha256,
        )
    ida = evaluate_ida(ida_metrics, limits, expected)
    report["evaluation"] = {"pure": pure, "ida_extract": ida}
    report["status"] = (
        "fail"
        if pure["status"] != "pass" or ida["status"] == "fail"
        else "pass"
        if ida["status"] == "pass"
        else "partial"
    )
    return report


def git_commit() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def validate_release_report(
    report: Json,
    limits: Json,
    *,
    expected_commit: str,
    expected_build_id: str,
    expected_limits_digest: str,
    expected_ida_executable_sha256: str,
) -> None:
    required = {
        "schema_version",
        "commit",
        "build_id",
        "expected_ida_executable_sha256",
        "implementation_sha256",
        "limits_sha256",
        "environment",
        "sampling",
        "workloads",
        "ida_metrics",
        "target_executed",
        "input_preserved",
        "evaluation",
        "status",
    }
    if set(report) != required:
        raise ValueError("benchmark report fields do not match the release contract")
    if report.get("schema_version") != "flow-benchmark-report/2":
        raise ValueError("benchmark report schema mismatch")
    if report.get("commit") != expected_commit:
        raise ValueError("benchmark report commit mismatch")
    if report.get("build_id") != expected_build_id:
        raise ValueError("benchmark report build ID mismatch")
    if report.get("implementation_sha256") != implementation_sha256():
        raise ValueError("benchmark report implementation is stale")
    if report.get("limits_sha256") != expected_limits_digest:
        raise ValueError("benchmark report limits digest mismatch")
    if (
        type(expected_ida_executable_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_ida_executable_sha256) is None
        or report.get("expected_ida_executable_sha256")
        != expected_ida_executable_sha256
    ):
        raise ValueError("benchmark report IDA executable identity mismatch")
    if report.get("sampling") != limits.get("sampling"):
        raise ValueError("benchmark report sampling contract mismatch")
    environment = report.get("environment")
    if type(environment) is not dict or set(environment) != {
        "system",
        "machine",
        "python",
    }:
        raise ValueError("benchmark report environment is malformed")
    for field in ("system", "machine", "python"):
        _string(environment.get(field), f"benchmark.environment.{field}")
    if (
        report.get("target_executed") is not False
        or report.get("input_preserved") is not True
    ):
        raise ValueError("benchmark report violated static-only safety")
    pure = evaluate_pure(report, limits)
    ida = evaluate_ida(
        report.get("ida_metrics"),
        limits,
        _expectations(
            limits,
            commit=expected_commit,
            build_id=expected_build_id,
            limits_digest=expected_limits_digest,
            ida_executable_sha256=expected_ida_executable_sha256,
        ),
    )
    if report.get("evaluation") != {"pure": pure, "ida_extract": ida}:
        raise ValueError("benchmark report evaluation is stale or tampered")
    if (
        pure.get("status") != "pass"
        or ida.get("status") != "pass"
        or report.get("status") != "pass"
    ):
        raise ValueError("benchmark report is not release-ready")


def _run_children(limits: Json, warmups: int, measurements: int) -> list[Json]:
    reports: list[Json] = []
    for name in ("b01", "b02", "b03"):
        completed = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--worker",
                name,
                "--warmups",
                str(warmups),
                "--measurements",
                str(measurements),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        reports.append(json.loads(completed.stdout))
    return reports


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limits", type=Path, default=DEFAULT_LIMITS)
    parser.add_argument("--ida-metrics", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-ida", action="store_true")
    parser.add_argument("--expected-ida-executable-sha256")
    parser.add_argument("--worker", choices=tuple(WORKLOADS))
    parser.add_argument("--warmups", type=int)
    parser.add_argument("--measurements", type=int)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if args.worker:
        warmups = 5 if args.warmups is None else args.warmups
        measurements = 30 if args.measurements is None else args.measurements
        report = measure_workload(
            args.worker,
            WORKLOADS[args.worker],
            warmups=warmups,
            measurements=measurements,
        )
        print(json.dumps(report, sort_keys=True))
        return 0

    limits = json.loads(args.limits.read_text())
    validate_limits(limits)
    warmups = limits["sampling"]["warmups"]
    measurements = limits["sampling"]["measurements"]
    workloads = _run_children(limits, warmups, measurements)
    ida_metrics = json.loads(args.ida_metrics.read_text()) if args.ida_metrics else None
    if ida_metrics is not None and args.expected_ida_executable_sha256 is None:
        raise ValueError("licensed IDA metrics require an expected executable digest")
    report = build_report(
        workloads,
        limits,
        ida_metrics,
        limits_digest=_sha256(args.limits.resolve()),
        expected_ida_executable_sha256=args.expected_ida_executable_sha256,
    )
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")
    if report["status"] == "fail":
        return 1
    if args.require_ida and report["status"] != "pass":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
