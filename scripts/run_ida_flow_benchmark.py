#!/usr/bin/env python3
"""Generate a licensed static microcode-extraction timing receipt.

The target is loaded for static analysis only. This script never starts a
debugger or executes the target program.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import platform
import re
import shlex
import statistics
import subprocess
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXTRACTION_ENTRY = ROOT / "scripts/flow_benchmark_extract.py"
INVENTORY = ROOT / "tests/flow_fixtures/manifests/p0_inventory.json"
DEFAULT_IDA = Path("/Applications/IDA Professional 9.3.app/Contents/MacOS/idat")
DEFAULT_LIMITS = ROOT / "tests/flow_fixtures/manifests/benchmark-limits.json"
STATS = ("median_ms", "p95_ms", "max_ms")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def sample_statistics(values: list[float]) -> dict[str, float]:
    if not values:
        raise ValueError("at least one measured sample is required")
    return {
        "median_ms": statistics.median(values),
        "p95_ms": percentile(values, 0.95),
        "max_ms": max(values),
    }


def parse_bsd_time(stderr: str) -> tuple[float, int]:
    elapsed = re.search(r"(?m)^\s*([0-9.]+)\s+real\s+", stderr)
    rss = re.search(r"(?m)^\s*([0-9]+)\s+maximum resident set size\s*$", stderr)
    if elapsed is None or rss is None:
        raise RuntimeError(f"unable to parse /usr/bin/time -l output:\n{stderr}")
    return float(elapsed.group(1)) * 1000, int(rss.group(1))


def parse_process_time(stderr: str) -> tuple[float, int]:
    if platform.system() == "Darwin":
        return parse_bsd_time(stderr)
    match = re.search(r"(?m)^__FLOW_TIME__ ([0-9.]+) ([0-9]+)$", stderr)
    if match is None:
        raise RuntimeError(f"unable to parse GNU time output:\n{stderr}")
    return float(match.group(1)) * 1000, int(match.group(2)) * 1024


def git_commit() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def run_sample(
    *,
    ida: Path,
    fixture: Path,
    profile_id: str,
    abi: str,
    selector: str,
    namespace: str,
    inventory: dict[str, Any],
    build_manifest: list[dict[str, Any]],
    directory: Path,
    ordinal: int,
) -> tuple[float, int, dict[str, Any]]:
    receipt = directory / f"receipt-{ordinal:02d}.json"
    request_path = directory / f"request-{ordinal:02d}.json"
    database = directory / f"benchmark-{ordinal:02d}.i64"
    log = directory / f"ida-{ordinal:02d}.log"
    request = {
        "schema_version": "flow-benchmark-extraction-request/1",
        "fixture_sha256": sha256(fixture),
        "profile_id": profile_id,
        "abi_id": abi,
        "selector": selector,
        "namespace": namespace,
        "inventory": inventory,
        "build_manifest": build_manifest,
    }
    request_path.write_text(json.dumps(request, sort_keys=True))
    script_command = shlex.join(
        [str(EXTRACTION_ENTRY), str(ROOT), str(receipt), str(request_path)]
    )
    benchmarked = [
        str(ida),
        "-A",
        "-c",
        f"-o{database}",
        f"-L{log}",
        f"-S{script_command}",
        str(fixture),
    ]
    command = (
        ["/usr/bin/time", "-l", *benchmarked]
        if platform.system() == "Darwin"
        else ["/usr/bin/time", "-f", "__FLOW_TIME__ %e %M", *benchmarked]
    )
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if completed.returncode != 0 or not receipt.is_file():
        details = log.read_text(errors="replace") if log.is_file() else "missing log"
        raise RuntimeError(
            f"licensed static IDA sample {ordinal} failed ({completed.returncode})\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}\n{details}"
        )
    elapsed_ms, peak_rss_bytes = parse_process_time(completed.stderr)
    document = json.loads(receipt.read_text())
    from ida_pro_mcp.flow_core.contracts import Snapshot
    from ida_pro_mcp.flow_core.serialization import digest

    if document.get("schema_version") != "flow-benchmark-extraction/1":
        raise RuntimeError("static extraction receipt schema mismatch")
    if (
        document.get("target_executed") is not False
        or document.get("input_preserved") is not True
        or document.get("repeat_equal") is not True
        or document.get("roundtrip_equal") is not True
    ):
        raise RuntimeError("static extraction evidence failed")
    snapshot = Snapshot.from_data(document.get("snapshot"))
    if document.get("snapshot_digest") != digest(snapshot):
        raise RuntimeError("static extraction snapshot digest mismatch")
    if document.get("profile", {}).get("profile_id") != profile_id:
        raise RuntimeError("static extraction receipt profile mismatch")
    return elapsed_ms, peak_rss_bytes, document


def generate(args: argparse.Namespace) -> dict[str, Any]:
    fixture = args.fixture.resolve()
    ida = args.ida.resolve()
    if not fixture.is_file() or not ida.is_file():
        raise FileNotFoundError("IDA executable or fixture is missing")
    if (
        re.fullmatch(r"[0-9a-f]{64}", args.expected_ida_executable_sha256) is None
        or sha256(ida) != args.expected_ida_executable_sha256
    ):
        raise ValueError("IDA executable does not match the reviewed digest")
    if args.warmups != 5 or args.measurements != 30:
        raise ValueError("flow-ida-benchmark/2 requires 5 warmups and 30 measurements")
    limits = json.loads(args.limits.read_text())
    expected = limits["stages"]["ida_extract"]["expectations"]
    fixture_digest = sha256(fixture)
    if fixture_digest != expected["fixture_sha256"]:
        raise ValueError("fixture hash does not match the reviewed benchmark limits")
    before = fixture_digest
    build_manifest = json.loads(args.build_manifest.read_text())
    if type(build_manifest) is not list:
        raise ValueError("benchmark build manifest must be an array")
    matches = [
        row
        for row in build_manifest
        if row.get("binary_sha256") == fixture_digest
        and row.get("abi_id") == args.abi
        and row.get("format") == args.format_id
    ]
    if len(matches) != 1:
        raise ValueError("benchmark fixture lacks one exact build row")
    inventory = json.loads(INVENTORY.read_text())
    rows = [
        row for row in inventory["profiles"] if row.get("profile_id") == args.profile
    ]
    if len(rows) != 1:
        raise ValueError("benchmark profile inventory row is missing")
    rows[0]["fixture_hashes"] = [fixture_digest]
    elapsed: list[float] = []
    peak_rss: list[int] = []
    receipt_digest: str | None = None
    observed_environment: dict[str, Any] | None = None
    total = args.warmups + args.measurements
    with tempfile.TemporaryDirectory(prefix=".flow-ida-benchmark-", dir=ROOT) as raw:
        directory = Path(raw)
        for ordinal in range(total):
            wall_ms, rss_bytes, receipt = run_sample(
                ida=ida,
                fixture=fixture,
                profile_id=args.profile,
                abi=args.abi,
                selector=args.selector,
                namespace=args.namespace,
                inventory=inventory,
                build_manifest=build_manifest,
                directory=directory,
                ordinal=ordinal,
            )
            digest = receipt["snapshot_digest"]
            environment = receipt["environment"]
            if observed_environment is None:
                observed_environment = environment
            elif observed_environment != environment:
                raise RuntimeError("licensed IDA environment changed between samples")
            if receipt_digest is None:
                receipt_digest = digest
            elif receipt_digest != digest:
                raise RuntimeError(
                    "static IDA extraction digest changed between samples"
                )
            if ordinal >= args.warmups:
                elapsed.append(wall_ms)
                peak_rss.append(rss_bytes)
    after = sha256(fixture)
    if before != after:
        raise RuntimeError("static benchmark modified the input fixture")
    if observed_environment is None:
        raise RuntimeError("licensed benchmark recorded no environment")
    from ida_pro_mcp.flow_core.build_identity import BUILD_ID

    observed_ida = observed_environment["ida_build"]
    observed_hexrays = observed_environment["hexrays_build"]
    hardware_class = f"{platform.system().lower()}-{platform.machine().lower()}"
    observed = {
        "fixture_sha256": fixture_digest,
        "profile": args.profile,
        "ida_build": observed_ida,
        "hexrays_build": observed_hexrays,
        "hardware_class": hardware_class,
    }
    if observed != expected:
        raise RuntimeError("licensed benchmark environment does not match limits")
    return {
        "schema_version": "flow-ida-benchmark/2",
        "ida_build": observed_ida,
        "ida_executable_sha256": sha256(ida),
        "hexrays_build": observed_hexrays,
        "hardware_class": hardware_class,
        "commit": git_commit(),
        "build_id": BUILD_ID,
        "limits_digest": "sha256-v1:" + sha256(args.limits),
        "fixture_sha256": fixture_digest,
        "profile": args.profile,
        "warmups": args.warmups,
        "measurements": args.measurements,
        "wall_time_ms": sample_statistics(elapsed),
        "peak_rss_bytes": max(peak_rss),
        "target_executed": False,
        "input_preserved": True,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--abi", required=True)
    parser.add_argument("--format", dest="format_id", required=True)
    parser.add_argument("--selector", default="p0_anchor")
    parser.add_argument("--namespace", default="flow-benchmark-static")
    parser.add_argument(
        "--build-manifest",
        type=Path,
        default=ROOT / "tests/flow_fixtures/benchmark/build.json",
    )
    parser.add_argument("--ida", type=Path, default=DEFAULT_IDA)
    parser.add_argument("--expected-ida-executable-sha256", required=True)
    parser.add_argument("--limits", type=Path, default=DEFAULT_LIMITS)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--measurements", type=int, default=30)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    receipt = generate(args)
    args.output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
