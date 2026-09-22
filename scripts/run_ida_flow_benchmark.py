#!/usr/bin/env python3
"""Generate a licensed static IDA timing receipt for one committed anchor.

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
import statistics
import subprocess
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXTRACTOR = ROOT / "scripts/flow_extract_receipt.py"
INVENTORY = ROOT / "tests/flow_fixtures/manifests/p0_inventory.json"
DEFAULT_IDA = Path("/Applications/IDA Professional 9.3.app/Contents/MacOS/idat")
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


def profile_row(profile_id: str) -> dict[str, Any]:
    inventory = json.loads(INVENTORY.read_text())
    rows = [row for row in inventory["profiles"] if row["profile_id"] == profile_id]
    if len(rows) != 1:
        raise ValueError(f"unknown or duplicate profile {profile_id}")
    return rows[0]


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
    directory: Path,
    ordinal: int,
) -> tuple[float, int, dict[str, Any]]:
    receipt = directory / f"receipt-{ordinal:02d}.json"
    database = directory / f"anchor-{ordinal:02d}.i64"
    log = directory / f"ida-{ordinal:02d}.log"
    script_command = " ".join(
        (
            str(EXTRACTOR),
            str(ROOT),
            str(receipt),
            profile_id,
            abi,
            selector,
            namespace,
        )
    )
    command = [
        "/usr/bin/time",
        "-l",
        str(ida),
        "-A",
        "-c",
        f"-o{database}",
        f"-L{log}",
        f"-S{script_command}",
        str(fixture),
    ]
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if completed.returncode != 0 or not receipt.is_file():
        details = (
            log.read_text(errors="replace") if log.is_file() else "missing IDA log"
        )
        raise RuntimeError(
            f"licensed static IDA sample {ordinal} failed ({completed.returncode})\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}\nlog:\n{details}"
        )
    elapsed_ms, peak_rss_bytes = parse_bsd_time(completed.stderr)
    document = json.loads(receipt.read_text())
    if document.get("target_executed") is not False:
        raise RuntimeError("static extraction receipt did not deny target execution")
    if document.get("profile", {}).get("profile_id") != profile_id:
        raise RuntimeError("static extraction receipt profile mismatch")
    return elapsed_ms, peak_rss_bytes, document


def generate(args: argparse.Namespace) -> dict[str, Any]:
    fixture = args.fixture.resolve()
    ida = args.ida.resolve()
    if not fixture.is_file() or not ida.is_file():
        raise FileNotFoundError("IDA executable or fixture is missing")
    if args.warmups != 5 or args.measurements != 30:
        raise ValueError("flow-ida-benchmark/1 requires 5 warmups and 30 measurements")
    row = profile_row(args.profile)
    fixture_digest = sha256(fixture)
    if fixture_digest not in row["fixture_hashes"]:
        raise ValueError("fixture hash is not pinned by the requested profile")
    before = fixture_digest
    elapsed: list[float] = []
    peak_rss: list[int] = []
    receipt_digest: str | None = None
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
                directory=directory,
                ordinal=ordinal,
            )
            digest = receipt["canonical_digest"]
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
    return {
        "schema_version": "flow-ida-benchmark/1",
        "ida_build": row["ida_build"],
        "hardware_id": f"{platform.system().lower()}-{platform.machine()}",
        "commit": git_commit(),
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
    parser.add_argument("--selector", default="p0_anchor")
    parser.add_argument("--namespace", default="flow-benchmark-static")
    parser.add_argument("--ida", type=Path, default=DEFAULT_IDA)
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
