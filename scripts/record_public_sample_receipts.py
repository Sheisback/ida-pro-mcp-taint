#!/usr/bin/env python3
"""Record actual static IDA receipts for pinned G015 public corpus builds."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXTRACTOR = ROOT / "scripts/flow_public_sample_extract.py"
DEFAULT_IDAT = Path("/Applications/IDA Professional 9.3.app/Contents/MacOS/idat")

FUNCTIONS = {
    "svf-pointer-copy": [("_main", "svf-pointer-copy-main")],
    "svf-pointer-store-load": [("_main", "svf-pointer-store-load-main")],
    "svf-field-sensitivity": [("_main", "svf-field-sensitivity-main")],
    "svf-context-call": [
        ("_main", "svf-context-call-main"),
        ("_foo", "svf-context-call-callee"),
    ],
    "juliet-cwe789-31": [
        ("_CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_31_bad", "juliet-31-bad"),
        ("_goodB2G", "juliet-31-good-bad-source-good-sink"),
    ],
    "juliet-cwe789-32": [
        ("_CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_32_bad", "juliet-32-bad"),
        ("_goodB2G", "juliet-32-good-bad-source-good-sink"),
    ],
    "juliet-cwe789-33": [
        (
            "__ZN51CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_333badEv",
            "juliet-33-bad",
        ),
        (
            "__ZN51CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_33L7goodB2GEv",
            "juliet-33-good-bad-source-good-sink",
        ),
    ],
    "juliet-cwe789-34": [
        ("_CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_34_bad", "juliet-34-bad"),
        ("_goodB2G", "juliet-34-good-bad-source-good-sink"),
    ],
    "juliet-cwe789-41": [
        ("_CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_41_bad", "juliet-41-bad"),
        ("_goodB2G", "juliet-41-good-bad-source-good-sink"),
        ("_goodB2GSink", "juliet-41-good-sink-callee"),
    ],
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(build_root: Path, output: Path, idat: Path) -> None:
    rows = json.loads((build_root / "build.json").read_text())
    if {row["case_id"] for row in rows} != set(FUNCTIONS):
        raise ValueError("Build manifest does not contain the exact public corpus")
    output.mkdir(parents=True, exist_ok=False)
    receipts = []
    for row in rows:
        binary = build_root / "fresh-1/binaries" / row["binary"]
        if sha256(binary) != row["binary_sha256"]:
            raise ValueError(f"Stale binary for {row['case_id']}")
        with tempfile.TemporaryDirectory(prefix="g015-static-") as directory:
            run = Path(directory)
            target = run / "target"
            shutil.copyfile(binary, target)
            request = {
                key: row[key]
                for key in (
                    "corpus",
                    "case_id",
                    "source_sha256",
                    "binary_sha256",
                    "compiler",
                    "sdk_version",
                )
            }
            request.update(
                {
                    "schema_version": "flow-public-sample-static-request/1",
                    "namespace": "g015-public-sample-corpus",
                    "functions": [
                        {"selector": selector, "function_key": function_key}
                        for selector, function_key in FUNCTIONS[row["case_id"]]
                    ],
                    "target_executed": False,
                }
            )
            request_path = run / "request.json"
            receipt_path = run / "receipt.json"
            log_path = run / "ida.log"
            request_path.write_text(json.dumps(request, indent=2) + "\n")
            command = [
                str(idat),
                f"-L{log_path}",
                "-c",
                "-A",
                f"-S{EXTRACTOR} {ROOT} {receipt_path} {request_path}",
                str(target),
            ]
            completed = subprocess.run(command, check=False)
            if completed.returncode != 0:
                log = log_path.read_text(errors="replace") if log_path.exists() else ""
                raise RuntimeError(
                    f"IDA extraction failed for {row['case_id']}:\n{log[-8000:]}"
                )
            if (
                sha256(binary) != row["binary_sha256"]
                or sha256(target) != row["binary_sha256"]
            ):
                raise ValueError(
                    f"Static analysis changed the input for {row['case_id']}"
                )
            receipt = json.loads(receipt_path.read_text())
            if receipt.get("target_executed") is not False:
                raise ValueError("Static receipt does not deny target execution")
            receipt.update(
                {
                    "input_preserved": True,
                    "invocation": [
                        "idat",
                        "-L$LOG",
                        "-c",
                        "-A",
                        "-Sscripts/flow_public_sample_extract.py $ROOT $OUTPUT $REQUEST",
                        "$BINARY",
                    ],
                    "ida_log_sha256": sha256(log_path),
                    "recorder_sha256": sha256(Path(__file__)),
                }
            )
            destination = output / f"{row['case_id']}.json"
            destination.write_text(json.dumps(receipt, indent=2) + "\n")
            receipts.append(
                {
                    "case_id": row["case_id"],
                    "path": destination.name,
                    "sha256": sha256(destination),
                    "binary_sha256": row["binary_sha256"],
                    "function_count": len(receipt["functions"]),
                    "target_executed": False,
                    "input_preserved": True,
                }
            )
    matrix = {
        "schema_version": "flow-public-sample-static-matrix/1",
        "build_manifest_sha256": sha256(build_root / "build.json"),
        "receipts": receipts,
        "target_executed": False,
        "input_preserved": True,
    }
    (output / "matrix.json").write_text(json.dumps(matrix, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_root", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--idat", type=Path, default=DEFAULT_IDAT)
    args = parser.parse_args()
    record(args.build_root, args.output, args.idat)


if __name__ == "__main__":
    main()
