#!/usr/bin/env python3
"""Promote validated actual semantic rows into checkout-bound release receipts.

This producer never invokes or executes a target.  It revalidates the checked-in
fresh-process IDA/Hex-Rays semantic artifacts with the current evaluator and
implementation hashes, then binds each available normal row to the reviewed
checkout and current flow build.  RV32 fallback evidence is deliberately not a
normal row and therefore produces no receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
from pathlib import Path
from typing import Any

from ida_pro_mcp.flow_core.build_identity import BUILD_ID, BUILD_SCOPE
from ida_pro_mcp.flow_core.serialization import digest

ROOT = Path(__file__).resolve().parents[1]
MATRIX = Path("tests/flow_fixtures/manifests/profile_semantics/matrix.json")
BUILD_MANIFEST = Path("tests/flow_fixtures/manifests/profiles/build.json")
SCHEMA = "flow-licensed-normal/1"
SHA1 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if type(value) is not dict:
        raise ValueError(f"Expected a JSON object: {path}")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _evaluator(root: Path):
    path = root / "scripts/evaluate_flow_profile_semantics.py"
    spec = importlib.util.spec_from_file_location("flow_normal_evaluator", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load profile semantic evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _build_rows(root: Path) -> dict[tuple[str, str], dict[str, Any]]:
    manifest = read_json(root / BUILD_MANIFEST)
    rows = [*manifest["profiles"], *manifest["format_variants"]]
    return {(row["profile_id"], row["format"]): row for row in rows}


def _licensed_receipt(
    source: dict[str, Any],
    matrix_row: dict[str, Any],
    build_row: dict[str, Any],
    *,
    checkout_sha: str,
    executable_sha256: str,
) -> dict[str, Any]:
    environment = source.get("environment")
    invocations = source.get("invocations")
    if type(environment) is not dict or type(invocations) is not list:
        raise ValueError(
            "Normal semantic environment or invocation evidence is missing"
        )
    expected_identity = {
        "profile_id": build_row["profile_id"],
        "abi_id": build_row["abi_id"],
        "format_id": build_row["format"],
        "maturity": "MMAT_CALLS",
        "processor": build_row["processor"],
        "bitness": build_row["bitness"],
        "data_endian": {"LE": "little", "BE": "big"}[build_row["data_endian"]],
    }
    observed_identity = {
        "profile_id": source.get("profile_id"),
        "abi_id": source.get("abi_id"),
        "format_id": environment.get("format_id"),
        "maturity": source.get("maturity"),
        "processor": environment.get("processor"),
        "bitness": environment.get("bitness"),
        "data_endian": environment.get("data_endian"),
    }
    if observed_identity != expected_identity:
        raise ValueError("Normal semantic profile identity was substituted")
    if (
        source.get("status") != "success"
        or source.get("target_executed") is not False
        or source.get("input_preserved") is not True
        or source.get("binary_sha256") != build_row["binary_sha256"]
        or matrix_row.get("receipt_digest") != source.get("receipt_digest")
    ):
        raise ValueError("Normal semantic source is not a passing static row")
    invocation_hashes = {
        item.get("ida_executable_sha256")
        for item in invocations
        if type(item) is dict
        and item.get("target_executed") is False
        and item.get("input_preserved") is True
        and item.get("exit_code") == 0
    }
    if invocation_hashes != {executable_sha256}:
        raise ValueError("Normal semantic IDA executable identity mismatch")

    runtime_environment = {
        "ida_version": environment.get("ida_build"),
        "hexrays_version": environment.get("hexrays_build"),
        "processor": environment.get("processor"),
        "bits": environment.get("bitness"),
        "endian": environment.get("data_endian"),
        "instruction_endian": environment.get("instruction_endian"),
        "abi": environment.get("abi"),
        "format_id": environment.get("format_id"),
        "platform_tag": environment.get("platform_tag"),
        "hexrays_initialization": {
            "status": "available",
            "reason": "validated fresh-process normal semantic receipt",
        },
    }
    capabilities = {
        "schema_version": "flow-capabilities/1",
        "build_id": BUILD_ID,
        "build_scope": BUILD_SCOPE,
        "environment": runtime_environment,
        "supported_profiles": [source["profile_id"]],
        "normal_evidence": {
            "receipt_file": matrix_row["receipt_file"],
            "receipt_digest": matrix_row["receipt_digest"],
        },
    }
    return {
        "schema_version": SCHEMA,
        "checkout_sha": checkout_sha,
        "fixture": Path(build_row["binary"]).name,
        "fixture_sha256": source["binary_sha256"],
        "ida_input_sha256": source["binary_sha256"],
        "profile_id": source["profile_id"],
        "abi_id": source["abi_id"],
        "format_id": environment["format_id"],
        "maturity": source["maturity"],
        "normal_status": "pass",
        "ida_build": environment["ida_build"],
        "ida_executable_sha256": executable_sha256,
        "hexrays_build": environment["hexrays_build"],
        "flow_build_id": BUILD_ID,
        "capabilities": capabilities,
        "capabilities_digest": digest(capabilities),
        "environment": runtime_environment,
        "supported_profiles": [source["profile_id"]],
        "input_preserved": True,
        "target_executed": False,
        "debugger_attached": False,
        "semantic_receipt_file": matrix_row["receipt_file"],
        "semantic_receipt_digest": matrix_row["receipt_digest"],
    }


def record(
    *,
    root: Path,
    output_dir: Path,
    checkout_sha: str,
    executable_sha256: str,
    expected_executable_sha256: str,
) -> list[Path]:
    root = root.resolve()
    output_dir = output_dir.resolve()
    if SHA1.fullmatch(checkout_sha) is None:
        raise ValueError("checkout_sha must be a full lowercase commit SHA")
    if (
        SHA256.fullmatch(executable_sha256) is None
        or executable_sha256 != expected_executable_sha256
    ):
        raise ValueError("IDA executable does not match the reviewed digest")
    if output_dir.exists() or output_dir.is_symlink():
        if output_dir.is_symlink() or not output_dir.is_dir():
            raise ValueError("Normal receipt output must be a regular directory")
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)

    matrix = read_json(root / MATRIX)
    _evaluator(root).validate_complete_matrix_artifacts(root, matrix)
    build_rows = _build_rows(root)
    written: list[Path] = []
    for index, item in enumerate(matrix["profiles"]):
        evidence_path = item.get("evidence_path")
        if evidence_path == "fallback":
            continue
        if evidence_path not in {"normal", "format"}:
            raise ValueError("Unknown semantic evidence path")
        identity = (item["profile_id"], item["format"])
        build_row = build_rows.get(identity)
        if build_row is None:
            raise ValueError("Semantic row has no canonical build identity")
        source = read_json(root / item["receipt_file"])
        receipt = _licensed_receipt(
            source,
            item,
            build_row,
            checkout_sha=checkout_sha,
            executable_sha256=executable_sha256,
        )
        name = (
            f"normal-{index:02d}-{item['profile_id'].lower()}-"
            f"{item['format'].removeprefix('FMT-').lower()}.json"
        )
        path = output_dir / name
        path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        written.append(path)
    if len(written) != 20:
        raise ValueError(
            "Expected exactly 20 actual normal semantic rows; RV32 is fallback"
        )
    return written


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checkout-sha", required=True)
    parser.add_argument("--ida", type=Path, required=True)
    parser.add_argument("--expected-ida-executable-sha256", required=True)
    arguments = parser.parse_args()
    ida = arguments.ida.resolve()
    if not ida.is_file():
        raise FileNotFoundError("Licensed IDA executable is missing")
    paths = record(
        root=arguments.root,
        output_dir=arguments.output,
        checkout_sha=arguments.checkout_sha,
        executable_sha256=sha256(ida),
        expected_executable_sha256=arguments.expected_ida_executable_sha256,
    )
    print(json.dumps({"schema_version": SCHEMA, "receipts": len(paths)}))


if __name__ == "__main__":
    main()
