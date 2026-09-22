#!/usr/bin/env python3
"""Record the sixteen normal G012 semantic profiles with actual static IDA.

Each row uses two fresh ``idat -c -A`` processes over disposable copies.  The
original rebuilt ELF is hash-checked before and after each process and is never
executed.  Receipts contain pure snapshots for offline replay.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ida_pro_mcp.flow_core.profile_semantics import (
    FORMAT_MATRIX_SCHEMA,
    FUNCTIONS,
    NORMAL_MATRIX_SCHEMA,
    NORMAL_PROFILE_IDS,
    NORMAL_RECEIPT_SCHEMA,
    ephemeral_registry,
    evaluate_normal_snapshots,
    receipt_digest,
    semantic_profile,
    validate_build_rows,
    validate_format_rows,
    validate_normal_process,
    validate_normal_receipt,
)
from ida_pro_mcp.flow_core.serialization import digest

IMPLEMENTATION_FILES = (
    "scripts/flow_profile_semantics.py",
    "scripts/record_flow_profile_semantics.py",
    "src/ida_pro_mcp/flow_core/profile_semantics.py",
    "src/ida_pro_mcp/ida_mcp/flow/extractor.py",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(
        path.read_text(),
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
    )


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def implementation_digests(root: Path) -> dict[str, str]:
    return {relative: sha256(root / relative) for relative in IMPLEMENTATION_FILES}


def _request(
    row: dict[str, Any],
    manifest_sha256: str,
    implementation: dict[str, str],
    registry,
) -> dict[str, Any]:
    return {
        "schema_version": "flow-profile-semantics-request/1",
        "manifest_sha256": manifest_sha256,
        "binary_sha256": row["binary_sha256"],
        "build_row": row,
        "registry": registry.to_data(),
        "profile": semantic_profile(row, manifest_sha256, registry),
        "functions": list(FUNCTIONS),
        "implementation": implementation,
    }


def _p0_evidence(
    p0_root: Path, p0_matrix: dict[str, Any], build_row: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], str]:
    p0_root = p0_root.resolve()
    if (
        p0_matrix.get("schema_version") != "flow-profile-receipt-matrix/1"
        or p0_matrix.get("target_executed") is not False
    ):
        raise ValueError("Unsupported P0 semantic-matrix prerequisite")
    matches = [
        row
        for row in p0_matrix.get("rows", [])
        if row.get("profile_id") == build_row["profile_id"]
        and row.get("format") == build_row["format"]
    ]
    if len(matches) != 1 or matches[0].get("status") != "success":
        raise ValueError(
            "Expected one successful P0 row for " + build_row["profile_id"]
        )
    relative = Path(matches[0]["result_file"])
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Unsafe P0 result path")
    result_path = (p0_root / relative).resolve()
    result_path.relative_to(p0_root)
    result = read_json(result_path)
    receipt_path = result_path.parent / result["stages"]["final"]["receipt_file"]
    receipt_path = receipt_path.resolve()
    receipt_path.relative_to(p0_root)
    receipt = read_json(receipt_path)
    logical_file = "actual-p0/" + receipt_path.relative_to(p0_root).as_posix()
    return result, receipt, logical_file


def _run_process(
    *,
    root: Path,
    ida_executable: Path,
    source_binary: Path,
    request: dict[str, Any],
    run_id: str,
    timeout_seconds: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    original_before = sha256(source_binary)
    with tempfile.TemporaryDirectory(prefix="flow-profile-semantics-") as temporary:
        work = Path(temporary)
        disposable = work / source_binary.name
        request_path = work / "request.json"
        output_path = work / "process-receipt.json"
        shutil.copyfile(source_binary, disposable)
        write_json(request_path, request)
        script_arguments = [
            str(root / "scripts/flow_profile_semantics.py"),
            str(root),
            str(output_path),
            str(request_path),
        ]
        loader_options: list[str] = []
        if request["build_row"].get("format") == "FMT-RAW":
            config = request["build_row"].get("raw_configuration")
            if type(config) is not dict:
                raise RuntimeError("Raw semantic configuration missing")
            load_address = config.get("load_address")
            entry_point = config.get("entry_point")
            if load_address != 0x10000 or entry_point != load_address:
                raise RuntimeError("Raw semantic configuration is not reviewed")
            loader_options = [
                "-TBinary",
                "-parm:ARMv7-A",
                f"-b{load_address // 16:x}",
                f"-i{entry_point:x}",
            ]
        command = [
            str(ida_executable),
            "-c",
            "-A",
            *loader_options,
            "-S" + shlex.join(script_arguments),
            str(disposable),
        ]
        completed = subprocess.run(
            command,
            cwd=work,
            check=False,
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout_seconds,
        )
        invocation = {
            "schema_version": "flow-profile-semantics-invocation/1",
            "run_id": run_id,
            "ida_executable_name": ida_executable.name,
            "ida_executable_sha256": sha256(ida_executable),
            "arguments_shape": [
                "-c",
                "-A",
                "-S<entry-script> <root> <output> <request>",
                "<disposable-copy>",
            ],
            "shell": False,
            "exit_code": completed.returncode,
            "target_executed": False,
            "input_preserved": sha256(source_binary) == original_before,
        }
        if completed.returncode != 0 or not output_path.is_file():
            process_failure = output_path.read_text() if output_path.is_file() else ""
            raise RuntimeError(
                f"IDA semantic process {run_id} failed with {completed.returncode}: "
                + (process_failure + "\n" + completed.stdout + "\n" + completed.stderr)[
                    -12000:
                ]
            )
        process = read_json(output_path)
        validate_normal_process(
            process, request["build_row"], request["manifest_sha256"]
        )
        if sha256(disposable) != original_before:
            raise RuntimeError("Disposable input changed during static extraction")
    if sha256(source_binary) != original_before:
        raise RuntimeError("Original input changed during static extraction")
    return process, invocation


def _oracle_profiles(oracle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    profiles = oracle.get("profiles")
    if type(profiles) is not list:
        raise ValueError("ISA profile oracle rows missing")
    result = {row["profile_id"]: row for row in profiles}
    if len(result) != 17:
        raise ValueError("ISA profile oracle coverage mismatch")
    return result


def record_matrix(
    *,
    root: Path,
    committed_manifest: Path,
    rebuilt_manifest: Path,
    build_root: Path,
    p0_root: Path,
    oracle_path: Path,
    output_dir: Path,
    ida_executable: Path,
    timeout_seconds: int = 180,
    profile_filter: tuple[str, ...] | None = NORMAL_PROFILE_IDS,
    format_only: bool = False,
) -> dict[str, Any]:
    root = root.resolve()
    committed = read_json(committed_manifest)
    rebuilt = read_json(rebuilt_manifest)
    rows = (
        validate_format_rows(committed, rebuilt)
        if format_only
        else validate_build_rows(committed, rebuilt)
    )
    p0_matrix = read_json(p0_root / "matrix.json")
    manifest_sha256 = sha256(committed_manifest)
    oracle = read_json(oracle_path)
    oracles = _oracle_profiles(oracle)
    implementation = implementation_digests(root)
    output_dir.mkdir(parents=True, exist_ok=True)
    results = []
    failures = []

    if format_only:
        selected_rows = list(rows)
    else:
        if not profile_filter or any(
            item not in NORMAL_PROFILE_IDS for item in profile_filter
        ):
            raise ValueError("Invalid semantic profile filter")
        by_id = {row["profile_id"]: row for row in rows}
        selected_rows = [by_id[profile_id] for profile_id in profile_filter]
    for row in selected_rows:
        profile_id = row["profile_id"]
        source_binary = (build_root / row["binary"]).resolve()
        expected_root = build_root.resolve()
        source_binary.relative_to(expected_root)
        result_stem = (
            profile_id.lower()
            if not format_only
            else profile_id.lower() + "--" + row["format"].removeprefix("FMT-").lower()
        )
        result_file = result_stem + ".json"
        try:
            if not source_binary.is_file():
                raise RuntimeError("Rebuilt profile binary missing")
            if sha256(source_binary) != row["binary_sha256"]:
                raise RuntimeError("Rebuilt profile binary hash mismatch")
            if source_binary.stat().st_size != row["binary_size"]:
                raise RuntimeError("Rebuilt profile binary size mismatch")
            p0_result, p0_receipt, p0_receipt_file = _p0_evidence(
                p0_root, p0_matrix, row
            )
            registry = ephemeral_registry(row, p0_result, p0_receipt, p0_receipt_file)
            request = _request(row, manifest_sha256, implementation, registry)
            first, first_invocation = _run_process(
                root=root,
                ida_executable=ida_executable,
                source_binary=source_binary,
                request=request,
                run_id="fresh-1",
                timeout_seconds=timeout_seconds,
            )
            second, second_invocation = _run_process(
                root=root,
                ida_executable=ida_executable,
                source_binary=source_binary,
                request=request,
                run_id="fresh-2",
                timeout_seconds=timeout_seconds,
            )
            if first != second:
                raise RuntimeError("Fresh-process semantic receipt drift")
            evaluation = evaluate_normal_snapshots(
                first["functions"], first["image_base"]
            )
            isa = oracles[profile_id]["isa_specific_expectations"]
            value = {
                "schema_version": NORMAL_RECEIPT_SCHEMA,
                "profile_id": profile_id,
                "abi_id": row["abi_id"],
                "bitness": row["bitness"],
                "data_endian": row["data_endian"],
                "instruction_endian": row["instruction_endian"],
                "maturity": "MMAT_CALLS",
                "evidence_path": (
                    "format_microcode" if format_only else "normal_microcode"
                ),
                "status": "success",
                "binary_sha256": row["binary_sha256"],
                "build_evidence": {
                    "committed_manifest_sha256": manifest_sha256,
                    "rebuilt_manifest_sha256": sha256(rebuilt_manifest),
                    "build_row_digest": digest(row),
                    "rebuilt_profile_rows_equal": True,
                    "binary_hash_equal": True,
                    "binary_size_equal": True,
                },
                "registry": first["registry"],
                "profile": first["profile"],
                "profile_digest": first["profile_digest"],
                "environment": first["environment"],
                "image_base": first["image_base"],
                "functions": first["functions"],
                "fresh_process_receipt_digests": [
                    first["receipt_digest"],
                    second["receipt_digest"],
                ],
                "fresh_process_equal": True,
                "invocations": [first_invocation, second_invocation],
                "implementation": implementation,
                "oracle_source": oracle_path.relative_to(root).as_posix(),
                "oracle_digest": digest(oracle),
                "isa_oracle_binding": {
                    "oracle_id": oracles[profile_id]["oracle_id"],
                    "integer_return_register": isa["integer_return_register"],
                    "stack_pointer_register": isa["stack_pointer_register"],
                    "call_instruction_family": isa["call_instruction_family"],
                    "observation_status": "bound_hand_authored_expectation_not_serialized",
                },
                "evaluation": evaluation,
                "target_executed": False,
                "input_preserved": True,
                "registry_promoted": False,
                "service_promoted": False,
                "capabilities_promoted": False,
                "support_status": "unverified_semantic_candidate_no_promotion",
            }
            value["receipt_digest"] = receipt_digest(value)
            validate_normal_receipt(value, row, oracles[profile_id])
            write_json(output_dir / result_file, value)
            result = {
                "profile_id": profile_id,
                "status": "success",
                "result_file": result_file,
                "receipt_digest": value["receipt_digest"],
            }
            if format_only:
                result["format"] = row["format"]
            results.append(result)
        except Exception as exc:
            failure = {
                "profile_id": profile_id,
                "status": "failed",
                "failure_kind": type(exc).__name__,
                "message": str(exc),
                "target_executed": False,
            }
            failure_file = result_stem + ".failure.json"
            write_json(output_dir / failure_file, failure)
            failures.append(failure)
            result = {
                "profile_id": profile_id,
                "status": "failed",
                "result_file": failure_file,
                "receipt_digest": None,
            }
            if format_only:
                result["format"] = row["format"]
            results.append(result)

    matrix = {
        "schema_version": FORMAT_MATRIX_SCHEMA if format_only else NORMAL_MATRIX_SCHEMA,
        "profiles": results,
        "success_count": sum(row["status"] == "success" for row in results),
        "failure_count": len(failures),
        "target_executed": False,
        "input_preserved": not failures
        or all(failure["target_executed"] is False for failure in failures),
        "status": "success" if not failures else "failed",
    }
    matrix["receipt_digest"] = receipt_digest(matrix)
    write_json(output_dir / "matrix.json", matrix)
    if failures:
        raise RuntimeError(f"{len(failures)} semantic profile rows failed")
    return matrix


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--committed-manifest",
        type=Path,
        default=Path("tests/flow_fixtures/manifests/profiles/build.json"),
    )
    parser.add_argument("--rebuilt-manifest", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--p0-root", type=Path, required=True)
    parser.add_argument(
        "--oracle",
        type=Path,
        default=Path("tests/flow_fixtures/oracles/isa_profiles.json"),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ida", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--profile", action="append", choices=NORMAL_PROFILE_IDS)
    parser.add_argument("--format-only", action="store_true")
    arguments = parser.parse_args()
    root = arguments.root.resolve()

    def rooted(path: Path) -> Path:
        return path if path.is_absolute() else root / path

    record_matrix(
        root=root,
        committed_manifest=rooted(arguments.committed_manifest),
        rebuilt_manifest=rooted(arguments.rebuilt_manifest),
        build_root=rooted(arguments.build_root),
        p0_root=rooted(arguments.p0_root),
        oracle_path=rooted(arguments.oracle),
        output_dir=rooted(arguments.output),
        ida_executable=rooted(arguments.ida),
        timeout_seconds=arguments.timeout,
        profile_filter=(
            None
            if arguments.format_only
            else tuple(arguments.profile or NORMAL_PROFILE_IDS)
        ),
        format_only=arguments.format_only,
    )


if __name__ == "__main__":
    main()
