#!/usr/bin/env python3
"""Bind current-run licensed IDA semantics into checkout-scoped release receipts.

Checked-in semantic receipts are archival expectations only.  Fresh release
receipts require separately generated normal/format matrices from the current
checkout and re-run public profile routing before publication.  The target is
never executed and RV32 fallback evidence is never promoted to a normal row.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Iterator
import uuid

from ida_pro_mcp.flow_core.build_identity import BUILD_ID, BUILD_SCOPE
from ida_pro_mcp.flow_core.semantic_equivalence import (
    normal_semantic_equivalence_digest,
)
from ida_pro_mcp.flow_core.profile_routing import (
    OpenDatabaseEvidence,
    resolve_open_database_profile,
)
from ida_pro_mcp.flow_core.serialization import digest

ROOT = Path(__file__).resolve().parents[1]
MATRIX = Path("tests/flow_fixtures/manifests/profile_semantics/matrix.json")
BUILD_MANIFEST = Path("tests/flow_fixtures/manifests/profiles/build.json")
SCHEMA = "flow-licensed-normal/2"
SHA1 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
OWNER_MARKER = ".flow-output-owner.json"


def _absolute_unresolved(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _reject_symlink_components(path: Path) -> Path:
    result = _absolute_unresolved(path)
    for candidate in reversed([result, *result.parents]):
        if os.path.lexists(candidate) and candidate.is_symlink():
            raise ValueError(f"Evidence output path contains a symlink: {candidate}")
    return result


@contextmanager
def staged_directory(output: Path, *, producer: str) -> Iterator[tuple[Path, Path]]:
    """Stage privately, then publish into a newly owned marked directory."""

    destination = _reject_symlink_components(output)
    _reject_symlink_components(destination.parent)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(destination.parent)
    if not destination.parent.is_dir():
        raise ValueError("Evidence output parent is not a directory")
    if os.path.lexists(destination):
        raise FileExistsError(f"Refusing to replace existing evidence output: {output}")
    stage = Path(
        tempfile.mkdtemp(prefix=".flow-evidence-stage-", dir=destination.parent)
    )
    try:
        yield stage, destination
        destination.mkdir()
        marker = {
            "schema_version": "flow-output-owner/1",
            "producer": producer,
            "nonce": uuid.uuid4().hex,
        }
        (destination / OWNER_MARKER).write_text(
            json.dumps(marker, sort_keys=True) + "\n", encoding="utf-8"
        )
        for child in sorted(stage.iterdir(), key=lambda item: item.name):
            os.replace(child, destination / child.name)
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if type(value) is not dict:
        raise ValueError(f"Expected a JSON object: {path}")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verified_receipt_digest(value: dict[str, Any], label: str) -> str:
    body = dict(value)
    claimed = body.pop("receipt_digest", None)
    if type(claimed) is not str or claimed != digest(body):
        raise ValueError(label + " digest is invalid")
    return claimed


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


def _safe_child(directory: Path, relative: object) -> Path:
    if type(relative) is not str:
        raise ValueError("Current semantic matrix result path is missing")
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("Unsafe current semantic matrix result path")
    path = (directory / candidate).resolve()
    path.relative_to(directory.resolve())
    if not path.is_file():
        raise ValueError("Current semantic receipt is missing")
    return path


def _current_sources(
    root: Path,
    normal_dir: Path,
    format_dir: Path,
) -> dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]]:
    archival = (root / "tests/flow_fixtures/manifests/profile_semantics").resolve()
    sources: dict[tuple[str, str], tuple[dict[str, Any], dict[str, Any]]] = {}
    build_rows = _build_rows(root)
    for evidence_path, directory in (
        ("normal", normal_dir),
        ("format", format_dir),
    ):
        directory = directory.resolve()
        if directory == archival or archival in directory.parents:
            raise ValueError("Checked-in semantic receipts are archival, not fresh")
        matrix = read_json(directory / "matrix.json")
        _verified_receipt_digest(matrix, "Current semantic matrix")
        if (
            matrix.get("status") != "success"
            or matrix.get("failure_count") != 0
            or matrix.get("target_executed") is not False
            or matrix.get("input_preserved") is not True
        ):
            raise ValueError("Current semantic matrix is incomplete or unsafe")
        profiles = matrix.get("profiles")
        if type(profiles) is not list:
            raise ValueError("Current semantic matrix profiles are missing")
        for item in profiles:
            if type(item) is not dict or item.get("status") != "success":
                raise ValueError("Current semantic matrix contains a failed row")
            profile_id = item.get("profile_id")
            if type(profile_id) is not str:
                raise ValueError("Current semantic profile identity is missing")
            if evidence_path == "format":
                format_id = item.get("format")
            else:
                formats = {
                    format_id
                    for candidate_profile, format_id in build_rows
                    if candidate_profile == profile_id and format_id == "FMT-ELF"
                }
                if len(formats) != 1:
                    raise ValueError(
                        "Current normal row has ambiguous canonical format"
                    )
                format_id = formats.pop()
            if type(format_id) is not str:
                raise ValueError("Current semantic format identity is missing")
            source = read_json(_safe_child(directory, item.get("result_file")))
            _verified_receipt_digest(source, "Current semantic receipt")
            if source.get("receipt_digest") != item.get("receipt_digest"):
                raise ValueError("Current semantic matrix/receipt digest mismatch")
            identity = (profile_id, format_id)
            if identity in sources:
                raise ValueError("Duplicate current semantic identity")
            sources[identity] = (source, matrix)
    return sources


def _validate_current_source(
    root: Path,
    source: dict[str, Any],
    build_row: dict[str, Any],
) -> tuple[dict[str, Any], str, str]:
    evaluator = _evaluator(root)
    oracle = read_json(root / evaluator.ISA_ORACLE)
    oracle_rows = {
        item["profile_id"]: item
        for item in oracle.get("profiles", [])
        if type(item) is dict and type(item.get("profile_id")) is str
    }
    oracle_row = oracle_rows.get(build_row["profile_id"])
    if type(oracle_row) is not dict:
        raise ValueError("Current semantic oracle identity is missing")
    evaluator.validate_normal_receipt(root, source, build_row, oracle_row)
    implementation = source.get("implementation")
    if type(implementation) is not dict or not implementation:
        raise ValueError("Current semantic implementation identity is missing")
    for relative, expected in implementation.items():
        if type(relative) is not str or type(expected) is not str:
            raise ValueError("Current semantic implementation identity is invalid")
        path = (root / relative).resolve()
        path.relative_to(root)
        if not path.is_file() or sha256(path) != expected:
            raise ValueError("Current semantic receipt is stale: " + relative)
    environment = source.get("environment")
    if type(environment) is not dict:
        raise ValueError("Current semantic environment is missing")
    observed = OpenDatabaseEvidence(
        "sha256-v1:" + source["binary_sha256"],
        environment["processor"],
        environment["bitness"],
        environment["data_endian"],
        environment["format_id"],
        environment["ida_build"],
        environment["hexrays_build"],
    )
    resolved = resolve_open_database_profile(
        observed, requested_profile=build_row["profile_id"]
    )
    if resolved.evidence.abi_id != build_row[
        "abi_id"
    ] or resolved.profile != source.get("profile"):
        raise ValueError("Current semantic public profile routing mismatch")
    extraction_digest = digest(
        {
            "profile": resolved.profile,
            "functions": source.get("functions"),
            "implementation": implementation,
        }
    )
    return (
        resolved.profile,
        extraction_digest,
        normal_semantic_equivalence_digest(source),
    )


def _validate_invocation_provenance(
    source: dict[str, Any], executable_sha256: str
) -> None:
    invocations = source.get("invocations")
    process_digests = source.get("fresh_process_receipt_digests")
    if (
        type(invocations) is not list
        or len(invocations) != 2
        or type(process_digests) is not list
        or len(process_digests) != 2
        or any(type(item) is not str for item in process_digests)
        or len(set(process_digests)) != 1
        or source.get("fresh_process_equal") is not True
    ):
        raise ValueError("Normal semantic fresh-process evidence is incomplete")
    for item in invocations:
        if (
            type(item) is not dict
            or set(item)
            != {
                "schema_version",
                "run_id",
                "ida_executable_name",
                "ida_executable_sha256",
                "arguments_shape",
                "shell",
                "exit_code",
                "target_executed",
                "input_preserved",
            }
            or item.get("schema_version") != "flow-profile-semantics-invocation/1"
            or item.get("run_id") not in {"fresh-1", "fresh-2"}
            or type(item.get("ida_executable_name")) is not str
            or not item["ida_executable_name"]
            or item.get("ida_executable_sha256") != executable_sha256
            or item.get("arguments_shape")
            != [
                "-c",
                "-A",
                "-S<entry-script> <root> <output> <request>",
                "<disposable-copy>",
            ]
            or item.get("shell") is not False
            or item.get("exit_code") != 0
            or item.get("target_executed") is not False
            or item.get("input_preserved") is not True
        ):
            raise ValueError("Normal semantic invocation provenance is invalid")
    if {item["run_id"] for item in invocations} != {"fresh-1", "fresh-2"}:
        raise ValueError("Normal semantic fresh-process run identities are invalid")
    for value in process_digests:
        if (
            type(value) is not str
            or re.fullmatch(r"sha256-v1:[0-9a-f]{64}", value) is None
        ):
            raise ValueError("Normal semantic process digest is invalid")


def _licensed_receipt(
    source: dict[str, Any],
    matrix_row: dict[str, Any],
    build_row: dict[str, Any],
    *,
    checkout_sha: str,
    executable_sha256: str,
    current_matrix: dict[str, Any],
    routed_profile: dict[str, Any],
    extraction_digest: str,
    semantic_equivalence_digest: str,
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
    ):
        raise ValueError("Normal semantic source is not a passing static row")
    _validate_invocation_provenance(source, executable_sha256)

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
        "semantic_equivalence_digest": semantic_equivalence_digest,
        "extraction_digest": extraction_digest,
        "public_profile_digest": digest(routed_profile),
        "current_run": {
            "kind": "current_checkout_actual_ida",
            "matrix_receipt_digest": current_matrix["receipt_digest"],
            "semantic_receipt_digest": source["receipt_digest"],
            "semantic_equivalence_digest": semantic_equivalence_digest,
            "process_receipt_digests": source["fresh_process_receipt_digests"],
            "build_evidence_digest": digest(source["build_evidence"]),
            "implementation": source["implementation"],
        },
    }


def record(
    *,
    root: Path,
    output_dir: Path,
    checkout_sha: str,
    executable_sha256: str,
    expected_executable_sha256: str,
    current_normal_dir: Path,
    current_format_dir: Path,
) -> list[Path]:
    root = root.resolve()
    if SHA1.fullmatch(checkout_sha) is None:
        raise ValueError("checkout_sha must be a full lowercase commit SHA")
    if (
        SHA256.fullmatch(executable_sha256) is None
        or executable_sha256 != expected_executable_sha256
    ):
        raise ValueError("IDA executable does not match the reviewed digest")
    with staged_directory(
        output_dir, producer="scripts/record_flow_licensed_normal.py"
    ) as (stage, destination):
        matrix = read_json(root / MATRIX)
        _evaluator(root).validate_complete_matrix_artifacts(root, matrix)
        build_rows = _build_rows(root)
        current = _current_sources(root, current_normal_dir, current_format_dir)
        expected_current = {
            (item["profile_id"], item["format"])
            for item in matrix["profiles"]
            if item.get("evidence_path") in {"normal", "format"}
        }
        if set(current) != expected_current:
            raise ValueError("Current licensed semantic row coverage mismatch")
        names: list[str] = []
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
            if identity not in current:
                raise ValueError("Current licensed semantic row is missing")
            source, current_matrix = current[identity]
            archival_source = read_json(root / item["receipt_file"])
            if _verified_receipt_digest(
                archival_source, "Archival semantic receipt"
            ) != item.get("receipt_digest"):
                raise ValueError("Reviewed semantic matrix/receipt digest mismatch")
            routed_profile, extraction_digest, semantic_equivalence_digest = (
                _validate_current_source(root, source, build_row)
            )
            if semantic_equivalence_digest != normal_semantic_equivalence_digest(
                archival_source
            ):
                raise ValueError(
                    "Current semantic result differs from reviewed meaning"
                )
            receipt = _licensed_receipt(
                source,
                item,
                build_row,
                checkout_sha=checkout_sha,
                executable_sha256=executable_sha256,
                current_matrix=current_matrix,
                routed_profile=routed_profile,
                extraction_digest=extraction_digest,
                semantic_equivalence_digest=semantic_equivalence_digest,
            )
            name = (
                f"normal-{index:02d}-{item['profile_id'].lower()}-"
                f"{item['format'].removeprefix('FMT-').lower()}.json"
            )
            (stage / name).write_text(
                json.dumps(receipt, indent=2, sort_keys=True) + "\n"
            )
            names.append(name)
        expected = sum(
            item.get("evidence_path") in {"normal", "format"}
            for item in matrix["profiles"]
        )
        if len(names) != expected:
            raise ValueError("Licensed normal rows do not match the canonical matrix")
    return [destination / name for name in names]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checkout-sha", required=True)
    parser.add_argument("--ida", type=Path, required=True)
    parser.add_argument("--expected-ida-executable-sha256", required=True)
    parser.add_argument("--current-normal-dir", type=Path, required=True)
    parser.add_argument("--current-format-dir", type=Path, required=True)
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
        current_normal_dir=arguments.current_normal_dir,
        current_format_dir=arguments.current_format_dir,
    )
    print(json.dumps({"schema_version": SCHEMA, "receipts": len(paths)}))


if __name__ == "__main__":
    main()
