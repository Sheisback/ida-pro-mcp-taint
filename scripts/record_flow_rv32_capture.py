"""Record two fresh-process RV32 structured captures from disposable inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from typing import Any, cast

from ida_pro_mcp.flow_core.rv32_capture import (
    BACKEND_IDENTITY,
    RECEIPT_SCHEMA,
    REQUEST_SCHEMA,
    CaptureBudgets,
    CaptureReceipt,
    CaptureRequest,
    FixtureEvidence,
    FreshProcessEvidence,
    FunctionSelector,
)
from ida_pro_mcp.flow_core.serialization import canonical_json, digest

PROFILE_MANIFEST = Path("tests/flow_fixtures/manifests/profiles/build.json")
FIXTURE_SOURCE = Path("tests/flow_fixtures/isa_profile_anchor.c")
ENTRY_SCRIPT = Path("scripts/flow_rv32_capture.py")
RV32_FUNCTIONS = (
    ("isa_scalar", 0x1258),
    ("isa_branch", 0x1284),
    ("isa_load", 0x12C2),
    ("isa_store", 0x12DC),
    ("isa_call", 0x12FE),
    ("isa_profile_entry", 0x1320),
)
IMPLEMENTATION_FILES = (
    Path("src/ida_pro_mcp/flow_core/rv32_capture.py"),
    Path("src/ida_pro_mcp/ida_mcp/flow/rv32_extractor.py"),
)


def _file_digest(path: Path) -> str:
    return "sha256-v1:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> Any:
    return json.loads(
        path.read_text(),
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
    )


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def _implementation_digest(root: Path) -> str:
    return digest(
        {str(path): _file_digest(root / path) for path in IMPLEMENTATION_FILES}
    )


def _processor_adapter(idat: Path) -> Path:
    candidate = idat.parent / "procs" / "riscv.dylib"
    if not candidate.is_file():
        raise ValueError(
            "Pinned RISC-V processor adapter is unavailable: " + str(candidate)
        )
    return candidate


def build_request(root: Path, binary: Path, idat: Path) -> CaptureRequest:
    """Bind one binary to the reviewed repository build evidence."""
    root = root.resolve()
    binary = binary.resolve()
    idat = idat.resolve()
    manifest_path = root / PROFILE_MANIFEST
    manifest = _read_json(manifest_path)
    if type(manifest) is not dict or manifest.get("manifest_kind") != "build_only":
        raise ValueError("Invalid profile build manifest")
    if manifest.get("source") != str(FIXTURE_SOURCE):
        raise ValueError("RV32 capture requires the pinned fixture source")
    rows = [
        row
        for row in manifest.get("profiles", [])
        if type(row) is dict and row.get("profile_id") == "RV32-LE"
    ]
    if len(rows) != 1:
        raise ValueError("Expected exactly one RV32-LE build row")
    row = rows[0]
    expected = {
        "profile_version": 1,
        "target_triple": "riscv32-linux-gnu",
        "abi_id": "riscv-ilp32",
        "bitness": 32,
        "data_endian": "LE",
        "instruction_endian": "LE",
        "mode": "RV32",
        "processor": "riscv",
        "format": "FMT-ELF",
        "platform_tag": "linux",
        "target_executed": False,
    }
    mismatches = {
        key: {"expected": value, "observed": row.get(key)}
        for key, value in expected.items()
        if row.get(key) != value
    }
    if mismatches:
        raise ValueError("RV32 build row drift: " + repr(mismatches))
    if row.get("function_selectors") != [
        {"kind": "debug_or_symbol_name", "value": name} for name, _rva in RV32_FUNCTIONS
    ]:
        raise ValueError("RV32 function selector set drift")
    command = row.get("command")
    if type(command) is not list or "-mabi=ilp32" not in command:
        raise ValueError("RV32 build does not carry reviewed ILP32 evidence")
    reproducibility = row.get("reproducibility")
    if reproducibility != {
        "fresh_builds": 2,
        "binary_sha256_equal": True,
        "binary_sha256s": [row.get("binary_sha256"), row.get("binary_sha256")],
    }:
        raise ValueError("RV32 build reproducibility evidence drift")
    raw_binary_digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if raw_binary_digest != row.get("binary_sha256"):
        raise ValueError("Selected RV32 binary does not match the pinned build")
    if binary.stat().st_size != row.get("binary_size"):
        raise ValueError("Selected RV32 binary size does not match the pinned build")
    source_path = root / FIXTURE_SOURCE
    source_digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
    if source_digest != manifest.get("source_sha256"):
        raise ValueError("Fixture source digest drift")

    profile = {
        "profile_id": "RV32-LE",
        "profile_version": 1,
        "mode": "RV32",
        "processor": "riscv",
        "bitness": 32,
        "data_endian": "LE",
        "instruction_endian": "LE",
        "format_id": "FMT-ELF",
        "platform_tag": "linux",
    }
    source_sha256 = "sha256-v1:" + source_digest
    manifest_sha256 = _file_digest(manifest_path)
    command_sha256 = "sha256-v1:" + str(row["command_sha256"])
    binary_sha256 = "sha256-v1:" + raw_binary_digest
    abi = {
        "abi_id": "riscv-ilp32",
        "target_triple": "riscv32-linux-gnu",
        "source_sha256": source_sha256,
        "build_manifest_sha256": manifest_sha256,
        "command_sha256": command_sha256,
        "binary_sha256": binary_sha256,
        "fresh_builds": 2,
        "binary_sha256_equal": True,
    }
    fixture = FixtureEvidence(
        "RV32-LE",
        1,
        "RV32",
        "riscv",
        32,
        "LE",
        "LE",
        "FMT-ELF",
        "riscv-ilp32",
        "riscv32-linux-gnu",
        "linux",
        source_sha256,
        manifest_sha256,
        command_sha256,
        binary_sha256,
        int(row["binary_size"]),
        2,
        True,
        digest(profile),
        digest(abi),
    )
    selectors = tuple(
        FunctionSelector(index, name, rva)
        for index, (name, rva) in enumerate(RV32_FUNCTIONS)
    )
    return CaptureRequest(
        REQUEST_SCHEMA,
        BACKEND_IDENTITY,
        fixture,
        selectors,
        CaptureBudgets(),
        "9.3",
        _file_digest(_processor_adapter(idat)),
        _implementation_digest(root),
    )


def _script_argument(root: Path, output: Path, request: Path) -> str:
    return " ".join(
        shlex.quote(str(value))
        for value in (root / ENTRY_SCRIPT, root, output, request)
    )


def record(
    root: Path,
    binary: Path,
    output: Path,
    idat: Path,
    *,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> CaptureReceipt:
    """Run two independent static IDA processes and validate exact equality."""
    from ida_pro_mcp.flow_core.rv32_capture import ProcessReceipt

    root = root.resolve()
    binary = binary.resolve()
    output = output.resolve()
    idat = idat.resolve()
    if idat.name not in {"idat", "idat64"} or not idat.is_file():
        raise ValueError("RV32 capture requires a recognized headless IDA executable")
    entry_script = (root / ENTRY_SCRIPT).resolve()
    recorder_script = Path(__file__).resolve()
    if recorder_script != (root / "scripts/record_flow_rv32_capture.py").resolve():
        raise ValueError(
            "Recorder implementation is outside the selected repository root"
        )
    if not entry_script.is_file():
        raise ValueError("RV32 IDA entry script is unavailable")

    def orchestration_digests() -> tuple[str, str, str]:
        return (
            _file_digest(entry_script),
            _file_digest(recorder_script),
            _file_digest(idat),
        )

    orchestration_before = orchestration_digests()
    original_input_digest = _file_digest(binary)
    request = build_request(root, binary, idat)
    if original_input_digest != request.fixture.binary_sha256:
        raise RuntimeError("Original RV32 input changed while binding capture evidence")
    output.mkdir(parents=True, exist_ok=False)
    request_path = output / "request.json"
    _write_json(request_path, request.to_data())
    evidence: list[FreshProcessEvidence] = []
    captures = []

    for run_id in ("fresh-1", "fresh-2"):
        if _file_digest(binary) != original_input_digest:
            raise RuntimeError("Original RV32 input changed before a fresh capture")
        run_dir = output / run_id
        run_dir.mkdir()
        process_path = run_dir / "process-receipt.json"
        with tempfile.TemporaryDirectory(prefix="flow-rv32-capture-") as temporary:
            work = Path(temporary)
            disposable = work / "rv32-capture.elf"
            shutil.copyfile(binary, disposable)
            command = [
                str(idat),
                "-c",
                "-A",
                "-S" + _script_argument(root, process_path, request_path),
                str(disposable),
            ]
            try:
                completed = run(
                    command,
                    cwd=work,
                    check=False,
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=request.budgets.deadline_millis / 1000 + 90,
                )
            except subprocess.TimeoutExpired as exc:
                _write_json(
                    run_dir / "failure.json",
                    {
                        "schema_version": "flow-rv32-recorder-failure/1",
                        "kind": "hard_timeout",
                        "message": str(exc),
                        "target_executed": False,
                        "support_status": "unverified",
                    },
                )
                raise RuntimeError(
                    "RV32 capture process exceeded its hard timeout"
                ) from exc
            (run_dir / "stdout.txt").write_text(completed.stdout)
            (run_dir / "stderr.txt").write_text(completed.stderr)
            _write_json(
                run_dir / "invocation.json",
                {
                    "schema_version": "flow-rv32-static-invocation/1",
                    "executable": idat.name,
                    "flags": ["-c", "-A", "-S<fixed-script-and-contract>"],
                    "shell": False,
                    "gui": False,
                    "target_executed": False,
                    "returncode": completed.returncode,
                },
            )
            if completed.returncode != 0 or not process_path.is_file():
                _write_json(
                    run_dir / "failure.json",
                    {
                        "schema_version": "flow-rv32-recorder-failure/1",
                        "kind": "ida_process_failure",
                        "returncode": completed.returncode,
                        "process_receipt_present": process_path.is_file(),
                        "target_executed": False,
                        "support_status": "unverified",
                    },
                )
                raise RuntimeError(f"RV32 capture {run_id} failed")
        if _file_digest(binary) != original_input_digest:
            raise RuntimeError("Original RV32 input changed during a fresh capture")
        if orchestration_digests() != orchestration_before:
            raise RuntimeError(
                "RV32 orchestration implementation changed during capture"
            )
        process = cast(
            ProcessReceipt, ProcessReceipt.from_json(process_path.read_text())
        )
        if (
            process.capture.backend != request.backend
            or process.capture.fixture != request.fixture
            or process.capture.budgets != request.budgets
            or process.capture.implementation_digest != request.implementation_digest
        ):
            raise RuntimeError("RV32 process receipt/request identity mismatch")
        captures.append(process.capture)
        evidence.append(
            FreshProcessEvidence(
                run_id,
                run_id + "/process-receipt.json",
                digest(process),
                process.capture_digest,
                True,
                True,
            )
        )
    if canonical_json(captures[0]) != canonical_json(captures[1]):
        raise RuntimeError("Fresh-process RV32 semantic capture drift")
    if _file_digest(binary) != original_input_digest:
        raise RuntimeError("Original RV32 input changed across capture recording")
    if orchestration_digests() != orchestration_before:
        raise RuntimeError(
            "RV32 orchestration implementation changed across capture recording"
        )
    receipt = CaptureReceipt(
        RECEIPT_SCHEMA,
        request.backend,
        request.fixture.binary_sha256,
        orchestration_before[0],
        orchestration_before[1],
        orchestration_before[2],
        tuple(evidence),
        True,
        True,
    )
    _write_json(output / "receipt.json", receipt.to_data())
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--ida", type=Path, required=True)
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    record(root, arguments.binary, arguments.output, arguments.ida)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
