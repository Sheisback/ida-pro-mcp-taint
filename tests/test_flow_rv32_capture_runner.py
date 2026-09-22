"""Pure tests for the fixed, shell-free RV32 capture recorder."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shlex
import struct
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest

from ida_pro_mcp.flow_core.rv32_capture import (
    CAPTURE_SCHEMA,
    PROCESS_SCHEMA,
    AddressRange,
    BlockCapture,
    CaptureBundle,
    CaptureDiagnostic,
    CaptureRequest,
    FunctionCapture,
    InstructionCapture,
    ProcessReceipt,
    ProcessorAdapterIdentity,
    RegisterMetadata,
    function_stable_key,
    parse_elf32_riscv_header,
)
from ida_pro_mcp.flow_core.serialization import canonical_json, digest


CONTRACT_FILE = sys.modules[CaptureRequest.__module__].__file__
assert CONTRACT_FILE is not None
CONTRACT_PATH = Path(CONTRACT_FILE)
REPO_ROOT = CONTRACT_PATH.parents[3]
RUNNER_PATH = REPO_ROOT / "scripts/record_flow_rv32_capture.py"
SPEC = importlib.util.spec_from_file_location("pure_rv32_capture_runner_test", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def _runner_file() -> Path:
    value = runner.__file__
    assert value is not None
    return Path(value)


def _raw_sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _binary() -> bytes:
    value = bytearray(0x300)
    value[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<H", value, 18, 243)
    struct.pack_into("<I", value, 36, 1)
    return bytes(value)


def _write_repo(tmp_path: Path):
    root = tmp_path / "repo"
    source = root / runner.FIXTURE_SOURCE
    source.parent.mkdir(parents=True)
    source.write_text("/* pinned RV32 fixture */\n")
    binary = root / "build" / "rv32.elf"
    binary.parent.mkdir()
    binary.write_bytes(_binary())
    row = {
        "profile_id": "RV32-LE",
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
        "binary_sha256": _raw_sha(binary.read_bytes()),
        "binary_size": binary.stat().st_size,
        "command": ["zig", "cc", "-mabi=ilp32"],
        "command_sha256": "1" * 64,
        "function_selectors": [
            {"kind": "debug_or_symbol_name", "value": name}
            for name, _rva in runner.RV32_FUNCTIONS
        ],
    }
    row["reproducibility"] = {
        "fresh_builds": 2,
        "binary_sha256_equal": True,
        "binary_sha256s": [row["binary_sha256"], row["binary_sha256"]],
    }
    manifest = {
        "manifest_kind": "build_only",
        "source": str(runner.FIXTURE_SOURCE),
        "source_sha256": _raw_sha(source.read_bytes()),
        "profiles": [row],
    }
    manifest_path = root / runner.PROFILE_MANIFEST
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text(json.dumps(manifest))
    for relative in runner.IMPLEMENTATION_FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {relative}\n")
    entry = root / runner.ENTRY_SCRIPT
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.write_bytes((REPO_ROOT / runner.ENTRY_SCRIPT).read_bytes())
    recorder = root / "scripts/record_flow_rv32_capture.py"
    recorder.write_bytes(RUNNER_PATH.read_bytes())
    runner.__file__ = str(recorder)
    ida = tmp_path / "ida"
    ida.mkdir()
    idat = ida / "idat"
    idat.write_text("headless IDA fixture")
    procs = ida / "procs"
    procs.mkdir()
    (procs / "riscv.dylib").write_bytes(b"pinned adapter")
    return root, binary, idat, manifest_path, manifest


def _capture(request: CaptureRequest, *, python_version: str = "3.11.15"):
    registers = (RegisterMetadata(0, "zero"), RegisterMetadata(1, "ra"))
    adapter = ProcessorAdapterIdentity(
        "riscv",
        15,
        1,
        0,
        8,
        8,
        request.processor_adapter_sha256,
        registers,
        digest({"registers": [item.to_data() for item in registers]}),
    )
    functions = []
    for selector in request.functions:
        instruction = InstructionCapture(
            selector.expected_rva,
            2,
            "0000",
            100 + selector.ordinal,
            True,
            False,
            0x100,
            0,
            0,
            0,
            0,
            (),
        )
        functions.append(
            FunctionCapture(
                selector.ordinal,
                function_stable_key(
                    binary_sha256=request.fixture.binary_sha256,
                    source_sha256=request.fixture.source_sha256,
                    command_sha256=request.fixture.command_sha256,
                    function_rva=selector.expected_rva,
                ),
                selector.expected_rva,
                (
                    AddressRange(
                        selector.expected_rva, selector.expected_rva + instruction.size
                    ),
                ),
                (
                    BlockCapture(
                        0,
                        selector.expected_rva,
                        selector.expected_rva + instruction.size,
                        (),
                        (),
                        (instruction,),
                    ),
                ),
            )
        )
    header = _binary()[:52]
    return CaptureBundle(
        CAPTURE_SCHEMA,
        request.backend,
        request.fixture,
        parse_elf32_riscv_header(header),
        "9.3",
        python_version,
        adapter,
        request.implementation_digest,
        0x10000,
        tuple(functions),
        (
            CaptureDiagnostic(
                "capture_only_unverified",
                "No lowering, SSA, or support claim",
                "information",
            ),
        ),
        request.budgets,
    )


class FakeIda:
    def __init__(self, *, returncode: int = 0, omit_receipt: bool = False, drift=False):
        self.returncode = returncode
        self.omit_receipt = omit_receipt
        self.drift = drift
        self.calls = []
        self.original = Path()

    def __call__(self, command, **kwargs):
        assert kwargs["check"] is False
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        assert kwargs["shell"] is False
        assert kwargs["timeout"] == 120
        assert command[1:3] == ["-c", "-A"]
        assert command[-1] != str(self.original)
        assert Path(command[-1]).is_file()
        script_args = shlex.split(command[3][2:])
        assert len(script_args) == 4
        output = Path(script_args[2])
        request = cast(
            CaptureRequest,
            CaptureRequest.from_json(Path(script_args[3]).read_text()),
        )
        call_index = len(self.calls)
        capture = _capture(
            request,
            python_version="3.11.16" if self.drift and call_index else "3.11.15",
        )
        receipt = ProcessReceipt(
            PROCESS_SCHEMA,
            capture,
            digest(capture),
            digest(capture),
            True,
            True,
        )
        if not self.omit_receipt:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(canonical_json(receipt))
        self.calls.append((command, kwargs, request))
        return subprocess.CompletedProcess(command, self.returncode, "stdout", "stderr")


class MutatingFakeIda(FakeIda):
    def __call__(self, command, **kwargs):
        completed = super().__call__(command, **kwargs)
        self.original.write_bytes(self.original.read_bytes() + b"tamper")
        return completed


class OrchestrationMutatingFakeIda(FakeIda):
    def __init__(self, target: Path):
        super().__init__()
        self.target = target

    def __call__(self, command, **kwargs):
        completed = super().__call__(command, **kwargs)
        self.target.write_bytes(self.target.read_bytes() + b"tamper")
        return completed


def test_build_request_binds_only_the_pinned_fixture_and_implementation(tmp_path):
    root, binary, idat, _, _ = _write_repo(tmp_path)
    request = runner.build_request(root, binary, idat)
    assert request.fixture.profile_id == "RV32-LE"
    assert request.fixture.abi_id == "riscv-ilp32"
    assert request.fixture.binary_sha256 == "sha256-v1:" + _raw_sha(binary.read_bytes())
    assert request.fixture.target_executed is False
    assert request.fixture.support_status == "unverified"
    assert tuple(selector.symbol for selector in request.functions) == tuple(
        name for name, _rva in runner.RV32_FUNCTIONS
    )
    assert tuple(selector.expected_rva for selector in request.functions) == tuple(
        rva for _name, rva in runner.RV32_FUNCTIONS
    )
    assert request.processor_adapter_sha256 == runner._file_digest(
        idat.parent / "procs/riscv.dylib"
    )
    assert request.implementation_digest == runner._implementation_digest(root)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("profile", "build row drift"),
        ("selectors", "selector set drift"),
        ("abi", "reviewed ILP32 evidence"),
        ("reproducibility", "reproducibility evidence drift"),
        ("binary", "pinned build"),
        ("source", "source digest drift"),
        ("adapter", "processor adapter is unavailable"),
    ],
)
def test_build_request_rejects_manifest_and_artifact_drift(tmp_path, mutation, message):
    root, binary, idat, manifest_path, manifest = _write_repo(tmp_path)
    row = manifest["profiles"][0]
    if mutation == "profile":
        row["bitness"] = 64
    elif mutation == "selectors":
        row["function_selectors"] = row["function_selectors"][:-1]
    elif mutation == "abi":
        row["command"] = ["zig", "cc"]
    elif mutation == "reproducibility":
        row["reproducibility"]["fresh_builds"] = 1
    elif mutation == "binary":
        binary.write_bytes(binary.read_bytes() + b"drift")
    elif mutation == "source":
        (root / runner.FIXTURE_SOURCE).write_text("source drift")
    else:
        (idat.parent / "procs/riscv.dylib").unlink()
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match=message):
        runner.build_request(root, binary, idat)


def test_two_fresh_processes_are_disposable_shell_free_and_byte_preserving(tmp_path):
    root, binary, idat, _, _ = _write_repo(tmp_path)
    original = binary.read_bytes()
    fake = FakeIda()
    fake.original = binary.resolve()
    output = tmp_path / "receipts"
    receipt = runner.record(root, binary, output, idat, run=fake)
    assert len(fake.calls) == 2
    assert fake.calls[0][0][-1] != fake.calls[1][0][-1]
    assert all(call[2] == fake.calls[0][2] for call in fake.calls)
    assert binary.read_bytes() == original
    assert receipt.fresh_process_repeat_equal is True
    assert receipt.input_preserved is True
    assert receipt.target_executed is False
    assert receipt.support_status == "unverified"
    assert receipt.entry_script_sha256 == runner._file_digest(root / runner.ENTRY_SCRIPT)
    assert receipt.recorder_script_sha256 == runner._file_digest(_runner_file())
    assert receipt.ida_executable_sha256 == runner._file_digest(idat)
    assert [run.run_id for run in receipt.runs] == ["fresh-1", "fresh-2"]
    assert (output / "request.json").is_file()
    assert (output / "receipt.json").is_file()
    for run_id in ("fresh-1", "fresh-2"):
        invocation = json.loads((output / run_id / "invocation.json").read_text())
        assert invocation["shell"] is False
        assert invocation["gui"] is False
        assert invocation["target_executed"] is False
        assert invocation["flags"] == ["-c", "-A", "-S<fixed-script-and-contract>"]


@pytest.mark.parametrize(
    ("fake", "message"),
    [
        (FakeIda(returncode=1), "fresh-1 failed"),
        (FakeIda(omit_receipt=True), "fresh-1 failed"),
        (FakeIda(drift=True), "semantic capture drift"),
    ],
)
def test_recorder_preserves_process_failures_and_rejects_fresh_drift(
    tmp_path, fake, message
):
    root, binary, idat, _, _ = _write_repo(tmp_path)
    fake.original = binary.resolve()
    output = tmp_path / "receipts"
    with pytest.raises(RuntimeError, match=message):
        runner.record(root, binary, output, idat, run=fake)
    if not fake.drift:
        failure = json.loads((output / "fresh-1/failure.json").read_text())
        assert failure["target_executed"] is False
        assert failure["support_status"] == "unverified"


def test_recorder_timeout_is_preserved_as_unverified_failure(tmp_path):
    root, binary, idat, _, _ = _write_repo(tmp_path)

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired([str(idat)], 120)

    output = tmp_path / "receipts"
    with pytest.raises(RuntimeError, match="hard timeout"):
        runner.record(root, binary, output, idat, run=timeout)
    failure = json.loads((output / "fresh-1/failure.json").read_text())
    assert failure["kind"] == "hard_timeout"
    assert failure["target_executed"] is False
    assert failure["support_status"] == "unverified"


def test_recorder_rejects_original_input_mutation_during_capture(tmp_path):
    root, binary, idat, _, _ = _write_repo(tmp_path)
    fake = MutatingFakeIda()
    fake.original = binary.resolve()
    with pytest.raises(RuntimeError, match="changed during a fresh capture"):
        runner.record(root, binary, tmp_path / "receipts", idat, run=fake)


@pytest.mark.parametrize("target_name", ["entry", "recorder", "idat"])
def test_recorder_rejects_orchestration_artifact_mutation(tmp_path, target_name):
    root, binary, idat, _, _ = _write_repo(tmp_path)
    targets = {
        "entry": root / runner.ENTRY_SCRIPT,
        "recorder": _runner_file(),
        "idat": idat,
    }
    fake = OrchestrationMutatingFakeIda(targets[target_name])
    fake.original = binary.resolve()
    with pytest.raises(RuntimeError, match="orchestration implementation changed"):
        runner.record(root, binary, tmp_path / "receipts", idat, run=fake)
