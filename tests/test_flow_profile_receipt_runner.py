"""Pure tests for the fail-closed G012 profile receipt orchestrator."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shlex
import subprocess
from pathlib import Path
from typing import Any, Callable

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = ROOT / "scripts/record_flow_profile_receipts.py"
PROBE_PATH = ROOT / "src/ida_pro_mcp/ida_mcp/flow/p0_probe.py"
DEFAULT_ENTRY = object()


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load(RUNNER_PATH, "flow_profile_receipt_runner_test")
probe = load(PROBE_PATH, "flow_profile_receipt_probe_test")


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def profile_row(
    binary: Path,
    *,
    profile_id: str = "X64-LE",
    expected_hash: str | None = None,
    binary_format: str = "FMT-ELF",
) -> dict:
    is_arm = profile_id.startswith("ARM")
    row = {
        "profile_id": profile_id,
        "profile_version": 1,
        "target_triple": "fixture-test",
        "abi_id": "aapcs32" if is_arm else "sysv-amd64",
        "bitness": 32 if is_arm else 64,
        "data_endian": "LE",
        "instruction_endian": "LE",
        "mode": "ARM32" if is_arm else "X64",
        "processor": "ARM" if is_arm else "metapc",
        "format": binary_format,
        "platform_tag": "test",
        "binary": binary.name,
        "binary_sha256": expected_hash or file_hash(binary),
        "binary_size": binary.stat().st_size,
        "function_selectors": [
            {"kind": "debug_or_symbol_name", "value": "isa_profile_entry"}
        ],
        "target_executed": False,
        "ida_receipt_recorded": False,
        "support_status": "build_only_unmeasured",
    }
    if binary_format == "FMT-RAW":
        row["function_selectors"] = []
        row["raw_configuration"] = {
            "processor": row["processor"],
            "bitness": row["bitness"],
            "data_endian": "LE",
            "instruction_endian": "LE",
            "mode": row["mode"],
            "load_address": 0x10000,
            "entry_offset": 0,
            "entry_point": 0x10000,
            "source_section": ".text",
            "function_selector": {"kind": "raw_offset", "value": 0},
        }
    return row


def write_manifest(
    path: Path, profiles: list[dict], variants: list[dict] | None = None
):
    value = {
        "schema_version": runner.BUILD_SCHEMA,
        "manifest_kind": "build_only",
        "profile_count": len(profiles),
        "target_executed": False,
        "new_profiles_advertised": [],
        "status": "builds_only_not_engine_validation",
        "profiles": profiles,
        "format_variants": variants or [],
    }
    path.write_text(json.dumps(value))
    return value


def executable(path: Path) -> Path:
    path.write_text("#!/bin/sh\nexit 99\n")
    path.chmod(0o755)
    return path


def observation(
    request: dict[str, Any],
    *,
    processor: str | None = None,
    entry: int | None | object = DEFAULT_ENTRY,
) -> dict[str, Any]:
    raw = request["binary"]["format"] == "RAW"
    if entry is DEFAULT_ENTRY:
        entry = request["entry"]["value"] if raw else 0x401000
    return {
        "binary_sha256": request["binary"]["sha256"],
        "format": request["binary"]["format"],
        "filetype": "Binary file" if raw else "ELF fixture for tests",
        "processor": processor or request["profile"]["processor"],
        "bits": request["profile"]["bits"],
        "data_endian": request["profile"]["data_endian"],
        "instruction_endian": None,
        "image_base": 0x10000 if raw else 0x400000,
        "entry_ea": entry,
    }


def receipt_for(
    request: dict[str, Any],
    *,
    processor: str | None = None,
    entry: int | None | object = DEFAULT_ENTRY,
    initialize: bool = True,
) -> dict[str, Any]:
    observed = observation(request, processor=processor, entry=entry)
    validation = probe.validate_observation(request, observed)
    accepted = validation["status"] == "accepted"
    probes = []
    if accepted and initialize:
        probes = [
            {"status": "success", "maturity": maturity, "repeat_equal": True}
            for maturity in probe.MATURITIES
        ]
    value = {
        "schema_version": probe.RECEIPT_SCHEMA,
        "request": request,
        "request_digest": probe.request_digest(request),
        "implementation_sha256": "f" * 64,
        "environment": {
            "ida_version": "9.3",
            "python_version": "3.13",
            "hexrays_version": "9.3" if accepted and initialize else None,
            "filetype_id": 1,
            **observed,
        },
        "validation": validation,
        "probe_status": (
            "success"
            if accepted and initialize
            else "failed"
            if accepted
            else "blocked"
        ),
        "support_status": "unverified",
        "target_executed": False,
        "binary": {"name": "disposable.bin", "sha256": request["binary"]["sha256"]},
        "entry": {"requested": request["entry"], "resolved_ea": observed["entry_ea"]},
        "initialization": initialize if accepted else None,
        "probes": probes,
        "failures": [],
        "lifetime": {
            "json_roundtrip": True,
            "repeat_after_gc": bool(probes),
            "native_leak_freedom": "not_proven",
        },
    }
    value["receipt_digest"] = probe.digest(value)
    return value


class FakeIda:
    def __init__(self, mutate=None):
        self.calls = []
        self.mutate = mutate

    def __call__(self, command, **kwargs):
        assert kwargs == {
            "cwd": kwargs["cwd"],
            "check": False,
            "capture_output": True,
            "text": True,
            "shell": False,
        }
        assert command[1:3] == ["-c", "-A"]
        script_index = next(
            index for index, argument in enumerate(command) if argument.startswith("-S")
        )
        script_args = shlex.split(command[script_index][2:])
        assert script_args[0] == str(ROOT / "scripts/flow_p0_probe.py")
        output = Path(script_args[2])
        request_path = Path(script_args[3])
        request = json.loads(request_path.read_text())
        stage = output.stem.removeprefix("receipt-")
        binary = Path(command[-1])
        assert binary.is_file()
        assert binary.parent == Path(kwargs["cwd"])
        value = receipt_for(request)
        if self.mutate is not None:
            value = self.mutate(stage, request, value)
        output.write_text(json.dumps(value))
        self.calls.append(
            {
                "command": command,
                "kwargs": kwargs,
                "stage": stage,
                "request": request,
                "binary": binary,
            }
        )
        return subprocess.CompletedProcess(command, 0, "", "")


def run_one(
    tmp_path: Path,
    monkeypatch,
    *,
    fake: FakeIda | None = None,
    repeat_final: bool = False,
    row: Callable[[Path], dict[str, Any]] | dict[str, Any] | None = None,
    binary_name: str = "anchor.elf",
):
    build = tmp_path / "build"
    build.mkdir()
    binary = build / binary_name
    binary.write_bytes(b"static fixture bytes")
    selected: dict[str, Any]
    selected = row(binary) if callable(row) else row or profile_row(binary)
    manifest = build / "build.json"
    write_manifest(manifest, [selected])
    ida = executable(tmp_path / "idat")
    fake = fake or FakeIda()
    monkeypatch.setattr(runner.subprocess, "run", fake)
    output = tmp_path / "receipts"
    result = runner.run_matrix(
        root=ROOT,
        build_manifest=manifest,
        output_dir=output,
        ida_executable=ida,
        repeat_final=repeat_final,
    )
    row_result = json.loads((output / result["rows"][0]["result_file"]).read_text())
    return result, row_result, fake, binary, output


def test_accepted_two_stage_repeat_is_disposable_shell_free_and_exact(
    tmp_path, monkeypatch
):
    matrix, result, fake, original, output = run_one(
        tmp_path, monkeypatch, repeat_final=True
    )

    assert matrix["status"] == result["status"] == "success"
    assert matrix["target_executed"] is result["target_executed"] is False
    assert matrix["support_status"] == result["support_status"] == "unverified"
    assert [call["stage"] for call in fake.calls] == ["bootstrap", "final", "repeat"]
    assert all(call["command"][-1] != str(original) for call in fake.calls)
    assert all(call["binary"] != original for call in fake.calls)
    assert not fake.calls[0]["binary"].parent.exists()
    assert fake.calls[0]["request"]["binary"]["filetype"] == runner.BOOTSTRAP_FILETYPE
    assert fake.calls[1]["request"] == fake.calls[2]["request"]
    assert fake.calls[1]["request"]["binary"]["filetype"] == "ELF fixture for tests"
    assert fake.calls[1]["request"]["load"] == {
        "kind": "loader",
        "image_base": 0x400000,
    }
    assert fake.calls[1]["request"]["entry"] == {
        "kind": "address",
        "value": 0x401000,
    }
    assert result["repeatability"] == {
        "requested": True,
        "performed": True,
        "semantic_equal": True,
        "ignored_fields": [],
    }
    assert set(result) == {
        "schema_version",
        "row_id",
        "profile_id",
        "format",
        "declared_profile",
        "binary",
        "status",
        "support_status",
        "target_executed",
        "stages",
        "repeatability",
        "failures",
        "receipt_digest",
    }
    assert set(matrix) == {
        "schema_version",
        "build_manifest_sha256",
        "profile_filter",
        "repeat_final",
        "row_count",
        "status_counts",
        "status",
        "support_status",
        "target_executed",
        "rows",
        "receipt_digest",
    }
    runner.validate_row_result(result)
    runner.validate_matrix_result(matrix)
    for name in ("bootstrap", "final", "repeat"):
        assert (output / result["row_id"] / f"receipt-{name}.json").is_file()


def test_internal_repeat_difference_fails_before_external_repeat(tmp_path, monkeypatch):
    def mutate(stage, _request, value):
        if stage == "final":
            value["probes"][0]["repeat_equal"] = False
            value["probe_status"] = "failed"
            value["failures"] = [
                {
                    "kind": "probe_failure",
                    "message": (
                        "One or more maturity probes failed or were not repeatable"
                    ),
                    "details": {},
                }
            ]
            value["lifetime"]["repeat_after_gc"] = False
            value["receipt_digest"] = probe.digest(
                {key: field for key, field in value.items() if key != "receipt_digest"}
            )
        return value

    matrix, result, fake, _original, output = run_one(
        tmp_path,
        monkeypatch,
        fake=FakeIda(mutate),
        repeat_final=True,
    )

    assert matrix["status"] == result["status"] == "failed"
    assert [call["stage"] for call in fake.calls] == ["bootstrap", "final"]
    assert result["repeatability"] == {
        "requested": True,
        "performed": False,
        "semantic_equal": None,
        "ignored_fields": [],
    }
    assert result["failures"][0]["kind"] == "probe_failure"
    retained = json.loads(
        (output / result["row_id"] / "receipt-final.json").read_text()
    )
    assert retained["probe_status"] == "failed"
    assert retained["probes"][0]["repeat_equal"] is False
    assert retained["lifetime"]["repeat_after_gc"] is False


def test_raw_external_repeat_requires_exact_semantic_equality(tmp_path, monkeypatch):
    def mutate(stage, _request, value):
        if stage == "repeat":
            value["probes"][0]["test_marker"] = "drift"
            value["receipt_digest"] = probe.digest(
                {key: field for key, field in value.items() if key != "receipt_digest"}
            )
        return value

    matrix, result, fake, _original, _output = run_one(
        tmp_path,
        monkeypatch,
        fake=FakeIda(mutate),
        repeat_final=True,
        row=lambda binary: profile_row(
            binary, profile_id="ARM32-LE", binary_format="FMT-RAW"
        ),
    )
    assert matrix["status"] == result["status"] == "failed"
    assert [call["stage"] for call in fake.calls] == ["bootstrap", "final", "repeat"]
    assert result["repeatability"]["performed"] is True
    assert result["repeatability"]["semantic_equal"] is False
    assert result["failures"][0]["kind"] == "semantic_repeat_mismatch"


def test_processor_mismatch_fails_before_final_probe(tmp_path, monkeypatch):
    def mutate(stage, request, value):
        if stage == "bootstrap":
            return receipt_for(request, processor="ARM")
        return value

    matrix, result, fake, _binary, _output = run_one(
        tmp_path, monkeypatch, fake=FakeIda(mutate)
    )
    assert matrix["status"] == result["status"] == "failed"
    assert [call["stage"] for call in fake.calls] == ["bootstrap"]
    assert result["failures"][0]["kind"] == "declared_profile_mismatch"
    assert "processor" in result["failures"][0]["details"]["mismatches"]


def test_decompiler_initialization_failure_is_retained(tmp_path, monkeypatch):
    def mutate(stage, request, value):
        if stage == "final":
            return receipt_for(request, initialize=False)
        return value

    _matrix, result, fake, _binary, output = run_one(
        tmp_path, monkeypatch, fake=FakeIda(mutate)
    )
    assert [call["stage"] for call in fake.calls] == ["bootstrap", "final"]
    assert result["status"] == "failed"
    assert result["failures"][0]["kind"] == "hexrays_initialization"
    retained = output / result["row_id"] / "receipt-final.json"
    assert retained.is_file()
    assert json.loads(retained.read_text())["initialization"] is False


def test_missing_entry_blocks_final_request(tmp_path, monkeypatch):
    def mutate(stage, request, value):
        if stage == "bootstrap":
            return receipt_for(request, entry=None)
        return value

    _matrix, result, fake, _binary, _output = run_one(
        tmp_path, monkeypatch, fake=FakeIda(mutate)
    )
    assert [call["stage"] for call in fake.calls] == ["bootstrap"]
    assert result["status"] == "failed"
    assert result["failures"][0]["kind"] == "entry_missing"


def test_raw_row_runs_exact_headless_flags_on_disposable_copy(tmp_path, monkeypatch):
    fake = FakeIda()
    matrix, result, fake, original, output = run_one(
        tmp_path,
        monkeypatch,
        fake=fake,
        repeat_final=True,
        row=lambda binary: profile_row(
            binary, profile_id="ARM32-LE", binary_format="FMT-RAW"
        ),
        binary_name="anchor;$(touch injected).raw",
    )
    assert matrix["status"] == result["status"] == "success"
    assert [call["stage"] for call in fake.calls] == ["bootstrap", "final", "repeat"]
    expected = ["-c", "-A", "-TBinary", "-parm:ARMv7-A", "-b1000", "-i10000"]
    for call in fake.calls:
        command = call["command"]
        assert command[1:7] == expected
        assert command[7].startswith("-S")
        assert command[8] == str(call["binary"])
        assert call["binary"] != original
        assert call["binary"].name == original.name
        assert call["request"]["load"] == {
            "kind": "raw",
            "file_offset": 0,
            "load_address": 0x10000,
        }
        assert call["request"]["entry"] == {"kind": "address", "value": 0x10000}
    assert not (tmp_path / "injected").exists()
    assert original.read_bytes() == b"static fixture bytes"
    assert matrix["target_executed"] is result["target_executed"] is False
    assert matrix["support_status"] == result["support_status"] == "unverified"
    retained = json.loads(
        (output / result["row_id"] / "receipt-final.json").read_text()
    )
    validation = retained["validation"]
    assert validation["raw_setup"]["status"] == "verified_observable_fields"
    assert validation["unverified"] == ["profile.instruction_endian"]
    reason = validation["raw_setup"]["reason"].lower()
    assert "observable" in reason
    assert "instruction endian" in reason and "unverified" in reason


def test_raw_row_rejects_gui_executable_before_subprocess(tmp_path, monkeypatch):
    build = tmp_path / "build"
    build.mkdir()
    binary = build / "anchor.raw"
    binary.write_bytes(b"static fixture bytes")
    manifest = build / "build.json"
    write_manifest(
        manifest,
        [],
        [profile_row(binary, profile_id="ARM32-LE", binary_format="FMT-RAW")],
    )
    gui = executable(tmp_path / "ida")
    fake = FakeIda()
    monkeypatch.setattr(runner.subprocess, "run", fake)

    with pytest.raises(ValueError, match="headless|console|idat"):
        runner.run_matrix(
            root=ROOT,
            build_manifest=manifest,
            output_dir=tmp_path / "receipts",
            ida_executable=gui,
        )
    assert fake.calls == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda config: config.update(extra_flags=["-z", "evil"]),
        lambda config: config.update(processor="metapc"),
        lambda config: config.update(bitness=64),
        lambda config: config.update(data_endian="BE"),
        lambda config: config.update(instruction_endian="BE"),
        lambda config: config.update(mode="THUMB"),
        lambda config: config.update(load_address=True),
        lambda config: config.update(load_address=0x10001),
        lambda config: config.update(entry_offset=-1),
        lambda config: config.update(entry_point=0x10004),
        lambda config: config.update(
            function_selector={"kind": "raw_offset", "value": 4}
        ),
    ],
)
def test_unsupported_or_malformed_raw_configuration_fails_before_ida(
    tmp_path, monkeypatch, mutate
):
    def row(binary):
        value = profile_row(binary, profile_id="ARM32-LE", binary_format="FMT-RAW")
        mutate(value["raw_configuration"])
        return value

    fake = FakeIda()
    matrix, result, fake, _binary, _output = run_one(
        tmp_path, monkeypatch, fake=fake, row=row
    )
    assert fake.calls == []
    assert matrix["status"] == result["status"] == "failed"
    assert result["failures"]
    assert result["target_executed"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("profile_id", "THUMB-LE"),
        ("profile_version", 2),
        ("abi_id", "not-aapcs32"),
        ("bitness", 64),
        ("data_endian", "BE"),
        ("instruction_endian", "BE"),
        ("mode", "THUMB"),
        ("processor", "ARMB"),
    ],
)
def test_raw_profile_tuple_is_exact_and_fails_before_ida(
    tmp_path, monkeypatch, field, value
):
    def row(binary):
        result = profile_row(binary, profile_id="ARM32-LE", binary_format="FMT-RAW")
        result[field] = value
        return result

    fake = FakeIda()
    matrix, result, fake, _binary, _output = run_one(
        tmp_path, monkeypatch, fake=fake, row=row
    )
    assert fake.calls == []
    assert matrix["status"] == result["status"] == "failed"
    assert result["failures"][0]["kind"] == "unsupported_raw_configuration"


@pytest.mark.parametrize("empty,load_address", [(True, 0x10000), (False, 0xFFFFFFF0)])
def test_raw_input_range_is_validated_before_ida(
    tmp_path, monkeypatch, empty, load_address
):
    def row(binary):
        if empty:
            binary.write_bytes(b"")
        result = profile_row(binary, profile_id="ARM32-LE", binary_format="FMT-RAW")
        config = result["raw_configuration"]
        config["load_address"] = load_address
        config["entry_point"] = load_address
        return result

    fake = FakeIda()
    matrix, result, fake, _binary, _output = run_one(
        tmp_path, monkeypatch, fake=fake, row=row
    )
    assert fake.calls == []
    assert matrix["status"] == result["status"] == "failed"
    assert result["failures"][0]["kind"] == "unsupported_raw_configuration"


def test_hash_mismatch_fails_before_ida(tmp_path, monkeypatch):
    fake = FakeIda()
    _matrix, result, fake, _binary, _output = run_one(
        tmp_path,
        monkeypatch,
        fake=fake,
        row=lambda binary: profile_row(binary, expected_hash="0" * 64),
    )
    assert fake.calls == []
    assert result["status"] == "failed"
    assert result["failures"][0]["kind"] == "binary_hash_mismatch"


def test_bad_receipt_digest_fails_closed(tmp_path, monkeypatch):
    def mutate(stage, request, value):
        if stage == "final":
            value["receipt_digest"] = "0" * 64
        return value

    _matrix, result, fake, _binary, _output = run_one(
        tmp_path, monkeypatch, fake=FakeIda(mutate)
    )
    assert [call["stage"] for call in fake.calls] == ["bootstrap", "final"]
    assert result["status"] == "failed"
    assert result["failures"][0]["kind"] == "receipt_digest_mismatch"


@pytest.mark.parametrize(
    "field,value,expected_failure",
    [
        ("support_status", "supported", "support_status_promoted"),
        ("target_executed", True, "target_execution_claimed"),
    ],
)
def test_probe_receipt_cannot_promote_support_or_claim_target_execution(
    tmp_path, monkeypatch, field, value, expected_failure
):
    def mutate(stage, _request, receipt):
        if stage == "bootstrap":
            receipt[field] = value
            receipt["receipt_digest"] = probe.digest(
                {
                    key: item
                    for key, item in receipt.items()
                    if key != "receipt_digest"
                }
            )
        return receipt

    _matrix, result, fake, _binary, _output = run_one(
        tmp_path, monkeypatch, fake=FakeIda(mutate)
    )
    assert [call["stage"] for call in fake.calls] == ["bootstrap"]
    assert result["status"] == "failed"
    assert result["failures"][0]["kind"] == expected_failure


def test_matrix_continues_after_one_row_hash_failure(tmp_path, monkeypatch):
    build = tmp_path / "build"
    build.mkdir()
    bad = build / "bad.elf"
    good = build / "good.elf"
    bad.write_bytes(b"bad row bytes")
    good.write_bytes(b"good row bytes")
    manifest = build / "build.json"
    write_manifest(
        manifest,
        [
            profile_row(bad, profile_id="X64-LE", expected_hash="0" * 64),
            profile_row(good, profile_id="ARM32-LE", binary_format="FMT-RAW"),
        ],
    )
    ida = executable(tmp_path / "idat")
    fake = FakeIda()
    monkeypatch.setattr(runner.subprocess, "run", fake)
    output = tmp_path / "receipts"

    matrix = runner.run_matrix(
        root=ROOT,
        build_manifest=manifest,
        output_dir=output,
        ida_executable=ida,
    )

    assert matrix["status"] == "partial"
    assert matrix["status_counts"] == {"success": 1, "failed": 1, "blocked": 0}
    assert [call["stage"] for call in fake.calls] == ["bootstrap", "final"]
    results = [
        json.loads((output / row["result_file"]).read_text()) for row in matrix["rows"]
    ]
    assert [item["status"] for item in results] == ["failed", "success"]
    assert all(item["target_executed"] is False for item in results)


def test_profile_filter_is_exact_and_unknown_filter_is_rejected(tmp_path, monkeypatch):
    build = tmp_path / "build"
    build.mkdir()
    first = build / "first.elf"
    second = build / "second.elf"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    manifest = build / "build.json"
    write_manifest(
        manifest,
        [profile_row(first), profile_row(second, profile_id="ARM32-LE")],
    )
    ida = executable(tmp_path / "idat")
    fake = FakeIda()
    monkeypatch.setattr(runner.subprocess, "run", fake)

    matrix = runner.run_matrix(
        root=ROOT,
        build_manifest=manifest,
        output_dir=tmp_path / "receipts",
        ida_executable=ida,
        profile_filter={"ARM32-LE"},
    )
    assert matrix["profile_filter"] == ["ARM32-LE"]
    assert [row["profile_id"] for row in matrix["rows"]] == ["ARM32-LE"]
    assert len(fake.calls) == 2

    with pytest.raises(ValueError, match="Unknown profile"):
        runner.run_matrix(
            root=ROOT,
            build_manifest=manifest,
            output_dir=tmp_path / "other",
            ida_executable=ida,
            profile_filter={"MISSING"},
        )
