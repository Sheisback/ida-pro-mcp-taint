"""Release workflow and aggregate contracts stay fail-closed."""

import ast
import importlib.util
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from ida_pro_mcp.flow_core.serialization import digest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "flow_release_gate", ROOT / "scripts/flow_release_gate.py"
)
assert SPEC is not None and SPEC.loader is not None
release_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_gate)
COMMIT = "a" * 40
BUILD_ID = "flow-build-sha256-v1:" + "b" * 64
VERSIONS = ("9.0.1", "9.1.2", "9.2.3", "9.3.4")


def mandatory_rows() -> list[dict[str, object]]:
    rows = []
    for index, (profile_id, abi_id, format_id) in enumerate(
        release_gate.MANDATORY_ROW_IDENTITIES
    ):
        ida_build = "9.3"
        processor, bits, endian = release_gate.PROFILE_FACTS[profile_id]
        rows.append(
            {
                "profile_id": profile_id,
                "fixture_sha256": f"{index + 1:064x}",
                "abi_id": abi_id,
                "format_id": format_id,
                "maturity": "MMAT_CALLS",
                "ida_build": ida_build,
                "hexrays_build": "9.3.0.260213",
                "ida_executable_sha256": f"{index + 101:064x}",
                "processor": processor,
                "bits": bits,
                "endian": endian,
                "evidence_path": "normal" if format_id == "FMT-ELF" else "format",
                "normal_status": "pass",
                "semantic_receipt_file": f"semantic/{index:02d}.json",
                "semantic_receipt_digest": "sha256-v1:" + f"{index + 201:064x}",
            }
        )
    return rows


def package() -> dict[str, object]:
    return {
        "schema_version": release_gate.PACKAGE_SCHEMA,
        "checkout_sha": COMMIT,
        "build_ids": {
            "source": BUILD_ID,
            "wheel": BUILD_ID,
            "gui_bootstrap": BUILD_ID,
        },
        "artifacts": {"project.whl": "c" * 64, "project.tar.gz": "d" * 64},
        "support_matrix": {
            "sha256": "e" * 64,
            "profile_count": 17,
            "semantic_row_count": 21,
            "normal_success_count": 17,
            "format_success_count": 4,
            "rv32_fallback_count": 1,
            "mandatory_normal_rows": mandatory_rows(),
            "fallback_promotes_readiness": False,
        },
        "target_executed": False,
        "gui_process_e2e": False,
    }


def licensed(path: Path, row: dict[str, object]) -> tuple[Path, dict[str, object]]:
    environment = {
        "ida_version": row["ida_build"],
        "hexrays_version": row["hexrays_build"],
        "processor": row["processor"],
        "bits": row["bits"],
        "endian": row["endian"],
        "hexrays_initialization": {"status": "available", "reason": "test"},
    }
    capabilities = {
        "schema_version": "flow-capabilities/1",
        "build_id": BUILD_ID,
        "environment": environment,
        "supported_profiles": [row["profile_id"]],
    }
    value: dict[str, object] = {
        "schema_version": release_gate.NORMAL_LICENSED_SCHEMA,
        "checkout_sha": COMMIT,
        "fixture": "owned.elf",
        "fixture_sha256": row["fixture_sha256"],
        "ida_input_sha256": row["fixture_sha256"],
        "profile_id": row["profile_id"],
        "abi_id": row["abi_id"],
        "format_id": row["format_id"],
        "maturity": "MMAT_CALLS",
        "normal_status": "pass",
        "ida_build": row["ida_build"],
        "ida_executable_sha256": row["ida_executable_sha256"],
        "hexrays_build": row["hexrays_build"],
        "flow_build_id": BUILD_ID,
        "capabilities": capabilities,
        "capabilities_digest": digest(capabilities),
        "environment": environment,
        "supported_profiles": [row["profile_id"]],
        "input_preserved": True,
        "target_executed": False,
        "debugger_attached": False,
        "semantic_receipt_file": row["semantic_receipt_file"],
        "semantic_receipt_digest": row["semantic_receipt_digest"],
    }
    path.write_text(json.dumps(value))
    return path, value


def compatibility(path: Path, version: str) -> tuple[Path, dict[str, object]]:
    environment = {
        "ida_version": version,
        "hexrays_version": version + ".123",
        "processor": "metapc",
        "bits": 64,
        "endian": "little",
        "hexrays_initialization": {"status": "available", "reason": "test"},
    }
    capabilities = {
        "schema_version": "flow-capabilities/1",
        "build_id": BUILD_ID,
        "environment": environment,
        "supported_profiles": [],
    }
    value: dict[str, object] = {
        "schema_version": release_gate.LICENSED_SCHEMA,
        "checkout_sha": COMMIT,
        "fixture": "compatibility.elf",
        "fixture_sha256": "f" * 64,
        "ida_input_sha256": "f" * 64,
        "profile_id": "X64-LE",
        "abi_id": "sysv-amd64",
        "format_id": "FMT-ELF",
        "maturity": "MMAT_CALLS",
        "normal_status": "unknown",
        "ida_build": version,
        "ida_executable_sha256": "e" * 64,
        "hexrays_build": version + ".123",
        "flow_build_id": BUILD_ID,
        "capabilities": capabilities,
        "capabilities_digest": digest(capabilities),
        "environment": environment,
        "supported_profiles": [],
        "input_preserved": True,
        "target_executed": False,
        "debugger_attached": False,
    }
    path.write_text(json.dumps(value))
    return path, value


def compatibility_receipts(tmp_path: Path):
    return [
        compatibility(tmp_path / f"licensed-{version}.json", version)
        for version in VERSIONS
    ]


def receipts(tmp_path: Path) -> list[tuple[Path, dict[str, object]]]:
    return [
        licensed(
            tmp_path
            / f"licensed-{index:02d}-{row['profile_id']}-{row['format_id']}.json",
            row,
        )
        for index, row in enumerate(mandatory_rows())
    ]


def gui_receipt() -> dict[str, object]:
    environment = {"ida_version": "9.3.4", "hexrays_version": "9.3.4.123"}
    capabilities = {
        "schema_version": "flow-capabilities/1",
        "build_id": BUILD_ID,
        "environment": environment,
        "supported_profiles": ["X64-LE"],
    }
    return {
        "schema_version": release_gate.GUI_SCHEMA,
        "checkout_sha": COMMIT,
        "flow_build_id": BUILD_ID,
        "ida_build": "9.3.4",
        "hexrays_build": "9.3.4.123",
        "ida_executable_sha256": "9" * 64,
        "capabilities": capabilities,
        "capabilities_digest": digest(capabilities),
        "process_kind": "ida-gui",
        "disposable_user_dir": True,
        "eula_accepted_during_probe": False,
        "target_executed": False,
        "input_preserved": True,
    }


def aggregate(monkeypatch, tmp_path, pkg=None, items=None, **overrides):
    monkeypatch.setattr(
        release_gate,
        "_load_benchmark_gate",
        lambda: SimpleNamespace(
            validate_limits=lambda value: None,
            validate_release_report=lambda *args, **kwargs: None,
        ),
    )
    limits_path = tmp_path / "limits.json"
    limits_path.write_text("{}")
    arguments = {
        "gui_receipt": gui_receipt(),
        "benchmark_report": {"limits_sha256": "sha256-v1:" + "1" * 64},
        "benchmark_limits": {},
        "benchmark_limits_path": limits_path,
        "expected_ida_executable_sha256": "f" * 64,
        "expected_gui_executable_sha256": "9" * 64,
        "compatibility_receipts": compatibility_receipts(tmp_path),
    }
    arguments.update(overrides)
    return release_gate.aggregate_manifest(
        package() if pkg is None else pkg,
        receipts(tmp_path) if items is None else items,
        {"9.0", "9.1", "9.2", "9.3"},
        COMMIT,
        **arguments,
    )


def test_release_aggregate_requires_every_normal_row_and_version(monkeypatch, tmp_path):
    result = aggregate(monkeypatch, tmp_path)
    assert result["schema_version"] == release_gate.AGGREGATE_SCHEMA
    assert result["build_id"] == BUILD_ID
    assert result["target_executed"] is False
    assert result["gui_process_e2e"] is True

    with pytest.raises(ValueError, match="mandatory normal row coverage"):
        aggregate(monkeypatch, tmp_path, items=receipts(tmp_path)[:-1])
    with pytest.raises(ValueError, match="version coverage"):
        aggregate(
            monkeypatch,
            tmp_path,
            compatibility_receipts=compatibility_receipts(tmp_path)[:-1],
        )


def test_compatibility_receipts_are_separate_and_non_promoting(monkeypatch, tmp_path):
    compatibility_items = compatibility_receipts(tmp_path)
    with pytest.raises(ValueError, match="normal receipt schema"):
        aggregate(monkeypatch, tmp_path, items=compatibility_items)
    path, receipt = compatibility_items[0]
    receipt["normal_status"] = "pass"
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="compatibility receipt is unsafe"):
        aggregate(
            monkeypatch,
            tmp_path,
            compatibility_receipts=compatibility_items,
        )


@pytest.mark.parametrize("version", ["9.3junk", "9.3.4junk", ".9.3", "9..3"])
def test_compatibility_version_syntax_is_strict(monkeypatch, tmp_path, version):
    items = compatibility_receipts(tmp_path)
    path, receipt = items[-1]
    receipt["ida_build"] = version
    environment = cast(dict[str, object], receipt["environment"])
    environment["ida_version"] = version
    capabilities = cast(dict[str, object], receipt["capabilities"])
    capabilities["environment"] = environment
    receipt["capabilities_digest"] = digest(capabilities)
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="IDA version is invalid"):
        aggregate(monkeypatch, tmp_path, compatibility_receipts=items)


@pytest.mark.parametrize("version", [None, "9.3junk", "9.3.4junk", ".9.3", "9..3"])
def test_compatibility_hexrays_version_syntax_is_strict(monkeypatch, tmp_path, version):
    items = compatibility_receipts(tmp_path)
    path, receipt = items[-1]
    receipt["hexrays_build"] = version
    environment = cast(dict[str, object], receipt["environment"])
    environment["hexrays_version"] = version
    capabilities = cast(dict[str, object], receipt["capabilities"])
    capabilities["environment"] = environment
    receipt["capabilities_digest"] = digest(capabilities)
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="runtime binding failed"):
        aggregate(monkeypatch, tmp_path, compatibility_receipts=items)


def test_release_rejects_empty_profiles_fallback_and_nonpass(monkeypatch, tmp_path):
    items = receipts(tmp_path)
    path, receipt = items[0]
    receipt["supported_profiles"] = []
    cast(dict[str, object], receipt["capabilities"])["supported_profiles"] = []
    receipt["capabilities_digest"] = digest(receipt["capabilities"])
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="supported profiles"):
        aggregate(monkeypatch, tmp_path, items=items)

    manifest = package()
    rows = cast(dict[str, object], manifest["support_matrix"])["mandatory_normal_rows"]
    cast(list[dict[str, object]], rows)[0]["evidence_path"] = "fallback"
    with pytest.raises(ValueError, match="passing normal row"):
        aggregate(monkeypatch, tmp_path, pkg=manifest)

    manifest = package()
    rows = cast(dict[str, object], manifest["support_matrix"])["mandatory_normal_rows"]
    cast(list[dict[str, object]], rows).pop()
    with pytest.raises(ValueError, match="every mandatory normal row"):
        aggregate(monkeypatch, tmp_path, pkg=manifest)

    manifest = package()
    rows = cast(
        list[dict[str, object]],
        cast(dict, manifest["support_matrix"])["mandatory_normal_rows"],
    )
    rows[-1]["profile_id"] = "UNKNOWN-LE"
    with pytest.raises(ValueError, match="mandatory row coverage"):
        aggregate(monkeypatch, tmp_path, pkg=manifest)

    manifest = package()
    rows = cast(
        list[dict[str, object]],
        cast(dict, manifest["support_matrix"])["mandatory_normal_rows"],
    )
    rows[0]["bits"] = 64
    with pytest.raises(ValueError, match="mandatory row coverage"):
        aggregate(monkeypatch, tmp_path, pkg=manifest)

    items = receipts(tmp_path)
    path, receipt = items[0]
    receipt["normal_status"] = "skipped"
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="mandatory normal row mismatch"):
        aggregate(monkeypatch, tmp_path, items=items)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("target_executed", True, "static-only"),
        ("input_preserved", False, "static-only"),
        ("flow_build_id", "flow-build-sha256-v1:" + "0" * 64, "build ID"),
        ("ida_input_sha256", "0" * 64, "input digest"),
    ],
)
def test_release_aggregate_rejects_unsafe_or_stale_receipts(
    monkeypatch, tmp_path, field, value, message
):
    items = receipts(tmp_path)
    path, receipt = items[0]
    receipt[field] = value
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match=message):
        aggregate(monkeypatch, tmp_path, items=items)


def test_release_recomputes_capability_digest(monkeypatch, tmp_path):
    items = receipts(tmp_path)
    path, receipt = items[0]
    cast(dict[str, object], receipt["capabilities"])["build_id"] = (
        "flow-build-sha256-v1:" + "0" * 64
    )
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="capability body digest"):
        aggregate(monkeypatch, tmp_path, items=items)


def test_release_rejects_cross_profile_observation(monkeypatch, tmp_path):
    items = receipts(tmp_path)
    path, receipt = items[2]
    environment = cast(dict[str, object], receipt["environment"])
    environment["bits"] = 64 if environment["bits"] == 32 else 32
    receipt["capabilities_digest"] = digest(receipt["capabilities"])
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="profile observation"):
        aggregate(monkeypatch, tmp_path, items=items)


def test_release_rejects_substituted_profile_identity(monkeypatch, tmp_path):
    items = receipts(tmp_path)
    path, receipt = items[0]
    receipt["profile_id"] = "X64-LE"
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="mandatory normal row"):
        aggregate(monkeypatch, tmp_path, items=items)


def test_release_requires_gui_and_benchmark_evidence(monkeypatch, tmp_path):
    with pytest.raises(ValueError, match="GUI-process evidence"):
        aggregate(monkeypatch, tmp_path, gui_receipt=None)
    with pytest.raises(ValueError, match="benchmark evidence"):
        aggregate(monkeypatch, tmp_path, benchmark_report=None)
    gui = gui_receipt()
    gui["ida_build"] = None
    gui["hexrays_build"] = None
    capabilities = cast(dict[str, object], gui["capabilities"])
    capabilities["environment"] = {}
    gui["capabilities_digest"] = digest(capabilities)
    with pytest.raises(ValueError, match="GUI-process evidence"):
        aggregate(monkeypatch, tmp_path, gui_receipt=gui)
    with pytest.raises(ValueError, match="GUI-process evidence"):
        aggregate(
            monkeypatch,
            tmp_path,
            expected_gui_executable_sha256="8" * 64,
        )


def test_release_aggregate_rejects_incomplete_support_matrix(monkeypatch, tmp_path):
    manifest = deepcopy(package())
    support_matrix = cast(dict[str, object], manifest["support_matrix"])
    support_matrix["normal_success_count"] = 16
    with pytest.raises(ValueError, match="support matrix"):
        aggregate(monkeypatch, tmp_path, pkg=manifest)


def test_release_artifacts_are_rehashed_after_download(tmp_path):
    manifest = package()
    artifacts = cast(dict[str, object], manifest["artifacts"])
    for name in tuple(artifacts):
        path = tmp_path / name
        path.write_text(name)
        artifacts[name] = release_gate.sha256(path)
    release_gate.validate_artifact_files(manifest, tmp_path)
    (tmp_path / "project.whl").write_text("tampered")
    with pytest.raises(ValueError, match="artifact digest"):
        release_gate.validate_artifact_files(manifest, tmp_path)


def test_licensed_cli_imports_idapro_before_sdk_modules():
    tree = ast.parse((ROOT / "scripts/flow_licensed_ci.py").read_text())
    record = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "record"
    )
    imports = [
        alias.name
        for node in ast.walk(record)
        if isinstance(node, ast.Import)
        for alias in node.names
        if alias.name in {"idapro", "ida_auto", "ida_kernwin", "ida_nalt"}
    ]
    assert imports.index("idapro") < min(
        imports.index(name) for name in imports if name != "idapro"
    )


def test_gui_producer_isolated_missing_executable_records_blocker(tmp_path):
    fixture = tmp_path / "fixture.elf"
    fixture.write_bytes(b"static fixture")
    output = tmp_path / "gui-process.json"
    output.write_text('{"stale": true}')
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/record_flow_gui_ci.py"),
            "--fixture",
            str(fixture),
            "--checkout-sha",
            COMMIT,
            "--ida",
            str(tmp_path / "missing-ida"),
            "--expected-ida-executable-sha256",
            "9" * 64,
            "--output",
            str(output),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    blocker = json.loads((tmp_path / "gui-process.blocker.json").read_text())
    assert completed.returncode == 0 and not output.exists()
    assert blocker["reason"] == "gui_executable_missing"
    assert blocker["disposable_user_dir"] is True
    assert blocker["eula_accepted_during_probe"] is False
    assert blocker["target_executed"] is False
    source = (ROOT / "scripts/record_flow_gui_ci.py").read_text()
    assert '"HOME": str(home)' in source and '"IDAUSR": str(user)' in source
    assert "accept-eula" not in source.lower()


def test_gui_timeout_escalates_to_sigkill_and_reaps(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location(
        "record_flow_gui_ci", ROOT / "scripts/record_flow_gui_ci.py"
    )
    assert spec is not None and spec.loader is not None
    recorder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(recorder)
    fixture = tmp_path / "fixture.elf"
    fixture.write_bytes(b"static fixture")
    ida = tmp_path / "ida"
    ida.write_bytes(b"gui")
    output = tmp_path / "gui-process.json"
    calls = []

    class Process:
        pid = 123
        returncode = None

        def communicate(self, timeout=None):
            calls.append(("communicate", timeout))
            if len([item for item in calls if item[0] == "communicate"]) < 3:
                raise subprocess.TimeoutExpired("ida", timeout)
            self.returncode = -9
            return "stdout", "stderr"

    monkeypatch.setattr(recorder.subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(
        recorder.os, "killpg", lambda pid, sig: calls.append(("killpg", pid, sig))
    )
    args = SimpleNamespace(
        fixture=fixture,
        ida=ida,
        output=output,
        checkout_sha=COMMIT,
        expected_ida_executable_sha256=recorder.sha256(ida),
        timeout=1,
    )
    blocker = recorder.record(args)
    assert blocker["reason"] == "gui_process_timeout_no_eula_interaction"
    assert ("killpg", 123, recorder.signal.SIGTERM) in calls
    assert ("killpg", 123, recorder.signal.SIGKILL) in calls
    assert calls[-1] == ("communicate", None)


def test_normal_producer_emits_only_actual_normal_rows(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "record_flow_licensed_normal",
        ROOT / "scripts/record_flow_licensed_normal.py",
    )
    assert spec is not None and spec.loader is not None
    producer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(producer)
    executable_sha256 = (
        "044e7d28a17ecaacaeb4e7d78147c11c7faaba79c6eec657f7924ec3d22a0380"
    )
    output = tmp_path / "normal"
    paths = producer.record(
        root=ROOT,
        output_dir=output,
        checkout_sha=COMMIT,
        executable_sha256=executable_sha256,
        expected_executable_sha256=executable_sha256,
    )
    assert len(paths) == 20
    receipts_by_identity = {}
    for path in paths:
        value = json.loads(path.read_text())
        assert value["schema_version"] == release_gate.NORMAL_LICENSED_SCHEMA
        assert value["normal_status"] == "pass"
        assert value["target_executed"] is False
        assert value["input_preserved"] is True
        assert value["profile_id"] != "RV32-LE"
        receipts_by_identity[
            (value["profile_id"], value["abi_id"], value["format_id"])
        ] = (path, value)
    matrix = json.loads(
        (
            ROOT / "tests/flow_fixtures/manifests/profile_semantics/matrix.json"
        ).read_text()
    )
    expected_rows = release_gate._mandatory_normal_rows(matrix)
    assert set(receipts_by_identity) == {
        (row["profile_id"], row["abi_id"], row["format_id"]) for row in expected_rows
    }
    for identity, (path, value) in receipts_by_identity.items():
        expected = next(
            row
            for row in expected_rows
            if (row["profile_id"], row["abi_id"], row["format_id"]) == identity
        )
        release_gate._validate_normal_receipt(
            value,
            expected,
            checkout_sha=COMMIT,
            build_id=producer.BUILD_ID,
            path=path,
        )


def test_workflows_keep_untrusted_and_release_paths_separate_and_pinned():
    licensed = (ROOT / ".github/workflows/idalib-tests.yml").read_text()
    release = (ROOT / ".github/workflows/flow-release.yml").read_text()
    combined = licensed + release
    assert "pull_request_target" not in licensed
    assert "allow-unsafe-pr-checkout" not in licensed
    assert "environment: licensed-ida" in licensed
    assert "workflow_call:" in licensed and "workflow_dispatch:" in licensed
    assert "scripts/flow_licensed_ci.py" in licensed
    assert "scripts/record_flow_licensed_normal.py" in licensed
    assert "uses: ./.github/workflows/idalib-tests.yml" in release
    assert "needs: [package-parity, licensed-ida]" in release
    assert "scripts/flow_release_gate.py package" in release
    assert "scripts/flow_release_gate.py aggregate" in release
    assert "--normal-dir licensed-reports/normal" in release
    assert "--benchmark-report" in release and "--gui-receipt" in release
    assert "scripts/run_ida_flow_benchmark.py" in licensed
    assert "scripts/record_flow_gui_ci.py" in licensed
    assert "--ida-metrics licensed-reports/benchmark-ida.json" in release
    assert "IDA_93_EXECUTABLE_SHA256" in licensed + release
    assert "IDA_93_GUI_EXECUTABLE_SHA256" in licensed + release
    assert "continue-on-error" not in release
    assert "actions/checkout@v" not in combined
    assert "astral-sh/setup-uv@v" not in combined
    assert "actions/upload-artifact@v" not in combined
    assert "actions/download-artifact@v" not in combined
    assert "ida@${{ matrix.image-digest }}" in licensed
    assert "^sha256:[0-9a-f]{64}$" in licensed
