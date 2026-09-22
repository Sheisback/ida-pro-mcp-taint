"""Release workflow and aggregate contracts stay fail-closed."""

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
from typing import cast

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "flow_release_gate", ROOT / "scripts/flow_release_gate.py"
)
assert SPEC is not None and SPEC.loader is not None
release_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_gate)
COMMIT = "a" * 40
BUILD_ID = "flow-build-sha256-v1:" + "b" * 64


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
            "normal_success_count": 16,
            "format_success_count": 4,
            "rv32_fallback_count": 1,
        },
        "target_executed": False,
        "gui_process_e2e": False,
    }


def licensed(path: Path, version: str) -> tuple[Path, dict[str, object]]:
    value: dict[str, object] = {
        "schema_version": release_gate.LICENSED_SCHEMA,
        "checkout_sha": COMMIT,
        "fixture": "owned.elf",
        "fixture_sha256": "f" * 64,
        "ida_input_sha256": "f" * 64,
        "ida_version": version,
        "flow_build_id": BUILD_ID,
        "capabilities_digest": "sha256-v1:" + "1" * 64,
        "environment": {
            "processor": "metapc",
            "bits": 64,
            "endian": "little",
            "hexrays_initialization": {"status": "available", "reason": "test"},
        },
        "supported_profiles": [],
        "input_preserved": True,
        "target_executed": False,
        "debugger_attached": False,
    }
    path.write_text(json.dumps(value))
    return path, value


def receipts(tmp_path: Path) -> list[tuple[Path, dict[str, object]]]:
    return [
        licensed(tmp_path / f"licensed-{version}.json", version)
        for version in ("9.0.1", "9.1.2", "9.2.3", "9.3.4")
    ]


def test_release_aggregate_requires_every_protected_version(tmp_path):
    items = receipts(tmp_path)
    result = release_gate.aggregate_manifest(
        package(), items, {"9.0", "9.1", "9.2", "9.3"}, COMMIT
    )
    assert result["schema_version"] == release_gate.AGGREGATE_SCHEMA
    assert result["build_id"] == BUILD_ID
    assert result["target_executed"] is False
    assert result["gui_process_e2e"] is False
    with pytest.raises(ValueError, match="version coverage"):
        release_gate.aggregate_manifest(
            package(), items[:-1], {"9.0", "9.1", "9.2", "9.3"}, COMMIT
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("target_executed", True, "executed a target"),
        ("input_preserved", False, "changed its fixture"),
        ("flow_build_id", "flow-build-sha256-v1:" + "0" * 64, "build ID"),
        ("capabilities_digest", "unbound", "capability digest"),
        ("ida_input_sha256", "0" * 64, "input digest"),
    ],
)
def test_release_aggregate_rejects_unsafe_or_stale_receipts(
    tmp_path, field, value, message
):
    items = receipts(tmp_path)
    path, receipt = items[0]
    receipt[field] = value
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match=message):
        release_gate.aggregate_manifest(
            package(), items, {"9.0", "9.1", "9.2", "9.3"}, COMMIT
        )


def test_release_aggregate_rejects_incomplete_support_matrix(tmp_path):
    manifest = deepcopy(package())
    support_matrix = cast(dict[str, object], manifest["support_matrix"])
    support_matrix["normal_success_count"] = 15
    with pytest.raises(ValueError, match="support matrix"):
        release_gate.aggregate_manifest(
            manifest,
            receipts(tmp_path),
            {"9.0", "9.1", "9.2", "9.3"},
            COMMIT,
        )


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


def test_workflows_keep_untrusted_and_release_paths_separate():
    licensed = (ROOT / ".github/workflows/idalib-tests.yml").read_text()
    release = (ROOT / ".github/workflows/flow-release.yml").read_text()
    assert "pull_request_target" not in licensed
    assert "allow-unsafe-pr-checkout" not in licensed
    assert "environment: licensed-ida" in licensed
    assert "workflow_call:" in licensed and "workflow_dispatch:" in licensed
    assert "scripts/flow_licensed_ci.py" in licensed
    assert "uses: ./.github/workflows/idalib-tests.yml" in release
    assert "needs: [package-parity, licensed-ida]" in release
    assert "scripts/flow_release_gate.py package" in release
    assert "scripts/flow_release_gate.py aggregate" in release
    assert "continue-on-error" not in release
