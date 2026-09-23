"""Release workflow and aggregate contracts stay fail-closed."""

import ast
import hashlib
import importlib.util
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from ida_pro_mcp.flow_core.serialization import ContractError, digest
from ida_pro_mcp.flow_core.semantic_equivalence import (
    normal_semantic_equivalence_digest,
)

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "flow_release_gate", ROOT / "scripts/flow_release_gate.py"
)
assert SPEC is not None and SPEC.loader is not None
release_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_gate)
VALIDATE_PACKAGE = release_gate._validate_package
COMMIT = "a" * 40
BUILD_ID = "flow-build-sha256-v1:" + "b" * 64
VERSIONS = ("9.3.4",)


def test_normal_semantic_equivalence_excludes_run_provenance_not_meaning():
    path = ROOT / "tests/flow_fixtures/manifests/profile_semantics/normal/x86-le.json"
    archival = json.loads(path.read_text())
    fresh = deepcopy(archival)
    for invocation in fresh["invocations"]:
        invocation["ida_executable_name"] = "idat-current"
        invocation["ida_executable_sha256"] = "f" * 64
    fresh["fresh_process_receipt_digests"] = [
        "sha256-v1:" + "e" * 64,
        "sha256-v1:" + "e" * 64,
    ]
    assert normal_semantic_equivalence_digest(fresh) == (
        normal_semantic_equivalence_digest(archival)
    )

    fresh["evaluation"]["alias_status"] = "forged_known_aliases"
    assert normal_semantic_equivalence_digest(fresh) != (
        normal_semantic_equivalence_digest(archival)
    )


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
                "processor": processor,
                "bits": bits,
                "endian": endian,
                "evidence_path": "normal" if format_id == "FMT-ELF" else "format",
                "normal_status": "pass",
                "semantic_receipt_file": f"semantic/{index:02d}.json",
                "semantic_receipt_digest": "sha256-v1:" + f"{index + 201:064x}",
                "semantic_equivalence_digest": "sha256-v1:" + f"{index + 301:064x}",
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
            "release_scope_sha256": release_gate.sha256(
                ROOT / release_gate.RELEASE_SCOPE
            ),
            "optional_profile_ids": ["RV32-LE"],
            "profile_count": 17,
            "semantic_row_count": 21,
            "normal_success_count": 17,
            "format_success_count": 4,
            "rv32_fallback_count": 0,
            "required_row_count": 21,
            "mandatory_normal_rows": mandatory_rows(),
            "unavailable_normal_rows": [],
            "fallback_promotes_readiness": False,
        },
        "target_executed": False,
        "gui_process_e2e": False,
    }


def canonical_package() -> dict[str, object]:
    value = package()
    readiness = release_gate._canonical_readiness_contract()
    available = cast(list[dict[str, object]], readiness["mandatory_normal_rows"])
    unavailable = cast(list[dict[str, object]], readiness["unavailable_normal_rows"])
    semantic = json.loads((ROOT / release_gate.SEMANTIC_MATRIX).read_text())
    matrix = cast(dict[str, object], value["support_matrix"])
    matrix.update(
        {
            "sha256": release_gate.sha256(ROOT / release_gate.SEMANTIC_MATRIX),
            "release_scope_sha256": release_gate.sha256(
                ROOT / release_gate.RELEASE_SCOPE
            ),
            "optional_profile_ids": list(readiness["optional_profiles"]),
            "profile_count": semantic["profile_count"],
            "semantic_row_count": semantic["semantic_row_count"],
            "normal_success_count": semantic["normal_success_count"],
            "format_success_count": semantic["format_success_count"],
            "rv32_fallback_count": semantic["rv32_fallback_count"],
            "required_row_count": len(available) + len(unavailable),
            "mandatory_normal_rows": deepcopy(available),
            "unavailable_normal_rows": deepcopy(unavailable),
        }
    )
    return value


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
        "ida_executable_sha256": "f" * 64,
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
        "semantic_equivalence_digest": row["semantic_equivalence_digest"],
        "extraction_digest": "sha256-v1:" + "4" * 64,
        "public_profile_digest": "sha256-v1:" + "5" * 64,
        "current_run": {
            "kind": "current_checkout_actual_ida",
            "matrix_receipt_digest": "sha256-v1:" + "6" * 64,
            "semantic_receipt_digest": "sha256-v1:" + "7" * 64,
            "semantic_equivalence_digest": row["semantic_equivalence_digest"],
            "process_receipt_digests": [
                "sha256-v1:" + "8" * 64,
                "sha256-v1:" + "8" * 64,
            ],
            "build_evidence_digest": "sha256-v1:" + "9" * 64,
            "implementation": {
                "scripts/flow_release_gate.py": hashlib.sha256(
                    (ROOT / "scripts/flow_release_gate.py").read_bytes()
                ).hexdigest()
            },
        },
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
        "module_origin": (
            "/tmp/flow-gui-ci-proof/idausr/plugins/"
            "_ida_pro_mcp_runtime/ida_mcp/api_flow.py"
        ),
        "loader_sha256": "7" * 64,
        "bundle_manifest_sha256": "8" * 64,
        "capabilities": capabilities,
        "capabilities_digest": digest(capabilities),
        "process_kind": "ida-gui",
        "disposable_user_dir": True,
        "eula_accepted_during_probe": False,
        "target_executed": False,
        "input_preserved": True,
    }


def aggregate(
    monkeypatch,
    tmp_path,
    pkg=None,
    items=None,
    *,
    validate_package=False,
    expected_versions=None,
    **overrides,
):
    monkeypatch.setattr(
        release_gate,
        "_load_benchmark_gate",
        lambda: SimpleNamespace(
            validate_limits=lambda value: None,
            validate_release_report=lambda *args, **kwargs: None,
        ),
    )
    if not validate_package:
        monkeypatch.setattr(
            release_gate,
            "_validate_package",
            lambda _package, _checkout_sha: BUILD_ID,
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
        {"9.3"} if expected_versions is None else expected_versions,
        COMMIT,
        **arguments,
    )


def test_release_aggregate_requires_every_normal_row_and_only_ida_93(
    monkeypatch, tmp_path
):
    result = aggregate(monkeypatch, tmp_path)
    assert result["schema_version"] == release_gate.AGGREGATE_SCHEMA
    assert result["build_id"] == BUILD_ID
    assert result["target_executed"] is False
    assert result["gui_process_e2e"] is True

    with pytest.raises(ValueError, match="mandatory normal row coverage"):
        aggregate(monkeypatch, tmp_path, items=receipts(tmp_path)[:-1])

    with pytest.raises(ValueError, match="exactly IDA 9.3"):
        aggregate(monkeypatch, tmp_path, expected_versions={"9.0", "9.3"})


def test_release_aggregate_binds_fresh_receipts_to_reviewed_executable(
    monkeypatch, tmp_path
):
    with pytest.raises(ValueError, match="IDA executable digest mismatch"):
        aggregate(
            monkeypatch,
            tmp_path,
            expected_ida_executable_sha256="0" * 64,
        )
    with pytest.raises(ValueError, match="version coverage"):
        aggregate(
            monkeypatch,
            tmp_path,
            compatibility_receipts=[
                compatibility(tmp_path / "licensed-9.2.json", "9.2.3")
            ],
        )


def test_canonical_readiness_retains_optional_rv32_without_release_promotion(
    monkeypatch, tmp_path
):
    readiness = release_gate._canonical_readiness_contract()
    available = cast(list[dict[str, object]], readiness["mandatory_normal_rows"])
    unavailable = cast(list[dict[str, object]], readiness["unavailable_normal_rows"])
    assert len(readiness["required_profiles"]) == 16
    assert readiness["optional_profiles"] == ("RV32-LE",)
    assert unavailable == []
    assert all(row["profile_id"] != "RV32-LE" for row in available)
    assert len(available) == 20

    manifest = canonical_package()
    assert (
        cast(dict[str, object], manifest["support_matrix"])["rv32_fallback_count"] == 1
    )
    with pytest.raises(ValueError, match="No current mandatory normal receipts"):
        aggregate(
            monkeypatch,
            tmp_path,
            pkg=manifest,
            items=[],
            validate_package=True,
        )


def test_release_scope_rejects_missing_or_reclassified_required_profile(
    monkeypatch, tmp_path
):
    scope = json.loads((ROOT / release_gate.RELEASE_SCOPE).read_text())
    scope["required_profile_ids"].remove("X64-LE")
    scope["optional_profile_ids"].append("X64-LE")
    path = tmp_path / "release-scope.json"
    path.write_text(json.dumps(scope))
    monkeypatch.setattr(release_gate, "RELEASE_SCOPE", path)
    with pytest.raises(ValueError, match="release scope"):
        release_gate._canonical_readiness_contract()


def test_required_profile_fallback_still_blocks_readiness(tmp_path):
    matrix = json.loads((ROOT / release_gate.SEMANTIC_MATRIX).read_text())
    build = json.loads((ROOT / release_gate.PROFILE_BUILD_MANIFEST).read_text())
    x64 = next(
        row
        for row in matrix["profiles"]
        if row["profile_id"] == "X64-LE" and row["evidence_path"] == "normal"
    )
    fallback = tmp_path / "x64-fallback.json"
    fallback.write_text(
        json.dumps(
            {
                "profile_id": "X64-LE",
                "normal_backend": {
                    "probe_status": "failed",
                    "support_status": "unverified",
                },
            }
        )
    )
    x64["evidence_path"] = "fallback"
    x64["receipt_file"] = str(fallback)
    readiness = release_gate._readiness_contract(matrix, build)
    unavailable = cast(list[dict[str, object]], readiness["unavailable_normal_rows"])
    assert [row["profile_id"] for row in unavailable] == ["X64-LE"]
    assert unavailable[0]["blocker"] == "normal_backend_unavailable"


def test_package_rejects_fallback_promotion_and_unbound_matrix_digest():
    with pytest.raises(ValueError, match="canonical readiness evidence"):
        release_gate._validate_package(package(), COMMIT)

    manifest = canonical_package()
    matrix = cast(dict[str, object], manifest["support_matrix"])
    matrix["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="canonical readiness evidence"):
        VALIDATE_PACKAGE(manifest, COMMIT)


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

    manifest = canonical_package()
    rows = cast(dict[str, object], manifest["support_matrix"])["mandatory_normal_rows"]
    cast(list[dict[str, object]], rows)[0]["evidence_path"] = "fallback"
    with pytest.raises(ValueError, match="passing normal row"):
        VALIDATE_PACKAGE(manifest, COMMIT)

    manifest = canonical_package()
    rows = cast(dict[str, object], manifest["support_matrix"])["mandatory_normal_rows"]
    cast(list[dict[str, object]], rows).pop()
    with pytest.raises(ValueError, match="canonical readiness"):
        VALIDATE_PACKAGE(manifest, COMMIT)

    manifest = canonical_package()
    rows = cast(
        list[dict[str, object]],
        cast(dict, manifest["support_matrix"])["mandatory_normal_rows"],
    )
    rows[-1]["profile_id"] = "UNKNOWN-LE"
    with pytest.raises(ValueError, match="canonical readiness"):
        VALIDATE_PACKAGE(manifest, COMMIT)

    manifest = canonical_package()
    rows = cast(
        list[dict[str, object]],
        cast(dict, manifest["support_matrix"])["mandatory_normal_rows"],
    )
    rows[0]["bits"] = 64
    with pytest.raises(ValueError, match="canonical readiness"):
        VALIDATE_PACKAGE(manifest, COMMIT)

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
    manifest = canonical_package()
    support_matrix = cast(dict[str, object], manifest["support_matrix"])
    support_matrix["normal_success_count"] = 15
    with pytest.raises(ValueError, match="support matrix"):
        VALIDATE_PACKAGE(manifest, COMMIT)


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
    arguments = [
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
    ]
    stale = tmp_path / "stale-gui-process.json"
    stale.write_text('{"stale": true}')
    refused = subprocess.run(
        [*arguments, str(stale)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert refused.returncode != 0
    assert stale.read_text() == '{"stale": true}'

    output = tmp_path / "gui-process.json"
    completed = subprocess.run(
        [*arguments, str(output)],
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

        def communicate(self, timeout: float | None = None):
            calls.append(("communicate", timeout))
            if len([item for item in calls if item[0] == "communicate"]) < 3:
                raise subprocess.TimeoutExpired(
                    "ida", 0 if timeout is None else timeout
                )
            self.returncode = -9
            return "stdout", "stderr"

    monkeypatch.setattr(recorder.subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(
        recorder,
        "build_and_install_gui_bundle",
        lambda work, user: (
            user / "plugins" / "ida_mcp.py",
            user / "plugins" / "_ida_pro_mcp_runtime" / "install-manifest.json",
        ),
    )
    monkeypatch.setattr(recorder, "sha256", lambda path: "a" * 64)
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


def test_normal_producer_binds_content_addressed_actual_rows(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "record_flow_licensed_normal",
        ROOT / "scripts/record_flow_licensed_normal.py",
    )
    assert spec is not None and spec.loader is not None
    producer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(producer)
    executable_sha256 = "f" * 64
    output = tmp_path / "normal"
    canonical = json.loads(
        (
            ROOT / "tests/flow_fixtures/manifests/profile_semantics/matrix.json"
        ).read_text()
    )
    current_dirs = {}
    for evidence_path in ("normal", "format"):
        directory = tmp_path / ("current-" + evidence_path)
        directory.mkdir()
        profiles = []
        for index, item in enumerate(canonical["profiles"]):
            if item["evidence_path"] != evidence_path:
                continue
            name = f"row-{index:02d}.json"
            current_receipt = json.loads((ROOT / item["receipt_file"]).read_text())
            for invocation in current_receipt["invocations"]:
                invocation["ida_executable_name"] = "idat-current"
                invocation["ida_executable_sha256"] = executable_sha256
            current_receipt.pop("receipt_digest")
            current_receipt["receipt_digest"] = digest(current_receipt)
            (directory / name).write_text(json.dumps(current_receipt))
            row = {
                "profile_id": item["profile_id"],
                "status": "success",
                "result_file": name,
                "receipt_digest": current_receipt["receipt_digest"],
            }
            if evidence_path == "format":
                row["format"] = item["format"]
            profiles.append(row)
        matrix = {
            "schema_version": "test-current-matrix/1",
            "profiles": profiles,
            "success_count": len(profiles),
            "failure_count": 0,
            "target_executed": False,
            "input_preserved": True,
            "status": "success",
        }
        matrix["receipt_digest"] = digest(matrix)
        (directory / "matrix.json").write_text(json.dumps(matrix))
        current_dirs[evidence_path] = directory
    paths = producer.record(
        root=ROOT,
        output_dir=output,
        checkout_sha=COMMIT,
        executable_sha256=executable_sha256,
        expected_executable_sha256=executable_sha256,
        current_normal_dir=current_dirs["normal"],
        current_format_dir=current_dirs["format"],
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
        assert value["ida_executable_sha256"] == executable_sha256
        assert (
            value["current_run"]["semantic_receipt_digest"]
            != value["semantic_receipt_digest"]
        )
        assert (
            value["current_run"]["semantic_equivalence_digest"]
            == value["semantic_equivalence_digest"]
        )
        receipts_by_identity[
            (value["profile_id"], value["abi_id"], value["format_id"])
        ] = (path, value)
    expected_rows = release_gate._mandatory_normal_rows(canonical)
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

    first_normal = current_dirs["normal"] / "row-00.json"
    normal_matrix_path = current_dirs["normal"] / "matrix.json"
    original_normal = first_normal.read_text()
    original_matrix = normal_matrix_path.read_text()
    semantic_drift = json.loads(original_normal)
    semantic_drift["evaluation"]["alias_status"] = "forged_known_aliases"
    semantic_drift.pop("receipt_digest")
    semantic_drift["receipt_digest"] = digest(semantic_drift)
    first_normal.write_text(json.dumps(semantic_drift))
    drift_matrix = json.loads(original_matrix)
    drift_matrix["profiles"][0]["receipt_digest"] = semantic_drift["receipt_digest"]
    drift_matrix.pop("receipt_digest")
    drift_matrix["receipt_digest"] = digest(drift_matrix)
    normal_matrix_path.write_text(json.dumps(drift_matrix))
    with pytest.raises((ValueError, ContractError)):
        producer.record(
            root=ROOT,
            output_dir=tmp_path / "semantic-drift",
            checkout_sha=COMMIT,
            executable_sha256=executable_sha256,
            expected_executable_sha256=executable_sha256,
            current_normal_dir=current_dirs["normal"],
            current_format_dir=current_dirs["format"],
        )
    first_normal.write_text(original_normal)
    normal_matrix_path.write_text(original_matrix)

    process_drift = json.loads(original_normal)
    process_drift["fresh_process_receipt_digests"] = [
        "sha256-v1:" + "0" * 64,
        "sha256-v1:" + "0" * 64,
    ]
    process_drift.pop("receipt_digest")
    process_drift["receipt_digest"] = digest(process_drift)
    first_normal.write_text(json.dumps(process_drift))
    drift_matrix = json.loads(original_matrix)
    drift_matrix["profiles"][0]["receipt_digest"] = process_drift["receipt_digest"]
    drift_matrix.pop("receipt_digest")
    drift_matrix["receipt_digest"] = digest(drift_matrix)
    normal_matrix_path.write_text(json.dumps(drift_matrix))
    with pytest.raises((ValueError, ContractError)):
        producer.record(
            root=ROOT,
            output_dir=tmp_path / "process-drift",
            checkout_sha=COMMIT,
            executable_sha256=executable_sha256,
            expected_executable_sha256=executable_sha256,
            current_normal_dir=current_dirs["normal"],
            current_format_dir=current_dirs["format"],
        )
    first_normal.write_text(original_normal)
    normal_matrix_path.write_text(original_matrix)

    preserved = tmp_path / "preserved"
    preserved.mkdir()
    sentinel = preserved / "sentinel"
    sentinel.write_text("keep")
    with pytest.raises(FileExistsError, match="Refusing to replace"):
        producer.record(
            root=ROOT,
            output_dir=preserved,
            checkout_sha=COMMIT,
            executable_sha256=executable_sha256,
            expected_executable_sha256=executable_sha256,
            current_normal_dir=current_dirs["normal"],
            current_format_dir=current_dirs["format"],
        )
    assert sentinel.read_text() == "keep"

    symlink = tmp_path / "symlink-output"
    symlink.symlink_to(preserved, target_is_directory=True)
    with pytest.raises(ValueError, match="contains a symlink"):
        producer.record(
            root=ROOT,
            output_dir=symlink,
            checkout_sha=COMMIT,
            executable_sha256=executable_sha256,
            expected_executable_sha256=executable_sha256,
            current_normal_dir=current_dirs["normal"],
            current_format_dir=current_dirs["format"],
        )

    tampered_normal = json.loads(original_normal)
    tampered_normal["status"] = "failed"
    first_normal.write_text(json.dumps(tampered_normal))
    with pytest.raises(ValueError, match="semantic receipt digest is invalid"):
        producer.record(
            root=ROOT,
            output_dir=tmp_path / "tampered-receipt",
            checkout_sha=COMMIT,
            executable_sha256=executable_sha256,
            expected_executable_sha256=executable_sha256,
            current_normal_dir=current_dirs["normal"],
            current_format_dir=current_dirs["format"],
        )
    first_normal.write_text(original_normal)

    tampered_matrix = json.loads(normal_matrix_path.read_text())
    tampered_matrix["success_count"] -= 1
    normal_matrix_path.write_text(json.dumps(tampered_matrix))
    with pytest.raises(ValueError, match="semantic matrix digest is invalid"):
        producer.record(
            root=ROOT,
            output_dir=tmp_path / "tampered-matrix",
            checkout_sha=COMMIT,
            executable_sha256=executable_sha256,
            expected_executable_sha256=executable_sha256,
            current_normal_dir=current_dirs["normal"],
            current_format_dir=current_dirs["format"],
        )

    archival = ROOT / "tests/flow_fixtures/manifests/profile_semantics"
    with pytest.raises(ValueError, match="archival, not fresh"):
        producer.record(
            root=ROOT,
            output_dir=tmp_path / "archival-refused",
            checkout_sha=COMMIT,
            executable_sha256=executable_sha256,
            expected_executable_sha256=executable_sha256,
            current_normal_dir=archival,
            current_format_dir=archival,
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
    p0_command = licensed.split("scripts/record_flow_profile_receipts.py", 1)[1].split(
        "scripts/record_flow_profile_semantics.py", 1
    )[0]
    assert "--repeat-final" in p0_command
    assert "--release-scope profiles/flow-release-scope.json" in p0_command
    assert "--current-normal-dir licensed-reports/current-normal" in licensed
    assert "--current-format-dir licensed-reports/current-format" in licensed
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
    assert licensed.count("ida-version: '9.3'") == 2
    assert all(
        f"IDA_IMAGE_{version}_DIGEST" not in licensed for version in ("90", "91", "92")
    )
    assert "--expected-ida-version 9.3" in release
    assert all(
        f"--expected-ida-version 9.{version}" not in release
        for version in ("0", "1", "2")
    )
    assert "continue-on-error" not in release
    assert "secrets: inherit" not in release
    assert "container_registry_token: ${{ secrets.GITHUB_TOKEN }}" in release
    assert (
        "password: ${{ secrets.container_registry_token || secrets.GITHUB_TOKEN }}"
        in licensed
    )
    assert "actions/checkout@v" not in combined
    assert "astral-sh/setup-uv@v" not in combined
    assert "actions/upload-artifact@v" not in combined
    assert "actions/download-artifact@v" not in combined
    assert "ida@${{ matrix.image-digest }}" in licensed
    assert "^sha256:[0-9a-f]{64}$" in licensed


def test_licensed_workflow_is_opt_in_for_normal_pushes():
    licensed = (ROOT / ".github/workflows/idalib-tests.yml").read_text()
    release = (ROOT / ".github/workflows/flow-release.yml").read_text()
    triggers = licensed.partition("\npermissions:")[0]
    assert "\n  push:" not in triggers
    assert "\n  workflow_dispatch:" in triggers
    assert "\n  workflow_call:" in triggers
    assert "uses: ./.github/workflows/idalib-tests.yml" in release
    assert 'test "$LICENSED_RESULT" = success' in release
