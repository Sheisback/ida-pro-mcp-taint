"""Build and verify release artifacts without executing target programs."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
SHA1 = re.compile(r"[0-9a-f]{40}")
BUILD_ID = re.compile(r"flow-build-sha256-v1:[0-9a-f]{64}")
PACKAGE_SCHEMA = "flow-release-package/1"
LICENSED_SCHEMA = "flow-licensed-ci/2"
NORMAL_LICENSED_SCHEMA = "flow-licensed-normal/2"
GUI_SCHEMA = "flow-gui-process/2"
AGGREGATE_SCHEMA = "flow-release-aggregate/1"
SEMANTIC_MATRIX = Path("tests/flow_fixtures/manifests/profile_semantics/matrix.json")
PROFILE_BUILD_MANIFEST = Path("tests/flow_fixtures/manifests/profiles/build.json")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text())
    if type(value) is not dict:
        raise ValueError(f"Expected a JSON object: {path}")
    return value


def write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _load_benchmark_gate():
    path = ROOT / "scripts/run_flow_benchmarks.py"
    spec = importlib.util.spec_from_file_location("flow_release_benchmarks", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load benchmark release validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _commit(value: object) -> str:
    if type(value) is not str or SHA1.fullmatch(value) is None:
        raise ValueError("Expected a full lowercase commit SHA")
    return value


def _build_id(value: object) -> str:
    if type(value) is not str or BUILD_ID.fullmatch(value) is None:
        raise ValueError("Invalid flow build ID")
    return value


def _version_id(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"\d+\.\d+(?:\.\d+)*", value) is not None


def _hex_sha256(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _isolated_build_id(package_root: Path, loader: Path | None = None) -> str:
    if loader is None:
        script = """
import sys
sys.path.insert(0, sys.argv[1])
from ida_pro_mcp.flow_core.build_identity import BUILD_ID
print(BUILD_ID)
"""
        arguments = [str(package_root)]
    else:
        script = """
import ast, hashlib, importlib.util, json, os, sys
path = sys.argv[1]
tree = ast.parse(open(path).read())
node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_prepare_runtime')
__file__ = path
exec(compile(ast.Module(body=[node], type_ignores=[]), path, 'exec'))
_prepare_runtime()
from ida_pro_mcp.flow_core.build_identity import BUILD_ID
print(BUILD_ID)
"""
        arguments = [str(loader)]
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", script, *arguments],
        check=True,
        capture_output=True,
        text=True,
        cwd=package_root,
    )
    return _build_id(result.stdout.strip().splitlines()[-1])


def _wheel_build_id(wheel: Path) -> str:
    with tempfile.TemporaryDirectory(prefix="flow-release-wheel-") as temporary:
        root = Path(temporary)
        with zipfile.ZipFile(wheel) as archive:
            archive.extractall(root)
        return _isolated_build_id(root)


def _gui_build_id() -> str:
    from ida_pro_mcp import installer

    with tempfile.TemporaryDirectory(prefix="flow-release-gui-") as temporary:
        root = Path(temporary)
        original = installer._get_ida_user_dir
        installer._get_ida_user_dir = lambda: str(root)
        try:
            installer.install_ida_plugin(quiet=True)
        finally:
            installer._get_ida_user_dir = original
        return _isolated_build_id(root, root / "plugins/ida_mcp.py")


def _mandatory_normal_rows(matrix: dict[str, object]) -> list[dict[str, object]]:
    from ida_pro_mcp.flow_core.semantic_equivalence import (
        normal_semantic_equivalence_digest,
    )

    rows: list[dict[str, object]] = []
    profiles = matrix.get("profiles")
    if type(profiles) is not list:
        raise ValueError("Semantic matrix rows are missing")
    for item in profiles:
        if type(item) is not dict or item.get("evidence_path") not in {
            "normal",
            "format",
        }:
            continue
        receipt_path = ROOT / str(item.get("receipt_file"))
        receipt = read_json(receipt_path)
        environment = receipt.get("environment")
        if type(environment) is not dict:
            raise ValueError("Normal semantic environment is missing")
        rows.append(
            {
                "profile_id": receipt.get("profile_id"),
                "fixture_sha256": receipt.get("binary_sha256"),
                "abi_id": receipt.get("abi_id"),
                "format_id": environment.get("format_id"),
                "maturity": receipt.get("maturity"),
                "ida_build": environment.get("ida_build"),
                "hexrays_build": environment.get("hexrays_build"),
                "processor": environment.get("processor"),
                "bits": environment.get("bitness"),
                "endian": environment.get("data_endian"),
                "evidence_path": item["evidence_path"],
                "normal_status": "pass"
                if receipt.get("status") == "success"
                else "unknown",
                "semantic_receipt_file": item.get("receipt_file"),
                "semantic_receipt_digest": item.get("receipt_digest"),
                "semantic_equivalence_digest": normal_semantic_equivalence_digest(
                    receipt
                ),
            }
        )
    return rows


def _readiness_contract(
    matrix: dict[str, object], build_manifest: dict[str, object]
) -> dict[str, object]:
    """Derive strict normal requirements and blockers from canonical data.

    Successful normal/format semantic rows are eligible requirements. Fallback
    rows remain required normal identities but are recorded separately as
    unavailable, so the package lane can complete while the strict aggregate
    continues to fail closed with an exact blocker.
    """

    available = _mandatory_normal_rows(matrix)
    build_rows = build_manifest.get("profiles")
    semantic_rows = matrix.get("profiles")
    if type(build_rows) is not list or type(semantic_rows) is not list:
        raise ValueError("Canonical readiness manifests are malformed")
    builds = {row.get("profile_id"): row for row in build_rows if type(row) is dict}
    unavailable: list[dict[str, object]] = []
    for item in semantic_rows:
        if type(item) is not dict or item.get("evidence_path") != "fallback":
            continue
        profile_id = item.get("profile_id")
        build = builds.get(profile_id)
        if type(profile_id) is not str or type(build) is not dict:
            raise ValueError("Fallback readiness row lacks canonical build identity")
        receipt_file = item.get("receipt_file")
        if type(receipt_file) is not str:
            raise ValueError("Fallback readiness row lacks a receipt")
        receipt = read_json(ROOT / receipt_file)
        normal_backend = receipt.get("normal_backend")
        data_endian = build.get("data_endian")
        if (
            receipt.get("profile_id") != profile_id
            or type(normal_backend) is not dict
            or normal_backend.get("probe_status") != "failed"
            or normal_backend.get("support_status") != "unverified"
            or type(data_endian) is not str
        ):
            raise ValueError("Fallback row does not prove normal unavailability")
        unavailable.append(
            {
                "profile_id": profile_id,
                "fixture_sha256": build.get("binary_sha256"),
                "abi_id": build.get("abi_id"),
                "format_id": build.get("format"),
                "maturity": "MMAT_CALLS",
                "processor": build.get("processor"),
                "bits": build.get("bitness"),
                "endian": {"LE": "little", "BE": "big"}.get(data_endian),
                "evidence_path": "fallback",
                "normal_status": "unavailable",
                "blocker": "normal_backend_unavailable",
                "fallback_receipt_file": receipt_file,
                "fallback_receipt_digest": item.get("receipt_digest"),
            }
        )
    profile_ids = tuple(
        row.get("profile_id") for row in build_rows if type(row) is dict
    )
    if len(profile_ids) != len(set(profile_ids)) or not profile_ids:
        raise ValueError("Canonical build profile identities are invalid")
    identities = [
        (row["profile_id"], row["abi_id"], row["format_id"])
        for row in [*available, *unavailable]
    ]
    if len(identities) != len(set(identities)):
        raise ValueError("Canonical readiness row identities are duplicated")
    return {
        "required_profiles": profile_ids,
        "required_row_identities": tuple(identities),
        "mandatory_normal_rows": available,
        "unavailable_normal_rows": unavailable,
    }


def _canonical_readiness_contract() -> dict[str, object]:
    return _readiness_contract(
        read_json(ROOT / SEMANTIC_MATRIX),
        read_json(ROOT / PROFILE_BUILD_MANIFEST),
    )


# Compatibility exports for focused tests and callers. They are derived from
# the canonical manifests at import, not maintained as parallel hardcoded lists.
_CANONICAL_READINESS = _canonical_readiness_contract()
MANDATORY_PROFILES = tuple(
    cast(tuple[str, ...], _CANONICAL_READINESS["required_profiles"])
)
MANDATORY_ROW_IDENTITIES = tuple(
    cast(
        tuple[tuple[object, object, object], ...],
        _CANONICAL_READINESS["required_row_identities"],
    )
)
_CANONICAL_AVAILABLE = cast(
    list[dict[str, object]], _CANONICAL_READINESS["mandatory_normal_rows"]
)
_CANONICAL_UNAVAILABLE = cast(
    list[dict[str, object]], _CANONICAL_READINESS["unavailable_normal_rows"]
)
PROFILE_FACTS = {
    row["profile_id"]: (row["processor"], row["bits"], row["endian"])
    for row in [*_CANONICAL_AVAILABLE, *_CANONICAL_UNAVAILABLE]
}


def package_manifest(dist: Path, checkout_sha: str) -> dict[str, object]:
    checkout_sha = _commit(checkout_sha)
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError("Release gate requires exactly one wheel and one sdist")

    from ida_pro_mcp.flow_core.build_identity import BUILD_ID as SOURCE_BUILD_ID
    from ida_pro_mcp.flow_core.profile_semantic_receipts import (
        validate_complete_matrix_receipt,
    )

    matrix_path = ROOT / SEMANTIC_MATRIX
    matrix = read_json(matrix_path)
    build_manifest = read_json(ROOT / PROFILE_BUILD_MANIFEST)
    validate_complete_matrix_receipt(matrix)
    readiness = _readiness_contract(matrix, build_manifest)
    required_row_identities = cast(
        tuple[tuple[object, object, object], ...],
        readiness["required_row_identities"],
    )
    source_id = _build_id(SOURCE_BUILD_ID)
    wheel_id = _wheel_build_id(wheels[0])
    gui_id = _gui_build_id()
    if len({source_id, wheel_id, gui_id}) != 1:
        raise ValueError("Source, wheel, and GUI bootstrap build IDs differ")
    return {
        "schema_version": PACKAGE_SCHEMA,
        "checkout_sha": checkout_sha,
        "build_ids": {
            "source": source_id,
            "wheel": wheel_id,
            "gui_bootstrap": gui_id,
        },
        "artifacts": {path.name: sha256(path) for path in (wheels[0], sdists[0])},
        "support_matrix": {
            "sha256": sha256(matrix_path),
            "profile_count": matrix["profile_count"],
            "semantic_row_count": matrix["semantic_row_count"],
            "normal_success_count": matrix["normal_success_count"],
            "format_success_count": matrix["format_success_count"],
            "rv32_fallback_count": matrix["rv32_fallback_count"],
            "required_row_count": len(required_row_identities),
            "mandatory_normal_rows": readiness["mandatory_normal_rows"],
            "unavailable_normal_rows": readiness["unavailable_normal_rows"],
            "fallback_promotes_readiness": False,
        },
        "target_executed": False,
        "gui_process_e2e": False,
    }


def _validate_package(value: dict[str, object], checkout_sha: str) -> str:
    if value.get("schema_version") != PACKAGE_SCHEMA:
        raise ValueError("Invalid package manifest schema")
    if _commit(value.get("checkout_sha")) != checkout_sha:
        raise ValueError("Package manifest commit mismatch")
    if value.get("target_executed") is not False:
        raise ValueError("Package manifest must preserve no-target-execution")
    if value.get("gui_process_e2e") is not False:
        raise ValueError("Package manifest overclaims GUI-process evidence")
    artifacts = value.get("artifacts")
    if type(artifacts) is not dict or len(artifacts) != 2:
        raise ValueError("Package artifact manifest is incomplete")
    for name, digest in artifacts.items():
        if (
            type(name) is not str
            or Path(name).name != name
            or type(digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise ValueError("Package artifact manifest is invalid")
    build_ids = value.get("build_ids")
    if type(build_ids) is not dict:
        raise ValueError("Package manifest build IDs are missing")
    ids = {
        _build_id(build_ids.get(name)) for name in ("source", "wheel", "gui_bootstrap")
    }
    if len(ids) != 1:
        raise ValueError("Package build IDs differ")
    matrix = value.get("support_matrix")
    if type(matrix) is not dict:
        raise ValueError("Package support matrix is incomplete")
    if matrix.get("fallback_promotes_readiness") is not False:
        raise ValueError("Package support matrix promotes fallback evidence")
    rows = matrix.get("mandatory_normal_rows")
    unavailable = matrix.get("unavailable_normal_rows")
    if type(rows) is not list or type(unavailable) is not list:
        raise ValueError("Package support matrix readiness rows are missing")
    for row in rows:
        if type(row) is not dict or set(row) != {
            "profile_id",
            "fixture_sha256",
            "abi_id",
            "format_id",
            "maturity",
            "ida_build",
            "hexrays_build",
            "processor",
            "bits",
            "endian",
            "evidence_path",
            "normal_status",
            "semantic_receipt_file",
            "semantic_receipt_digest",
            "semantic_equivalence_digest",
        }:
            raise ValueError("Package support matrix row is malformed")
        profile_id = row.get("profile_id")
        if type(profile_id) is not str:
            raise ValueError("Package support matrix profile is malformed")
        if (
            row.get("evidence_path") not in {"normal", "format"}
            or row.get("normal_status") != "pass"
            or row.get("maturity") != "MMAT_CALLS"
            or row.get("format_id") not in {"FMT-ELF", "FMT-PE", "FMT-MACHO", "FMT-RAW"}
            or type(row.get("abi_id")) is not str
            or not row["abi_id"]
            or not _version_id(row.get("ida_build"))
            or not _version_id(row.get("hexrays_build"))
            or type(row.get("processor")) is not str
            or not row["processor"]
            or type(row.get("bits")) is not int
            or row["bits"] not in {16, 32, 64}
            or row.get("endian") not in {"little", "big"}
            or type(row.get("fixture_sha256")) is not str
            or re.fullmatch(r"[0-9a-f]{64}", row["fixture_sha256"]) is None
            or type(row.get("semantic_receipt_file")) is not str
            or not row["semantic_receipt_file"]
            or type(row.get("semantic_receipt_digest")) is not str
            or re.fullmatch(r"sha256-v1:[0-9a-f]{64}", row["semantic_receipt_digest"])
            is None
            or type(row.get("semantic_equivalence_digest")) is not str
            or re.fullmatch(
                r"sha256-v1:[0-9a-f]{64}", row["semantic_equivalence_digest"]
            )
            is None
        ):
            raise ValueError("Package support matrix row is not a passing normal row")
    for row in unavailable:
        if type(row) is not dict or set(row) != {
            "profile_id",
            "fixture_sha256",
            "abi_id",
            "format_id",
            "maturity",
            "processor",
            "bits",
            "endian",
            "evidence_path",
            "normal_status",
            "blocker",
            "fallback_receipt_file",
            "fallback_receipt_digest",
        }:
            raise ValueError("Package unavailable normal row is malformed")
        if (
            type(row.get("profile_id")) is not str
            or not row["profile_id"]
            or type(row.get("abi_id")) is not str
            or not row["abi_id"]
            or row.get("format_id") not in {"FMT-ELF", "FMT-PE", "FMT-MACHO", "FMT-RAW"}
            or row.get("maturity") != "MMAT_CALLS"
            or type(row.get("processor")) is not str
            or not row["processor"]
            or type(row.get("bits")) is not int
            or row["bits"] not in {16, 32, 64}
            or row.get("endian") not in {"little", "big"}
            or row.get("evidence_path") != "fallback"
            or row.get("normal_status") != "unavailable"
            or row.get("blocker") != "normal_backend_unavailable"
            or not _hex_sha256(row.get("fixture_sha256"))
            or type(row.get("fallback_receipt_file")) is not str
            or not row["fallback_receipt_file"]
            or type(row.get("fallback_receipt_digest")) is not str
            or re.fullmatch(r"sha256-v1:[0-9a-f]{64}", row["fallback_receipt_digest"])
            is None
        ):
            raise ValueError("Package unavailable normal row is invalid")
    all_rows = [*rows, *unavailable]
    identities = [
        (row["profile_id"], row["abi_id"], row["format_id"]) for row in all_rows
    ]
    profiles = {row["profile_id"] for row in all_rows}
    facts: dict[object, tuple[object, object, object]] = {}
    facts_match = True
    for row in all_rows:
        identity = (row["processor"], row["bits"], row["endian"])
        previous = facts.setdefault(row["profile_id"], identity)
        facts_match = facts_match and previous == identity
    counts = {
        "profile_count": len(profiles),
        "semantic_row_count": len(all_rows),
        "normal_success_count": sum(row["evidence_path"] == "normal" for row in rows),
        "format_success_count": sum(row["evidence_path"] == "format" for row in rows),
        "rv32_fallback_count": len(unavailable),
        "required_row_count": len(all_rows),
    }
    canonical_matrix_sha256 = sha256(ROOT / SEMANTIC_MATRIX)
    if (
        matrix.get("sha256") != canonical_matrix_sha256
        or rows != _CANONICAL_AVAILABLE
        or unavailable != _CANONICAL_UNAVAILABLE
    ):
        raise ValueError(
            "Package support matrix diverges from canonical readiness evidence"
        )
    if (
        any(matrix.get(name) != count for name, count in counts.items())
        or len(identities) != len(set(identities))
        or set(identities) != set(MANDATORY_ROW_IDENTITIES)
        or profiles != set(MANDATORY_PROFILES)
        or any(
            facts.get(profile_id) != PROFILE_FACTS[profile_id]
            for profile_id in MANDATORY_PROFILES
        )
        or not facts_match
    ):
        raise ValueError(
            "Package support matrix lacks every mandatory normal row; "
            "mandatory row coverage is incomplete"
        )
    return ids.pop()


def validate_artifact_files(value: dict[str, object], directory: Path) -> None:
    artifacts = value["artifacts"]
    if type(artifacts) is not dict:
        raise ValueError("Package artifact manifest is missing")
    for name, expected in artifacts.items():
        if type(name) is not str or type(expected) is not str:
            raise ValueError("Package artifact manifest is invalid")
        path = directory / name
        if not path.is_file() or sha256(path) != expected:
            raise ValueError(f"Release artifact digest mismatch: {name}")


def _minor_version(value: object) -> str:
    if not _version_id(value):
        raise ValueError("Licensed receipt IDA version is invalid")
    assert isinstance(value, str)
    return ".".join(value.split(".")[:2])


def _validate_normal_receipt(
    receipt: dict[str, object],
    expected: dict[str, object],
    *,
    checkout_sha: str,
    build_id: str,
    path: Path,
    expected_executable_sha256: str | None = None,
) -> str:
    from ida_pro_mcp.flow_core.serialization import digest

    required = {
        "schema_version",
        "checkout_sha",
        "fixture",
        "fixture_sha256",
        "ida_input_sha256",
        "profile_id",
        "abi_id",
        "format_id",
        "maturity",
        "normal_status",
        "ida_build",
        "ida_executable_sha256",
        "hexrays_build",
        "flow_build_id",
        "capabilities",
        "capabilities_digest",
        "environment",
        "supported_profiles",
        "input_preserved",
        "target_executed",
        "debugger_attached",
        "semantic_receipt_file",
        "semantic_receipt_digest",
        "semantic_equivalence_digest",
        "extraction_digest",
        "public_profile_digest",
        "current_run",
    }
    if (
        set(receipt) != required
        or receipt.get("schema_version") != NORMAL_LICENSED_SCHEMA
    ):
        raise ValueError(f"Invalid licensed normal receipt schema: {path}")
    if _commit(receipt.get("checkout_sha")) != checkout_sha:
        raise ValueError(f"Licensed receipt commit mismatch: {path}")
    if _build_id(receipt.get("flow_build_id")) != build_id:
        raise ValueError(f"Licensed receipt build ID mismatch: {path}")
    if (
        receipt.get("target_executed") is not False
        or receipt.get("debugger_attached") is not False
        or receipt.get("input_preserved") is not True
    ):
        raise ValueError(f"Licensed receipt violated static-only safety: {path}")
    expected_fields = {
        "profile_id": expected["profile_id"],
        "fixture_sha256": expected["fixture_sha256"],
        "abi_id": expected["abi_id"],
        "format_id": expected["format_id"],
        "maturity": expected["maturity"],
        "ida_build": expected["ida_build"],
        "hexrays_build": expected["hexrays_build"],
        "normal_status": "pass",
        "semantic_receipt_file": expected["semantic_receipt_file"],
        "semantic_receipt_digest": expected["semantic_receipt_digest"],
        "semantic_equivalence_digest": expected["semantic_equivalence_digest"],
    }
    if any(receipt.get(field) != value for field, value in expected_fields.items()):
        raise ValueError(f"Licensed mandatory normal row mismatch: {path}")
    if receipt.get("ida_input_sha256") != receipt.get("fixture_sha256"):
        raise ValueError(f"Licensed IDA input digest mismatch: {path}")
    if (
        not _hex_sha256(receipt.get("ida_executable_sha256"))
        or expected_executable_sha256 is not None
        and receipt.get("ida_executable_sha256") != expected_executable_sha256
    ):
        raise ValueError(f"Licensed IDA executable digest mismatch: {path}")
    current_run = receipt.get("current_run")
    extraction_digest = receipt.get("extraction_digest")
    public_profile_digest = receipt.get("public_profile_digest")
    if (
        type(current_run) is not dict
        or set(current_run)
        != {
            "kind",
            "matrix_receipt_digest",
            "semantic_receipt_digest",
            "semantic_equivalence_digest",
            "process_receipt_digests",
            "build_evidence_digest",
            "implementation",
        }
        or current_run.get("kind") != "current_checkout_actual_ida"
        or not isinstance(current_run.get("matrix_receipt_digest"), str)
        or re.fullmatch(r"sha256-v1:[0-9a-f]{64}", current_run["matrix_receipt_digest"])
        is None
        or type(current_run.get("semantic_receipt_digest")) is not str
        or re.fullmatch(
            r"sha256-v1:[0-9a-f]{64}", current_run["semantic_receipt_digest"]
        )
        is None
        or current_run.get("semantic_equivalence_digest")
        != receipt.get("semantic_equivalence_digest")
        or type(current_run.get("process_receipt_digests")) is not list
        or len(current_run["process_receipt_digests"]) != 2
        or any(
            type(item) is not str
            or re.fullmatch(r"sha256-v1:[0-9a-f]{64}", item) is None
            for item in current_run["process_receipt_digests"]
        )
        or len(set(current_run["process_receipt_digests"])) != 1
        or type(current_run.get("build_evidence_digest")) is not str
        or re.fullmatch(r"sha256-v1:[0-9a-f]{64}", current_run["build_evidence_digest"])
        is None
        or type(current_run.get("implementation")) is not dict
        or not current_run["implementation"]
        or type(extraction_digest) is not str
        or re.fullmatch(r"sha256-v1:[0-9a-f]{64}", extraction_digest) is None
        or type(public_profile_digest) is not str
        or re.fullmatch(r"sha256-v1:[0-9a-f]{64}", public_profile_digest) is None
    ):
        raise ValueError(f"Licensed receipt lacks current-run extraction proof: {path}")
    for relative, expected_digest in current_run["implementation"].items():
        if (
            type(relative) is not str
            or type(expected_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
        ):
            raise ValueError(f"Licensed implementation identity is invalid: {path}")
        implementation_path = (ROOT / relative).resolve()
        try:
            implementation_path.relative_to(ROOT)
        except ValueError as exc:
            raise ValueError(
                f"Licensed implementation identity escapes checkout: {path}"
            ) from exc
        if (
            not implementation_path.is_file()
            or sha256(implementation_path) != expected_digest
        ):
            raise ValueError(f"Licensed implementation identity is stale: {path}")
    supported = receipt.get("supported_profiles")
    if supported != [expected["profile_id"]]:
        raise ValueError(f"Licensed supported profiles are empty or inexact: {path}")
    capabilities = receipt.get("capabilities")
    if type(capabilities) is not dict or receipt.get("capabilities_digest") != digest(
        capabilities
    ):
        raise ValueError(f"Licensed capability body digest mismatch: {path}")
    if (
        capabilities.get("schema_version") != "flow-capabilities/1"
        or capabilities.get("build_id") != build_id
        or capabilities.get("supported_profiles") != supported
        or capabilities.get("environment") != receipt.get("environment")
    ):
        raise ValueError(f"Licensed capability body is unbound: {path}")
    environment = receipt.get("environment")
    if type(environment) is not dict:
        raise ValueError(f"Licensed receipt environment is missing: {path}")
    hexrays = environment.get("hexrays_initialization")
    if (
        environment.get("ida_version") != receipt.get("ida_build")
        or environment.get("hexrays_version") != receipt.get("hexrays_build")
        or not _version_id(receipt.get("hexrays_build"))
        or type(hexrays) is not dict
        or hexrays.get("status") != "available"
    ):
        raise ValueError(f"Licensed exact IDA/Hex-Rays binding failed: {path}")
    if (
        type(environment.get("processor")) is not str
        or environment["processor"] != expected["processor"]
        or type(environment.get("bits")) is not int
        or environment["bits"] != expected["bits"]
        or environment.get("endian") != expected["endian"]
    ):
        raise ValueError(f"Licensed profile observation is invalid: {path}")
    return _minor_version(receipt.get("ida_build"))


def _validate_compatibility_receipt(
    receipt: dict[str, object],
    *,
    checkout_sha: str,
    build_id: str,
    path: Path,
) -> str:
    """Validate fresh build/runtime compatibility without promoting a profile row."""

    from ida_pro_mcp.flow_core.serialization import digest

    required = {
        "schema_version",
        "checkout_sha",
        "fixture",
        "fixture_sha256",
        "ida_input_sha256",
        "profile_id",
        "abi_id",
        "format_id",
        "maturity",
        "normal_status",
        "ida_build",
        "ida_executable_sha256",
        "hexrays_build",
        "flow_build_id",
        "capabilities",
        "capabilities_digest",
        "environment",
        "supported_profiles",
        "input_preserved",
        "target_executed",
        "debugger_attached",
    }
    if set(receipt) != required or receipt.get("schema_version") != LICENSED_SCHEMA:
        raise ValueError(f"Invalid licensed compatibility receipt schema: {path}")
    if _commit(receipt.get("checkout_sha")) != checkout_sha:
        raise ValueError(f"Licensed compatibility receipt commit mismatch: {path}")
    if _build_id(receipt.get("flow_build_id")) != build_id:
        raise ValueError(f"Licensed compatibility receipt build ID mismatch: {path}")
    if (
        receipt.get("normal_status") != "unknown"
        or receipt.get("target_executed") is not False
        or receipt.get("debugger_attached") is not False
        or receipt.get("input_preserved") is not True
        or receipt.get("ida_input_sha256") != receipt.get("fixture_sha256")
        or not _hex_sha256(receipt.get("fixture_sha256"))
        or not _hex_sha256(receipt.get("ida_executable_sha256"))
    ):
        raise ValueError(f"Licensed compatibility receipt is unsafe: {path}")
    capabilities = receipt.get("capabilities")
    supported = receipt.get("supported_profiles")
    environment = receipt.get("environment")
    if (
        type(capabilities) is not dict
        or receipt.get("capabilities_digest") != digest(capabilities)
        or capabilities.get("schema_version") != "flow-capabilities/1"
        or capabilities.get("build_id") != build_id
        or capabilities.get("supported_profiles") != supported
        or capabilities.get("environment") != environment
        or type(supported) is not list
        or type(environment) is not dict
    ):
        raise ValueError(f"Licensed compatibility capability body is unbound: {path}")
    hexrays = environment.get("hexrays_initialization")
    if (
        environment.get("ida_version") != receipt.get("ida_build")
        or environment.get("hexrays_version") != receipt.get("hexrays_build")
        or not _version_id(receipt.get("hexrays_build"))
        or type(hexrays) is not dict
        or hexrays.get("status") != "available"
    ):
        raise ValueError(f"Licensed compatibility runtime binding failed: {path}")
    return _minor_version(receipt.get("ida_build"))


def _validate_gui_receipt(
    receipt: dict[str, object] | None,
    *,
    checkout_sha: str,
    build_id: str,
    expected_executable_sha256: str | None = None,
) -> None:
    from ida_pro_mcp.flow_core.serialization import digest

    if receipt is None:
        raise ValueError("Disposable GUI-process evidence is missing")
    required = {
        "schema_version",
        "checkout_sha",
        "flow_build_id",
        "ida_build",
        "hexrays_build",
        "ida_executable_sha256",
        "module_origin",
        "loader_sha256",
        "bundle_manifest_sha256",
        "capabilities",
        "capabilities_digest",
        "process_kind",
        "disposable_user_dir",
        "eula_accepted_during_probe",
        "target_executed",
        "input_preserved",
    }
    capabilities = receipt.get("capabilities")
    if (
        set(receipt) != required
        or receipt.get("schema_version") != GUI_SCHEMA
        or receipt.get("checkout_sha") != checkout_sha
        or receipt.get("flow_build_id") != build_id
        or receipt.get("process_kind") != "ida-gui"
        or receipt.get("disposable_user_dir") is not True
        or receipt.get("eula_accepted_during_probe") is not False
        or receipt.get("target_executed") is not False
        or receipt.get("input_preserved") is not True
        or not _version_id(receipt.get("ida_build"))
        or not _version_id(receipt.get("hexrays_build"))
        or not _hex_sha256(receipt.get("ida_executable_sha256"))
        or not _hex_sha256(receipt.get("loader_sha256"))
        or not _hex_sha256(receipt.get("bundle_manifest_sha256"))
        or (
            expected_executable_sha256 is not None
            and receipt.get("ida_executable_sha256") != expected_executable_sha256
        )
        or type(capabilities) is not dict
        or receipt.get("capabilities_digest") != digest(capabilities)
        or capabilities.get("build_id") != build_id
    ):
        raise ValueError("Disposable GUI-process evidence is invalid or stale")
    module_origin = receipt.get("module_origin")
    normalized_origin = (
        module_origin.replace("\\", "/") if type(module_origin) is str else ""
    )
    if (
        "/idausr/plugins/_ida_pro_mcp_runtime/" not in normalized_origin
        or not normalized_origin.endswith("/ida_mcp/api_flow.py")
    ):
        raise ValueError("Disposable GUI-process module origin is not installed")
    environment = capabilities.get("environment")
    if (
        type(environment) is not dict
        or capabilities.get("schema_version") != "flow-capabilities/1"
        or type(capabilities.get("supported_profiles")) is not list
        or environment.get("ida_version") != receipt.get("ida_build")
        or environment.get("hexrays_version") != receipt.get("hexrays_build")
    ):
        raise ValueError("Disposable GUI-process build identity mismatch")


def aggregate_manifest(
    package: dict[str, object],
    normal_receipts: list[tuple[Path, dict[str, object]]],
    expected_versions: set[str],
    checkout_sha: str,
    *,
    compatibility_receipts: list[tuple[Path, dict[str, object]]] | None = None,
    gui_receipt: dict[str, object] | None = None,
    benchmark_report: dict[str, object] | None = None,
    benchmark_limits: dict[str, object] | None = None,
    benchmark_limits_path: Path | None = None,
    expected_ida_executable_sha256: str | None = None,
    expected_gui_executable_sha256: str | None = None,
) -> dict[str, object]:
    checkout_sha = _commit(checkout_sha)
    build_id = _validate_package(package, checkout_sha)
    matrix = package["support_matrix"]
    if (
        type(matrix) is not dict
        or type(matrix.get("unavailable_normal_rows")) is not list
    ):
        raise ValueError("Package mandatory rows are missing")
    unavailable_rows = matrix["unavailable_normal_rows"]
    if unavailable_rows:
        blockers = ", ".join(
            str(row.get("profile_id")) for row in unavailable_rows if type(row) is dict
        )
        raise ValueError("Mandatory normal rows unavailable: " + blockers)
    if not normal_receipts:
        raise ValueError("No current mandatory normal receipts were supplied")
    if not compatibility_receipts:
        raise ValueError("No licensed version-compatibility receipts were supplied")
    if not _hex_sha256(expected_gui_executable_sha256):
        raise ValueError("Reviewed GUI executable digest is missing")
    _validate_gui_receipt(
        gui_receipt,
        checkout_sha=checkout_sha,
        build_id=build_id,
        expected_executable_sha256=expected_gui_executable_sha256,
    )
    if (
        benchmark_report is None
        or benchmark_limits is None
        or benchmark_limits_path is None
        or expected_ida_executable_sha256 is None
    ):
        raise ValueError("Fresh B01-B03 benchmark evidence is missing")
    run_flow_benchmarks = _load_benchmark_gate()
    run_flow_benchmarks.validate_limits(benchmark_limits)
    run_flow_benchmarks.validate_release_report(
        benchmark_report,
        benchmark_limits,
        expected_commit=checkout_sha,
        expected_build_id=build_id,
        expected_limits_digest="sha256-v1:" + sha256(benchmark_limits_path),
        expected_ida_executable_sha256=expected_ida_executable_sha256,
    )
    observed_versions: set[str] = set()
    compatibility_hashes: dict[str, str] = {}
    for path, receipt in compatibility_receipts:
        observed_versions.add(
            _validate_compatibility_receipt(
                receipt,
                checkout_sha=checkout_sha,
                build_id=build_id,
                path=path,
            )
        )
        compatibility_hashes[path.name] = sha256(path)
    if observed_versions != expected_versions:
        raise ValueError("Licensed IDA version coverage is incomplete")

    normal_hashes: dict[str, str] = {}
    if (
        type(matrix) is not dict
        or type(matrix.get("mandatory_normal_rows")) is not list
        or type(matrix.get("unavailable_normal_rows")) is not list
    ):
        raise ValueError("Package mandatory rows are missing")
    expected_rows = {
        (row["profile_id"], row["abi_id"], row["format_id"]): row
        for row in matrix["mandatory_normal_rows"]
        if type(row) is dict
    }
    covered_rows: set[tuple[object, object, object]] = set()
    for path, receipt in normal_receipts:
        identity = (
            receipt.get("profile_id"),
            receipt.get("abi_id"),
            receipt.get("format_id"),
        )
        expected = expected_rows.get(identity)
        if expected is None:
            raise ValueError(f"Licensed receipt is not a mandatory normal row: {path}")
        _validate_normal_receipt(
            receipt,
            expected,
            checkout_sha=checkout_sha,
            build_id=build_id,
            path=path,
            expected_executable_sha256=expected_ida_executable_sha256,
        )
        covered_rows.add(identity)
        normal_hashes[path.name] = sha256(path)
    if covered_rows != set(expected_rows):
        raise ValueError("Licensed mandatory normal row coverage is incomplete")
    return {
        "schema_version": AGGREGATE_SCHEMA,
        "checkout_sha": checkout_sha,
        "build_id": build_id,
        "licensed_ida_versions": sorted(observed_versions),
        "licensed_compatibility_receipt_sha256": dict(
            sorted(compatibility_hashes.items())
        ),
        "licensed_normal_receipt_sha256": dict(sorted(normal_hashes.items())),
        "package_artifacts": package["artifacts"],
        "support_matrix": package["support_matrix"],
        "target_executed": False,
        "benchmark_limits_sha256": benchmark_report["limits_sha256"],
        "gui_process_e2e": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    package = commands.add_parser("package")
    package.add_argument("--dist", type=Path, required=True)
    package.add_argument("--checkout-sha", required=True)
    package.add_argument("--output", type=Path, required=True)
    aggregate = commands.add_parser("aggregate")
    aggregate.add_argument("--package-manifest", type=Path, required=True)
    aggregate.add_argument("--licensed-dir", type=Path, required=True)
    aggregate.add_argument("--normal-dir", type=Path, required=True)
    aggregate.add_argument("--checkout-sha", required=True)
    aggregate.add_argument("--expected-ida-version", action="append", required=True)
    aggregate.add_argument("--gui-receipt", type=Path, required=True)
    aggregate.add_argument("--benchmark-report", type=Path, required=True)
    aggregate.add_argument("--benchmark-limits", type=Path, required=True)
    aggregate.add_argument("--expected-ida-executable-sha256", required=True)
    aggregate.add_argument("--expected-gui-executable-sha256", required=True)
    aggregate.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.command == "package":
        result = package_manifest(arguments.dist.resolve(), arguments.checkout_sha)
    else:
        package_path = arguments.package_manifest.resolve()
        package_value = read_json(package_path)
        validate_artifact_files(package_value, package_path.parent)
        compatibility_paths = sorted(
            arguments.licensed_dir.resolve().glob("licensed-*.json")
        )
        normal_paths = sorted(arguments.normal_dir.resolve().glob("normal-*.json"))
        gui_path = arguments.gui_receipt.resolve()
        result = aggregate_manifest(
            package_value,
            [(path, read_json(path)) for path in normal_paths],
            set(arguments.expected_ida_version),
            arguments.checkout_sha,
            compatibility_receipts=[
                (path, read_json(path)) for path in compatibility_paths
            ],
            gui_receipt=read_json(gui_path) if gui_path.is_file() else None,
            benchmark_report=read_json(arguments.benchmark_report.resolve()),
            benchmark_limits=read_json(arguments.benchmark_limits.resolve()),
            benchmark_limits_path=arguments.benchmark_limits.resolve(),
            expected_ida_executable_sha256=arguments.expected_ida_executable_sha256,
            expected_gui_executable_sha256=arguments.expected_gui_executable_sha256,
        )
    write_json(arguments.output.resolve(), result)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
