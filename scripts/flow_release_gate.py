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

ROOT = Path(__file__).resolve().parents[1]
SHA1 = re.compile(r"[0-9a-f]{40}")
BUILD_ID = re.compile(r"flow-build-sha256-v1:[0-9a-f]{64}")
PACKAGE_SCHEMA = "flow-release-package/1"
LICENSED_SCHEMA = "flow-licensed-ci/2"
NORMAL_LICENSED_SCHEMA = "flow-licensed-normal/1"
GUI_SCHEMA = "flow-gui-process/1"
AGGREGATE_SCHEMA = "flow-release-aggregate/1"
MANDATORY_PROFILES = (
    "X86-LE",
    "X64-LE",
    "ARM32-LE",
    "ARM32-BE",
    "THUMB-LE",
    "THUMB-BE",
    "A64-LE",
    "MIPS32-LE",
    "MIPS32-BE",
    "MIPS64-LE",
    "MIPS64-BE",
    "PPC32-LE",
    "PPC32-BE",
    "PPC64-LE",
    "PPC64-BE",
    "RV32-LE",
    "RV64-LE",
)
MANDATORY_ROW_IDENTITIES = (
    ("X86-LE", "sysv-i386", "FMT-ELF"),
    ("X64-LE", "sysv-amd64", "FMT-ELF"),
    ("ARM32-LE", "aapcs32", "FMT-ELF"),
    ("ARM32-BE", "aapcs32", "FMT-ELF"),
    ("THUMB-LE", "aapcs32", "FMT-ELF"),
    ("THUMB-BE", "aapcs32", "FMT-ELF"),
    ("A64-LE", "aapcs64", "FMT-ELF"),
    ("MIPS32-LE", "mips-o32", "FMT-ELF"),
    ("MIPS32-BE", "mips-o32", "FMT-ELF"),
    ("MIPS64-LE", "mips-n64", "FMT-ELF"),
    ("MIPS64-BE", "mips-n64", "FMT-ELF"),
    ("PPC32-LE", "sysv-ppc32", "FMT-ELF"),
    ("PPC32-BE", "sysv-ppc32", "FMT-ELF"),
    ("PPC64-LE", "elfv2-ppc64", "FMT-ELF"),
    ("PPC64-BE", "elfv2-ppc64", "FMT-ELF"),
    ("RV32-LE", "riscv-ilp32", "FMT-ELF"),
    ("RV64-LE", "riscv-lp64", "FMT-ELF"),
    ("X64-LE", "windows-x64", "FMT-PE"),
    ("ARM32-LE", "aapcs32", "FMT-RAW"),
    ("X64-LE", "darwin-x86_64-sysv-derived", "FMT-MACHO"),
    ("A64-LE", "darwin-aarch64", "FMT-MACHO"),
)
PROFILE_FACTS = {
    "X86-LE": ("metapc", 32, "little"),
    "X64-LE": ("metapc", 64, "little"),
    "ARM32-LE": ("ARM", 32, "little"),
    "ARM32-BE": ("ARMB", 32, "big"),
    "THUMB-LE": ("ARM", 32, "little"),
    "THUMB-BE": ("ARMB", 32, "big"),
    "A64-LE": ("ARM", 64, "little"),
    "MIPS32-LE": ("mipsl", 32, "little"),
    "MIPS32-BE": ("mipsb", 32, "big"),
    "MIPS64-LE": ("mipsl", 64, "little"),
    "MIPS64-BE": ("mipsb", 64, "big"),
    "PPC32-LE": ("PPCL", 32, "little"),
    "PPC32-BE": ("PPC", 32, "big"),
    "PPC64-LE": ("PPCL", 64, "little"),
    "PPC64-BE": ("PPC", 64, "big"),
    "RV32-LE": ("riscv", 32, "little"),
    "RV64-LE": ("riscv", 64, "little"),
}


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
        invocations = receipt.get("invocations")
        executable_hashes = (
            {
                invocation.get("ida_executable_sha256")
                for invocation in invocations
                if type(invocation) is dict
            }
            if type(invocations) is list
            else set()
        )
        if len(executable_hashes) != 1:
            raise ValueError("Normal semantic IDA executable identity is missing")
        rows.append(
            {
                "profile_id": receipt.get("profile_id"),
                "fixture_sha256": receipt.get("binary_sha256"),
                "abi_id": receipt.get("abi_id"),
                "format_id": environment.get("format_id"),
                "maturity": receipt.get("maturity"),
                "ida_build": environment.get("ida_build"),
                "hexrays_build": environment.get("hexrays_build"),
                "ida_executable_sha256": executable_hashes.pop(),
                "processor": environment.get("processor"),
                "bits": environment.get("bitness"),
                "endian": environment.get("data_endian"),
                "evidence_path": item["evidence_path"],
                "normal_status": "pass"
                if receipt.get("status") == "success"
                else "unknown",
                "semantic_receipt_file": item.get("receipt_file"),
                "semantic_receipt_digest": item.get("receipt_digest"),
            }
        )
    return rows


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

    matrix_path = ROOT / "tests/flow_fixtures/manifests/profile_semantics/matrix.json"
    matrix = read_json(matrix_path)
    validate_complete_matrix_receipt(matrix)
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
            "mandatory_normal_rows": _mandatory_normal_rows(matrix),
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
    if (
        type(matrix) is not dict
        or matrix.get("profile_count") != len(MANDATORY_PROFILES)
        or matrix.get("semantic_row_count") != 21
        or matrix.get("normal_success_count") != len(MANDATORY_PROFILES)
        or matrix.get("format_success_count") != 4
    ):
        raise ValueError("Package support matrix is incomplete")
    if matrix.get("fallback_promotes_readiness") is not False:
        raise ValueError("Package support matrix promotes fallback evidence")
    rows = matrix.get("mandatory_normal_rows")
    if type(rows) is not list or len(rows) != 21:
        raise ValueError("Package support matrix lacks every mandatory normal row")
    for row in rows:
        if type(row) is not dict or set(row) != {
            "profile_id",
            "fixture_sha256",
            "abi_id",
            "format_id",
            "maturity",
            "ida_build",
            "hexrays_build",
            "ida_executable_sha256",
            "processor",
            "bits",
            "endian",
            "evidence_path",
            "normal_status",
            "semantic_receipt_file",
            "semantic_receipt_digest",
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
            or type(row.get("ida_executable_sha256")) is not str
            or re.fullmatch(r"[0-9a-f]{64}", row["ida_executable_sha256"]) is None
            or type(row.get("fixture_sha256")) is not str
            or re.fullmatch(r"[0-9a-f]{64}", row["fixture_sha256"]) is None
            or type(row.get("semantic_receipt_file")) is not str
            or not row["semantic_receipt_file"]
            or type(row.get("semantic_receipt_digest")) is not str
            or re.fullmatch(r"sha256-v1:[0-9a-f]{64}", row["semantic_receipt_digest"])
            is None
        ):
            raise ValueError("Package support matrix row is not a passing normal row")
    normal_profiles = tuple(
        row["profile_id"] for row in rows if row["evidence_path"] == "normal"
    )
    identities = {(row["profile_id"], row["abi_id"], row["format_id"]) for row in rows}
    facts_match = all(
        (row["processor"], row["bits"], row["endian"])
        == PROFILE_FACTS.get(row["profile_id"])
        for row in rows
    )
    if (
        normal_profiles != MANDATORY_PROFILES
        or identities != set(MANDATORY_ROW_IDENTITIES)
        or not facts_match
        or sum(row["evidence_path"] == "format" for row in rows) != 4
    ):
        raise ValueError("Package support matrix mandatory row coverage is incomplete")
    if (
        not isinstance(matrix.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", matrix["sha256"]) is None
    ):
        raise ValueError("Package support matrix digest is invalid")
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
        "ida_executable_sha256": expected["ida_executable_sha256"],
        "normal_status": "pass",
        "semantic_receipt_file": expected["semantic_receipt_file"],
        "semantic_receipt_digest": expected["semantic_receipt_digest"],
    }
    if any(receipt.get(field) != value for field, value in expected_fields.items()):
        raise ValueError(f"Licensed mandatory normal row mismatch: {path}")
    if receipt.get("ida_input_sha256") != receipt.get("fixture_sha256"):
        raise ValueError(f"Licensed IDA input digest mismatch: {path}")
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
        or (
            expected_executable_sha256 is not None
            and receipt.get("ida_executable_sha256") != expected_executable_sha256
        )
        or type(capabilities) is not dict
        or receipt.get("capabilities_digest") != digest(capabilities)
        or capabilities.get("build_id") != build_id
    ):
        raise ValueError("Disposable GUI-process evidence is invalid or stale")
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
    matrix = package["support_matrix"]
    if (
        type(matrix) is not dict
        or type(matrix.get("mandatory_normal_rows")) is not list
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
