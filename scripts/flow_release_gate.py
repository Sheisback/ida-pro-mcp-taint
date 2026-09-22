"""Build and verify release artifacts without executing target programs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SHA1 = re.compile(r"[0-9a-f]{40}")
BUILD_ID = re.compile(r"flow-build-sha256-v1:[0-9a-f]{64}")
PACKAGE_SCHEMA = "flow-release-package/1"
LICENSED_SCHEMA = "flow-licensed-ci/1"
AGGREGATE_SCHEMA = "flow-release-aggregate/1"


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


def _commit(value: object) -> str:
    if type(value) is not str or SHA1.fullmatch(value) is None:
        raise ValueError("Expected a full lowercase commit SHA")
    return value


def _build_id(value: object) -> str:
    if type(value) is not str or BUILD_ID.fullmatch(value) is None:
        raise ValueError("Invalid flow build ID")
    return value


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
    if type(matrix) is not dict or {
        "profile_count": matrix.get("profile_count"),
        "semantic_row_count": matrix.get("semantic_row_count"),
        "normal_success_count": matrix.get("normal_success_count"),
        "format_success_count": matrix.get("format_success_count"),
        "rv32_fallback_count": matrix.get("rv32_fallback_count"),
    } != {
        "profile_count": 17,
        "semantic_row_count": 21,
        "normal_success_count": 16,
        "format_success_count": 4,
        "rv32_fallback_count": 1,
    }:
        raise ValueError("Package support matrix is incomplete")
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
    if type(value) is not str:
        raise ValueError("Licensed receipt IDA version is missing")
    match = re.match(r"(\d+\.\d+)", value)
    if match is None:
        raise ValueError("Licensed receipt IDA version is invalid")
    return match.group(1)


def aggregate_manifest(
    package: dict[str, object],
    receipts: list[tuple[Path, dict[str, object]]],
    expected_versions: set[str],
    checkout_sha: str,
) -> dict[str, object]:
    checkout_sha = _commit(checkout_sha)
    build_id = _validate_package(package, checkout_sha)
    if not receipts:
        raise ValueError("No licensed receipts were supplied")
    observed_versions: set[str] = set()
    receipt_hashes: dict[str, str] = {}
    for path, receipt in receipts:
        if receipt.get("schema_version") != LICENSED_SCHEMA:
            raise ValueError(f"Invalid licensed receipt schema: {path}")
        if _commit(receipt.get("checkout_sha")) != checkout_sha:
            raise ValueError(f"Licensed receipt commit mismatch: {path}")
        if receipt.get("target_executed") is not False:
            raise ValueError(f"Licensed receipt executed a target: {path}")
        if receipt.get("debugger_attached") is not False:
            raise ValueError(f"Licensed receipt attached a debugger: {path}")
        if receipt.get("input_preserved") is not True:
            raise ValueError(f"Licensed receipt changed its fixture: {path}")
        if _build_id(receipt.get("flow_build_id")) != build_id:
            raise ValueError(f"Licensed receipt build ID mismatch: {path}")
        environment = receipt.get("environment")
        if type(environment) is not dict:
            raise ValueError(f"Licensed receipt environment is missing: {path}")
        hexrays = environment.get("hexrays_initialization")
        if type(hexrays) is not dict or hexrays.get("status") != "available":
            raise ValueError(f"Licensed Hex-Rays initialization failed: {path}")
        observed_versions.add(_minor_version(receipt.get("ida_version")))
        fixture_hash = receipt.get("fixture_sha256")
        if (
            type(fixture_hash) is not str
            or re.fullmatch(r"[0-9a-f]{64}", fixture_hash) is None
        ):
            raise ValueError(f"Licensed fixture digest is invalid: {path}")
        if receipt.get("ida_input_sha256") != fixture_hash:
            raise ValueError(f"Licensed IDA input digest mismatch: {path}")
        capabilities_digest = receipt.get("capabilities_digest")
        if (
            not isinstance(capabilities_digest, str)
            or re.fullmatch(r"sha256-v1:[0-9a-f]{64}", capabilities_digest) is None
        ):
            raise ValueError(f"Licensed capability digest is invalid: {path}")
        if (
            not isinstance(environment.get("processor"), str)
            or not environment["processor"]
            or environment.get("bits") not in {16, 32, 64}
            or environment.get("endian") not in {"little", "big"}
        ):
            raise ValueError(f"Licensed profile observation is invalid: {path}")
        receipt_hashes[path.name] = sha256(path)
    if observed_versions != expected_versions:
        raise ValueError("Licensed IDA version coverage is incomplete")
    return {
        "schema_version": AGGREGATE_SCHEMA,
        "checkout_sha": checkout_sha,
        "build_id": build_id,
        "licensed_ida_versions": sorted(observed_versions),
        "licensed_receipt_sha256": dict(sorted(receipt_hashes.items())),
        "package_artifacts": package["artifacts"],
        "support_matrix": package["support_matrix"],
        "target_executed": False,
        "gui_process_e2e": False,
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
    aggregate.add_argument("--checkout-sha", required=True)
    aggregate.add_argument("--expected-ida-version", action="append", required=True)
    aggregate.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.command == "package":
        result = package_manifest(arguments.dist.resolve(), arguments.checkout_sha)
    else:
        package_path = arguments.package_manifest.resolve()
        package_value = read_json(package_path)
        validate_artifact_files(package_value, package_path.parent)
        paths = sorted(arguments.licensed_dir.resolve().glob("licensed-*.json"))
        result = aggregate_manifest(
            package_value,
            [(path, read_json(path)) for path in paths],
            set(arguments.expected_ida_version),
            arguments.checkout_sha,
        )
    write_json(arguments.output.resolve(), result)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
