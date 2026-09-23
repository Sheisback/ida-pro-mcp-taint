#!/usr/bin/env python3
"""Attempt isolated GUI-process evidence without mutating persistent profiles."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "scripts/flow_gui_ci.py"
SHA1 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _absolute_unresolved(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _reject_symlink_components(path: Path) -> Path:
    result = _absolute_unresolved(path)
    for candidate in reversed([result, *result.parents]):
        if os.path.lexists(candidate) and candidate.is_symlink():
            raise ValueError(
                f"GUI evidence output path contains a symlink: {candidate}"
            )
    return result


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def blocker_path(output: Path) -> Path:
    return output.with_name(output.stem + ".blocker.json")


def seed_existing_registry(source: Path, user: Path) -> None:
    """Reuse an already accepted IDA registry in a disposable user directory."""
    source = _reject_symlink_components(source.expanduser())
    if source.name != "ida.reg" or not source.is_file():
        raise ValueError("Accepted IDA registry must be an existing ida.reg file")
    destination = user / "ida.reg"
    with source.open("rb") as reader, destination.open("xb") as writer:
        shutil.copyfileobj(reader, writer)
    destination.chmod(0o600)


def record_blocker(
    output: Path,
    *,
    checkout_sha: str,
    gui_sha256: str,
    reason: str,
    details: str,
) -> dict[str, Any]:
    value = {
        "schema_version": "flow-gui-blocker/1",
        "checkout_sha": checkout_sha,
        "ida_gui_executable_sha256": gui_sha256,
        "status": "blocked",
        "reason": reason,
        "details": details[-4000:],
        "disposable_user_dir": True,
        "eula_accepted_during_probe": False,
        "target_executed": False,
    }
    write_json(blocker_path(output), value)
    return value


def build_and_install_gui_bundle(work: Path, user: Path) -> tuple[Path, Path]:
    """Build the current wheel and install its plugin into disposable IDAUSR."""
    uv = shutil.which("uv")
    if uv is None:
        raise RuntimeError("uv is required to build disposable GUI evidence")
    sdists = work / "sdist"
    sdists.mkdir()
    wheels = work / "wheel"
    wheels.mkdir()
    build_environment = os.environ.copy()
    build_environment.pop("PYTHONPATH", None)
    subprocess.run(
        [uv, "build", "--sdist", "--out-dir", str(sdists), str(ROOT)],
        cwd=work,
        env=build_environment,
        check=True,
        capture_output=True,
        text=True,
    )
    sources = tuple(sdists.glob("*.tar.gz"))
    if len(sources) != 1:
        raise RuntimeError("Expected exactly one current-checkout GUI evidence sdist")
    # Build the wheel from the fresh sdist rather than ROOT. Backends are allowed
    # to reuse an ignored build/lib tree for a direct wheel build, which can make
    # the installed GUI bundle stale even though the checkout itself is current.
    subprocess.run(
        [uv, "build", "--wheel", "--out-dir", str(wheels), str(sources[0])],
        cwd=work,
        env=build_environment,
        check=True,
        capture_output=True,
        text=True,
    )
    built = tuple(wheels.glob("*.whl"))
    if len(built) != 1:
        raise RuntimeError("Expected exactly one current-checkout GUI evidence wheel")
    site = work / "wheel-site"
    site.mkdir()
    with zipfile.ZipFile(built[0]) as archive:
        for member in archive.infolist():
            parts = PurePosixPath(member.filename).parts
            if member.filename.startswith("/") or ".." in parts:
                raise RuntimeError("Unsafe path in GUI evidence wheel")
        archive.extractall(site)
    plugins = user / "plugins"
    plugins.mkdir()
    install = """
import pathlib
import sys
site = pathlib.Path(sys.argv[1]).resolve()
plugins = pathlib.Path(sys.argv[2]).resolve()
sys.path.insert(0, str(site))
from ida_pro_mcp import installer
if not pathlib.Path(installer.__file__).resolve().is_relative_to(site):
    raise RuntimeError("GUI installer did not load from the built wheel")
installer._install_gui_bundle(str(plugins))
"""
    subprocess.run(
        [sys.executable, "-I", "-c", install, str(site), str(plugins)],
        cwd=work,
        env=build_environment,
        check=True,
        capture_output=True,
        text=True,
    )
    loader = plugins / "ida_mcp.py"
    manifest = plugins / "_ida_pro_mcp_runtime" / "install-manifest.json"
    if not loader.is_file() or not manifest.is_file():
        raise RuntimeError("Disposable GUI plugin installation is incomplete")
    return loader, manifest


def _release_gate():
    path = ROOT / "scripts/flow_release_gate.py"
    spec = importlib.util.spec_from_file_location("flow_gui_release_gate", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load GUI receipt validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_installed_receipt(
    receipt: dict[str, Any],
    *,
    user: Path,
    loader_sha256: str,
    bundle_manifest_sha256: str,
) -> None:
    expected_origin = (
        user / "plugins" / "_ida_pro_mcp_runtime" / "ida_mcp" / "api_flow.py"
    ).resolve()
    origin = receipt.get("module_origin")
    if type(origin) is not str or Path(origin).resolve() != expected_origin:
        raise ValueError("GUI receipt module origin does not match installed bundle")
    if receipt.get("loader_sha256") != loader_sha256:
        raise ValueError("GUI receipt loader digest does not match installed loader")
    if receipt.get("bundle_manifest_sha256") != bundle_manifest_sha256:
        raise ValueError("GUI receipt manifest digest does not match installed bundle")


def record(args: argparse.Namespace) -> dict[str, Any]:
    fixture = args.fixture.resolve()
    ida = args.ida.resolve()
    output = _reject_symlink_components(args.output)
    blocker = _reject_symlink_components(blocker_path(output))
    if output in {fixture, ida} or blocker in {fixture, ida}:
        raise ValueError("GUI evidence output aliases an input")
    # Publication requires a fresh destination. Never erase an unrelated or
    # stale-looking file merely because the caller selected its path.
    if os.path.lexists(output) or os.path.lexists(blocker):
        raise FileExistsError("Refusing to replace existing GUI evidence output")
    if SHA1.fullmatch(args.checkout_sha) is None:
        raise ValueError("checkout_sha must be a full lowercase commit SHA")
    if SHA256.fullmatch(args.expected_ida_executable_sha256) is None:
        raise ValueError("expected GUI executable digest is invalid")
    if not fixture.is_file():
        raise FileNotFoundError("GUI evidence fixture is missing")
    if not ida.is_file():
        return record_blocker(
            output,
            checkout_sha=args.checkout_sha,
            gui_sha256=args.expected_ida_executable_sha256,
            reason="gui_executable_missing",
            details=str(ida),
        )
    observed_gui = sha256(ida)
    if observed_gui != args.expected_ida_executable_sha256:
        return record_blocker(
            output,
            checkout_sha=args.checkout_sha,
            gui_sha256=observed_gui,
            reason="gui_executable_digest_mismatch",
            details="actual GUI executable does not match reviewed digest",
        )

    original = sha256(fixture)
    with tempfile.TemporaryDirectory(prefix="flow-gui-ci-") as raw:
        work = Path(raw)
        home = work / "home"
        user = work / "idausr"
        temp = work / "tmp"
        for directory in (home, user, temp):
            directory.mkdir()
        accepted_registry = getattr(args, "accepted_registry", None)
        if accepted_registry is not None:
            seed_existing_registry(accepted_registry, user)
        loader, bundle_manifest = build_and_install_gui_bundle(work, user)
        disposable = work / fixture.name
        shutil.copyfile(fixture, disposable)
        request_path = work / "request.json"
        process_output = work / "gui-process.json"
        database = work / "gui-probe.i64"
        log = work / "ida.log"
        loader_sha256 = sha256(loader)
        bundle_manifest_sha256 = sha256(bundle_manifest)
        write_json(
            request_path,
            {
                "schema_version": "flow-gui-request/2",
                "checkout_sha": args.checkout_sha,
                "fixture_sha256": original,
                "ida_executable_sha256": observed_gui,
                "loader_sha256": loader_sha256,
                "bundle_manifest_sha256": bundle_manifest_sha256,
            },
        )
        script = shlex.join([str(ENTRY), str(process_output), str(request_path)])
        command = [
            str(ida),
            "-A",
            "-c",
            f"-o{database}",
            f"-L{log}",
            f"-S{script}",
            str(disposable),
        ]
        environment = os.environ.copy()
        # The GUI process must prove the installed bundle, not an import made
        # available by the calling checkout or its virtual environment.
        environment.pop("PYTHONPATH", None)
        environment.update(
            {"HOME": str(home), "IDAUSR": str(user), "TMPDIR": str(temp)}
        )
        if sys.platform != "darwin":
            environment.setdefault("QT_QPA_PLATFORM", "offscreen")
        process = subprocess.Popen(
            command,
            cwd=work,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout, stderr = process.communicate()
            return record_blocker(
                output,
                checkout_sha=args.checkout_sha,
                gui_sha256=observed_gui,
                reason="gui_process_timeout_no_eula_interaction",
                details=stdout + "\n" + stderr,
            )
        log_text = log.read_text(errors="replace") if log.is_file() else ""
        if process.returncode != 0 or not process_output.is_file():
            return record_blocker(
                output,
                checkout_sha=args.checkout_sha,
                gui_sha256=observed_gui,
                reason="gui_process_evidence_unavailable",
                details=stdout + "\n" + stderr + "\n" + log_text,
            )
        if sha256(disposable) != original or sha256(fixture) != original:
            raise RuntimeError("GUI evidence probe changed its input")
        receipt = json.loads(process_output.read_text())
        validate_installed_receipt(
            receipt,
            user=user,
            loader_sha256=loader_sha256,
            bundle_manifest_sha256=bundle_manifest_sha256,
        )
        from ida_pro_mcp.flow_core.build_identity import BUILD_ID

        gate = _release_gate()
        gate._validate_gui_receipt(
            receipt,
            checkout_sha=args.checkout_sha,
            build_id=BUILD_ID,
            expected_executable_sha256=args.expected_ida_executable_sha256,
        )
        write_json(output, receipt)
        return receipt


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--checkout-sha", required=True)
    parser.add_argument("--ida", type=Path, required=True)
    parser.add_argument("--expected-ida-executable-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument(
        "--accepted-registry",
        type=Path,
        help="Copy an existing user-accepted ida.reg into the disposable IDAUSR; never change the original",
    )
    return parser.parse_args()


def main() -> int:
    result = record(parse_args())
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
