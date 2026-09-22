#!/usr/bin/env python3
"""Attempt isolated GUI-process evidence without accepting EULA or touching profiles."""

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
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "scripts/flow_gui_ci.py"
SHA1 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def blocker_path(output: Path) -> Path:
    return output.with_name(output.stem + ".blocker.json")


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


def _release_gate():
    path = ROOT / "scripts/flow_release_gate.py"
    spec = importlib.util.spec_from_file_location("flow_gui_release_gate", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load GUI receipt validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record(args: argparse.Namespace) -> dict[str, Any]:
    fixture = args.fixture.resolve()
    ida = args.ida.resolve()
    output = args.output.resolve()
    # A failed or blocked retry must never leave an earlier success looking
    # current.  Remove both mutually exclusive outcomes before validating or
    # launching the disposable process.
    output.unlink(missing_ok=True)
    blocker_path(output).unlink(missing_ok=True)
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
        disposable = work / fixture.name
        shutil.copyfile(fixture, disposable)
        request_path = work / "request.json"
        process_output = work / "gui-process.json"
        database = work / "gui-probe.i64"
        log = work / "ida.log"
        write_json(
            request_path,
            {
                "schema_version": "flow-gui-request/1",
                "checkout_sha": args.checkout_sha,
                "fixture_sha256": original,
                "ida_executable_sha256": observed_gui,
            },
        )
        script = shlex.join(
            [str(ENTRY), str(ROOT), str(process_output), str(request_path)]
        )
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
    return parser.parse_args()


def main() -> int:
    result = record(parse_args())
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
