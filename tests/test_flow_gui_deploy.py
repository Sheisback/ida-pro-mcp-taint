"""Disposable GUI evidence must come from the installed plugin bundle."""

from __future__ import annotations

import importlib.util
import json
import shlex
import subprocess
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from ida_pro_mcp import installer
from ida_pro_mcp.flow_core.build_identity import BUILD_ID
from ida_pro_mcp.flow_core.serialization import digest

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "1" * 40


def load_script(name: str):
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bootstrap_installed_loader(loader: Path) -> subprocess.CompletedProcess[str]:
    script = """
import ast, hashlib, importlib.util, json, os, sys
path = sys.argv[1]
tree = ast.parse(open(path).read())
node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_prepare_runtime')
__file__ = path
exec(compile(ast.Module(body=[node], type_ignores=[]), path, 'exec'))
before = list(sys.path)
_prepare_runtime()
import ida_pro_mcp
from ida_pro_mcp.flow_core.build_identity import BUILD_ID
assert sys.path == before
print(ida_pro_mcp.__file__)
print(BUILD_ID)
"""
    return subprocess.run(
        [sys.executable, "-I", "-c", script, str(loader)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_gui_recorder_installs_bundle_and_proves_process_origin(monkeypatch, tmp_path):
    recorder = load_script("record_flow_gui_ci")
    fixture = tmp_path / "fixture.elf"
    fixture.write_bytes(b"static fixture")
    ida = tmp_path / "ida"
    ida.write_bytes(b"reviewed GUI")
    accepted_registry = tmp_path / "ida.reg"
    accepted_registry.write_bytes(b"existing IDA-owned acceptance state")
    output = tmp_path / "gui-process.json"
    observed: dict[str, object] = {}

    def install_from_source(work, user):
        observed["build_called"] = (work, user)
        plugins = user / "plugins"
        plugins.mkdir()
        installer._install_gui_bundle(str(plugins))
        return (
            plugins / "ida_mcp.py",
            plugins / installer.GUI_BUNDLE / installer.GUI_MANIFEST,
        )

    class Process:
        pid = 123
        returncode = 0

        def communicate(self, timeout=None):
            observed["timeout"] = timeout
            return "", ""

    def popen(command, *, cwd, env, **kwargs):
        observed.update(command=command, cwd=cwd, env=env, kwargs=kwargs)
        script_argument = next(item[2:] for item in command if item.startswith("-S"))
        entry, process_output, request_path = shlex.split(script_argument)
        request = json.loads(Path(request_path).read_text())
        user = Path(env["IDAUSR"])
        assert (user / "ida.reg").read_bytes() == accepted_registry.read_bytes()
        bundle = user / "plugins" / "_ida_pro_mcp_runtime"
        loader = user / "plugins" / "ida_mcp.py"
        manifest = bundle / "install-manifest.json"
        assert Path(entry) == recorder.ENTRY
        assert loader.is_file() and manifest.is_file()
        assert recorder.sha256(loader) == request["loader_sha256"]
        assert recorder.sha256(manifest) == request["bundle_manifest_sha256"]
        capabilities = {
            "schema_version": "flow-capabilities/1",
            "build_id": BUILD_ID,
            "environment": {
                "ida_version": "9.3.4",
                "hexrays_version": "9.3.4.123",
            },
            "supported_profiles": ["X64-LE"],
        }
        receipt = {
            "schema_version": "flow-gui-process/2",
            "checkout_sha": request["checkout_sha"],
            "flow_build_id": BUILD_ID,
            "ida_build": "9.3.4",
            "hexrays_build": "9.3.4.123",
            "ida_executable_sha256": request["ida_executable_sha256"],
            "module_origin": str(bundle / "ida_mcp" / "api_flow.py"),
            "loader_sha256": request["loader_sha256"],
            "bundle_manifest_sha256": request["bundle_manifest_sha256"],
            "capabilities": capabilities,
            "capabilities_digest": digest(capabilities),
            "process_kind": "ida-gui",
            "disposable_user_dir": True,
            "eula_accepted_during_probe": False,
            "target_executed": False,
            "input_preserved": True,
        }
        Path(process_output).write_text(json.dumps(receipt))
        observed["request"] = request
        return Process()

    monkeypatch.setenv("PYTHONPATH", str(ROOT / "src"))
    monkeypatch.setattr(recorder, "build_and_install_gui_bundle", install_from_source)
    monkeypatch.setattr(recorder.subprocess, "Popen", popen)
    result = recorder.record(
        SimpleNamespace(
            fixture=fixture,
            ida=ida,
            output=output,
            checkout_sha=COMMIT,
            expected_ida_executable_sha256=recorder.sha256(ida),
            accepted_registry=accepted_registry,
            timeout=7,
        )
    )

    assert result == json.loads(output.read_text())
    assert observed["build_called"]
    assert observed["timeout"] == 7
    environment = cast(dict[str, str], observed["env"])
    request = cast(dict[str, object], observed["request"])
    assert "PYTHONPATH" not in environment
    assert set(request) == {
        "schema_version",
        "checkout_sha",
        "fixture_sha256",
        "ida_executable_sha256",
        "loader_sha256",
        "bundle_manifest_sha256",
    }
    assert "/idausr/plugins/_ida_pro_mcp_runtime/" in result["module_origin"].replace(
        "\\", "/"
    )


def test_gui_entry_never_injects_checkout_source():
    source = (ROOT / "scripts" / "flow_gui_ci.py").read_text()
    assert "sys.path.insert" not in source
    assert 'os.environ["IDAUSR"]' in source
    assert "loader._prepare_runtime()" in source
    assert "module_origin.is_relative_to(bundle.resolve())" in source


def test_gui_registry_seed_is_disposable_and_rejects_symlinks(tmp_path):
    recorder = load_script("record_flow_gui_ci")
    source = tmp_path / "ida.reg"
    original = b"existing IDA-owned acceptance state"
    source.write_bytes(original)
    user = tmp_path / "idausr"
    user.mkdir()

    recorder.seed_existing_registry(source, user)
    destination = user / "ida.reg"
    assert destination.read_bytes() == source.read_bytes() == original
    assert destination.stat().st_mode & 0o777 == 0o600

    linked = tmp_path / "linked"
    linked.mkdir()
    (linked / "ida.reg").symlink_to(source)
    with pytest.raises(ValueError, match="symlink"):
        recorder.seed_existing_registry(linked / "ida.reg", tmp_path / "other-user")
    assert source.read_bytes() == original


def test_gui_bundle_is_installed_from_current_checkout_wheel(tmp_path):
    recorder = load_script("record_flow_gui_ci")
    user = tmp_path / "idausr"
    user.mkdir()
    loader, manifest = recorder.build_and_install_gui_bundle(tmp_path, user)
    assert loader.is_file() and manifest.is_file()
    value = json.loads(manifest.read_text())
    assert value["owner"] == "ida-pro-mcp"
    assert value["version"] == 1
    assert value["loader_sha256"] == recorder.sha256(loader)
    assert value["files"]
    bootstrapped = bootstrap_installed_loader(loader)
    assert bootstrapped.returncode == 0, bootstrapped.stderr
    assert str(user / "plugins" / "_ida_pro_mcp_runtime") in bootstrapped.stdout
    assert BUILD_ID in bootstrapped.stdout


def test_gui_bundle_builds_wheel_from_fresh_sdist(monkeypatch, tmp_path):
    recorder = load_script("record_flow_gui_ci")
    user = tmp_path / "idausr"
    user.mkdir()
    commands: list[list[str]] = []

    def run(command, **_kwargs):
        commands.append(command)
        if command[0] == "/test/uv" and "--sdist" in command:
            output = Path(command[command.index("--out-dir") + 1])
            (output / "ida_pro_mcp-2.0.0.tar.gz").write_bytes(b"fresh sdist")
        elif command[0] == "/test/uv" and "--wheel" in command:
            source = Path(command[-1])
            assert source.parent == tmp_path / "sdist"
            assert source.name.endswith(".tar.gz")
            output = Path(command[command.index("--out-dir") + 1])
            with zipfile.ZipFile(output / "ida_pro_mcp-2.0.0.whl", "w"):
                pass
        else:
            plugins = user / "plugins"
            (plugins / "_ida_pro_mcp_runtime").mkdir(parents=True)
            (plugins / "ida_mcp.py").write_text("# installed loader\n")
            (plugins / "_ida_pro_mcp_runtime" / "install-manifest.json").write_text(
                "{}\n"
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(recorder.shutil, "which", lambda _name: "/test/uv")
    monkeypatch.setattr(recorder.subprocess, "run", run)
    loader, manifest = recorder.build_and_install_gui_bundle(tmp_path, user)
    assert loader.is_file() and manifest.is_file()
    assert [command[2] for command in commands[:2]] == ["--sdist", "--wheel"]
    assert commands[1][-1] == str(tmp_path / "sdist" / "ida_pro_mcp-2.0.0.tar.gz")


def test_gui_release_validation_rejects_checkout_module_origin(tmp_path):
    gate = load_script("flow_release_gate")
    capabilities = {
        "schema_version": "flow-capabilities/1",
        "build_id": BUILD_ID,
        "environment": {
            "ida_version": "9.3.4",
            "hexrays_version": "9.3.4.123",
        },
        "supported_profiles": ["X64-LE"],
    }
    receipt = {
        "schema_version": "flow-gui-process/2",
        "checkout_sha": COMMIT,
        "flow_build_id": BUILD_ID,
        "ida_build": "9.3.4",
        "hexrays_build": "9.3.4.123",
        "ida_executable_sha256": "9" * 64,
        "module_origin": str(ROOT / "src/ida_pro_mcp/ida_mcp/api_flow.py"),
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
    with pytest.raises(ValueError, match="module origin"):
        gate._validate_gui_receipt(
            receipt,
            checkout_sha=COMMIT,
            build_id=BUILD_ID,
            expected_executable_sha256="9" * 64,
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("module_origin", "/checkout/src/ida_pro_mcp/ida_mcp/api_flow.py", "origin"),
        ("loader_sha256", "1" * 64, "loader digest"),
        ("bundle_manifest_sha256", "2" * 64, "manifest digest"),
    ],
)
def test_gui_recorder_rejects_spoofed_installation_identity(
    tmp_path, field, value, message
):
    recorder = load_script("record_flow_gui_ci")
    user = tmp_path / "idausr"
    expected_origin = (
        user / "plugins" / "_ida_pro_mcp_runtime" / "ida_mcp" / "api_flow.py"
    )
    receipt = {
        "module_origin": str(expected_origin),
        "loader_sha256": "7" * 64,
        "bundle_manifest_sha256": "8" * 64,
    }
    receipt[field] = value
    with pytest.raises(ValueError, match=message):
        recorder.validate_installed_receipt(
            receipt,
            user=user,
            loader_sha256="7" * 64,
            bundle_manifest_sha256="8" * 64,
        )


def test_missing_gui_keeps_eula_blocker_without_installing(monkeypatch, tmp_path):
    recorder = load_script("record_flow_gui_ci")
    fixture = tmp_path / "fixture.elf"
    fixture.write_bytes(b"static fixture")
    output = tmp_path / "gui-process.json"
    monkeypatch.setattr(
        recorder,
        "build_and_install_gui_bundle",
        lambda *args: pytest.fail("missing GUI must not install or launch"),
    )
    result = recorder.record(
        SimpleNamespace(
            fixture=fixture,
            ida=tmp_path / "missing-ida",
            output=output,
            checkout_sha=COMMIT,
            expected_ida_executable_sha256="9" * 64,
            timeout=1,
        )
    )
    assert result["reason"] == "gui_executable_missing"
    assert result["eula_accepted_during_probe"] is False
    assert result["target_executed"] is False
    assert not output.exists()


def test_gui_recorder_refuses_symlink_alias_and_existing_outputs(tmp_path):
    recorder = load_script("record_flow_gui_ci")
    fixture = tmp_path / "fixture.elf"
    fixture.write_bytes(b"preserve static fixture")
    ida = tmp_path / "missing-ida"

    symlink = tmp_path / "receipt.json"
    symlink.symlink_to(fixture)
    with pytest.raises(ValueError, match="contains a symlink"):
        recorder.record(
            SimpleNamespace(
                fixture=fixture,
                ida=ida,
                output=symlink,
                checkout_sha=COMMIT,
                expected_ida_executable_sha256="9" * 64,
                timeout=1,
            )
        )
    assert fixture.read_bytes() == b"preserve static fixture"
    assert symlink.is_symlink()

    with pytest.raises(ValueError, match="aliases an input"):
        recorder.record(
            SimpleNamespace(
                fixture=fixture,
                ida=ida,
                output=fixture,
                checkout_sha=COMMIT,
                expected_ida_executable_sha256="9" * 64,
                timeout=1,
            )
        )
    assert fixture.read_bytes() == b"preserve static fixture"

    existing = tmp_path / "existing.json"
    existing.write_text("keep\n")
    with pytest.raises(FileExistsError, match="Refusing to replace"):
        recorder.record(
            SimpleNamespace(
                fixture=fixture,
                ida=ida,
                output=existing,
                checkout_sha=COMMIT,
                expected_ida_executable_sha256="9" * 64,
                timeout=1,
            )
        )
    assert existing.read_text() == "keep\n"
