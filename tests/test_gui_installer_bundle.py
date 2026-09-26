"""GUI packaging checks use temporary roots and no IDA SDK imports."""

import hashlib
import ast
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch
import types

import pytest

from ida_pro_mcp import installer
from ida_pro_mcp.flow_core.build_identity import BUILD_ID


def install(tmp_path):
    with patch.object(installer, "_get_ida_user_dir", return_value=str(tmp_path)):
        installer.install_ida_plugin(quiet=True)
    return tmp_path / "plugins"


def bootstrap(folder, *, foreign=False):
    # Execute the real loader's bootstrap in a clean process, without its UI classes.
    script = """
import ast, hashlib, importlib.util, json, os, sys
path = sys.argv[1]
tree = ast.parse(open(path).read())
node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == '_prepare_runtime')
__file__ = path
exec(compile(ast.Module(body=[node], type_ignores=[]), path, 'exec'))
before = list(sys.path)
if len(sys.argv) > 2:
    import types
    foreign = types.ModuleType('ida_pro_mcp')
    foreign.__file__ = '/unrelated/ida_pro_mcp/__init__.py'
    sys.modules['ida_pro_mcp'] = foreign
_prepare_runtime()
import ida_pro_mcp.flow_core as core
from ida_pro_mcp.flow_core.build_identity import BUILD_ID
from ida_pro_mcp.flow_core.angr_client import default_runner_path
runner = default_runner_path()
assert runner.is_file()
assert runner.parent.parent == __import__('pathlib').Path(core.__file__).resolve().parents[1]
assert 'angr' not in sys.modules
print(runner)
assert sys.path == before
assert 'idaapi' not in sys.modules
print(core.__file__)
print(BUILD_ID)
"""
    return subprocess.run(
        [sys.executable, "-I", "-c", script, str(folder / "ida_mcp.py")]
        + (["foreign"] if foreign else []),
        capture_output=True,
        text=True,
    )


def test_bundle_manifest_and_isolated_import(tmp_path):
    folder = install(tmp_path)
    root = folder / installer.GUI_BUNDLE
    manifest = json.loads((root / installer.GUI_MANIFEST).read_text())
    assert manifest["files"] == installer._bundle_files(str(root))
    for name, value in manifest["files"].items():
        assert (
            hashlib.sha256((Path(installer.SCRIPT_DIR) / name).read_bytes()).hexdigest()
            == value
        )
    result = bootstrap(folder)
    assert result.returncode == 0, result.stderr
    assert str(root / "flow_core") in result.stdout
    assert BUILD_ID in result.stdout


@pytest.mark.parametrize("damage", ["missing", "changed", "extra"])
def test_missing_stale_core_fails_closed(tmp_path, damage):
    folder = install(tmp_path)
    root = folder / installer.GUI_BUNDLE
    path = root / "flow_core" / "__init__.py"
    if damage == "missing":
        path.unlink()
    elif damage == "changed":
        path.write_text("# stale\n")
    else:
        (root / "flow_core" / "stale.py").write_text("# stale\n")
    result = bootstrap(folder)
    assert result.returncode != 0
    assert "missing or stale" in result.stderr


def test_reinstall_replaces_stale_owned_core(tmp_path):
    folder = install(tmp_path)
    path = folder / installer.GUI_BUNDLE / "flow_core" / "__init__.py"
    path.write_text("# stale\n")
    install(tmp_path)
    result = bootstrap(folder)
    assert result.returncode == 0, result.stderr


def test_uninstall_preserves_unowned_files(tmp_path):
    folder = install(tmp_path)
    root = folder / installer.GUI_BUNDLE
    extra = root / "keep.txt"
    extra.write_text("user file")
    unrelated = folder / "other_plugin.py"
    unrelated.write_text("# unrelated")
    with patch.object(installer, "_get_ida_user_dir", return_value=str(tmp_path)):
        installer.install_ida_plugin(uninstall=True, quiet=True)
    assert extra.read_text() == "user file"
    assert unrelated.exists()
    assert not (root / "flow_core" / "__init__.py").exists()
    assert not (folder / "ida_mcp.py").exists()


def test_reinstall_refuses_unowned_additions(tmp_path):
    folder = install(tmp_path)
    extra = folder / installer.GUI_BUNDLE / "keep.txt"
    extra.write_text("user file")
    with pytest.raises(RuntimeError, match="Unowned files"):
        install(tmp_path)
    assert extra.read_text() == "user file"


def test_reinstall_refuses_modified_owned_loader(tmp_path):
    folder = install(tmp_path)
    loader = folder / "ida_mcp.py"
    loader.write_text("# locally modified plugin loader\n")
    with pytest.raises(RuntimeError, match="modified GUI loader"):
        install(tmp_path)
    assert loader.read_text() == "# locally modified plugin loader\n"


def test_failed_copy_preserves_previous_install(tmp_path):
    folder = install(tmp_path)
    before = installer._bundle_files(str(folder / installer.GUI_BUNDLE))
    with patch.object(installer.shutil, "copytree", side_effect=OSError("copy failed")):
        with pytest.raises(OSError, match="copy failed"):
            install(tmp_path)
    assert installer._bundle_files(str(folder / installer.GUI_BUNDLE)) == before


def test_source_bootstrap_keeps_core_sdk_free():
    result = bootstrap(Path(installer.SCRIPT_DIR))
    assert result.returncode == 0, result.stderr


def test_install_refuses_unowned_loader(tmp_path):
    folder = tmp_path / "plugins"
    folder.mkdir()
    loader = folder / "ida_mcp.py"
    loader.write_text("# unrelated user plugin\n")
    with pytest.raises(RuntimeError, match="unowned GUI loader"):
        install(tmp_path)
    assert loader.read_text() == "# unrelated user plugin\n"


def test_legacy_install_upgrade_preserves_other_paths(tmp_path):
    folder = tmp_path / "plugins"
    folder.mkdir()
    (folder / "ida_mcp.py").symlink_to(installer.IDA_PLUGIN_LOADER)
    legacy = folder / "ida_mcp"
    legacy.symlink_to(installer.IDA_PLUGIN_PKG, target_is_directory=True)
    install(tmp_path)
    assert legacy.is_symlink()  # not part of the new bundle's ownership
    assert not (folder / "ida_mcp.py").is_symlink()
    assert bootstrap(folder).returncode == 0


def test_preloaded_foreign_package_fails_closed(tmp_path):
    result = bootstrap(install(tmp_path), foreign=True)
    assert result.returncode != 0
    assert "Another ida_pro_mcp runtime is loaded" in result.stderr


def _loader_helpers(*names):
    path = Path(installer.IDA_PLUGIN_LOADER)
    tree = ast.parse(path.read_text())
    nodes = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    namespace = {"sys": sys}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    return [namespace[name] for name in names]


def test_loader_shutdown_releases_flow_runtime_before_reload(monkeypatch):
    (shutdown,) = _loader_helpers("_shutdown_flow_runtime")
    calls = []
    runtime = types.SimpleNamespace(
        shutdown=lambda timeout: calls.append(timeout) or ("retired-job",)
    )
    monkeypatch.setitem(sys.modules, "ida_pro_mcp.ida_mcp.flow.runtime", runtime)
    assert shutdown(0.25) == ("retired-job",)
    assert calls == [0.25]


def test_loader_unload_clears_parent_package_reference(monkeypatch):
    (unload,) = _loader_helpers("unload_package")
    parent = types.ModuleType("loader_parent")
    child = types.ModuleType("loader_parent.child")
    parent.child = child
    monkeypatch.setitem(sys.modules, "loader_parent", parent)
    monkeypatch.setitem(sys.modules, "loader_parent.child", child)
    monkeypatch.setitem(
        sys.modules, "loader_parent.child.nested", types.ModuleType("nested")
    )
    unload("loader_parent.child")
    assert "loader_parent.child" not in sys.modules
    assert "loader_parent.child.nested" not in sys.modules
    assert not hasattr(parent, "child")


def test_loader_wires_runtime_shutdown_before_reload_and_termination():
    tree = ast.parse(Path(installer.IDA_PLUGIN_LOADER).read_text())
    plugin = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "MCP"
    )
    methods = {
        node.name: node
        for node in plugin.body
        if isinstance(node, ast.FunctionDef) and node.name in {"run", "term"}
    }

    def calls(function, name):
        return [
            node.lineno
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == name
        ]

    assert calls(methods["run"], "_shutdown_flow_runtime")
    assert min(calls(methods["run"], "_shutdown_flow_runtime")) < min(
        calls(methods["run"], "unload_package")
    )
    assert calls(methods["term"], "_shutdown_flow_runtime")


def test_bundle_includes_sidecar_runner_and_resolves_it_locally(tmp_path):
    folder = install(tmp_path)
    root = folder / installer.GUI_BUNDLE
    manifest = json.loads((root / installer.GUI_MANIFEST).read_text())
    assert {"flow_angr/__init__.py", "flow_angr/runner.py"} <= set(manifest["files"])
    result = bootstrap(folder)
    assert result.returncode == 0, result.stderr
    assert str(root / "flow_angr" / "runner.py") in result.stdout


@pytest.mark.parametrize("damage", ["missing", "changed"])
def test_missing_or_modified_sidecar_runner_fails_closed(tmp_path, damage):
    folder = install(tmp_path)
    runner = folder / installer.GUI_BUNDLE / "flow_angr" / "runner.py"
    if damage == "missing":
        runner.unlink()
    else:
        runner.write_text("# modified runner\n")
    result = bootstrap(folder)
    assert result.returncode != 0
    assert "missing or stale" in result.stderr


def test_runner_only_change_changes_runtime_build_identity(tmp_path, monkeypatch):
    from ida_pro_mcp.flow_core import build_identity

    root = install(tmp_path) / installer.GUI_BUNDLE
    # Hash the disposable installed runtime without touching checkout sources.
    monkeypatch.setattr(build_identity, "__file__", str(root / "flow_core" / "build_identity.py"))
    before = build_identity.extension_build_id()
    assert before == BUILD_ID
    runner = root / "flow_angr" / "runner.py"
    assert runner.is_file()
    runner.write_text(runner.read_text() + "\n# changed runner only\n")
    assert build_identity.extension_build_id() != before
    assert "flow_angr/*.py" in build_identity.BUILD_SCOPE
