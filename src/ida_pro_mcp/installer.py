import glob
import hashlib
import json
import os
import shutil
import sys
import tempfile
import tomllib
import tomli_w
from urllib.parse import urlparse, urlunparse

try:
    from .installer_data import (
        GLOBAL_SPECIAL_JSON_STRUCTURES,
        PROJECT_LEVEL_CONFIGS,
        PROJECT_SPECIAL_JSON_STRUCTURES,
        get_global_configs,
        get_project_configs,
        resolve_client_name,
    )
    from .installer_tui import interactive_choose, interactive_select
except ImportError:
    from installer_data import (
        GLOBAL_SPECIAL_JSON_STRUCTURES,
        PROJECT_LEVEL_CONFIGS,
        PROJECT_SPECIAL_JSON_STRUCTURES,
        get_global_configs,
        get_project_configs,
        resolve_client_name,
    )
    from installer_tui import interactive_choose, interactive_select

MCP_SERVER_NAME = "ida-pro-mcp"
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
SERVER_SCRIPT = os.path.join(SCRIPT_DIR, "server.py")
IDA_PLUGIN_PKG = os.path.join(SCRIPT_DIR, "ida_mcp")
IDA_PLUGIN_LOADER = os.path.join(SCRIPT_DIR, "ida_mcp.py")
IDA_HOST = "127.0.0.1"
IDA_PORT = 13337

# NOTE: This is in the global scope on purpose
if not os.path.exists(IDA_PLUGIN_PKG):
    raise RuntimeError(
        f"IDA plugin package not found at {IDA_PLUGIN_PKG} (did you move it?)"
    )
if not os.path.exists(IDA_PLUGIN_LOADER):
    raise RuntimeError(
        f"IDA plugin loader not found at {IDA_PLUGIN_LOADER} (did you move it?)"
    )


def set_ida_rpc(host: str, port: int) -> None:
    global IDA_HOST, IDA_PORT
    IDA_HOST = host
    IDA_PORT = port


def get_python_executable():
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python

    for path in sys.path:
        if sys.platform == "win32":
            path = path.replace("/", "\\")

        split = path.split(os.sep)
        if split[-1].endswith(".zip"):
            path = os.path.dirname(path)
            if sys.platform == "win32":
                python_executable = os.path.join(path, "python.exe")
            else:
                python_executable = os.path.join(path, "..", "bin", "python3")
            python_executable = os.path.abspath(python_executable)
            if os.path.exists(python_executable):
                return python_executable
    return sys.executable


def copy_python_env(env: dict[str, str]):
    # MCP servers are run without inheriting the environment, so we need to forward
    # the environment variables that affect Python's dependency resolution by hand.
    # Issue: https://github.com/mrexodia/ida-pro-mcp/issues/111
    python_vars = [
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
    ]
    result = False
    for var in python_vars:
        value = os.environ.get(var)
        if value:
            result = True
            env[var] = value
    return result


def normalize_transport_url(transport: str) -> str:
    url = urlparse(transport)
    if url.hostname is None or url.port is None:
        raise Exception(f"Invalid transport URL: {transport}")
    path = url.path or "/mcp"
    if path == "/":
        path = "/mcp"
    return urlunparse((url.scheme, f"{url.hostname}:{url.port}", path, "", "", ""))


def force_mcp_path(transport_url: str) -> str:
    url = urlparse(transport_url)
    return urlunparse((url.scheme, f"{url.hostname}:{url.port}", "/mcp", "", "", ""))


def infer_http_transport_type(transport_url: str) -> str:
    return "sse" if urlparse(transport_url).path.rstrip("/") == "/sse" else "http"


def generate_mcp_config(*, client_name: str, transport: str = "stdio"):
    if transport == "stdio":
        # No --ida-rpc: server auto-discovers running IDA instances
        if client_name == "Opencode":
            mcp_config = {
                "type": "local",
                "command": [
                    get_python_executable(),
                    SERVER_SCRIPT,
                ],
            }
        else:
            mcp_config = {
                "command": get_python_executable(),
                "args": [
                    SERVER_SCRIPT,
                ],
            }
        env = {}
        if copy_python_env(env):
            print("[WARNING] Custom Python environment variables detected")
            mcp_config["env"] = env
        return mcp_config

    if transport == "streamable-http":
        transport = f"http://{IDA_HOST}:{IDA_PORT}/mcp"
    elif transport == "sse":
        transport = f"http://{IDA_HOST}:{IDA_PORT}/sse"

    transport_url = normalize_transport_url(transport)
    if client_name == "Opencode":
        return {"type": "remote", "url": transport_url}
    if client_name == "Codex":
        return {"url": force_mcp_path(transport_url)}
    if client_name in ("Claude", "Claude Code"):
        return {"type": infer_http_transport_type(transport_url), "url": transport_url}
    if client_name == "Antigravity IDE":
        return {"type": "http", "serverUrl": force_mcp_path(transport_url)}
    return {"type": "http", "url": force_mcp_path(transport_url)}


def print_mcp_config():
    print("[STDIO MCP CONFIGURATION]")
    print(
        json.dumps(
            {
                "mcpServers": {
                    MCP_SERVER_NAME: generate_mcp_config(
                        client_name="Generic", transport="stdio"
                    )
                }
            },
            indent=2,
        )
    )
    print("\n[STREAMABLE HTTP MCP CONFIGURATION]")
    print(
        json.dumps(
            {
                "mcpServers": {
                    MCP_SERVER_NAME: generate_mcp_config(
                        client_name="Generic",
                        transport=f"http://{IDA_HOST}:{IDA_PORT}/mcp",
                    )
                }
            },
            indent=2,
        )
    )
    print("\n[SSE MCP CONFIGURATION]")
    print(
        json.dumps(
            {
                "mcpServers": {
                    MCP_SERVER_NAME: generate_mcp_config(
                        client_name="Generic",
                        transport=f"http://{IDA_HOST}:{IDA_PORT}/sse",
                    )
                }
            },
            indent=2,
        )
    )


def _get_scope_config_spec(
    *, project: bool, project_dir: str | None = None
) -> tuple[dict[str, tuple[str, str]], dict[str, tuple[str | None, str]]]:
    if project:
        return (
            get_project_configs(project_dir or os.getcwd()),
            PROJECT_SPECIAL_JSON_STRUCTURES,
        )
    return get_global_configs(), GLOBAL_SPECIAL_JSON_STRUCTURES


def _read_config_file(config_path: str, *, is_toml: bool) -> dict | None:
    try:
        if is_toml:
            with open(config_path, "rb") as f:
                data = f.read()
                return tomllib.loads(data.decode("utf-8")) if data else {}
        with open(config_path, "r", encoding="utf-8") as f:
            data = f.read().strip()
            return json.loads(data) if data else {}
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, OSError):
        return None


def _write_config_file(config_path: str, config: dict, *, is_toml: bool) -> None:
    config_dir = os.path.dirname(config_path)
    suffix = ".toml" if is_toml else ".json"
    fd, temp_path = tempfile.mkstemp(
        dir=config_dir, prefix=".tmp_", suffix=suffix, text=True
    )
    try:
        with os.fdopen(
            fd, "wb" if is_toml else "w", encoding=None if is_toml else "utf-8"
        ) as f:
            if is_toml:
                f.write(tomli_w.dumps(config).encode("utf-8"))
            else:
                json.dump(config, f, indent=2)
        os.replace(temp_path, config_path)
    except Exception:
        os.unlink(temp_path)
        raise


def _get_mcp_servers_view(
    config: dict,
    *,
    client_name: str,
    is_toml: bool,
    special_json_structures: dict[str, tuple[str | None, str]],
) -> dict:
    if is_toml:
        return config.setdefault("mcp_servers", {})
    if client_name in special_json_structures:
        top_key, nested_key = special_json_structures[client_name]
        if top_key is None:
            return config.setdefault(nested_key, {})
        return config.setdefault(top_key, {}).setdefault(nested_key, {})
    return config.setdefault("mcpServers", {})


def _resolve_client_targets(
    configs: dict[str, tuple[str, str]],
    only: list[str] | None,
    *,
    project: bool,
) -> dict[str, tuple[str, str]]:
    if only is None:
        return configs

    available = list(configs.keys())
    other_scope_configs = (
        get_global_configs() if project else get_project_configs(os.getcwd())
    )
    other_scope_name = "global" if project else "project"
    filtered: dict[str, tuple[str, str]] = {}
    for target_name in only:
        resolved = resolve_client_name(target_name, available)
        if resolved is None:
            other_scope_match = resolve_client_name(
                target_name, list(other_scope_configs.keys())
            )
            if other_scope_match is not None:
                print(
                    f"Client '{other_scope_match}' is not supported for "
                    f"--scope {'project' if project else 'global'}. "
                    f"Use --scope {other_scope_name} for this target."
                )
            else:
                print(
                    f"Unknown client: '{target_name}'. Use --list-clients to see available targets."
                )
        elif resolved not in filtered:
            filtered[resolved] = configs[resolved]
    return filtered


def is_client_installed(
    name: str, config_dir: str, config_file: str, *, project: bool = False
) -> bool:
    config_path = os.path.join(config_dir, config_file)
    if not os.path.exists(config_path):
        return False

    is_toml = config_file.endswith(".toml")
    config = _read_config_file(config_path, is_toml=is_toml)
    if config is None:
        return False

    _, special_json_structures = _get_scope_config_spec(project=project)
    mcp_servers = _get_mcp_servers_view(
        config,
        client_name=name,
        is_toml=is_toml,
        special_json_structures=special_json_structures,
    )
    return MCP_SERVER_NAME in mcp_servers


def list_available_clients():
    configs = get_global_configs()
    if not configs:
        print(f"Unsupported platform: {sys.platform}")
        return

    print("Available installation targets:\n")
    print("  MCP Clients:")
    for name, (config_dir, _) in configs.items():
        supports_project = name in PROJECT_LEVEL_CONFIGS
        project_marker = " [supports --project]" if supports_project else ""
        status = "found" if os.path.exists(config_dir) else "not found"
        print(f"    {name:<25} ({status}){project_marker}")

    print()
    print("Usage examples:")
    print(
        "  ida-pro-mcp --install                                    # Interactive selector"
    )
    print(
        "  ida-pro-mcp --install claude,cursor                       # Specific client targets"
    )
    print(
        "  ida-pro-mcp --install vscode --scope project              # Project-level config"
    )
    print(
        "  ida-pro-mcp --install cursor --transport streamable-http  # Streamable HTTP config"
    )
    print(
        "  ida-pro-mcp --uninstall cursor                            # Uninstall specific target"
    )


def install_mcp_servers(
    *,
    transport: str = "stdio",
    uninstall: bool = False,
    quiet: bool = False,
    only: list[str] | None = None,
    project: bool = False,
):
    configs, special_json_structures = _get_scope_config_spec(project=project)
    if not configs:
        print(f"Unsupported platform: {sys.platform}")
        return

    configs = _resolve_client_targets(configs, only, project=project)
    if not configs:
        return

    changed = 0
    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)
        is_toml = config_file.endswith(".toml")

        if not os.path.exists(config_dir):
            if project and not uninstall:
                os.makedirs(config_dir, exist_ok=True)
            else:
                action = "uninstall" if uninstall else "installation"
                if not quiet:
                    print(
                        f"Skipping {name} {action}\n  Config: {config_path} (not found)"
                    )
                continue

        config = {}
        if os.path.exists(config_path):
            config = _read_config_file(config_path, is_toml=is_toml)
            if config is None:
                if not quiet:
                    kind = "TOML" if is_toml else "JSON"
                    action = "uninstall" if uninstall else "installation"
                    print(
                        f"Skipping {name} {action}\n"
                        f"  Config: {config_path} (invalid {kind})"
                    )
                continue

        mcp_servers = _get_mcp_servers_view(
            config,
            client_name=name,
            is_toml=is_toml,
            special_json_structures=special_json_structures,
        )
        old_name = "github.com/mrexodia/ida-pro-mcp"
        if old_name in mcp_servers:
            mcp_servers[MCP_SERVER_NAME] = mcp_servers[old_name]
            del mcp_servers[old_name]

        if uninstall:
            if MCP_SERVER_NAME not in mcp_servers:
                if not quiet:
                    print(
                        f"Skipping {name} uninstall\n  Config: {config_path} (not installed)"
                    )
                continue
            del mcp_servers[MCP_SERVER_NAME]
        else:
            mcp_servers[MCP_SERVER_NAME] = generate_mcp_config(
                client_name=name,
                transport=transport,
            )

        _write_config_file(config_path, config, is_toml=is_toml)
        if not quiet:
            action = "Uninstalled" if uninstall else "Installed"
            print(
                f"{action} {name} MCP server (restart required)\n  Config: {config_path}"
            )
        changed += 1

    if not uninstall and changed == 0:
        print(
            "No MCP servers installed. For unsupported MCP clients, use the following config:\n"
        )
        print_mcp_config()


def _get_ida_user_dir() -> str:
    if sys.platform == "win32":
        return os.path.join(os.environ["APPDATA"], "Hex-Rays", "IDA Pro")
    return os.path.join(os.path.expanduser("~"), ".idapro")


def _remove_path(path: str) -> None:
    if not os.path.lexists(path):
        return
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    else:
        os.remove(path)


GUI_BUNDLE = "_ida_pro_mcp_runtime"
GUI_MANIFEST = "install-manifest.json"


def _bundle_files(root: str) -> dict[str, str]:
    """Hash deployed source, never interpreter-generated caches."""
    result = {}
    for directory, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for name in sorted(files):
            relative = os.path.relpath(os.path.join(directory, name), root)
            if relative == GUI_MANIFEST:
                continue
            with open(os.path.join(root, relative), "rb") as stream:
                result[relative] = hashlib.sha256(stream.read()).hexdigest()
    return result


def _owned_manifest(root: str) -> dict | None:
    path = os.path.join(root, GUI_MANIFEST)
    if not os.path.isfile(path) or os.path.islink(root):
        return None
    with open(path, encoding="utf-8") as stream:
        manifest = json.load(stream)
    if manifest.get("owner") != "ida-pro-mcp" or manifest.get("version") != 1:
        raise RuntimeError("Unrecognized GUI installation manifest")
    for name in manifest["files"]:
        if os.path.isabs(name) or ".." in name.replace("\\", "/").split("/"):
            raise RuntimeError("Invalid GUI installation manifest path")
    return manifest


def _install_gui_bundle(folder: str) -> None:
    destination = os.path.join(folder, GUI_BUNDLE)
    existing = _owned_manifest(destination)
    loader_destination = os.path.join(folder, "ida_mcp.py")
    if os.path.lexists(loader_destination) and existing is None:
        # Recognize the legacy installer loader, but never replace arbitrary plugins.
        with open(loader_destination, encoding="utf-8") as stream:
            if not stream.read().startswith('"""IDA Pro MCP Plugin Loader'):
                raise RuntimeError("Refusing to replace an unowned GUI loader")
    if existing is not None and os.path.isfile(loader_destination):
        with open(loader_destination, "rb") as stream:
            loader_hash = hashlib.sha256(stream.read()).hexdigest()
        if loader_hash != existing["loader_sha256"]:
            raise RuntimeError("Refusing to replace a modified GUI loader")
    if os.path.lexists(destination):
        if existing is None:
            raise RuntimeError(f"Refusing to replace unowned directory: {destination}")
        extras = set(_bundle_files(destination)) - set(existing["files"])
        if extras:
            raise RuntimeError(f"Unowned files in GUI bundle: {sorted(extras)}")
    with tempfile.TemporaryDirectory(prefix=".ida-mcp-stage-", dir=folder) as staging:
        bundle = os.path.join(staging, GUI_BUNDLE)
        os.mkdir(bundle)
        shutil.copy2(os.path.join(SCRIPT_DIR, "__init__.py"), bundle)
        for name, source in (
            ("ida_mcp", IDA_PLUGIN_PKG),
            ("flow_core", os.path.join(SCRIPT_DIR, "flow_core")),
        ):
            shutil.copytree(
                source,
                os.path.join(bundle, name),
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
        loader = os.path.join(staging, "ida_mcp.py")
        shutil.copy2(IDA_PLUGIN_LOADER, loader)
        with open(loader, "rb") as stream:
            loader_hash = hashlib.sha256(stream.read()).hexdigest()
        manifest = {
            "owner": "ida-pro-mcp",
            "version": 1,
            "files": _bundle_files(bundle),
            "loader_sha256": loader_hash,
        }
        with open(os.path.join(bundle, GUI_MANIFEST), "w", encoding="utf-8") as stream:
            json.dump(manifest, stream, sort_keys=True)
        backup = os.path.join(staging, "previous")
        if existing is not None:
            os.replace(destination, backup)
        try:
            os.replace(bundle, destination)
            os.replace(loader, os.path.join(folder, "ida_mcp.py"))
        except BaseException:
            _remove_path(destination)
            if existing is not None:
                os.replace(backup, destination)
            raise


def _uninstall_gui_bundle(folder: str) -> bool:
    root = os.path.join(folder, GUI_BUNDLE)
    manifest = _owned_manifest(root)
    if manifest is None:
        return False
    loader = os.path.join(folder, "ida_mcp.py")
    if os.path.isfile(loader) and not os.path.islink(loader):
        with open(loader, "rb") as stream:
            if hashlib.sha256(stream.read()).hexdigest() == manifest["loader_sha256"]:
                os.unlink(loader)
    for name in manifest["files"]:
        path = os.path.join(root, name)
        # Do not follow a replaced directory symlink outside the owned root.
        if os.path.commonpath(
            (os.path.realpath(path), os.path.realpath(root))
        ) != os.path.realpath(root):
            continue
        if os.path.isfile(path) or os.path.islink(path):
            os.unlink(path)
    os.unlink(os.path.join(root, GUI_MANIFEST))
    for directory, _, _ in os.walk(root, topdown=False):
        try:
            os.rmdir(directory)
        except OSError:
            pass  # Preserve unowned additions and generated caches.
    return True


def is_ida_plugin_installed() -> bool:
    return os.path.lexists(os.path.join(_get_ida_user_dir(), "plugins", "ida_mcp.py"))


def install_ida_plugin(
    *, uninstall: bool = False, quiet: bool = False, allow_ida_free: bool = False
):
    ida_folder = _get_ida_user_dir()
    if not allow_ida_free:
        free_licenses = glob.glob(os.path.join(ida_folder, "idafree_*.hexlic"))
        if free_licenses:
            print(
                "IDA Free does not support plugins and cannot be used. Purchase and install IDA Pro instead."
            )
            sys.exit(1)

    ida_plugin_folder = os.path.join(ida_folder, "plugins")
    if uninstall:
        removed = _uninstall_gui_bundle(ida_plugin_folder)
        if not quiet:
            print(
                "Uninstalled IDA Pro plugin"
                if removed
                else "Skipping IDA plugin uninstall (no owned bundle)"
            )
        return

    os.makedirs(ida_plugin_folder, exist_ok=True)
    _install_gui_bundle(ida_plugin_folder)
    if not quiet:
        print("Installed IDA Pro plugin (IDA restart required)")


def _resolve_transport(value: str) -> str:
    v = value.strip().lower()
    if v == "stdio":
        return "stdio"
    if v == "sse":
        return "sse"
    if v in ("http", "streamable-http", "streamable"):
        return "streamable-http"
    return "streamable-http"


def _get_install_transport(*, uninstall: bool, args, interactive: bool) -> str | None:
    if uninstall:
        return "stdio"
    if args.transport is not None:
        return _resolve_transport(args.transport)
    if not interactive:
        return "streamable-http"

    choice = interactive_choose(
        ["Streamable HTTP (recommended)", "stdio", "SSE"],
        "Select transport mode:",
    )
    if choice is None:
        return None
    if choice.startswith("stdio"):
        return "stdio"
    if choice.startswith("Streamable"):
        return "streamable-http"
    return "sse"


def _get_install_scope(args, *, interactive: bool) -> str | None:
    if args.scope:
        return args.scope
    if not interactive:
        return "project"

    choice = interactive_choose(
        ["Project (current directory)", "Global (user-level)"],
        "Select installation scope:",
    )
    if choice is None:
        return None
    if choice.startswith("Project"):
        return "project"
    return "global"


def _get_scope_selection_items(*, project: bool) -> list[tuple[str, bool]]:
    configs, _ = _get_scope_config_spec(project=project)
    return [
        (
            name,
            is_client_installed(name, config_dir, config_file, project=project),
        )
        for name, (config_dir, config_file) in configs.items()
    ]


def _apply_client_install(
    *,
    scope: str,
    transport: str,
    uninstall: bool,
    client_targets: list[str],
) -> None:
    if client_targets:
        install_mcp_servers(
            transport=transport,
            uninstall=uninstall,
            only=client_targets,
            project=(scope == "project"),
        )


def _parse_client_targets(targets_str: str) -> list[str]:
    return [
        target.strip()
        for target in targets_str.split(",")
        if target.strip() and target.strip().lower() != "ida-plugin"
    ]


def _interactive_install(*, uninstall: bool, args):
    action = "uninstall" if uninstall else "install"
    transport = _get_install_transport(uninstall=uninstall, args=args, interactive=True)
    if transport is None:
        print("Cancelled.")
        return

    scope = _get_install_scope(args, interactive=True)
    if scope is None:
        print("Cancelled.")
        return

    items = _get_scope_selection_items(project=(scope == "project"))
    if not items:
        print(f"Unsupported platform: {sys.platform}")
        return

    selected = interactive_select(items, f"Select {scope} targets to {action}:")
    if selected is None:
        print("Cancelled.")
        return

    _apply_client_install(
        scope=scope,
        transport=transport,
        uninstall=uninstall,
        client_targets=selected,
    )


def run_install_command(*, uninstall: bool, targets_str: str, args) -> None:
    install_ida_plugin(uninstall=uninstall, allow_ida_free=args.allow_ida_free)

    if targets_str:
        _apply_client_install(
            scope=_get_install_scope(args, interactive=False),
            transport=_get_install_transport(
                uninstall=uninstall, args=args, interactive=False
            ),
            uninstall=uninstall,
            client_targets=_parse_client_targets(targets_str),
        )
        return

    if sys.stdin.isatty():
        _interactive_install(uninstall=uninstall, args=args)
        return

    action = "installed" if not uninstall else "uninstalled"
    print(
        f"IDA plugin {action}. No TTY available for interactive client selection; "
        "pass explicit client targets to configure MCP clients."
    )
