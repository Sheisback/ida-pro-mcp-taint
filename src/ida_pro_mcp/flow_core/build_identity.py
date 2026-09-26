"""Content identity shared by source, wheel, headless, and GUI runtimes."""

import hashlib
from pathlib import Path

from .serialization import digest


def _runtime_files() -> tuple[Path, ...]:
    package = Path(__file__).resolve().parents[1]
    files = list((package / "flow_core").glob("*.py"))
    files.extend((package / "flow_angr").glob("*.py"))
    files.extend((package / "ida_mcp" / "flow").glob("*.py"))
    files.append(package / "ida_mcp" / "api_flow.py")
    return tuple(sorted(files, key=lambda path: str(path.relative_to(package))))


def extension_build_id() -> str:
    """Hash the complete flow runtime without depending on a checkout or git."""
    package = Path(__file__).resolve().parents[1]
    manifest = {
        str(path.relative_to(package)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in _runtime_files()
    }
    return "flow-build-" + digest(manifest)


BUILD_ID = extension_build_id()
BUILD_SCOPE = (
    "flow_core/*.py, flow_angr/*.py, ida_mcp/flow/*.py, "
    "and ida_mcp/api_flow.py content manifest"
)


__all__ = ["BUILD_ID", "BUILD_SCOPE", "extension_build_id"]
