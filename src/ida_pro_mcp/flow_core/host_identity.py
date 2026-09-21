"""POSIX host-owned namespace registry; paths and secrets never come from MCP."""

import json
import os
from pathlib import Path
import secrets
import re

from .persistence import _directory, _file_check, _sync_directory, require
from .serialization import canonical_json, digest


def identity(root, database_path):
    require(os.name == "posix", "flow_runtime_unavailable_non_posix")
    import fcntl

    root = Path(root).absolute()
    _directory(root, create=True)
    lockpath = root / "registry.lock"
    fd = os.open(lockpath, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        _file_check(lockpath)
        fcntl.flock(fd, fcntl.LOCK_EX)
        path = root / "registry.json"
        if path.exists() or path.is_symlink():
            _file_check(path)
            data = json.loads(path.read_text())
            require(
                set(data) == {"version", "owner", "databases"} and data["version"] == 1,
                "invalid_host_registry",
            )
        else:
            data = {"version": 1, "owner": secrets.token_hex(32), "databases": {}}
        require(
            type(data["owner"]) is str and re.fullmatch(r"[0-9a-f]{64}", data["owner"]),
            "invalid_host_owner",
        )
        require(
            type(data["databases"]) is dict
            and all(
                type(key) is str
                and re.fullmatch(r"sha256-v1:[0-9a-f]{64}", key)
                and type(value) is str
                and re.fullmatch(r"database_[0-9a-f]{48}", value)
                for key, value in data["databases"].items()
            ),
            "invalid_host_namespaces",
        )
        key = digest({"database_path": str(Path(database_path).absolute())})
        if key not in data["databases"]:
            data["databases"][key] = "database_" + secrets.token_hex(24)
            temp = root / ("registry-" + secrets.token_hex(16) + ".tmp")
            out = os.open(
                temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
            try:
                with os.fdopen(out, "wb") as stream:
                    stream.write(canonical_json(data).encode())
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temp, path)
                _sync_directory(root)
            finally:
                temp.unlink(missing_ok=True)
        return data["databases"][key], data["owner"]
    finally:
        os.close(fd)
