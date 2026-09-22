"""IDA GUI-process entry point for one static capability receipt."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import traceback

import ida_auto  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
import ida_kernwin  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
import ida_nalt  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
import ida_pro  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
import idc  # pyright: ignore[reportMissingImports, reportMissingModuleSource]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    root_text, output_text, request_text = idc.ARGV[1:]
    root = Path(root_text).resolve()
    output = Path(output_text)
    request = json.loads(Path(request_text).read_text())
    if (
        set(request)
        != {
            "schema_version",
            "checkout_sha",
            "fixture_sha256",
            "ida_executable_sha256",
        }
        or request["schema_version"] != "flow-gui-request/1"
    ):
        raise ValueError("Invalid GUI evidence request")
    input_path = Path(ida_nalt.get_input_file_path())
    before = sha256(input_path)
    if before != request["fixture_sha256"]:
        raise ValueError("GUI process opened unexpected input bytes")

    sys.path.insert(0, str(root / "src"))
    from ida_pro_mcp.flow_core.serialization import digest
    from ida_pro_mcp.ida_mcp import api_flow

    ida_auto.auto_wait()
    capabilities = api_flow.flow_get_capabilities()
    environment = capabilities["environment"]
    if sha256(input_path) != before:
        raise RuntimeError("GUI capability probe changed its input")
    receipt = {
        "schema_version": "flow-gui-process/1",
        "checkout_sha": request["checkout_sha"],
        "flow_build_id": capabilities["build_id"],
        "ida_build": ida_kernwin.get_kernel_version(),
        "hexrays_build": environment["hexrays_version"],
        "ida_executable_sha256": request["ida_executable_sha256"],
        "capabilities": capabilities,
        "capabilities_digest": digest(capabilities),
        "process_kind": "ida-gui",
        "disposable_user_dir": True,
        "eula_accepted_during_probe": False,
        "target_executed": False,
        "input_preserved": True,
    }
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        ida_pro.qexit(1)
    ida_pro.qexit(0)
