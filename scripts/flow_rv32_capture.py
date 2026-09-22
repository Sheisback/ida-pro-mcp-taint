"""IDA ``-A -S`` entry point for static RV32 structured capture.

Usage: idat -c -A '-S/path/flow_rv32_capture.py ROOT OUTPUT REQUEST' BINARY

The binary is a disposable copy.  This script never initializes Hex-Rays,
opens a debugger, emulates code, or executes the target.
"""

import gc
import json
from pathlib import Path
import sys
from typing import cast

import ida_auto  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
import ida_pro  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
import idc  # pyright: ignore[reportMissingImports, reportMissingModuleSource]


def _write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def main() -> int:
    if len(idc.ARGV) != 4:
        return 2
    root, output_name, request_name = map(Path, idc.ARGV[1:])
    sys.path.insert(0, str(root / "src"))

    from ida_pro_mcp.flow_core.rv32_capture import (
        PROCESS_SCHEMA,
        CaptureRequest,
        ProcessReceipt,
    )
    from ida_pro_mcp.flow_core.serialization import canonical_json, digest
    from ida_pro_mcp.ida_mcp.flow.rv32_extractor import capture

    output = Path(output_name)
    try:
        request = cast(
            CaptureRequest, CaptureRequest.from_json(Path(request_name).read_text())
        )
        ida_auto.auto_wait()
        first = capture(request)
        gc.collect()
        second = capture(request)
        first_digest = digest(first)
        second_digest = digest(second)
        if first_digest != second_digest or first != second:
            raise RuntimeError("In-session RV32 capture drift")
        if type(first).from_json(canonical_json(first)) != first:
            raise RuntimeError("RV32 capture JSON roundtrip drift")
        receipt = ProcessReceipt(
            PROCESS_SCHEMA,
            first,
            first_digest,
            second_digest,
            True,
            True,
        )
        encoded = canonical_json(receipt).encode()
        if len(encoded) > request.budgets.max_output_bytes:
            raise RuntimeError("RV32 process receipt output budget exceeded")
        _write(output, receipt.to_data())
        return 0
    except Exception as exc:
        _write(
            output,
            {
                "schema_version": "flow-rv32-disassembly-process-failure/1",
                "status": "failed",
                "failure_type": type(exc).__name__,
                "failure_message": str(exc),
                "target_executed": False,
                "support_status": "unverified",
            },
        )
        return 1


if __name__ == "__main__":
    ida_pro.qexit(main())
