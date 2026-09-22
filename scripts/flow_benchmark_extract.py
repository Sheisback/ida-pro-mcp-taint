"""IDA entry point for one measured static microcode extraction benchmark."""

from __future__ import annotations

import gc
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import traceback

import ida_auto  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
import ida_name  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
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
            "fixture_sha256",
            "profile_id",
            "abi_id",
            "selector",
            "namespace",
            "inventory",
            "build_manifest",
        }
        or request["schema_version"] != "flow-benchmark-extraction-request/1"
    ):
        raise ValueError("Invalid benchmark extraction request")
    input_path = Path(ida_nalt.get_input_file_path())
    before = sha256(input_path)
    if before != request["fixture_sha256"]:
        raise ValueError("Benchmark input digest mismatch")

    sys.path.insert(0, str(root / "src"))
    from ida_pro_mcp.flow_core.contracts import Snapshot
    from ida_pro_mcp.flow_core.serialization import canonical_json, digest

    extractor_path = root / "src/ida_pro_mcp/ida_mcp/flow/extractor.py"
    spec = importlib.util.spec_from_file_location("benchmark_extractor", extractor_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load the reviewed extractor")
    extractor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(extractor)
    profile = extractor.anchor_profile(
        request["inventory"],
        request["profile_id"],
        request["abi_id"],
        request["build_manifest"],
    )

    ida_auto.auto_wait()
    ea = int(ida_name.get_name_ea(idc.BADADDR, request["selector"]))
    if ea == idc.BADADDR:
        raise ValueError("Benchmark selector was not resolved")
    first = extractor.extract_snapshot(
        ea,
        namespace=request["namespace"],
        function_key="benchmark-function-0",
        profile=profile,
    )
    gc.collect()
    second = extractor.extract_snapshot(
        ea,
        namespace=request["namespace"],
        function_key="benchmark-function-0",
        profile=profile,
    )
    if canonical_json(first) != canonical_json(second):
        raise RuntimeError("Benchmark extraction was nondeterministic")
    if Snapshot.from_json(canonical_json(first)) != first:
        raise RuntimeError("Benchmark snapshot roundtrip failed")
    if sha256(input_path) != before:
        raise RuntimeError("Benchmark extraction changed its input")
    receipt = {
        "schema_version": "flow-benchmark-extraction/1",
        "entry_sha256": sha256(Path(__file__)),
        "extractor_sha256": sha256(extractor_path),
        "snapshot": first.to_data(),
        "snapshot_digest": digest(first),
        "environment": first.identity.environment.to_data(),
        "repeat_equal": True,
        "roundtrip_equal": True,
        "input_preserved": True,
        "target_executed": False,
        "profile": profile,
    }
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        ida_pro.qexit(1)
    ida_pro.qexit(0)
