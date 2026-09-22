"""Static-only IDA extraction for one pinned G015 public sample binary."""

import gc
import hashlib
import importlib.util
import json
import sys
from copy import deepcopy
from pathlib import Path

import ida_auto
import ida_hexrays
import ida_kernwin
import ida_name
import ida_nalt
import ida_pro
import idc


def main():
    root, output, request_path = idc.ARGV[1:]
    root = Path(root)
    output = Path(output)
    request = json.loads(Path(request_path).read_text())
    sys.path.insert(0, str(root / "src"))
    from ida_pro_mcp.flow_core import canonical_json, digest
    from ida_pro_mcp.flow_core.contracts import Snapshot

    extractor_path = root / "src/ida_pro_mcp/ida_mcp/flow/extractor.py"
    spec = importlib.util.spec_from_file_location(
        "public_sample_extractor", extractor_path
    )
    extractor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(extractor)
    profile = deepcopy(
        json.loads(
            (
                root / "tests/flow_fixtures/manifests/calls/extraction_x86_64.json"
            ).read_text()
        )["profile"]
    )
    profile["abi_provenance"] = {
        "kind": "measured_anchor_build",
        "corpus": request["corpus"],
        "case_id": request["case_id"],
        "source_sha256": request["source_sha256"],
        "binary_sha256": request["binary_sha256"],
        "compiler": request["compiler"],
        "sdk_version": request["sdk_version"],
    }
    input_path = Path(ida_nalt.get_input_file_path())
    observed_binary_sha256 = hashlib.sha256(input_path.read_bytes()).hexdigest()
    if observed_binary_sha256 != request["binary_sha256"]:
        raise ValueError("IDA input hash does not match the pinned build")
    ida_auto.auto_wait()
    functions = []
    for row in request["functions"]:
        ea = ida_name.get_name_ea(idc.BADADDR, row["selector"])
        if ea == idc.BADADDR:
            raise ValueError("Pinned function selector not found: " + row["selector"])
        kwargs = {
            "namespace": request["namespace"],
            "function_key": row["function_key"],
            "profile": profile,
            "include_calls": True,
        }
        # The first microcode generation may refine IDA's inferred types. Freeze
        # receipts only after that deterministic warm-up boundary.
        extractor.extract_snapshot(ea, **kwargs)
        gc.collect()
        first = extractor.extract_snapshot(ea, **kwargs)
        gc.collect()
        second = extractor.extract_snapshot(ea, **kwargs)
        if canonical_json(first) != canonical_json(second):
            raise ValueError("Post-warm-up static extraction is not repeatable")
        if Snapshot.from_json(canonical_json(first.snapshot)) != first.snapshot:
            raise ValueError("Static extraction does not round-trip")
        calls = []
        for call in first.calls:
            observation = call.to_data()
            callee_ea = observation["call"]["callee_ea"]
            observation["callee_name"] = (
                ida_name.get_name(callee_ea) if callee_ea is not None else None
            )
            calls.append(observation)
        functions.append(
            {
                **row,
                "image_base": first.image_base,
                "function_rva": first.function_rva,
                "snapshot": first.snapshot.to_data(),
                "calls": calls,
                "canonical_digest": digest(first.snapshot),
                "repeat_equal": True,
                "roundtrip_equal": True,
            }
        )
    receipt = {
        "schema_version": "flow-public-sample-static/1",
        "corpus": request["corpus"],
        "case_id": request["case_id"],
        "binary_sha256": observed_binary_sha256,
        "source_sha256": request["source_sha256"],
        "profile": profile,
        "environment": {
            "ida_version": ida_kernwin.get_kernel_version(),
            "hexrays_version": ida_hexrays.get_hexrays_version(),
        },
        "functions": functions,
        "extractor_sha256": hashlib.sha256(extractor_path.read_bytes()).hexdigest(),
        "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "target_executed": False,
    }
    output.write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback

        traceback.print_exc()
        ida_pro.qexit(1)
    ida_pro.qexit(0)
