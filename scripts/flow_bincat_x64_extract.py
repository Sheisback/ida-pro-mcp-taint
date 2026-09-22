"""IDA-only structured extraction for the pinned BinCAT Windows x64 PE."""

from __future__ import annotations

import gc
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import cast

import ida_auto
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_name
import ida_nalt
import ida_pro
import idc


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    root_text, output_text, request_text = idc.ARGV[1:]
    root = Path(root_text).resolve()
    output = Path(output_text)
    request = json.loads(Path(request_text).read_text())
    if set(request) != {
        "schema_version",
        "binary_sha256",
        "pdb_sha256",
        "identity_sha256",
        "namespace",
        "functions",
        "profile",
        "registry",
        "implementation",
    }:
        raise ValueError("BinCAT flow request keys mismatch")
    if request["schema_version"] != "bincat-x64-flow-request/1":
        raise ValueError("Unsupported BinCAT flow request")
    sys.path.insert(0, str(root / "src"))

    from ida_pro_mcp.flow_core.contracts import Snapshot
    from ida_pro_mcp.flow_core.profile_registry import ProfileRegistry
    from ida_pro_mcp.flow_core.serialization import canonical_json, digest

    extractor_path = root / "src/ida_pro_mcp/ida_mcp/flow/extractor.py"
    spec = importlib.util.spec_from_file_location(
        "bincat_flow_extractor", extractor_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load structured extractor")
    extractor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(extractor)
    for relative, expected in request["implementation"].items():
        path = (root / relative).resolve()
        path.relative_to(root)
        if sha256(path) != expected:
            raise ValueError("BinCAT flow implementation digest mismatch: " + relative)

    registry = cast(ProfileRegistry, ProfileRegistry.from_data(request["registry"]))
    registry.validate_extraction_profile(request["profile"])
    provenance = request["profile"]["abi_provenance"]
    if (
        provenance.get("binary_sha256") != request["binary_sha256"]
        or provenance.get("pdb_sha256") != request["pdb_sha256"]
        or provenance.get("source_correspondence") != "unproven"
    ):
        raise ValueError("BinCAT flow profile provenance mismatch")

    input_path = Path(ida_nalt.get_input_file_path())
    if sha256(input_path) != request["binary_sha256"]:
        raise ValueError("IDA input does not match the pinned BinCAT PE")
    ida_auto.auto_wait()
    image_base = int(ida_nalt.get_imagebase())
    rows = []
    for selector in request["functions"]:
        ea = ida_name.get_name_ea(idc.BADADDR, selector["name"])
        if ea == idc.BADADDR:
            raise ValueError(
                "Missing PDB-selected BinCAT function: " + selector["name"]
            )
        function = ida_funcs.get_func(ea)
        if function is None or int(function.start_ea) != ea:
            raise ValueError("Invalid PDB-selected BinCAT function entry")
        if ea - image_base != selector["rva"]:
            raise ValueError("BinCAT snapshot-local x64 RVA drift")
        kwargs = {
            "namespace": request["namespace"],
            "function_key": selector["function_key"],
            "profile": request["profile"],
            "include_calls": True,
            "registry": registry,
        }
        extractor.extract_snapshot(ea, **kwargs)
        gc.collect()
        first = extractor.extract_snapshot(ea, **kwargs)
        gc.collect()
        second = extractor.extract_snapshot(ea, **kwargs)
        if canonical_json(first) != canonical_json(second):
            raise ValueError("BinCAT structured extraction is not repeatable")
        if Snapshot.from_json(canonical_json(first.snapshot)) != first.snapshot:
            raise ValueError("BinCAT structured snapshot does not round-trip")
        rows.append(
            {
                **selector,
                "image_base": first.image_base,
                "function_rva": first.function_rva,
                "function_size": int(function.end_ea) - int(function.start_ea),
                "snapshot": first.snapshot.to_data(),
                "calls": [call.to_data() for call in first.calls],
                "canonical_digest": digest(first.snapshot),
                "repeat_equal": True,
                "roundtrip_equal": True,
            }
        )
    receipt = {
        "schema_version": "bincat-x64-flow-static/1",
        "binary_sha256": request["binary_sha256"],
        "pdb_sha256": request["pdb_sha256"],
        "identity_sha256": request["identity_sha256"],
        "profile": request["profile"],
        "registry_digest": digest(registry),
        "environment": {
            "ida_version": ida_kernwin.get_kernel_version(),
            "hexrays_version": ida_hexrays.get_hexrays_version(),
        },
        "functions": rows,
        "extractor_sha256": sha256(extractor_path),
        "generator_sha256": sha256(Path(__file__)),
        "target_executed": False,
        "debugger_attached": False,
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
