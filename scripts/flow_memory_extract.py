"""Static G007 IDA receipt: ROOT BUILD_MANIFEST OUTPUT_DIR ARCH. No target execution."""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import ida_auto
import ida_name
import ida_pro
import idc


def main():
    root, manifest, output, arch = idc.ARGV[1:]
    root, output = Path(root), Path(output)
    output.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(root / "src"))
    from ida_pro_mcp.flow_core import canonical_json, digest
    from ida_pro_mcp.flow_core.contracts import Snapshot

    path = root / "src/ida_pro_mcp/ida_mcp/flow/extractor.py"
    spec = importlib.util.spec_from_file_location("g007_extractor", path)
    extractor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(extractor)
    inventory = json.loads(
        (root / "tests/flow_fixtures/manifests/p0_inventory.json").read_text()
    )
    build = next(
        row for row in json.loads(Path(manifest).read_text()) if row["arch"] == arch
    )
    profile_id = "X64-LE" if arch == "x86_64" else "A64-LE"
    # Same already-measured ISA/ABI/maturity, new repository-owned fixture hash.
    inventory = json.loads(json.dumps(inventory))
    row = next(row for row in inventory["profiles"] if row["profile_id"] == profile_id)
    row["fixture_hashes"] = [build["binary_sha256"]]
    profile = extractor.anchor_profile(inventory, profile_id, build["abi_id"], [build])
    ida_auto.auto_wait()
    global_ea = ida_name.get_name_ea(idc.BADADDR, "memory_global")
    if global_ea == idc.BADADDR:
        global_ea = ida_name.get_name_ea(idc.BADADDR, "_memory_global")
    if global_ea == idc.BADADDR:
        raise ValueError("Fixture global symbol unavailable")
    for name in build["functions"]:
        ea = ida_name.get_name_ea(idc.BADADDR, name)
        if ea == idc.BADADDR:
            raise ValueError("Fixture function unavailable: " + name)
        first = extractor.extract_snapshot(
            ea, namespace="g007-" + arch, function_key=name, profile=profile
        )
        second = extractor.extract_snapshot(
            ea, namespace="g007-" + arch, function_key=name, profile=profile
        )
        assert canonical_json(first) == canonical_json(second)
        assert Snapshot.from_json(canonical_json(first)) == first
        receipt = {
            "schema_version": "flow-memory-extraction/1",
            "snapshot": first.to_data(),
            "canonical_digest": digest(first),
            "profile": profile,
            "function": name,
            "global_symbol": {
                "name": "memory_global",
                "ea": global_ea,
                "size_bytes": 1,
            },
            "extractor_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "repeat_equal": True,
            "roundtrip_equal": True,
            "target_executed": False,
        }
        (output / (arch + "_" + name + ".json")).write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        )


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback

        traceback.print_exc()
        ida_pro.qexit(1)
    ida_pro.qexit(0)
