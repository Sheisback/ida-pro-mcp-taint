"""Static IDA startup regression: ROOT OUTPUT PROFILE ABI FUNCTION NAME_SPACE."""

import gc
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import ida_auto
import ida_name
import ida_pro
import idc


def main():
    root, output, profile_id, abi, selector, namespace = idc.ARGV[1:]
    root = Path(root)
    sys.path.insert(0, str(root / "src"))
    from ida_pro_mcp.flow_core import canonical_json, digest
    from ida_pro_mcp.flow_core.contracts import Snapshot

    path = root / "src/ida_pro_mcp/ida_mcp/flow/extractor.py"
    spec = importlib.util.spec_from_file_location("receipt_extractor", path)
    extractor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(extractor)
    inventory = json.loads(
        (root / "tests/flow_fixtures/manifests/p0_inventory.json").read_text()
    )
    profile = extractor.anchor_profile(
        inventory,
        profile_id,
        abi,
        json.loads((root / "tests/flow_fixtures/manifests/build.json").read_text()),
    )
    ida_auto.auto_wait()
    ea = ida_name.get_name_ea(idc.BADADDR, selector)
    first = extractor.extract_snapshot(
        ea, namespace=namespace, function_key="fixture-function-0", profile=profile
    )
    gc.collect()
    second = extractor.extract_snapshot(
        ea, namespace=namespace, function_key="fixture-function-0", profile=profile
    )
    assert canonical_json(first) == canonical_json(second)
    assert Snapshot.from_json(canonical_json(first)) == first
    other = extractor.extract_snapshot(
        ea,
        namespace=namespace + "-other",
        function_key="fixture-function-0",
        profile=profile,
    )
    assert first.snapshot_id != other.snapshot_id
    receipt = {
        "schema_version": "flow-extraction-receipt/1",
        "extractor_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "snapshot": first.to_data(),
        "canonical_digest": digest(first),
        "repeat_equal": True,
        "roundtrip_equal": True,
        "namespace_isolated": True,
        "target_executed": False,
        "profile": profile,
    }
    Path(output).write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback

        traceback.print_exc()
        ida_pro.qexit(1)
    ida_pro.qexit(0)
