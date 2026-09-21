"""IDA startup smoke: ROOT EXTRACTION OUTPUT. Static input only; never execute."""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import ida_auto
import ida_kernwin
import ida_nalt
import ida_pro
import idc


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load module: " + str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    root, extraction_path, output = idc.ARGV[1:]
    root = Path(root)
    extraction_path = Path(extraction_path)
    sys.path.insert(0, str(root / "src"))
    from ida_pro_mcp.flow_core.call_composition import CallCompositionResult
    from ida_pro_mcp.flow_core.summaries import SummaryCatalog

    extractor = load(
        root / "src/ida_pro_mcp/ida_mcp/flow/extractor.py",
        "g011_native_smoke_extractor",
    )
    catalog_module = load(
        root / "src/ida_pro_mcp/ida_mcp/flow/summary_catalog.py",
        "g011_native_smoke_catalog",
    )
    extraction = json.loads(extraction_path.read_text())
    ida_auto.auto_wait()
    input_digest = bytes(ida_nalt.retrieve_input_file_sha256()).hex()
    assert input_digest == extraction["binary"]["sha256"]
    catalog = SummaryCatalog.from_data(extraction["catalog"])
    assert catalog.catalog_digest == extraction["catalog_digest"]
    assert all(
        record["runtime"]["snapshot"]["identity"]["summary_digest"]
        == catalog.catalog_digest
        for record in extraction["functions"]
    )
    callee_snapshots = {
        record["rva"]: extractor.ExtractedFunction.from_data(
            record["baseline"]
        ).snapshot
        for record in extraction["functions"]
    }
    compositions = []
    for record in extraction["functions"]:
        function = extractor.ExtractedFunction.from_data(record["runtime"])
        bindings = tuple(
            catalog_module.CallBinding.from_data(value)
            for value in record["bindings"]
        )
        stored = tuple(
            CallCompositionResult.from_data(value)
            for value in record["compositions"]
        )
        assert len(bindings) == len(stored)
        for binding, expected in zip(bindings, stored):
            actual = catalog_module.compose_binding(
                function,
                binding,
                catalog,
                callee_snapshots=callee_snapshots,
            )
            assert actual == expected
            compositions.append(actual)
    receipt = {
        "schema_version": "flow-call-native-smoke/1",
        "ida_version": ida_kernwin.get_kernel_version(),
        "input_sha256": input_digest,
        "extraction_file_sha256": hashlib.sha256(
            extraction_path.read_bytes()
        ).hexdigest(),
        "catalog_digest": catalog.catalog_digest,
        "function_count": len(extraction["functions"]),
        "snapshot_catalog_scope_match": True,
        "actual_call_composition_verified": True,
        "actual_composition_count": len(compositions),
        "partial_composition_count": sum(
            item.status == "partial" for item in compositions
        ),
        "target_executed": False,
    }
    Path(output).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback

        traceback.print_exc()
        ida_pro.qexit(1)
    ida_pro.qexit(0)
