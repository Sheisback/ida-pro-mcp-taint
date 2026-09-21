"""Static G011 IDA receipt: ROOT MANIFEST BINARY OUTPUT ARCH.

The fixture target is loaded and decompiled only. It is never executed.
"""

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import ida_auto
import ida_name
import ida_pro
import idc


REVIEWED = (
    "call_identity",
    "call_copy",
    "call_fill",
    "call_output",
    "call_global",
    "call_alloc",
    "call_free",
)

# Source-reviewed shapes for entrypoints that have no native caller in this
# fixture. Called summaries use the observed CallInfo projection instead.
REVIEWED_SHAPES = {
    "call_identity": ([32], 32, False, 20, [32]),
    "call_copy": ([64, 64, 64], None, True, 0, []),
    "call_fill": ([64, 8, 64], None, True, 0, []),
    "call_output": ([64, 32], None, True, 0, []),
    "call_global": ([32], 32, False, 20, [32]),
    "call_alloc": ([64], 64, False, 10, [64]),
    "call_free": ([64], None, True, 0, []),
}


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load module: " + str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def symbol(name):
    ea = ida_name.get_name_ea(idc.BADADDR, name)
    if ea == idc.BADADDR:
        ea = ida_name.get_name_ea(idc.BADADDR, "_" + name)
    if ea == idc.BADADDR:
        raise ValueError("Fixture symbol unavailable: " + name)
    return int(ea)


def effect_specs(global_rva, summaries):
    MemoryEffect = summaries.MemoryEffect
    MemoryExtent = summaries.MemoryExtent
    ReturnEffect = summaries.ReturnEffect
    LifetimeEffect = summaries.LifetimeEffect
    return {
        "call_identity": (
            "identity",
            (ReturnEffect("argument", 32, argument_index=0),),
            (),
            (),
        ),
        "call_copy": (
            "copy",
            (),
            (
                MemoryEffect(
                    "copy",
                    "argument",
                    "argument_memory",
                    MemoryExtent(argument_index=2),
                    target_index=0,
                    source_index=1,
                ),
            ),
            (),
        ),
        "call_fill": (
            "fill",
            (),
            (
                MemoryEffect(
                    "fill",
                    "argument",
                    "argument",
                    MemoryExtent(argument_index=2),
                    target_index=0,
                    source_index=1,
                ),
            ),
            (),
        ),
        "call_output": (
            "output",
            (),
            (
                MemoryEffect(
                    "output",
                    "argument",
                    "argument",
                    MemoryExtent(fixed_bytes=4),
                    target_index=0,
                    source_index=1,
                ),
            ),
            (),
        ),
        "call_global": (
            "global",
            (ReturnEffect("global", 32, global_rva=global_rva),),
            (
                MemoryEffect(
                    "global_write",
                    "global",
                    "argument",
                    MemoryExtent(fixed_bytes=4),
                    target_rva=global_rva,
                    source_index=0,
                ),
            ),
            (),
        ),
        "call_alloc": (
            "alloc",
            (ReturnEffect("allocation", 64),),
            (),
            (LifetimeEffect("allocate", size_argument_index=0),),
        ),
        "call_free": (
            "free",
            (),
            (),
            (LifetimeEffect("free", pointer_argument_index=0),),
        ),
    }


def main():
    root, manifest_path, binary_path, output_path, arch = idc.ARGV[1:]
    root = Path(root)
    manifest_path = Path(manifest_path)
    binary_path = Path(binary_path)
    output_path = Path(output_path)
    sys.path.insert(0, str(root / "src"))

    from ida_pro_mcp.flow_core import canonical_json, digest
    from ida_pro_mcp.flow_core.contracts import Snapshot
    from ida_pro_mcp.flow_core.summaries import (
        ReviewedSummary,
        SummaryCatalog,
        SummaryIdentity,
    )

    extractor_path = root / "src/ida_pro_mcp/ida_mcp/flow/extractor.py"
    catalog_path = root / "src/ida_pro_mcp/ida_mcp/flow/summary_catalog.py"
    extractor = load(extractor_path, "g011_receipt_extractor")
    catalog_module = load(catalog_path, "g011_receipt_catalog")
    manifest = json.loads(manifest_path.read_text())
    build = next(row for row in manifest if row["arch"] == arch)
    actual_binary_sha256 = hashlib.sha256(binary_path.read_bytes()).hexdigest()
    if actual_binary_sha256 != build["binary_sha256"]:
        raise ValueError("Loaded binary differs from pinned build manifest")
    inventory = json.loads(
        (root / "tests/flow_fixtures/manifests/p0_inventory.json").read_text()
    )
    inventory = json.loads(json.dumps(inventory))
    profile_id = "X64-LE" if arch == "x86_64" else "A64-LE"
    row = next(row for row in inventory["profiles"] if row["profile_id"] == profile_id)
    row["fixture_hashes"] = [actual_binary_sha256]
    profile = extractor.anchor_profile(inventory, profile_id, build["abi_id"], [build])
    ida_auto.auto_wait()

    addresses = {name: symbol(name) for name in build["functions"]}
    image_base = min(
        extractor.extract_snapshot(
            addresses[build["functions"][0]],
            namespace="g011-probe-" + arch,
            function_key="image-base-probe",
            profile=profile,
            summary_digest=catalog_module.EMPTY_CATALOG.catalog_digest,
            include_calls=True,
        ).image_base,
        min(addresses.values()),
    )
    rvas = {name: ea - image_base for name, ea in addresses.items()}
    if any(rva < 0 for rva in rvas.values()):
        raise ValueError("Fixture function precedes image base")

    def extract_all(namespace, summary_digest):
        result = {}
        for name in build["functions"]:
            first = extractor.extract_snapshot(
                addresses[name],
                namespace=namespace,
                function_key=f"function-rva:{rvas[name]:x}",
                profile=profile,
                summary_digest=summary_digest,
                include_calls=True,
            )
            second = extractor.extract_snapshot(
                addresses[name],
                namespace=namespace,
                function_key=f"function-rva:{rvas[name]:x}",
                profile=profile,
                summary_digest=summary_digest,
                include_calls=True,
            )
            if canonical_json(first) != canonical_json(second):
                raise ValueError("Nondeterministic extraction: " + name)
            if extractor.ExtractedFunction.from_json(canonical_json(first)) != first:
                raise ValueError("Extraction roundtrip failed: " + name)
            result[name] = first
        return result

    baseline = extract_all(
        "g011-baseline-" + arch, catalog_module.EMPTY_CATALOG.catalog_digest
    )
    by_rva = {rvas[name]: function for name, function in baseline.items()}
    observed = {}
    direct_convention_codes = set()
    for caller in baseline.values():
        for observation in caller.calls:
            if observation.call.callee_ea is not None:
                target_rva = observation.call.callee_ea - caller.image_base
                if target_rva in by_rva:
                    direct_convention_codes.add(observation.call.convention)
                    observed.setdefault(target_rva, []).append((caller, observation.call))
    if len(direct_convention_codes) != 1:
        raise ValueError(
            "Fixture needs one measured C calling convention: "
            + repr(sorted(direct_convention_codes))
        )
    convention_code = next(iter(direct_convention_codes))

    global_rva = symbol("call_global_value") - image_base
    specs = effect_specs(global_rva, sys.modules[SummaryIdentity.__module__])
    reviewed = []
    identities = {}
    for name in REVIEWED:
        function = baseline[name]
        entries = observed.get(rvas[name], [])
        if entries:
            keys = {
                (
                    catalog_module.calling_convention(caller.snapshot, call),
                    catalog_module.signature_digest(call),
                )
                for caller, call in entries
            }
            if len(keys) != 1:
                raise ValueError("Inconsistent observed signature: " + name)
            convention, signature = next(iter(keys))
        else:
            arguments, width, void, type_code, returns = REVIEWED_SHAPES[name]
            projection = {
                "version": 1,
                "argument_width_bits": arguments,
                "return_width_bits": width,
                "return_is_void": void,
                "return_type_code": type_code,
                "return_operand_width_bits": returns,
            }
            convention = (
                f"{function.snapshot.identity.environment.abi}:"
                f"ida-cc-{convention_code}"
            )
            signature = digest(projection)
        identity = SummaryIdentity(
            actual_binary_sha256,
            rvas[name],
            function.snapshot.snapshot_id,
            function.snapshot.identity.profile_digest,
            convention,
            signature,
        )
        identities[name] = identity
        kind, returns, memory, lifetime = specs[name]
        reviewed.append(
            ReviewedSummary(
                identity,
                name,
                kind,
                returns,
                memory,
                lifetime,
                "g011-fixture-review",
                digest(
                    {
                        "fixture": "tests/flow_fixtures/call_heap_anchor.c",
                        "oracle": "tests/flow_fixtures/oracles/calls.json",
                        "summary": name,
                        "effects": {
                            "returns": [value.to_data() for value in returns],
                            "memory": [value.to_data() for value in memory],
                            "lifetime": [value.to_data() for value in lifetime],
                        },
                    }
                ),
            )
        )
    catalog = SummaryCatalog(
        tuple(sorted(reviewed, key=lambda item: item.identity.sort_key))
    )
    runtime = extract_all("g011-runtime-" + arch, catalog.catalog_digest)
    baseline_by_rva = {rvas[name]: value.snapshot for name, value in baseline.items()}
    runtime_by_rva = {rvas[name]: value for name, value in runtime.items()}
    bindings = {}
    compositions = {}
    for name, function in runtime.items():
        rows = []
        for observation in function.calls:
            candidates = ()
            exhaustive = False
            if observation.call.callee_ea is None and name == "call_indirect":
                candidates = tuple(
                    sorted(
                        (
                            identities[target]
                            if target in identities
                            else catalog_module.target_identity(
                                function.snapshot,
                                observation.call,
                                rvas[target],
                                baseline[target].snapshot,
                            )
                            for target in (
                                "call_identity",
                                "call_candidate_increment",
                            )
                        ),
                        key=lambda item: item.sort_key,
                    )
                )
            rows.append(
                catalog_module.bind_call(
                    function,
                    observation,
                    catalog,
                    baseline_by_rva,
                    indirect_candidates=candidates,
                    exhaustive=exhaustive,
                )
            )
        bindings[name] = rows
        compositions[name] = [
            catalog_module.compose_binding(
                function,
                binding,
                catalog,
                callee_snapshots=baseline_by_rva,
            )
            for binding in rows
        ]
    closure, boundaries = catalog_module.bounded_callee_closure(
        tuple(sorted(runtime_by_rva)), runtime_by_rva, max_depth=8, max_functions=64
    )
    receipt = {
        "schema_version": "flow-call-extraction/1",
        "arch": arch,
        "binary": {
            "path": build["binary"],
            "sha256": actual_binary_sha256,
            "image_base": image_base,
        },
        "profile": profile,
        "build_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "extractor_sha256": hashlib.sha256(extractor_path.read_bytes()).hexdigest(),
        "catalog_module_sha256": hashlib.sha256(catalog_path.read_bytes()).hexdigest(),
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "baseline_summary_digest": catalog_module.EMPTY_CATALOG.catalog_digest,
        "catalog": catalog.to_data(),
        "catalog_digest": catalog.catalog_digest,
        "functions": [
            {
                "name": name,
                "rva": rvas[name],
                "baseline": baseline[name].to_data(),
                "baseline_digest": digest(baseline[name]),
                "runtime": runtime[name].to_data(),
                "runtime_digest": digest(runtime[name]),
                "bindings": [binding.to_data() for binding in bindings[name]],
                "compositions": [
                    composition.to_data() for composition in compositions[name]
                ],
            }
            for name in build["functions"]
        ],
        "closure": {
            "root_rvas": sorted(runtime_by_rva),
            "visited_rvas": list(closure),
            "boundaries": [boundary.to_data() for boundary in boundaries],
            "max_depth": 8,
            "max_functions": 64,
        },
        "repeat_equal": True,
        "roundtrip_equal": all(
            Snapshot.from_data(value.snapshot.to_data()) == value.snapshot
            for value in runtime.values()
        ),
        "target_executed": False,
        "fresh_static_ida_extraction": True,
        "limitations": [
            "Fixture symbols are discovery metadata only; bindings use pinned identities.",
            "CallInfo exposes width/type-code shape but not complete native type and argloc normalization.",
            "Non-exhaustive indirect and unreviewed direct targets retain explicit unknown effects.",
            "No automatic CWE, severity, safe, or vulnerable verdict is produced.",
        ],
    }
    output_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback

        traceback.print_exc()
        ida_pro.qexit(1)
    ida_pro.qexit(0)
