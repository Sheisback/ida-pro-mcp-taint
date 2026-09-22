#!/usr/bin/env python3
"""Record and replay the pinned BinCAT x64 structured extraction statically."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
import tempfile
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import cast


ROOT = Path(__file__).resolve().parents[1]
ACQUIRE_SCRIPT = ROOT / "scripts/acquire_bincat_x64.py"
IDA_SCRIPT = ROOT / "scripts/flow_bincat_x64_extract.py"
MANIFEST = ROOT / "tests/flow_fixtures/public/bincat_x64/provenance.json"
IDENTITY = ROOT / "tests/flow_fixtures/public/bincat_x64/identity.json"
PE_PROFILE_RECEIPT = (
    ROOT / "tests/flow_fixtures/manifests/profile_semantics/formats/x64-le--pe.json"
)
DEFAULT_IDAT = Path("/Applications/IDA Professional 9.3.app/Contents/MacOS/idat")
FUNCTIONS = (
    {"name": "custom_crc32", "rva": 0x10EC, "function_key": "bincat-custom-crc32"},
    {"name": "compute_hash", "rva": 0x1134, "function_key": "bincat-compute-hash"},
    {"name": "main", "rva": 0x1258, "function_key": "bincat-main"},
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_script(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load " + name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def replay(functions: list[dict]) -> dict:
    from ida_pro_mcp.flow_core.analysis import Seed, analyze
    from ida_pro_mcp.flow_core.contracts import Snapshot
    from ida_pro_mcp.flow_core.memory import build_memory_plan
    from ida_pro_mcp.flow_core.memory_analysis import analyze_memory
    from ida_pro_mcp.flow_core.ssa import build_ssa
    from ida_pro_mcp.flow_core.states import Labels

    rows = []
    for function in functions:
        snapshot = cast(Snapshot, Snapshot.from_data(function["snapshot"]))
        program = build_ssa(snapshot)
        scalar = analyze(program.graph)
        plan = build_memory_plan(program)
        memory = analyze_memory(plan, ())
        nodes = {node.node_id: node for node in program.graph.nodes}
        row = {
            "function_key": function["function_key"],
            "graph_digest": program.graph.graph_digest,
            "node_kinds": dict(
                sorted(Counter(n.kind for n in program.graph.nodes).items())
            ),
            "edge_kinds": dict(
                sorted(Counter(e.kind for e in program.graph.edges).items())
            ),
            "program_diagnostics": list(program.diagnostics),
            "scalar_status": scalar.status,
            "scalar_diagnostics": list(scalar.diagnostics),
            "memory_status": memory.status,
            "memory_diagnostics": list(memory.diagnostics),
            "memory_access_count": len(memory.accesses),
            "memory_dependency_count": len(memory.dependencies),
            "call_count": len(function["calls"]),
            "unresolved_call_count": sum(
                bool(call["call"]["unresolved"]) or call["call"]["callee_ea"] is None
                for call in function["calls"]
            ),
        }
        if function["function_key"] == "bincat-custom-crc32":
            loads = [node for node in program.graph.nodes if node.kind == "Load"]
            if len(loads) != 1 or loads[0].memory_operands is None:
                raise ValueError("Unexpected custom_crc32 load inventory")
            load = loads[0]
            memory_operands = load.memory_operands
            if memory_operands is None:
                raise ValueError("custom_crc32 load lacks memory operands")
            address_node = memory_operands.address
            pointer = analyze_memory(
                plan,
                (),
                value_seeds=(Seed(address_node, Labels(("pointer_value",))),),
            )
            load_fact = next(
                item for item in pointer.facts if item.node_id == load.node_id
            )
            row["pointer_value_probe"] = {
                "load_node": load.node_id,
                "address_node": address_node,
                "load_labels": load_fact.labels.to_data(),
                "address_labels": load_fact.address_labels.to_data(),
                "separation_proven": (
                    "pointer_value" not in load_fact.labels.explicit
                    and "pointer_value" in load_fact.address_labels.explicit
                ),
                "pointed_bytes_status": "unknown_without_memory_object_seed",
                "memory_status": pointer.status,
                "memory_diagnostics": list(pointer.diagnostics),
            }
        if function["function_key"] == "bincat-compute-hash":
            offsets = []
            load_nodes = []
            for node in program.graph.nodes:
                if node.kind != "Load" or node.width_bits != 64:
                    continue
                if node.memory_operands is None:
                    raise ValueError("Load lacks structured memory operands")
                address = nodes[node.memory_operands.address]
                if address.kind == "InputValue":
                    offset = 0
                elif address.kind == "Binary" and address.operation == "add":
                    constants = [
                        nodes[item].constant
                        for item in address.inputs
                        if nodes[item].kind == "Constant"
                    ]
                    if len(constants) != 1 or type(constants[0]) is not int:
                        raise ValueError("Ambiguous user_info field offset")
                    offset = constants[0]
                else:
                    raise ValueError("Unexpected user_info field address shape")
                offsets.append(offset)
                load_nodes.append(node.node_id)
            if sorted(offsets) != [0, 8, 16, 24] or len(set(load_nodes)) != 4:
                raise ValueError("user_info field-load separation drift")
            row["user_info_fields"] = {
                "offsets": sorted(offsets),
                "width_bytes": 8,
                "load_nodes": sorted(load_nodes),
                "whole_struct_collapsed": False,
            }
        rows.append(row)
    return {
        "schema_version": "bincat-x64-core-replay/1",
        "functions": rows,
        "status": "partial",
        "buffer_write_status": "partial_unresolved_boundary",
        "buffer_write_reason": (
            "sprintf output-buffer effects have no reviewed summary in this receipt; "
            "the engine retains call/memory uncertainty and does not claim propagation"
        ),
        "vulnerability_or_safety_verdict": False,
    }


def record(cache_root: Path, output: Path, idat: Path = DEFAULT_IDAT) -> dict:
    acquisition = load_script(ACQUIRE_SCRIPT, "bincat_x64_acquisition_flow")
    manifest = acquisition.load_manifest(MANIFEST)
    acquisition.verify_cache(manifest, cache_root)
    identity = acquisition.identity_report(cache_root)
    if identity["binary_pdb_correspondence"]["status"] != "proven":
        raise ValueError("BinCAT PE/PDB identity is not proven")
    if identity["source_correspondence"]["status"] != "unproven":
        raise ValueError("BinCAT source authority must remain downgraded")
    if not idat.is_file() or idat.name != "idat":
        raise ValueError("BinCAT flow recorder requires IDA text executable idat")

    profile_evidence = json.loads(PE_PROFILE_RECEIPT.read_text())
    profile = deepcopy(profile_evidence["profile"])
    binary = cache_root / "doc/get_key/get_key_x64_win.exe"
    pdb = cache_root / "doc/get_key/get_key_x64_win.pdb"
    profile["abi_provenance"] = {
        "kind": "measured_anchor_build",
        "scope": (
            "prior measured Windows-x64 PE extractor configuration applied to this "
            "exact runtime binary; not source-build correspondence"
        ),
        "binary_sha256": sha256(binary),
        "pdb_sha256": sha256(pdb),
        "pdb_guid": identity["pdb"]["guid"],
        "pdb_age": identity["pdb"]["age"],
        "source_correspondence": "unproven",
    }
    implementation = {
        "scripts/flow_bincat_x64_extract.py": sha256(IDA_SCRIPT),
        "src/ida_pro_mcp/ida_mcp/flow/extractor.py": sha256(
            ROOT / "src/ida_pro_mcp/ida_mcp/flow/extractor.py"
        ),
    }
    request = {
        "schema_version": "bincat-x64-flow-request/1",
        "binary_sha256": sha256(binary),
        "pdb_sha256": sha256(pdb),
        "identity_sha256": sha256(IDENTITY),
        "namespace": "g015-bincat-x64",
        "functions": list(FUNCTIONS),
        "profile": profile,
        "registry": profile_evidence["registry"],
        "implementation": implementation,
    }

    before = sha256(binary)
    with tempfile.TemporaryDirectory(prefix="g015-bincat-flow-") as directory:
        run = Path(directory)
        target = run / binary.name
        pdb_copy = run / pdb.name
        pdb_alias = run / "Bincat_get_key.pdb"
        request_path = run / "request.json"
        receipt_path = run / "receipt.json"
        log_path = run / "ida.log"
        shutil.copy2(binary, target)
        shutil.copy2(pdb, pdb_copy)
        shutil.copy2(pdb, pdb_alias)
        request_path.write_text(json.dumps(request, indent=2) + "\n")
        command = [
            str(idat),
            f"-L{log_path}",
            "-c",
            "-A",
            f"-S{IDA_SCRIPT} {ROOT} {receipt_path} {request_path}",
            str(target),
        ]
        process = subprocess.run(command, check=False, timeout=180)
        if process.returncode != 0:
            log = log_path.read_text(errors="replace") if log_path.exists() else ""
            raise RuntimeError("BinCAT structured extraction failed:\n" + log[-8000:])
        if sha256(binary) != before or sha256(target) != before:
            raise ValueError("BinCAT structured extraction changed its input")
        receipt = json.loads(receipt_path.read_text())
        if receipt.get("target_executed") is not False:
            raise ValueError("BinCAT flow receipt executed the target")
        receipt.update(
            {
                "input_preserved": True,
                "invocation": [
                    "idat",
                    "-L$LOG",
                    "-c",
                    "-A",
                    "-Sscripts/flow_bincat_x64_extract.py $ROOT $OUTPUT $REQUEST",
                    "$BINARY",
                ],
                "ida_log_captured": log_path.is_file(),
                "recorder_sha256": sha256(Path(__file__)),
                "identity": identity,
                "core_replay": replay(receipt["functions"]),
            }
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache_root", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--idat", type=Path, default=DEFAULT_IDAT)
    arguments = parser.parse_args()
    record(
        arguments.cache_root.resolve(),
        arguments.output.resolve(),
        arguments.idat.resolve(),
    )


if __name__ == "__main__":
    main()
