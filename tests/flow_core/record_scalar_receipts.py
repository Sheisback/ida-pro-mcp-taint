"""Recompute pure scalar receipts from pinned G005 static snapshots; no target runs."""

from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

from ida_pro_mcp.flow_core import digest
from ida_pro_mcp.flow_core.analysis import Seed, analyze
from ida_pro_mcp.flow_core.contracts import Snapshot
from ida_pro_mcp.flow_core.ssa import SSAProgram, build_ssa
from ida_pro_mcp.flow_core.serialization import canonical_json
from ida_pro_mcp.flow_core.states import Labels

ROOT = Path(__file__).resolve().parents[2]


def receipt(anchor):
    path = ROOT / f"tests/flow_fixtures/manifests/extraction_{anchor}.json"
    extraction = json.loads(path.read_text())
    snapshot = Snapshot.from_data(extraction["snapshot"])
    if digest(snapshot) != extraction["canonical_digest"]:
        raise ValueError("Stale G005 snapshot receipt")
    program = build_ssa(snapshot)
    # Structural selector, not an ABI argument-number inference.
    storage = snapshot.function.blocks[1].instructions[0].operands[0].storage
    entries = [
        e
        for e in program.entry_storage
        if (e.storage.address_space, e.storage.name)
        == (storage.address_space, storage.name)
        and storage.bit_offset <= e.storage.bit_offset
        and e.storage.bit_offset + e.storage.width_bits
        <= storage.bit_offset + storage.width_bits
    ]
    if not entries or sum(e.storage.width_bits for e in entries) != storage.width_bits:
        raise ValueError("Entry selector range not covered by scalar atoms")
    seeds = tuple(
        sorted(
            (Seed(e.node_id, Labels(("ANCHOR_ENTRY",))) for e in entries),
            key=lambda s: s.node_id,
        )
    )
    analysis = analyze(program.graph, seeds)
    facts = {f.node_id: f for f in analysis.facts}
    observable = next(n for n in program.graph.nodes if n.operation == "zext")

    def operations(op):
        out = [op.operation] if op.operation else []
        for child in op.children:
            out.extend(operations(child))
        return out

    coverage = Counter(
        i.opcode for b in snapshot.function.blocks for i in b.instructions
    )
    for b in snapshot.function.blocks:
        for i in b.instructions:
            for op in i.operands:
                coverage.update(operations(op))
    return {
        "schema_version": "flow-scalar-receipt/1",
        "scope": "G006 scalar structure and explicit provenance; NOT memory/ABI/function-return correctness",
        "input_receipt": str(path.relative_to(ROOT)),
        "input_file_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "snapshot_digest": digest(snapshot),
        "implementation_sha256": {
            p: hashlib.sha256(
                (ROOT / "src/ida_pro_mcp/flow_core" / p).read_bytes()
            ).hexdigest()
            for p in ("cfg.py", "ssa.py", "analysis.py")
        },
        "graph_digest": program.graph.graph_digest,
        "source_digest": analysis.source_digest,
        "policy_digest": analysis.policy_digest,
        "analysis_cache_key": analysis.cache_key,
        "repeat_equal": build_ssa(snapshot) == program,
        "roundtrip_equal": SSAProgram.from_json(canonical_json(program)) == program,
        "node_count": len(program.graph.nodes),
        "edge_count": len(program.graph.edges),
        "kind_counts": dict(
            sorted(Counter(n.kind for n in program.graph.nodes).items())
        ),
        "microcode_operation_counts": dict(sorted(coverage.items())),
        "entry_seed": {
            "selector": "block[1].instruction[0].operand[0] storage entry; no ABI arg mapping",
            "storage": storage.to_data(),
            "seeds": [seed.to_data() for seed in seeds],
        },
        "observable": {
            "selector": "sole normalized explicit zext output, not inferred function return",
            "node_id": observable.node_id,
            "width_bits": observable.width_bits,
            "fact": facts[observable.node_id].to_data(),
        },
        "analysis_status": analysis.status,
        "diagnostics": list(program.diagnostics),
        "evaluations": analysis.evaluations,
        "target_executed": False,
        "new_ida_extraction": False,
    }


def main():
    # Explicit output directory prevents silently replacing trusted source fixtures.
    output = Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=True)
    for anchor in ("x64", "a64"):
        (output / f"ssa_{anchor}.json").write_text(
            json.dumps(receipt(anchor), indent=2, sort_keys=True) + "\n"
        )


if __name__ == "__main__":
    main()
