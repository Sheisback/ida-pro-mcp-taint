"""Fresh content bindings and independent witness replay for static public paths."""

import hashlib
import json
from pathlib import Path

from ida_pro_mcp.flow_core.build_identity import BUILD_ID, extension_build_id
from ida_pro_mcp.flow_core.constraints import ConstraintAssignment, ConstraintQuery
from ida_pro_mcp.flow_core.proof import validate_witness
from native_path_smoke import COMPILER_VERSION, SDK_VERSION

ROOT = Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_public_program_path_receipt_is_current_exact_and_static_only():
    receipt = json.loads(
        (ROOT / "tests/flow_fixtures/manifests/path_public_smoke.json").read_text()
    )
    assert receipt["schema_version"] == "flow-path-public-smoke/1"
    assert receipt["target_executed"] is False
    assert receipt["build_id"] == BUILD_ID == extension_build_id()
    assert receipt["source"] == "tests/flow_fixtures/path_anchor.c"
    assert receipt["script"] == "tests/flow_core/native_path_smoke.py"
    assert receipt["source_sha256"] == sha(ROOT / receipt["source"])
    assert receipt["script_sha256"] == sha(ROOT / receipt["script"])
    paths = {
        ROOT / "src/ida_pro_mcp/ida_mcp/api_flow.py",
        ROOT / "src/ida_pro_mcp/ida_mcp/zeromcp/mcp.py",
        ROOT / "src/ida_pro_mcp/ida_mcp.py",
        ROOT / "src/ida_pro_mcp/idalib_server.py",
        ROOT / "src/ida_pro_mcp/idalib_supervisor.py",
        ROOT / "src/ida_pro_mcp/installer.py",
        ROOT / "profiles/flow-readonly.txt",
        *(ROOT / "src/ida_pro_mcp/flow_core").glob("*.py"),
        *(ROOT / "src/ida_pro_mcp/ida_mcp/flow").glob("*.py"),
    }
    assert receipt["implementation_sha256"] == {
        str(path.relative_to(ROOT)): sha(path) for path in paths
    }
    assert {a["profile"] for a in receipt["anchors"]} == {"X64-LE", "A64-LE"}
    for anchor in receipt["anchors"]:
        assert anchor["build_id"] == receipt["build_id"]
        assert anchor["target_executed"] is False
        assert anchor["compiler"].splitlines()[0] == COMPILER_VERSION
        assert anchor["sdk_version"] == SDK_VERSION
        assert anchor["flags"] == [
            "-arch",
            anchor["arch"],
            "-O1",
            "-fomit-frame-pointer",
            "-fno-stack-protector",
            "-Wl,-no_uuid",
        ]
        assert anchor["fresh_builds"] == 2
        assert len(anchor["binary_sha256"]) == 2
        assert set(anchor["binary_sha256"]) == {anchor["copied_binary_sha256"]}
        # P5 reviewed surface: the opt-in path refinement tool joins the
        # read-only profile alongside the v1 path proof tool.
        assert {t for t in anchor["registered_tools"] if "path" in t} == {
            "flow_check_path",
            "flow_refine_path_proof",
        }
        assert all(
            0 < call["response_chars"] < 40000 and call["truncated"] is False
            for call in anchor["calls"]
        )
        assert {call["tool"] for call in anchor["calls"]} == {
            "flow_get_capabilities",
            "flow_create_snapshot",
            "flow_get_job",
            "flow_get_cfg",
            "flow_get_graph",
            "flow_check_path",
        }
        cfg = {block["block"]: block for block in anchor["cfg"]}
        nodes = {n["node_id"]: n for n in anchor["graph"] if n["type"] == "node"}
        assert len(anchor["proofs"]) == 2
        for proof in anchor["proofs"]:
            path = proof["selector"]["blocks"]
            assert cfg[path[0]]["predecessors"] == []
            assert all(b in cfg[a]["successors"] for a, b in zip(path, path[1:]))
            assert proof["metadata"]["status"] == "feasible"
            assert proof["metadata"]["model_kind"] == "exact"
            assert proof["metadata"]["witness_valid"] is True
            assert proof["metadata"]["target_executed"] is False
            assert proof["metadata"]["no_auto_vulnerability_verdict"] is True
            assert proof["metadata"]["scope"] == "within_bounds"
            items = proof["items"]

            def values(kind):
                return [
                    {k: v for k, v in item.items() if k != "type"}
                    for item in items
                    if item["type"] == kind
                ]

            header = values("proof")[0]
            query = ConstraintQuery.from_data(
                {
                    "schema_version": 1,
                    "bindings": header["bindings"],
                    "variables": values("path_variable"),
                    "constraints": values("path_constraint"),
                    "assumptions": header["assumptions"],
                    "bounds": header["bounds"],
                    "budget": header["budget"],
                    "coverage": header["coverage"],
                }
            )
            assert (
                query.query_digest
                == proof["metadata"]["query_digest"]
                == header["query_digest"]
            )
            assert query.bindings.to_data() == proof["selector"]["bindings"]
            assert query.bounds.loop_bound == query.bounds.call_bound == 0
            assert len(query.variables) == 1
            variable = query.variables[0]
            assert nodes[variable.name]["kind"] == "InputValue"
            assert nodes[variable.name]["width_bits"] == variable.width_bits == 8
            assert variable.domain == tuple(range(256))
            for constraint in query.constraints:
                assert nodes[constraint.origin_id]["kind"] == "Branch"
                assert constraint.evidence_ids
            replay = validate_witness(
                query,
                tuple(
                    ConstraintAssignment.from_data(item)
                    for item in values("witness_assignment")
                ),
            )
            assert replay.valid
            assert [item.to_data() for item in replay.evaluations] == values(
                "witness_evaluation"
            )
            # Independent source-level bit predicate, including both byte classes.
            constraint = query.constraints[0]
            actual_byte = replay.assignments[0].value
            assert ((actual_byte & 1) != 0) == constraint.expected
