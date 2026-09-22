"""Packaging smoke: extract a wheel and import core in an isolated interpreter."""

import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from ida_pro_mcp.flow_core.build_identity import BUILD_ID as SOURCE_BUILD_ID


def check(directory: Path):
    wheels = list(directory.glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError("Expected exactly one wheel")
    with tempfile.TemporaryDirectory(prefix="flow-core-wheel-") as temp:
        with zipfile.ZipFile(wheels[0]) as wheel:
            expected = {
                "ida_pro_mcp/flow_core/__init__.py",
                "ida_pro_mcp/flow_core/build_identity.py",
                "ida_pro_mcp/flow_core/serialization.py",
                "ida_pro_mcp/flow_core/states.py",
                "ida_pro_mcp/flow_core/contracts.py",
                "ida_pro_mcp/flow_core/cfg.py",
                "ida_pro_mcp/flow_core/ssa.py",
                "ida_pro_mcp/flow_core/analysis.py",
                "ida_pro_mcp/flow_core/implicit_cfg.py",
                "ida_pro_mcp/flow_core/implicit_analysis.py",
                "ida_pro_mcp/flow_core/memory.py",
                "ida_pro_mcp/flow_core/memory_analysis.py",
                "ida_pro_mcp/flow_core/memory_graph.py",
                "ida_pro_mcp/flow_core/heap.py",
                "ida_pro_mcp/flow_core/heap_analysis.py",
                "ida_pro_mcp/flow_core/summaries.py",
                "ida_pro_mcp/flow_core/interproc.py",
                "ida_pro_mcp/flow_core/call_composition.py",
                "ida_pro_mcp/flow_core/runtime_contracts.py",
                "ida_pro_mcp/flow_core/persistence.py",
                "ida_pro_mcp/flow_core/runtime.py",
                "ida_pro_mcp/flow_core/query.py",
                "ida_pro_mcp/flow_core/host_identity.py",
                "ida_pro_mcp/flow_core/profile_registry.py",
                "ida_pro_mcp/flow_core/constraints.py",
                "ida_pro_mcp/flow_core/proof.py",
            }
            if not expected <= set(wheel.namelist()):
                raise RuntimeError("Core files missing from wheel")
            wheel.extractall(temp)
        script = """
import importlib.abc, sys
sys.path.insert(0, sys.argv[1])
class RejectIDA(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith("ida_pro_mcp.ida_mcp") or fullname == "idapro" or (fullname.startswith("ida_") and not fullname.startswith("ida_pro_mcp")):
            raise AssertionError("SDK import attempted: " + fullname)
sys.meta_path.insert(0, RejectIDA())
from ida_pro_mcp.flow_core.ssa import build_ssa
from ida_pro_mcp.flow_core.analysis import analyze
from ida_pro_mcp.flow_core.implicit_cfg import ImplicitCFGPolicy
from ida_pro_mcp.flow_core.implicit_analysis import ImplicitPolicy
from ida_pro_mcp.flow_core.memory_analysis import analyze_memory
from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
from ida_pro_mcp.flow_core.heap import build_heap_plan
from ida_pro_mcp.flow_core.heap_analysis import analyze_heap
from ida_pro_mcp.flow_core.summaries import SummaryCatalog
from ida_pro_mcp.flow_core.interproc import CallContext
from ida_pro_mcp.flow_core.call_composition import CallState
from ida_pro_mcp.flow_core.persistence import Store
from ida_pro_mcp.flow_core.runtime import Runtime
from ida_pro_mcp.flow_core.query import Queries
from ida_pro_mcp.flow_core.host_identity import identity
from ida_pro_mcp.flow_core.profile_registry import PROFILE_IDS, REGISTRY
from ida_pro_mcp.flow_core.constraints import ConstraintBindings, ConstraintExpression, ConstraintQuery, ConstraintVariable, DeclaredCoverage, PathConstraint, ProofBounds, ProofBudget, variable_domain_digest
from ida_pro_mcp.flow_core.proof import ProofResult, ReferenceProofEngine, classify_proof
from ida_pro_mcp.flow_core.build_identity import BUILD_ID
from ida_pro_mcp.flow_core.runtime_contracts import RuntimeScope
from ida_pro_mcp.flow_core.contracts import ResultAxes
from ida_pro_mcp.flow_core.states import BitValue
from ida_pro_mcp.flow_core import canonical_json, digest, stable_id
assert BitValue.from_json(canonical_json(BitValue(8, 7))) == BitValue(8, 7)
assert ResultAxes().analysis == "partial"
assert ImplicitCFGPolicy.from_json(canonical_json(ImplicitCFGPolicy())) == ImplicitCFGPolicy()
assert ImplicitPolicy.from_json(canonical_json(ImplicitPolicy())) == ImplicitPolicy()
assert SummaryCatalog(()).summaries == ()
assert CallContext().frames == ()
assert CallState().objects == ()
variables = (ConstraintVariable("x", 2, (0, 1)),)
constraint = PathConstraint(
    "c:wheel",
    ConstraintExpression("variable", 2, variable="x"),
    "eq",
    ConstraintExpression("constant", 2, value=1),
    None,
    True,
    "rule:wheel",
    "origin:wheel",
    (stable_id("evidence", "wheel"),),
)
binding_digest = digest("wheel")
query = ConstraintQuery(
    ConstraintBindings(stable_id("snapshot", "wheel"), binding_digest, binding_digest, binding_digest),
    variables,
    (constraint,),
    (),
    ProofBounds(1, 1),
    ProofBudget(2, 6, 1000),
    DeclaredCoverage(
        "fixed_width_bitvectors",
        ("x",),
        variable_domain_digest(variables),
        ("c:wheel",),
        ("eq",),
    ),
)
assert ConstraintQuery.from_json(canonical_json(query)) == query
proof = classify_proof(query, ReferenceProofEngine())
assert proof.status == "feasible"
assert ProofResult.from_json(canonical_json(proof)) == proof
assert BUILD_ID.startswith("flow-build-sha256-v1:")
assert BUILD_ID == sys.argv[2]
assert tuple(profile.profile_id for profile in REGISTRY.profiles) == PROFILE_IDS
print("Wheel core import/roundtrip passed without SDK imports")
"""
        subprocess.run(
            [sys.executable, "-I", "-S", "-c", script, temp, SOURCE_BUILD_ID],
            check=True,
            cwd=temp,
        )


if __name__ == "__main__":
    check(Path(sys.argv[1]))
