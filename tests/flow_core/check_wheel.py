"""Packaging smoke: extract a wheel and import core in an isolated interpreter."""

from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile


def check(directory: Path):
    wheels = list(directory.glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError("Expected exactly one wheel")
    with tempfile.TemporaryDirectory(prefix="flow-core-wheel-") as temp:
        with zipfile.ZipFile(wheels[0]) as wheel:
            expected = {
                "ida_pro_mcp/flow_core/__init__.py",
                "ida_pro_mcp/flow_core/serialization.py",
                "ida_pro_mcp/flow_core/states.py",
                "ida_pro_mcp/flow_core/contracts.py",
                "ida_pro_mcp/flow_core/cfg.py",
                "ida_pro_mcp/flow_core/ssa.py",
                "ida_pro_mcp/flow_core/analysis.py",
                "ida_pro_mcp/flow_core/memory.py",
                "ida_pro_mcp/flow_core/memory_analysis.py",
                "ida_pro_mcp/flow_core/heap.py",
                "ida_pro_mcp/flow_core/heap_analysis.py",
                "ida_pro_mcp/flow_core/runtime_contracts.py",
                "ida_pro_mcp/flow_core/persistence.py",
                "ida_pro_mcp/flow_core/runtime.py",
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
from ida_pro_mcp.flow_core.memory_analysis import analyze_memory
from ida_pro_mcp.flow_core.heap import build_heap_plan
from ida_pro_mcp.flow_core.heap_analysis import analyze_heap
from ida_pro_mcp.flow_core.persistence import Store
from ida_pro_mcp.flow_core.runtime import Runtime
from ida_pro_mcp.flow_core.runtime_contracts import RuntimeScope
from ida_pro_mcp.flow_core.contracts import ResultAxes
from ida_pro_mcp.flow_core.states import BitValue
from ida_pro_mcp.flow_core import canonical_json
assert BitValue.from_json(canonical_json(BitValue(8, 7))) == BitValue(8, 7)
assert ResultAxes().analysis == "partial"
print("Wheel core import/roundtrip passed without SDK imports")
"""
        subprocess.run(
            [sys.executable, "-I", "-S", "-c", script, temp], check=True, cwd=temp
        )


if __name__ == "__main__":
    check(Path(sys.argv[1]))
