"""IDA -A -S entry point; only statically analyze a disposable working copy.

Usage: idat -A '-S/path/flow_p0_probe.py ROOT OUTPUT FUNCTION' BINARY
"""

import gc
import hashlib
import importlib.util
import json
import platform
import sys
import time
from pathlib import Path

import ida_auto
import ida_hexrays
import ida_ida
import ida_kernwin
import ida_nalt
import ida_name
import ida_pro
import idc


def main():
    root, output, name = idc.ARGV[1:]
    spec = importlib.util.spec_from_file_location(
        "p0_probe", Path(root) / "src/ida_pro_mcp/ida_mcp/flow/p0_probe.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    ida_auto.auto_wait()
    ready = ida_hexrays.init_hexrays_plugin()
    result = {
        "schema_version": module.SCHEMA,
        "implementation_sha256": hashlib.sha256(
            Path(spec.origin).read_bytes()
        ).hexdigest(),
        "environment": {
            "ida_version": ida_kernwin.get_kernel_version(),
            "python_version": platform.python_version(),
            "hexrays_version": ida_hexrays.get_hexrays_version() if ready else None,
            "processor": ida_ida.inf_get_procname(),
            "bits": 64 if ida_ida.inf_is_64bit() else 32,
            "data_endian": "BE" if ida_ida.inf_is_be() else "LE",
        },
        "initialization": bool(ready),
        "target_executed": False,
        "binary": {
            "name": Path(ida_nalt.get_input_file_path()).name,
            "sha256": hashlib.sha256(
                Path(ida_nalt.get_input_file_path()).read_bytes()
            ).hexdigest(),
        },
        "function_name": name,
        "probes": [],
    }
    ea = ida_name.get_name_ea(idc.BADADDR, name)
    if ready:
        for maturity in module.MATURITIES:
            first = module.probe(ea, maturity)
            gc.collect()
            second = module.probe(ea, maturity)
            first["repeat_equal"] = first == second
            result["probes"].append(first)
        checks = {}
        for key, kwargs in [
            ("pre_cancel", {"cancelled": lambda: True}),
            ("expired_deadline", {"deadline": time.monotonic() - 1}),
        ]:
            try:
                module.probe(ea, module.MATURITIES[0], **kwargs)
                checks[key] = False
            except InterruptedError:
                checks[key] = True
        result["cancellation"] = {
            **checks,
            "during_native_call": "not_preemptible_by_python_poll",
            "during_serialization": "cooperative_poll",
            "native_cancel_tested": False,
        }
    result["lifetime"] = {
        "json_roundtrip": json.loads(json.dumps(result)) == result,
        "repeat_after_gc": bool(result["probes"])
        and all(p.get("repeat_equal", False) for p in result["probes"]),
        "native_leak_freedom": "not_proven",
    }
    Path(output).write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback

        traceback.print_exc()
        ida_pro.qexit(1)
    ida_pro.qexit(0)
