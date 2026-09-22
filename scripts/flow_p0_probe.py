"""IDA -A -S entry point; only statically analyze a disposable working copy.

Usage: idat -A '-S/path/flow_p0_probe.py ROOT OUTPUT REQUEST_JSON' BINARY

The request is validated before Hex-Rays is initialized. Raw loader state is
applied only by the reviewed headless IDA invocation and then observed here;
this entry point never mutates loader state or executes the target.
"""

import gc
import hashlib
import importlib.util
import json
import platform
import sys
import time
from pathlib import Path

import ida_auto  # pyright: ignore[reportMissingImports]
import ida_funcs  # pyright: ignore[reportMissingImports]
import ida_hexrays  # pyright: ignore[reportMissingImports]
import ida_ida  # pyright: ignore[reportMissingImports]
import ida_kernwin  # pyright: ignore[reportMissingImports]
import ida_loader  # pyright: ignore[reportMissingImports]
import ida_nalt  # pyright: ignore[reportMissingImports]
import ida_name  # pyright: ignore[reportMissingImports]
import ida_pro  # pyright: ignore[reportMissingImports]
import idc  # pyright: ignore[reportMissingImports]


def _observed_format(filetype):
    for name, constant in (
        ("RAW", "f_BIN"),
        ("PE", "f_PE"),
        ("ELF", "f_ELF"),
        ("MACH-O", "f_MACHO"),
    ):
        if filetype == getattr(ida_ida, constant, object()):
            return name
    return "UNKNOWN"


def _failure(kind, message, **details):
    return {"kind": kind, "message": message, "details": details}


def _reject_json_constant(value):
    raise ValueError("Non-finite JSON constant: " + value)


def _write_receipt(module, output, result):
    result["receipt_digest"] = module.digest(result)
    detached = json.loads(json.dumps(result, allow_nan=False))
    Path(output).write_text(json.dumps(detached, indent=2) + "\n")


def main():
    root, output, request_path = idc.ARGV[1:]
    spec = importlib.util.spec_from_file_location(
        "p0_probe", Path(root) / "src/ida_pro_mcp/ida_mcp/flow/p0_probe.py"
    )
    if spec is None or spec.loader is None or spec.origin is None:
        raise RuntimeError("Cannot load the P0 probe contract")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    raw_request = None
    try:
        raw_request = json.loads(
            Path(request_path).read_text(), parse_constant=_reject_json_constant
        )
        request = module.validate_request(raw_request)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        _write_receipt(
            module,
            output,
            {
                "schema_version": module.RECEIPT_SCHEMA,
                "request": raw_request,
                "request_digest": None,
                "implementation_sha256": hashlib.sha256(
                    Path(spec.origin).read_bytes()
                ).hexdigest(),
                "probe_status": "invalid_request",
                "support_status": "unverified",
                "target_executed": False,
                "initialization": None,
                "probes": [],
                "failures": [
                    _failure("invalid_request", f"{type(exc).__name__}: {exc}")
                ],
            },
        )
        return

    ida_auto.auto_wait()
    input_path = Path(ida_nalt.get_input_file_path())
    binary_sha256 = hashlib.sha256(input_path.read_bytes()).hexdigest()
    filetype_id = int(ida_ida.inf_get_filetype())
    is_raw = request["load"]["kind"] == "raw"
    if is_raw:
        # IDA 9.3 creates the raw entry function supplied by ``-i`` but leaves
        # inf_get_start_ea() at BADADDR. Verify the requested address resolves
        # to an actual function start instead of echoing that address back.
        requested_ea = request["entry"]["value"]
        entry_function = ida_funcs.get_func(requested_ea)
        resolved_ea = (
            int(entry_function.start_ea)
            if entry_function is not None
            and int(entry_function.start_ea) == requested_ea
            else None
        )
        observed_load_address = int(ida_ida.inf_get_min_ea())
    elif request["entry"]["kind"] == "name":
        resolved_ea = ida_name.get_name_ea(idc.BADADDR, request["entry"]["value"])
        if resolved_ea == idc.BADADDR:
            resolved_ea = None
        observed_load_address = int(ida_nalt.get_imagebase())
    else:
        resolved_ea = request["entry"]["value"]
        observed_load_address = int(ida_nalt.get_imagebase())
    observation = {
        "binary_sha256": binary_sha256,
        "format": _observed_format(filetype_id),
        "filetype": ida_loader.get_file_type_name(),
        "processor": ida_ida.inf_get_procname(),
        "bits": 64 if ida_ida.inf_is_64bit() else 32,
        "data_endian": "BE" if ida_ida.inf_is_be() else "LE",
        # IDA's database endian flag does not prove instruction endian (for
        # example ARM BE8), so this remains explicitly unobserved.
        "instruction_endian": None,
        # The validation schema retains one address slot. For loader formats it
        # is the image base; for RAW it is the first loaded address observed
        # from the database, never the requested address echoed back.
        "image_base": observed_load_address,
        "entry_ea": None if resolved_ea is None else int(resolved_ea),
    }
    validation = module.validate_observation(request, observation)
    result = {
        "schema_version": module.RECEIPT_SCHEMA,
        "request": request,
        "request_digest": module.request_digest(request),
        "implementation_sha256": hashlib.sha256(
            Path(spec.origin).read_bytes()
        ).hexdigest(),
        "environment": {
            "ida_version": ida_kernwin.get_kernel_version(),
            "python_version": platform.python_version(),
            "hexrays_version": None,
            "filetype_id": filetype_id,
            **observation,
        },
        "validation": validation,
        "probe_status": "blocked",
        "support_status": "unverified",
        "target_executed": False,
        "binary": {"name": input_path.name, "sha256": binary_sha256},
        "entry": {
            "requested": request["entry"],
            "resolved_ea": observation["entry_ea"],
        },
        "initialization": None,
        "probes": [],
        "failures": [],
    }
    if validation["status"] != "accepted":
        result["failures"].append(
            _failure(
                "request_validation_" + validation["status"],
                "Probe request did not pass fail-closed runtime validation",
                mismatches=validation["mismatches"],
                raw_setup=validation["raw_setup"],
            )
        )
        result["lifetime"] = {
            "json_roundtrip": True,
            "repeat_after_gc": False,
            "native_leak_freedom": "not_proven",
        }
        _write_receipt(module, output, result)
        return

    ready = ida_hexrays.init_hexrays_plugin()
    result["initialization"] = bool(ready)
    result["environment"]["hexrays_version"] = (
        ida_hexrays.get_hexrays_version() if ready else None
    )
    if not ready:
        result["probe_status"] = "failed"
        result["failures"].append(
            _failure("hexrays_initialization", "Hex-Rays initialization failed")
        )
    else:
        for maturity in request["probe"]["maturities"]:
            try:
                first = module.probe(resolved_ea, maturity)
                gc.collect()
                second = module.probe(resolved_ea, maturity)
                first["repeat_equal"] = first == second
                result["probes"].append(first)
            except Exception as exc:
                result["probes"].append(
                    {
                        "status": "failed",
                        "maturity": maturity,
                        "failure_kind": "exception",
                        "failure_type": type(exc).__name__,
                        "failure_message": str(exc),
                        "repeat_equal": False,
                    }
                )

        checks = {}
        for key, kwargs in (
            ("pre_cancel", {"cancelled": lambda: True}),
            ("expired_deadline", {"deadline": time.monotonic() - 1}),
        ):
            try:
                module.probe(resolved_ea, module.MATURITIES[0], **kwargs)
                checks[key] = False
            except InterruptedError:
                checks[key] = True
        result["cancellation"] = {
            **checks,
            "during_native_call": "not_preemptible_by_python_poll",
            "during_serialization": "cooperative_poll",
            "native_cancel_tested": False,
        }
        all_success = len(result["probes"]) == len(module.MATURITIES) and all(
            row.get("status") == "success" and row.get("repeat_equal") is True
            for row in result["probes"]
        )
        result["probe_status"] = "success" if all_success else "failed"
        if not all_success:
            result["failures"].append(
                _failure(
                    "probe_failure",
                    "One or more maturity probes failed or were not repeatable",
                )
            )

    result["lifetime"] = {
        "json_roundtrip": True,
        "repeat_after_gc": bool(result["probes"])
        and all(row.get("repeat_equal", False) for row in result["probes"]),
        "native_leak_freedom": "not_proven",
    }
    _write_receipt(module, output, result)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback

        traceback.print_exc()
        ida_pro.qexit(1)
    ida_pro.qexit(0)
