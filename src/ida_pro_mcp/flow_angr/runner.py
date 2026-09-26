#!/usr/bin/env python3
"""angr sidecar runner: prefix feasibility as bounded symbolic execution.

Usage: runner.py <request.json> <response.json>

Runs under an angr-capable interpreter (see IDA_MCP_ANGR_PYTHON), NOT the
project venv: claripy pins z3 4.x while the host verifies against z3 5.x.
Stdlib + angr only; must never import ida_pro_mcp (absent over there).

The binary is lifted to VEX and explored symbolically; the target program is
never executed natively. Exit 0 with a verdict object (feasible, infeasible,
or unknown); nonzero only for runner misuse or crashes.
"""

import hashlib
import json
import logging
import sys
from typing import NoReturn

RUNNER_VERSION = "flow-angr-runner/1"
NUM_FIND_ALL = 65536


def fail(message: str) -> NoReturn:
    print(f"angr-runner: {message}", file=sys.stderr)
    raise SystemExit(2)


def load_request(path):
    try:
        raw = json.loads(open(path).read())
    except (OSError, ValueError):
        fail("unreadable request file")
    if type(raw) is not dict:
        fail("request must be an object")
    for key in ("binary_path", "binary_sha256", "image_base", "entry_ea",
                "find_eas", "symbolic_registers", "loop_bound", "timeout_ms",
                "schema_version"):
        if key not in raw:
            fail(f"request missing {key}")
    if raw["schema_version"] != 1:
        fail("unsupported request version")
    if not raw["find_eas"]:
        fail("find_eas needs at least one address")
    return raw


def check_binary(path, expected):
    try:
        digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    except OSError:
        fail("binary unreadable")
    return ("sha256-v1:" + digest) == expected


def versions():
    import angr

    try:
        import z3

        z3_version = z3.get_version_string()
    except Exception:
        z3_version = "unavailable"
    return angr.__version__, z3_version, angr


def hooked_procedures(proj):
    names = set()
    try:
        symbols = list(proj.loader.symbols)
    except Exception:
        return []
    for sym in symbols:
        try:
            addr = sym.rebased_addr
        except Exception:
            continue
        try:
            if proj.is_hooked(addr):
                names.add(getattr(sym, "name", None) or hex(addr))
        except Exception:
            continue
    return sorted(names)


def main(request_path, response_path):
    logging.getLogger("angr").setLevel(logging.ERROR)
    logging.getLogger("claripy").setLevel(logging.ERROR)
    logging.getLogger("cle").setLevel(logging.ERROR)
    request = load_request(request_path)
    binary = request["binary_path"]
    if not check_binary(binary, request["binary_sha256"]):
        write(response_path, {
            "status": "unknown", "witness": [], "engine": None,
            "unresolved": ["binary_mismatch"], "target_executed": False,
        })
        return
    angr_version, z3_version, angr = versions()
    import claripy

    image_base = request["image_base"]
    if type(image_base) is not int or image_base < 0:
        fail("image_base must be a non-negative integer")
    # Load at the IDA image base so IDA EAs address the same bytes here.
    proj = angr.Project(binary, auto_load_libs=False,
                        main_opts={"base_addr": image_base})
    entry = request["entry_ea"]
    state = proj.factory.call_state(entry)
    symbols = {}
    for item in request["symbolic_registers"]:
        name, width = item["name"], item["width_bits"]
        if not hasattr(state.regs, name):
            fail(f"unknown register {name}")
        if name not in symbols:
            symbols[name] = claripy.BVS(f"angr_{name}", 64)
        setattr(state.regs, name, symbols[name])
    simgr = proj.factory.simulation_manager(state)
    loop_seer = angr.exploration_techniques.LoopSeer(
        bound=request["loop_bound"])
    simgr.use_technique(loop_seer)
    steps_before = len(simgr.active)
    simgr.explore(find=tuple(request["find_eas"]),
                  avoid=tuple(request.get("avoid_eas", ())),
                  num_find=NUM_FIND_ALL)
    steps = steps_before  # replaced below by history depth accounting
    engine = {
        "name": "angr-sidecar",
        "runner_version": RUNNER_VERSION,
        "angr_version": angr_version,
        "z3_version": z3_version,
        "simprocedures": hooked_procedures(proj),
        "loop_bound": request["loop_bound"],
        "exploration_steps": steps,
    }
    if simgr.found:
        found = sorted(simgr.found, key=lambda s: tuple(s.history.bbl_addrs))
        witness_state = found[0]
        engine["exploration_steps"] = len(witness_state.history.bbl_addrs)
        witness = []
        for item in request["symbolic_registers"]:
            name, width = item["name"], item["width_bits"]
            value = witness_state.solver.eval(symbols[name][width - 1:0])
            witness.append({"name": name, "width_bits": width,
                            "value_hex": hex(value)})
        write(response_path, {
            "status": "feasible", "witness": witness, "engine": engine,
            "unresolved": [], "target_executed": False,
        })
        return
    engine["exploration_steps"] = 0
    limited = len(getattr(simgr, "spinning", []) or []) > 0
    if getattr(simgr, "unconstrained", []):
        write(response_path, {
            "status": "unknown", "witness": [], "engine": engine,
            "unresolved": ["unconstrained_states"], "target_executed": False,
        })
        return
    if simgr.errored:
        write(response_path, {
            "status": "unknown", "witness": [], "engine": engine,
            "unresolved": ["unexplored_errors"], "target_executed": False,
        })
        return
    if simgr.active:
        write(response_path, {
            "status": "unknown", "witness": [], "engine": engine,
            "unresolved": ["exploration_incomplete"], "target_executed": False,
        })
        return
    if limited:
        write(response_path, {
            "status": "unknown", "witness": [], "engine": engine,
            "unresolved": ["loop_bound_exceeded"], "target_executed": False,
        })
        return
    write(response_path, {
        "status": "infeasible", "witness": [], "engine": engine,
        "unresolved": [], "target_executed": False,
    })


def write(path, payload):
    with open(path, "w") as handle:
        json.dump(payload, handle)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        fail("usage: runner.py <request.json> <response.json>")
    main(sys.argv[1], sys.argv[2])
