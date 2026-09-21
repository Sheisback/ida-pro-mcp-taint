"""Bounded static microcode capability probe; run only on IDA's main thread.

This is not a snapshot schema or SSA engine. No SDK objects cross probe().
"""

import hashlib
import json
import time
from collections import Counter

SCHEMA = "flow-p0-probe/1"
MATURITIES = ("MMAT_CALLS", "MMAT_GLBOPT3")


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def probe(function_ea, maturity, *, deadline=None, cancelled=lambda: False):
    """Serialize one MBA; cancellation is cooperative, never native preemption."""
    import ida_funcs
    import ida_hexrays as hx
    import ida_idaapi

    if maturity not in MATURITIES:
        raise ValueError("Unsupported probe maturity")

    def check():
        if cancelled() or (deadline is not None and time.monotonic() >= deadline):
            raise InterruptedError("cooperative probe cancellation")

    check()
    function = ida_funcs.get_func(function_ea)
    if function is None:
        raise ValueError("Not a function")
    failure = hx.hexrays_failure_t()
    mba = hx.gen_microcode(
        hx.mba_ranges_t(function), failure, None, 0, getattr(hx, maturity)
    )
    if mba is None:
        return {
            "status": "failed",
            "failure_code": int(failure.code),
            "failure_ea": int(failure.errea),
            "maturity": maturity,
        }
    check()
    op_names = {
        getattr(hx, name): name
        for name in dir(hx)
        if name.startswith("m_") and isinstance(getattr(hx, name), int)
    }
    kinds = {
        getattr(hx, name): name
        for name in dir(hx)
        if name.startswith("mop_") and isinstance(getattr(hx, name), int)
    }
    op_counts, kind_counts = Counter(), Counter()
    warnings = []

    def operand(op, depth=0):
        kind_counts[kinds.get(op.t, str(op.t))] += 1
        result = {"kind": kinds.get(op.t, str(op.t)), "size": int(op.size)}
        if depth >= 32:
            result["truncated"] = True
            warnings.append("nested operand depth cap")
        elif op.t == hx.mop_d:
            result["instruction"] = instruction(op.d, depth + 1)
        elif op.t == hx.mop_r:
            result["register"] = int(op.r)
        elif op.t == hx.mop_n:
            result["value"] = int(op.nnn.value)
        elif op.t == hx.mop_v:
            result["ea"] = int(op.g)
        elif op.t == hx.mop_S:
            result["stack_offset"] = int(op.s.off)
        elif op.t == hx.mop_b:
            result["block"] = int(op.b)
        elif op.t == hx.mop_f:
            ci = op.f
            result["callinfo"] = {
                "callee": int(ci.callee),
                "cc": int(ci.cc),
                "args": [operand(a, depth + 1) for a in ci.args],
                "return_size": int(ci.return_type.get_size()),
                "spoiled_nonempty": not ci.spoiled.empty(),
                "return_locations_nonempty": not ci.return_regs.empty(),
            }
        return result

    def instruction(ins, depth=0):
        check()
        name = op_names.get(ins.opcode, str(ins.opcode))
        op_counts[name] += 1
        return {
            "opcode": name,
            "ea": None if ins.ea == ida_idaapi.BADADDR else int(ins.ea),
            "operands": [operand(o, depth) for o in (ins.l, ins.r, ins.d)],
        }

    blocks = []
    list_checks = Counter()
    for index in range(mba.qty):
        block = mba.get_mblock(index)
        rows = []
        ins = block.head
        while ins is not None:
            rows.append(instruction(ins))
            for access in ("MAY_ACCESS", "MUST_ACCESS"):
                for method in ("build_use_list", "build_def_list"):
                    try:
                        locations = getattr(block, method)(ins, getattr(hx, access))
                        list_checks[method + ":" + access + ":ok"] += 1
                        list_checks[method + ":" + access + ":nonempty"] += int(
                            not locations.empty()
                        )
                    except Exception as exc:
                        warnings.append(
                            method + ":" + type(exc).__name__ + ":" + str(exc)
                        )
            ins = ins.next
        blocks.append(
            {
                "id": index,
                "successors": [block.succ(i) for i in range(block.nsucc())],
                "predecessors": [block.pred(i) for i in range(block.npred())],
                "instructions": rows,
            }
        )
    chains = {}
    graph_result = int(mba.build_graph())
    graph = mba.get_graph()
    for direction in ("get_ud", "get_du"):
        try:
            chain = getattr(graph, direction)(hx.GC_REGS_AND_STKVARS)
            chains[direction] = {
                "status": "available" if chain is not None else "unavailable",
                "block_count": int(chain.size()) if chain is not None else 0,
            }
        except Exception as exc:
            chains[direction] = {
                "status": "blocked",
                "reason": type(exc).__name__ + ": " + str(exc),
            }
    result = {
        "status": "success",
        "failure_code": 0,
        "maturity": maturity,
        "actual_maturity": int(mba.maturity),
        "python_owns_mba": bool(mba.thisown),
        "function_ea": int(function.start_ea),
        "block_count": len(blocks),
        "instruction_count": sum(len(b["instructions"]) for b in blocks),
        "blocks": blocks,
        "opcode_counts": dict(sorted(op_counts.items())),
        "operand_kind_counts": dict(sorted(kind_counts.items())),
        "use_def_checks": dict(sorted(list_checks.items())),
        "graph_build_result": graph_result,
        "chains": chains,
        "warnings": sorted(set(warnings)),
    }
    source_eas = [row["ea"] for block in blocks for row in block["instructions"]]
    result["source_map"] = {
        "top_level_with_ea": sum(ea is not None for ea in source_eas),
        "top_level_synthetic": sum(ea is None for ea in source_eas),
        "unique_eas": sorted(set(ea for ea in source_eas if ea is not None)),
        "reconstruction": "observed_microcode_ea_only_not_full_native_origin_sets",
    }
    result["digest"] = digest(result)
    # JSON round trip rejects accidental native objects; local wrappers die here.
    return json.loads(json.dumps(result))
