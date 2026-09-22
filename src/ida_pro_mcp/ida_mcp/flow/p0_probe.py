"""Bounded static microcode capability probe; run only on IDA's main thread.

This is not a snapshot schema or SSA engine. No SDK objects cross probe().
"""

import hashlib
import json
import time
from collections import Counter

SCHEMA = "flow-p0-probe/1"
RECEIPT_SCHEMA = "flow-p0-probe/2"
REQUEST_SCHEMA = "flow-p0-probe-request/1"
VALIDATION_SCHEMA = "flow-p0-probe-validation/1"
RAW_SETUP_SCHEMA = "flow-p0-raw-setup/1"
LEGACY_IMPLEMENTATION_SHA256 = (
    "2b924038da8ca62ce98704ed22600ad8fba413c35318e1e153d036212937596e"
)
MATURITIES = ("MMAT_CALLS", "MMAT_GLBOPT3")
FORMATS = ("ELF", "PE", "MACH-O", "RAW")
OBSERVED_FORMATS = FORMATS + ("UNKNOWN",)
ENDIANS = ("LE", "BE")


def digest(value):
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _exact_keys(value, expected, label):
    if type(value) is not dict:
        raise ValueError(label + " must be an object")
    actual = set(value)
    expected = set(expected)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"{label} keys mismatch; missing={missing!r}, extra={extra!r}")


def _nonempty(value, label):
    if type(value) is not str or not value.strip():
        raise ValueError(label + " must be a non-empty string")
    return value


def _integer(value, label, *, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value


def _endian(value, label, *, nullable=False):
    if value is None and nullable:
        return None
    if value not in ENDIANS:
        raise ValueError(label + " must be LE or BE")
    return value


def _sha256(value, label):
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(label + " must be a lowercase SHA-256 hex digest")
    return value


def _json_copy(value):
    """Reject native wrappers, tuples, NaN, and other non-contract values."""

    def check(item, label):
        if item is None or type(item) in (bool, int, str):
            return
        if type(item) is list:
            for index, child in enumerate(item):
                check(child, f"{label}[{index}]")
            return
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str:
                    raise ValueError(label + " contains a non-string key")
                check(child, f"{label}.{key}")
            return
        raise ValueError(label + " contains a non-JSON value")

    check(value, "request")
    return json.loads(json.dumps(value, allow_nan=False))


def validate_request(value):
    """Validate and detach one explicit static-probe request.

    The request records declared profile and ABI identity separately from fields
    IDA can observe. Validation never upgrades a profile's support status.
    """

    request = _json_copy(value)
    _exact_keys(
        request,
        ("schema_version", "profile", "binary", "load", "entry", "probe"),
        "request",
    )
    if request["schema_version"] != REQUEST_SCHEMA:
        raise ValueError("Unsupported probe request schema")

    profile = request["profile"]
    _exact_keys(
        profile,
        (
            "profile_id",
            "profile_version",
            "mode",
            "processor",
            "bits",
            "data_endian",
            "instruction_endian",
            "abi_id",
        ),
        "profile",
    )
    for field in ("profile_id", "mode", "processor", "abi_id"):
        _nonempty(profile[field], "profile." + field)
    _integer(profile["profile_version"], "profile.profile_version", minimum=1)
    if profile["bits"] not in (32, 64):
        raise ValueError("profile.bits must be 32 or 64")
    _endian(profile["data_endian"], "profile.data_endian")
    _endian(
        profile["instruction_endian"],
        "profile.instruction_endian",
        nullable=True,
    )

    binary = request["binary"]
    _exact_keys(binary, ("format", "filetype", "sha256"), "binary")
    if binary["format"] not in FORMATS:
        raise ValueError("Unsupported binary format")
    _nonempty(binary["filetype"], "binary.filetype")
    _sha256(binary["sha256"], "binary.sha256")

    load = request["load"]
    if type(load) is not dict:
        raise ValueError("load must be an object")
    if load.get("kind") == "loader":
        _exact_keys(load, ("kind", "image_base"), "load")
        _integer(load["image_base"], "load.image_base")
        if binary["format"] == "RAW":
            raise ValueError("RAW inputs require raw load settings")
    elif load.get("kind") == "raw":
        _exact_keys(load, ("kind", "file_offset", "load_address"), "load")
        _integer(load["file_offset"], "load.file_offset")
        _integer(load["load_address"], "load.load_address")
        if binary["format"] != "RAW":
            raise ValueError("Raw load settings require RAW format")
        if load["file_offset"] != 0:
            raise ValueError("Raw requests require file offset zero")
        if profile["instruction_endian"] is None:
            raise ValueError("Raw requests require explicit instruction endian")
    else:
        raise ValueError("load.kind must be loader or raw")

    entry = request["entry"]
    _exact_keys(entry, ("kind", "value"), "entry")
    if entry["kind"] == "name":
        _nonempty(entry["value"], "entry.value")
        if load["kind"] == "raw":
            raise ValueError("Raw requests require an address entry")
    elif entry["kind"] == "address":
        _integer(entry["value"], "entry.value")
    else:
        raise ValueError("entry.kind must be name or address")

    probe_request = request["probe"]
    _exact_keys(probe_request, ("maturities",), "probe")
    if probe_request["maturities"] != list(MATURITIES):
        raise ValueError("Probe maturities must be MMAT_CALLS then MMAT_GLBOPT3")
    return request


def request_digest(value):
    return digest(validate_request(value))


def raw_setup_contract(value):
    """Describe the pre-script raw-loader boundary without mutating the IDB."""

    request = validate_request(value)
    if request["load"]["kind"] != "raw":
        return {
            "schema_version": RAW_SETUP_SCHEMA,
            "status": "not_applicable",
            "reason": "input is configured by an IDA loader",
        }
    return {
        "schema_version": RAW_SETUP_SCHEMA,
        "status": "required",
        "owner": "external_ida_invocation",
        "stage": "before_idapython_entrypoint",
        "reason": (
            "Raw processor, load, and entry configuration must be applied before "
            "this IDAPython script starts; the probe does not mutate loader state"
        ),
        "required": {
            "processor": request["profile"]["processor"],
            "bits": request["profile"]["bits"],
            "data_endian": request["profile"]["data_endian"],
            "instruction_endian": request["profile"]["instruction_endian"],
            "file_offset": request["load"]["file_offset"],
            "load_address": request["load"]["load_address"],
            "entry_address": request["entry"]["value"],
        },
    }


def validate_observation(request_value, observation_value):
    """Compare runtime-observable fields and retain declared-only boundaries."""

    request = validate_request(request_value)
    observation = _json_copy(observation_value)
    _exact_keys(
        observation,
        (
            "binary_sha256",
            "format",
            "filetype",
            "processor",
            "bits",
            "data_endian",
            "instruction_endian",
            "image_base",
            "entry_ea",
        ),
        "observation",
    )
    _sha256(observation["binary_sha256"], "observation.binary_sha256")
    if observation["format"] not in OBSERVED_FORMATS:
        raise ValueError("Unsupported observed binary format")
    _nonempty(observation["filetype"], "observation.filetype")
    _nonempty(observation["processor"], "observation.processor")
    if observation["bits"] not in (32, 64):
        raise ValueError("observation.bits must be 32 or 64")
    _endian(observation["data_endian"], "observation.data_endian")
    _endian(
        observation["instruction_endian"],
        "observation.instruction_endian",
        nullable=True,
    )
    _integer(observation["image_base"], "observation.image_base")
    if observation["entry_ea"] is not None:
        _integer(observation["entry_ea"], "observation.entry_ea")

    expected = {
        "binary.sha256": request["binary"]["sha256"],
        "binary.format": request["binary"]["format"],
        "binary.filetype": request["binary"]["filetype"],
        "profile.processor": request["profile"]["processor"],
        "profile.bits": request["profile"]["bits"],
        "profile.data_endian": request["profile"]["data_endian"],
        "load.address": request["load"].get(
            "image_base", request["load"].get("load_address")
        ),
    }
    actual = {
        "binary.sha256": observation["binary_sha256"],
        "binary.format": observation["format"],
        "binary.filetype": observation["filetype"],
        "profile.processor": observation["processor"],
        "profile.bits": observation["bits"],
        "profile.data_endian": observation["data_endian"],
        "load.address": observation["image_base"],
    }
    checks = [
        {
            "field": field,
            "expected": expected[field],
            "observed": actual[field],
            "status": "matched" if expected[field] == actual[field] else "mismatch",
        }
        for field in expected
    ]
    entry_expected = request["entry"]["value"]
    entry_observed = observation["entry_ea"]
    entry_matches = entry_observed is not None and (
        request["entry"]["kind"] == "name" or entry_expected == entry_observed
    )
    checks.append(
        {
            "field": "entry",
            "expected": request["entry"],
            "observed": entry_observed,
            "status": "matched" if entry_matches else "mismatch",
        }
    )

    instruction_expected = request["profile"]["instruction_endian"]
    instruction_observed = observation["instruction_endian"]
    if instruction_expected is None:
        instruction_status = "not_requested"
    elif instruction_observed is None:
        instruction_status = "unverified"
    elif instruction_expected == instruction_observed:
        instruction_status = "matched"
    else:
        instruction_status = "mismatch"
    checks.append(
        {
            "field": "profile.instruction_endian",
            "expected": instruction_expected,
            "observed": instruction_observed,
            "status": instruction_status,
        }
    )

    mismatches = [check["field"] for check in checks if check["status"] == "mismatch"]
    is_raw = request["load"]["kind"] == "raw"
    raw_setup = raw_setup_contract(request)
    if is_raw and not mismatches:
        raw_setup = dict(raw_setup)
        raw_setup.update(
            status="verified_observable_fields",
            reason=(
                "Observable hash, format/filetype, processor, bits, data endian, "
                "load address, and entry matched; instruction endian remains "
                "declared and unverified"
            ),
        )
    if mismatches:
        status = "mismatch"
    else:
        status = "accepted"
    return {
        "schema_version": VALIDATION_SCHEMA,
        "request_digest": digest(request),
        "status": status,
        "checks": checks,
        "mismatches": mismatches,
        "declared_only": [
            "profile.profile_id",
            "profile.profile_version",
            "profile.mode",
            "profile.abi_id",
        ],
        "unverified": [
            check["field"] for check in checks if check["status"] == "unverified"
        ],
        "raw_setup": raw_setup,
    }


def probe(function_ea, maturity, *, deadline=None, cancelled=lambda: False):
    """Serialize one MBA; cancellation is cooperative, never native preemption."""
    import ida_funcs  # pyright: ignore[reportMissingImports]
    import ida_hexrays as hx  # pyright: ignore[reportMissingImports]
    import ida_idaapi  # pyright: ignore[reportMissingImports]

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
