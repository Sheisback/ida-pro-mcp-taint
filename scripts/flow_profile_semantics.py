"""IDA ``-c -A`` entry point for one G012 normal semantic profile.

The script receives ``ROOT OUTPUT REQUEST`` through ``idc.ARGV``.  It selects
the six fixture symbols only to locate entries; snapshot function identities
are derived from binary hash, profile id, and function RVA.
"""

from __future__ import annotations

import hashlib
import json
import sys
import traceback
from pathlib import Path
from typing import Any, cast

import ida_auto  # pyright: ignore[reportMissingModuleSource]
import ida_funcs  # pyright: ignore[reportMissingModuleSource]
import ida_ida  # pyright: ignore[reportMissingModuleSource]
import ida_name  # pyright: ignore[reportMissingModuleSource]
import ida_nalt  # pyright: ignore[reportMissingModuleSource]
import ida_pro  # pyright: ignore[reportMissingModuleSource]
import idc  # pyright: ignore[reportMissingModuleSource]


class SemanticEntryBlocker(ValueError):
    def __init__(self, data):
        super().__init__("Proven extraction entry is not an exact IDA function")
        self.data = data


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _first_difference(left, right, path="$"):
    if type(left) is not type(right):
        return f"{path}: type {type(left).__name__} != {type(right).__name__}"
    if isinstance(left, dict):
        if set(left) != set(right):
            return f"{path}: keys {sorted(left)} != {sorted(right)}"
        for key in sorted(left):
            difference = _first_difference(left[key], right[key], f"{path}.{key}")
            if difference is not None:
                return difference
        return None
    if isinstance(left, list):
        if len(left) != len(right):
            return f"{path}: length {len(left)} != {len(right)}"
        for index, (left_item, right_item) in enumerate(zip(left, right, strict=True)):
            difference = _first_difference(left_item, right_item, f"{path}[{index}]")
            if difference is not None:
                return difference
        return None
    if left != right:
        return f"{path}: {left!r} != {right!r}"
    return None


def main() -> None:
    root_text, output_text, request_text = idc.ARGV[1:]
    root = Path(root_text).resolve()
    output = Path(output_text)
    request = json.loads(
        Path(request_text).read_text(),
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
    )
    sys.path.insert(0, str(root / "src"))

    from ida_pro_mcp.flow_core.contracts import Snapshot
    from ida_pro_mcp.flow_core.profile_registry import ProfileRegistry
    from ida_pro_mcp.flow_core.profile_semantics import (
        FUNCTIONS,
        EXPECTED_CALLS,
        NORMAL_PROCESS_SCHEMA,
        receipt_digest,
        select_ida_extraction,
        semantic_entry_proofs,
        snapshot_calls,
        structural_function_key,
        validate_semantic_profile,
    )
    from ida_pro_mcp.flow_core.serialization import (
        ContractError,
        canonical_json,
        digest,
    )
    from ida_pro_mcp.ida_mcp.flow import extractor

    expected_request_keys = {
        "schema_version",
        "manifest_sha256",
        "binary_sha256",
        "build_row",
        "registry",
        "profile",
        "functions",
        "implementation",
    }
    if set(request) != expected_request_keys:
        raise ValueError("Semantic process request keys mismatch")
    if request["schema_version"] != "flow-profile-semantics-request/1":
        raise ValueError("Unsupported semantic process request")
    if tuple(request["functions"]) != FUNCTIONS:
        raise ValueError("Semantic function set/order mismatch")
    registry = cast(ProfileRegistry, ProfileRegistry.from_data(request["registry"]))
    validate_semantic_profile(
        request["profile"],
        request["build_row"],
        request["manifest_sha256"],
        registry,
    )
    for relative, expected in request["implementation"].items():
        path = (root / relative).resolve()
        path.relative_to(root)
        if _sha256(path) != expected:
            raise ValueError("Semantic implementation digest mismatch: " + relative)

    input_path = Path(ida_nalt.get_input_file_path())
    if _sha256(input_path) != request["binary_sha256"]:
        raise ValueError("Disposable semantic input hash mismatch")

    ida_auto.auto_wait()
    image_base = (
        int(ida_ida.inf_get_min_ea())
        if request["build_row"]["format"] == "FMT-RAW"
        else int(ida_nalt.get_imagebase())
    )
    rows = []
    environment = None
    entry_proofs = {
        entry["name"]: entry for entry in semantic_entry_proofs(request["build_row"])
    }
    selectors = {
        item.get("function", item.get("value")): item
        for item in request["build_row"]["function_selectors"]
    }
    materializations: dict[str, dict[str, Any] | None] = {
        symbol: None for symbol in FUNCTIONS
    }
    if request["build_row"]["format"] == "FMT-RAW":
        config = request["build_row"].get("raw_configuration")
        if (
            type(config) is not dict
            or config.get("load_address") != image_base
            or config.get("entry_offset") != 0
            or config.get("entry_point") != image_base
            or config.get("source_section") != ".text"
        ):
            raise ValueError("Raw semantic loader configuration mismatch")
        for symbol in FUNCTIONS:
            proof = entry_proofs[symbol]
            start_ea = image_base + proof["logical_rva"]
            end_ea = start_ea + proof["extent_size"]
            existing = ida_funcs.get_func(start_ea)
            add_called = False
            if existing is None:
                if ida_funcs.get_func(end_ea - 1) is not None:
                    raise ValueError("Raw manifest function overlaps existing analysis")
                add_called = True
                if not ida_funcs.add_func(start_ea, end_ea):
                    raise ValueError("Raw manifest function materialization failed")
                ida_auto.auto_wait()
                existing = ida_funcs.get_func(start_ea)
            if (
                existing is None
                or int(existing.start_ea) != start_ea
                or not start_ea < int(existing.end_ea) <= end_ea
            ):
                raise ValueError("Raw manifest function bounds conflict with IDA")
            materializations[symbol] = {
                "kind": (
                    "manifest_add_func"
                    if add_called
                    else "preexisting_exact_start_within_manifest_extent"
                ),
                "requested_start_rva": proof["logical_rva"],
                "requested_end_rva": proof["logical_rva"] + proof["extent_size"],
                "observed_start_rva": int(existing.start_ea) - image_base,
                "observed_end_rva": int(existing.end_ea) - image_base,
                "add_func_called": add_called,
            }
    for symbol in FUNCTIONS:
        proof = entry_proofs[symbol]
        function_rva = proof["logical_rva"]
        logical_ea = image_base + function_rva
        selector = selectors[symbol]
        named_ea = (
            logical_ea
            if selector["kind"] == "raw_offset"
            else int(ida_name.get_name_ea(idc.BADADDR, selector["value"]))
        )
        if named_ea != logical_ea:
            raise ValueError("Fixture symbol does not match manifest RVA: " + symbol)
        logical_function = ida_funcs.get_func(logical_ea)
        if logical_function is None or int(logical_function.start_ea) != logical_ea:
            raise ValueError("Missing exact logical fixture entry: " + symbol)
        manifest_extraction_rva = proof["extraction_rva"]
        manifest_extraction_ea = image_base + manifest_extraction_rva
        function = ida_funcs.get_func(manifest_extraction_ea)
        try:
            if function is None:
                raise ContractError("Manifest extraction entry has no IDA function")
            selection = select_ida_extraction(
                proof,
                int(function.start_ea) - image_base,
                int(function.end_ea) - image_base,
            )
        except ContractError:
            observed = None
            if function is not None:
                observed = {
                    "start_ea": int(function.start_ea),
                    "start_rva": int(function.start_ea) - image_base,
                    "end_ea": int(function.end_ea),
                    "end_rva": int(function.end_ea) - image_base,
                    "name": ida_name.get_name(int(function.start_ea)),
                }
            raise SemanticEntryBlocker(
                {
                    "kind": "proven_extraction_entry_missing_in_ida",
                    "function": symbol,
                    "manifest_entry": proof,
                    "materialization": materializations[symbol],
                    "image_base": image_base,
                    "logical_ea": logical_ea,
                    "logical_rva": function_rva,
                    "logical_ida_bounds": {
                        "start_ea": int(logical_function.start_ea),
                        "start_rva": int(logical_function.start_ea) - image_base,
                        "end_ea": int(logical_function.end_ea),
                        "end_rva": int(logical_function.end_ea) - image_base,
                    },
                    "requested_extraction_ea": manifest_extraction_ea,
                    "requested_extraction_rva": manifest_extraction_rva,
                    "observed_containing_function": observed,
                    "completed_functions": [
                        {
                            "symbol": item["symbol"],
                            "function_rva": item["function_rva"],
                            "snapshot_digest": item["snapshot_digest"],
                            "entry_selection": item["entry_selection"],
                        }
                        for item in rows
                    ],
                }
            )
        ida_extraction_rva = selection["ida_extraction_rva"]
        extraction_ea = image_base + ida_extraction_rva
        if int(function.start_ea) != extraction_ea:
            raise ValueError("Selected IDA extraction start drifted: " + symbol)
        extent_size = proof.get("symbol_size", proof.get("extent_size"))
        extent_end_ea = logical_ea + extent_size if type(extent_size) is int else None
        if not extraction_ea < int(function.end_ea) or (
            extent_end_ea is not None and int(function.end_ea) > extent_end_ea
        ):
            raise ValueError("IDA extraction bounds escape manifest entry: " + symbol)
        if (
            selection["selection_kind"] == "exact_local_function"
            and proof.get("local_entry_offset", 0)
            and int(logical_function.end_ea) != extraction_ea
        ):
            raise ValueError("IDA logical/local entry boundary mismatch: " + symbol)
        function_key = structural_function_key(
            request["binary_sha256"], request["profile"]["profile_id"], function_rva
        )
        extractor.extract_snapshot(
            extraction_ea,
            namespace="g012-phase2-semantic-matrix",
            function_key=function_key,
            profile=request["profile"],
            registry=registry,
        )
        first = cast(
            Snapshot,
            extractor.extract_snapshot(
                extraction_ea,
                namespace="g012-phase2-semantic-matrix",
                function_key=function_key,
                profile=request["profile"],
                registry=registry,
            ),
        )
        second = cast(
            Snapshot,
            extractor.extract_snapshot(
                extraction_ea,
                namespace="g012-phase2-semantic-matrix",
                function_key=function_key,
                profile=request["profile"],
                registry=registry,
            ),
        )
        first_json = canonical_json(first)
        if first_json != canonical_json(second):
            raise ValueError(
                "In-process semantic snapshot drift: "
                + symbol
                + "; "
                + str(_first_difference(first.to_data(), second.to_data()))
            )
        if Snapshot.from_json(first_json) != first:
            raise ValueError("Semantic snapshot strict roundtrip drift: " + symbol)
        observed_environment = first.identity.environment.to_data()
        if environment is None:
            environment = observed_environment
        elif environment != observed_environment:
            raise ValueError("Semantic environment drift across functions")
        rows.append(
            {
                "symbol": symbol,
                "function_rva": function_rva,
                "structural_identity": {
                    "binary_sha256": request["binary_sha256"],
                    "profile_id": request["profile"]["profile_id"],
                    "function_rva": function_rva,
                },
                "entry_selection": {
                    "logical_rva": function_rva,
                    "manifest_extraction_rva": manifest_extraction_rva,
                    "ida_extraction_rva": ida_extraction_rva,
                    "selection_kind": selection["selection_kind"],
                    "proof_kind": proof["proof_kind"],
                    "manifest_entry": proof,
                    "materialization": materializations[symbol],
                    "named_ea": named_ea,
                    "named_rva": named_ea - image_base,
                    "logical_ida_bounds": {
                        "start_ea": int(logical_function.start_ea),
                        "start_rva": int(logical_function.start_ea) - image_base,
                        "end_ea": int(logical_function.end_ea),
                        "end_rva": int(logical_function.end_ea) - image_base,
                    },
                    "extraction_ida_bounds": {
                        "start_ea": int(function.start_ea),
                        "start_rva": int(function.start_ea) - image_base,
                        "end_ea": int(function.end_ea),
                        "end_rva": int(function.end_ea) - image_base,
                    },
                },
                "function_key": function_key,
                "call_target_resolutions": [],
                "snapshot": first.to_data(),
                "snapshot_digest": digest(first),
                "warmup_performed": True,
                "repeat_equal": True,
                "roundtrip_equal": True,
            }
        )

    rows_by_symbol = {row["symbol"]: row for row in rows}
    for row in rows:
        snapshot = cast(Snapshot, Snapshot.from_data(row["snapshot"]))
        calls = snapshot_calls(snapshot)
        expected = EXPECTED_CALLS[row["symbol"]]
        if len(calls) != len(expected):
            raise ValueError("Direct-call count mismatch: " + row["symbol"])
        resolutions = []
        for call, expected_symbol in zip(calls, expected, strict=True):
            raw_target = call.callee_ea
            resolved = None if raw_target is None else ida_funcs.get_func(raw_target)
            resolved_ea = None if resolved is None else int(resolved.start_ea)
            resolved_end_ea = None if resolved is None else int(resolved.end_ea)
            resolved_name = (
                None if resolved_ea is None else ida_name.get_name(resolved_ea)
            )
            expected_row = rows_by_symbol[expected_symbol]
            expected_rva = expected_row["function_rva"]
            expected_selection = expected_row["entry_selection"]
            expected_manifest_extraction_rva = expected_selection[
                "manifest_extraction_rva"
            ]
            expected_ida_extraction_rva = expected_selection["ida_extraction_rva"]
            expected_ea = image_base + expected_ida_extraction_rva
            expected_function = ida_funcs.get_func(expected_ea)
            if (
                expected_function is None
                or int(expected_function.start_ea) != expected_ea
            ):
                raise ValueError("Expected selected callee entry missing")
            expected_end_ea = int(expected_function.end_ea)
            resolved_to_expected = (
                resolved_ea == expected_ea and resolved_end_ea == expected_end_ea
            )
            resolutions.append(
                {
                    "raw_target_ea": raw_target,
                    "raw_target_rva": (
                        None if raw_target is None else raw_target - image_base
                    ),
                    "resolved_function_ea": resolved_ea,
                    "resolved_function_rva": (
                        None if resolved_ea is None else resolved_ea - image_base
                    ),
                    "resolved_function_end_ea": resolved_end_ea,
                    "resolved_function_end_rva": (
                        None
                        if resolved_end_ea is None
                        else resolved_end_ea - image_base
                    ),
                    "resolved_function_name": resolved_name,
                    "expected_symbol": expected_symbol,
                    "expected_function_rva": expected_rva,
                    "expected_manifest_extraction_rva": (
                        expected_manifest_extraction_rva
                    ),
                    "expected_ida_extraction_rva": expected_ida_extraction_rva,
                    "expected_selection_kind": expected_selection["selection_kind"],
                    "expected_entry_proof_kind": expected_selection["proof_kind"],
                    "expected_selected_entry_ea": expected_ea,
                    "expected_selected_end_ea": expected_end_ea,
                    "expected_selected_end_rva": expected_end_ea - image_base,
                    "resolution_kind": (
                        expected_selection["proof_kind"]
                        if resolved_to_expected
                        else "unresolved_or_mismatched"
                    ),
                    "resolved_to_expected": resolved_to_expected,
                }
            )
        row["call_target_resolutions"] = resolutions

    value = {
        "schema_version": NORMAL_PROCESS_SCHEMA,
        "registry": registry.to_data(),
        "profile": request["profile"],
        "profile_digest": digest(request["profile"]),
        "binary_sha256": request["binary_sha256"],
        "image_base": image_base,
        "environment": environment,
        "functions": rows,
        "implementation": request["implementation"],
        "target_executed": False,
        "input_preserved": True,
    }
    value["receipt_digest"] = receipt_digest(value)
    output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        failure = traceback.format_exc()
        traceback.print_exc()
        try:
            value = {
                "schema_version": "flow-profile-semantics-process-failure/1",
                "error": failure,
                "target_executed": False,
            }
            if isinstance(exc, SemanticEntryBlocker):
                value["schema_version"] = "flow-profile-semantics-process-blocker/1"
                value["blocker"] = exc.data
            Path(idc.ARGV[2]).write_text(
                json.dumps(
                    value,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )
        except Exception:
            traceback.print_exc()
        ida_pro.qexit(1)
    ida_pro.qexit(0)
