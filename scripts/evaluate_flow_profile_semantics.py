#!/usr/bin/env python3
"""Build and validate pure G012 semantic receipts without invoking IDA or targets."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, cast

from ida_pro_mcp.flow_core import digest
from ida_pro_mcp.flow_core.analysis import Seed, analyze
from ida_pro_mcp.flow_core.contracts import Snapshot, StructuredSnapshot
from ida_pro_mcp.flow_core.memory_graph import build_memory_graph
from ida_pro_mcp.flow_core.profile_registry import ProfileRegistry
from ida_pro_mcp.flow_core.profile_semantic_receipts import (
    COMPLETE_MATRIX_SCHEMA,
    RV32_EVALUATION_SCHEMA,
    RV32_RECEIPT_SCHEMA,
    validate_complete_matrix_receipt as validate_core_complete_matrix_receipt,
    validate_rv32_receipt as validate_core_rv32_receipt,
)
from ida_pro_mcp.flow_core.profile_semantics import (
    FORMAT_MATRIX_SCHEMA,
    FORMAT_VARIANT_KEYS,
    FUNCTIONS,
    NORMAL_MATRIX_SCHEMA,
    NORMAL_PROFILE_IDS,
    NORMAL_RECEIPT_SCHEMA,
)
from ida_pro_mcp.flow_core.rv32_capture import ProcessReceipt
from ida_pro_mcp.flow_core.rv32_lowering import lower_bundle
from ida_pro_mcp.flow_core.ssa import build_ssa
from ida_pro_mcp.flow_core.states import Labels


RV32_PROFILE_ID = "RV32-LE"
RV32_ABI_ID = "riscv-ilp32"
RV32_CAPTURE_ROOT = Path("tests/flow_fixtures/manifests/rv32_capture")
RV32_ORACLE = Path("tests/flow_fixtures/oracles/rv32_lowering.json")
ISA_ORACLE = Path("tests/flow_fixtures/oracles/isa_profiles.json")
RV32_OUTPUT = Path("tests/flow_fixtures/manifests/profile_semantics/rv32-fallback.json")
RV32_LIMITATIONS = [
    "normal_hexrays_unavailable",
    "implicit_flow_deferred_g013",
    "call_effects_partial",
    "memory_effects_unknown",
    "no_registry_service_or_capability_promotion",
]
RV32_FUNCTION_SYMBOLS = list(FUNCTIONS)
NORMAL_EXPECTED_CALLS = {
    "isa_scalar": (),
    "isa_branch": (),
    "isa_load": (),
    "isa_store": (),
    "isa_call": ("isa_scalar",),
    "isa_profile_entry": ("isa_load", "isa_call", "isa_branch", "isa_store"),
}
NORMAL_DIR = Path("tests/flow_fixtures/manifests/profile_semantics/normal")
FORMAT_DIR = Path("tests/flow_fixtures/manifests/profile_semantics/formats")
MATRIX_OUTPUT = Path("tests/flow_fixtures/manifests/profile_semantics/matrix.json")
PROFILE_BUILD = Path("tests/flow_fixtures/manifests/profiles/build.json")
LOWERING_IMPLEMENTATION = Path("src/ida_pro_mcp/flow_core/rv32_lowering.py")
EVALUATOR_IMPLEMENTATION = Path("scripts/evaluate_flow_profile_semantics.py")


def _reject_constant(value: str) -> None:
    raise ValueError(f"Non-finite JSON constant: {value}")


def _object_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path) -> Any:
    return json.loads(
        path.read_text(),
        object_pairs_hook=_object_pairs,
        parse_constant=_reject_constant,
    )


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def sha256_file(path: Path) -> str:
    return "sha256-v1:" + hashlib.sha256(path.read_bytes()).hexdigest()


def raw_sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _exact_keys(value: Any, expected: set[str], label: str) -> None:
    if type(value) is not dict or set(value) != expected:
        raise ValueError(f"Wrong fields for {label}")


def _artifact(root: Path, relative: Path) -> tuple[Path, Any, str]:
    path = root / relative
    value = read_json(path)
    return path, value, digest(value)


def _entry(program: Any, name: str) -> Any:
    try:
        return next(item for item in program.entry_storage if item.storage.name == name)
    except StopIteration as exc:
        raise ValueError(f"Missing entry storage: {name}") from exc


def _fact_for_kind(program: Any, result: Any, kind: str) -> Any:
    nodes = [item for item in program.graph.nodes if item.kind == kind]
    if len(nodes) != 1:
        raise ValueError(f"Expected exactly one {kind} node")
    facts = {item.node_id: item for item in result.facts}
    return nodes[0], facts[nodes[0].node_id]


def _explicit_labels(
    snapshot: StructuredSnapshot, register: str, kind: str
) -> list[str]:
    program = build_ssa(snapshot)
    result = analyze(
        program.graph,
        (Seed(_entry(program, register).node_id, Labels((register,))),),
    )
    _, fact = _fact_for_kind(program, result, kind)
    return list(fact.labels.explicit)


def _call_rows(snapshot: StructuredSnapshot) -> list[dict[str, Any]]:
    result = []
    for block in snapshot.function.blocks:
        for instruction in block.instructions:
            if instruction.opcode != "m_call":
                continue
            call_operands = [item.call for item in instruction.operands if item.call]
            if len(call_operands) != 1:
                raise ValueError("Every call must carry exactly one CallInfo")
            call = call_operands[0]
            if call is None:
                raise ValueError("Missing CallInfo")
            arguments = []
            returns = []
            for operand in call.arguments:
                if operand.storage is None:
                    raise ValueError("Call argument lacks storage identity")
                arguments.append(operand.storage.name)
            for operand in call.return_operands:
                if operand.storage is None:
                    raise ValueError("Call return lacks storage identity")
                returns.append(operand.storage.name)
            result.append(
                {
                    "site_ea": instruction.source_eas[0],
                    "callee_ea": call.callee_ea,
                    "arguments": arguments,
                    "returns": returns,
                    "return_is_void": call.return_is_void,
                    "return_width_bits": call.return_width_bits,
                    "return_locations": call.return_locations.to_data(),
                    "spoiled_locations": call.spoiled_locations.to_data(),
                    "unresolved": list(call.unresolved),
                }
            )
    return result


def evaluate_rv32_snapshots(
    snapshots: tuple[StructuredSnapshot, ...],
) -> dict[str, Any]:
    """Evaluate exact semantic axes from replayable snapshots."""

    if len(snapshots) != 6:
        raise ValueError("RV32 fallback requires exactly six snapshots")
    scalar, branch, load, store, call, entry = snapshots

    scalar_ops = sorted(
        {
            instruction.opcode
            for block in scalar.function.blocks
            for instruction in block.instructions
            if instruction.opcode in {"m_add", "m_xor"}
        }
    )
    scalar_axis = {
        "operations": scalar_ops,
        "a0_return_labels": _explicit_labels(scalar, "rv32:a0", "Return"),
        "a1_return_labels": _explicit_labels(scalar, "rv32:a1", "Return"),
        "unrelated_ra_return_labels": _explicit_labels(scalar, "rv32:ra", "Return"),
    }

    branch_program = build_ssa(branch)
    selector_result = analyze(
        branch_program.graph,
        (
            Seed(
                _entry(branch_program, "rv32:a1").node_id,
                Labels(("rv32:a1",)),
            ),
        ),
    )
    selector_facts = {item.node_id: item for item in selector_result.facts}
    predicate_nodes = [
        item
        for item in branch_program.graph.nodes
        if item.kind == "Branch" and item.inputs
    ]
    if len(predicate_nodes) != 1:
        raise ValueError("Expected one explicit branch predicate")
    _, selector_return = _fact_for_kind(branch_program, selector_result, "Return")
    branch_axis = {
        "cfg_successors": [list(block.successors) for block in branch.function.blocks],
        "phi_predecessors": [
            [item.predecessor for item in node.phi_inputs]
            for node in branch_program.graph.nodes
            if node.kind == "Phi"
        ],
        "value_return_labels": _explicit_labels(branch, "rv32:a0", "Return"),
        "selector_predicate_labels": list(
            selector_facts[predicate_nodes[0].inputs[0]].labels.explicit
        ),
        "selector_return_labels": list(selector_return.labels.explicit),
        "implicit_flow_claimed": False,
    }

    memory_rows = []
    for symbol, snapshot, kind in (
        ("isa_load", load, "Load"),
        ("isa_store", store, "Store"),
    ):
        analysis = build_memory_graph(snapshot)
        nodes = [item for item in analysis.graph.nodes if item.kind == kind]
        if len(nodes) != 1 or nodes[0].memory is None:
            raise ValueError(f"Expected one precise {kind} memory node")
        node = nodes[0]
        memory = node.memory
        assert memory is not None
        objects = [
            item
            for item in analysis.graph.objects
            if item.object_id == memory.object_id
        ]
        if len(objects) != 1:
            raise ValueError("Missing exact memory object")
        memory_rows.append(
            {
                "symbol": symbol,
                "kind": kind,
                "width_bits": node.width_bits,
                "interval": [memory.interval.start, memory.interval.end],
                "address_space": memory.address_space,
                "object_kind": objects[0].kind,
                "object_singleton": objects[0].singleton,
                "policy_digest": analysis.result.policy_digest,
            }
        )
    store_program = build_ssa(store)
    store_returns = [
        item for item in store_program.graph.nodes if item.kind == "Return"
    ]
    if len(store_returns) != 1:
        raise ValueError("Expected one isa_store return")

    call_rows = _call_rows(call) + _call_rows(entry)
    call_axis = {
        "calls": call_rows,
        "all_effects_partial": all(
            row["unresolved"]
            == [
                "call_effects_partial",
                "memory_effects_unknown",
                "numeric_calling_convention_unavailable",
            ]
            for row in call_rows
        ),
    }

    return {
        "schema_version": RV32_EVALUATION_SCHEMA,
        "status": "partial",
        "scalar": scalar_axis,
        "branch": branch_axis,
        "memory": memory_rows,
        "isa_store_return": {
            "inputs": list(store_returns[0].inputs),
            "width_bits": store_returns[0].width_bits,
        },
        "calls": call_axis,
    }


def _snapshots_from_receipt(receipt: dict[str, Any]) -> tuple[StructuredSnapshot, ...]:
    result: list[StructuredSnapshot] = []
    for index, item in enumerate(receipt["functions"]):
        _exact_keys(
            item,
            {
                "oracle_id",
                "symbol",
                "selector_ordinal",
                "function_rva",
                "snapshot_id",
                "snapshot_digest",
                "snapshot",
            },
            f"RV32 function {index}",
        )
        snapshot = cast(
            StructuredSnapshot, StructuredSnapshot.from_data(item["snapshot"])
        )
        if item["snapshot_id"] != snapshot.snapshot_id:
            raise ValueError("RV32 snapshot id mismatch")
        if item["snapshot_digest"] != digest(snapshot):
            raise ValueError("RV32 snapshot digest mismatch")
        result.append(snapshot)
    return tuple(result)


def _validate_evaluation_against_oracle(
    evaluation: dict[str, Any], oracle: dict[str, Any]
) -> None:
    expected = oracle["semantic_contract"]
    scalar = evaluation["scalar"]
    if scalar != {
        "operations": expected["scalar"]["operations"],
        "a0_return_labels": [expected["scalar"]["return_explicit_sources"][0]],
        "a1_return_labels": [expected["scalar"]["return_explicit_sources"][1]],
        "unrelated_ra_return_labels": expected["scalar"]["unrelated_return_sources"],
    }:
        raise ValueError("RV32 scalar semantic oracle mismatch")

    branch = evaluation["branch"]
    branch_expected = expected["branch"]
    if branch != {
        "cfg_successors": branch_expected["cfg_successors"],
        "phi_predecessors": branch_expected["phi_predecessors"],
        "value_return_labels": branch_expected["value_return_sources"],
        "selector_predicate_labels": branch_expected["selector_predicate_sources"],
        "selector_return_labels": branch_expected["selector_return_sources"],
        "implicit_flow_claimed": branch_expected["implicit_flow_claimed"],
    }:
        raise ValueError("RV32 branch semantic oracle mismatch")
    if evaluation["memory"] != expected["memory"]:
        raise ValueError("RV32 memory semantic oracle mismatch")
    if evaluation["isa_store_return"] != expected["isa_store_return"]:
        raise ValueError("RV32 void return semantic oracle mismatch")

    calls = evaluation["calls"]
    call_expected = expected["calls"]
    if calls["all_effects_partial"] is not True:
        raise ValueError("RV32 calls must remain explicitly partial")
    entry_by_symbol = {item["symbol"]: item["entry_ea"] for item in oracle["functions"]}
    actual_rows = calls["calls"]
    if len(actual_rows) != len(call_expected["rows"]):
        raise ValueError("RV32 call semantic row count mismatch")
    for actual, expected_row in zip(actual_rows, call_expected["rows"]):
        semantic_actual = {
            key: actual[key]
            for key in (
                "site_ea",
                "arguments",
                "returns",
                "return_is_void",
                "return_width_bits",
            )
        }
        semantic_expected = {
            key: expected_row[key]
            for key in (
                "site_ea",
                "arguments",
                "returns",
                "return_is_void",
                "return_width_bits",
            )
        }
        if semantic_actual != semantic_expected:
            raise ValueError("RV32 call ABI semantic oracle mismatch")
        if actual["callee_ea"] != entry_by_symbol[expected_row["callee_symbol"]]:
            raise ValueError("RV32 direct call target semantic oracle mismatch")
        if actual["unresolved"] != call_expected["unresolved"]:
            raise ValueError("RV32 call limitation semantic oracle mismatch")
        if (
            digest(actual["spoiled_locations"])
            != call_expected["spoiled_locations_digest"]
        ):
            raise ValueError("RV32 call spoil semantic oracle mismatch")
        expected_return_digest = (
            call_expected["void_return_locations_digest"]
            if actual["return_is_void"]
            else call_expected["nonvoid_return_locations_digest"]
        )
        if digest(actual["return_locations"]) != expected_return_digest:
            raise ValueError("RV32 call return-location semantic oracle mismatch")


def _graph_predecessors(graph: Any) -> dict[str, tuple[str, ...]]:
    return {
        node.node_id: node.inputs + tuple(item.node_id for item in node.phi_inputs)
        for node in graph.nodes
    }


def _depends_on(graph: Any, target: str, source: str) -> bool:
    predecessors = _graph_predecessors(graph)
    pending = [target]
    seen: set[str] = set()
    while pending:
        current = pending.pop()
        if current == source:
            return True
        if current in seen:
            continue
        seen.add(current)
        pending.extend(predecessors.get(current, ()))
    return False


def _normal_nodes(program: Any, kind: str) -> list[Any]:
    return [node for node in program.graph.nodes if node.kind == kind]


def _constant_input(program: Any, node: Any, value: int) -> bool:
    by_id = {item.node_id: item for item in program.graph.nodes}
    return any(
        by_id[item].kind == "Constant" and by_id[item].constant == value
        for item in node.inputs
    )


def _binary_with_constant(program: Any, operation: str, value: int) -> list[Any]:
    return [
        node
        for node in program.graph.nodes
        if node.kind == "Binary"
        and node.operation == operation
        and _constant_input(program, node, value)
    ]


def _walk_operand(value: Any):
    yield value
    for child in value.children:
        yield from _walk_operand(child)
    if value.call is not None:
        for child in value.call.arguments + value.call.return_operands:
            yield from _walk_operand(child)


def _normal_calls(snapshot: Snapshot) -> list[Any]:
    result = []
    for block in snapshot.function.blocks:
        for instruction in block.instructions:
            for root in instruction.operands:
                result.extend(
                    item.call for item in _walk_operand(root) if item.call is not None
                )
    return result


def _normal_limitations(program: Any) -> list[str]:
    limitations = set(program.diagnostics)
    if not _normal_nodes(program, "Return"):
        limitations.add("normal_terminal_return_not_serialized")
    if any(node.kind == "UnknownValue" for node in program.graph.nodes):
        limitations.add("opaque_graph_nodes_retained")
    return sorted(limitations)


def evaluate_normal_functions(
    functions: list[dict[str, Any]], image_base: int
) -> dict[str, Any]:
    """Independently replay the six normal snapshots against source oracles."""

    if [item.get("symbol") for item in functions] != RV32_FUNCTION_SYMBOLS:
        raise ValueError("Normal semantic function set/order mismatch")
    snapshots: dict[str, Snapshot] = {
        item["symbol"]: cast(Snapshot, Snapshot.from_data(item["snapshot"]))
        for item in functions
    }
    programs = {name: build_ssa(snapshot) for name, snapshot in snapshots.items()}
    replay = {
        name: {
            "ssa_equal": build_ssa(snapshot) == programs[name],
            "memory_equal": build_memory_graph(snapshot)
            == build_memory_graph(snapshot),
        }
        for name, snapshot in snapshots.items()
    }
    if not all(all(item.values()) for item in replay.values()):
        raise ValueError("Normal offline graph replay drift")

    scalar = programs["isa_scalar"]
    adds = [
        node
        for node in scalar.graph.nodes
        if node.kind == "Binary" and node.operation == "add"
    ]
    xors = _binary_with_constant(scalar, "xor", 0x013579BD)
    if (
        not adds
        or not xors
        or not any(
            _depends_on(scalar.graph, xor.node_id, add.node_id)
            for xor in xors
            for add in adds
        )
    ):
        raise ValueError("Normal scalar add/xor oracle mismatch")

    branch = programs["isa_branch"]
    branch_snapshot = snapshots["isa_branch"]
    if not (
        any(len(block.successors) == 2 for block in branch_snapshot.function.blocks)
        and any(
            len(block.predecessors) == 2 for block in branch_snapshot.function.blocks
        )
        and _normal_nodes(branch, "Branch")
        and _binary_with_constant(branch, "add", 3)
        and _binary_with_constant(branch, "xor", 5)
    ):
        raise ValueError("Normal branch semantic oracle mismatch")

    load = programs["isa_load"]
    loads = _normal_nodes(load, "Load")
    if (
        len(loads) != 1
        or loads[0].width_bits != 32
        or loads[0].memory_operands is None
        or loads[0].memory_operands.address not in loads[0].inputs
    ):
        raise ValueError("Normal exact four-byte load oracle mismatch")

    store = programs["isa_store"]
    stores = _normal_nodes(store, "Store")
    if len(stores) != 1 or stores[0].width_bits != 32:
        raise ValueError("Normal exact four-byte store oracle mismatch")
    roles = stores[0].memory_operands
    if (
        roles is None
        or roles.address == roles.data
        or roles.address not in stores[0].inputs
        or roles.data not in stores[0].inputs
    ):
        raise ValueError("Normal store address/content oracle mismatch")

    rvas = {item["symbol"]: item["function_rva"] for item in functions}
    calls = _normal_calls(snapshots["isa_call"])
    call_resolutions = functions[4]["call_target_resolutions"]
    call_complete = (
        len(calls) == 1
        and len(call_resolutions) == 1
        and call_resolutions[0]["expected_symbol"] == "isa_scalar"
        and call_resolutions[0]["expected_function_rva"] == rvas["isa_scalar"]
        and call_resolutions[0]["resolved_to_expected"] is True
        and len(calls[0].arguments) == 2
        and calls[0].return_is_void is False
        and calls[0].return_width_bits == 32
        and any(
            operand.kind == "constant" and operand.constant == 7
            for argument in calls[0].arguments
            for operand in _walk_operand(argument)
        )
    )
    entry_calls = _normal_calls(snapshots["isa_profile_entry"])
    entry_resolutions = functions[5]["call_target_resolutions"]
    expected_entry_symbols = ("isa_load", "isa_call", "isa_branch", "isa_store")
    entry_targets_complete = (
        len(entry_calls) == len(entry_resolutions) == 4
        and tuple(item["expected_symbol"] for item in entry_resolutions)
        == expected_entry_symbols
        and all(item["resolved_to_expected"] is True for item in entry_resolutions)
        and sum(call.return_is_void for call in entry_calls) == 1
    )

    limitations_set = {
        "native_register_names_not_serialized",
        "native_instruction_families_not_serialized",
        *(
            limitation
            for program in programs.values()
            for limitation in _normal_limitations(program)
        ),
    }
    if not call_complete:
        limitations_set.add("direct_call_target_or_argument_metadata_unresolved")
    if not entry_targets_complete:
        limitations_set.add("profile_entry_direct_target_set_unresolved")
    limitations = sorted(limitations_set)
    return {
        "schema_version": "flow-profile-semantics-evaluation/1",
        "status": "pass_with_named_partiality" if limitations else "pass",
        "generic_oracles": {
            "ISA-G01": "pass_scalar_add_then_xor",
            "ISA-G02": "pass_cfg_add_xor_arms_explicit_flow_partial",
            "ISA-G03": "pass_exact_4byte_load_address_content_separate",
            "ISA-G04": "pass_exact_4byte_store_address_content_separate",
            "ISA-G05": (
                "pass_direct_target_args_return_void_partial_effects"
                if call_complete and entry_targets_complete
                else "partial_direct_target_or_argument_metadata_unresolved"
            ),
        },
        "call_observation": {
            "expected_scalar_rva": rvas["isa_scalar"],
            "observed_isa_call_target_rvas": [
                call.callee_ea - image_base
                for call in calls
                if call.callee_ea is not None
            ],
            "observed_isa_call_argument_counts": [
                len(call.arguments) for call in calls
            ],
            "isa_call_target_resolutions": call_resolutions,
            "profile_entry_target_resolutions": entry_resolutions,
        },
        "offline_replay": replay,
        "alias_status": "conservative_unknown",
        "limitations": limitations,
    }


def _structural_function_key(
    binary_sha256: str, profile_id: str, function_rva: int
) -> str:
    value = {
        "binary_sha256": binary_sha256,
        "profile_id": profile_id,
        "function_rva": function_rva,
    }
    return "g012-function-v1:" + digest(value).split(":", 1)[1]


FUNCTION_ENTRY_KEYS = {
    "name",
    "symbol_value",
    "symbol_size",
    "symbol_other",
    "symbol_table",
    "logical_rva",
    "local_entry_offset",
    "extraction_rva",
    "proof_kind",
}


def _function_entry_proofs(build_row: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    raw_entries = build_row.get("function_entries")
    if type(raw_entries) is not list or not all(
        type(item) is dict for item in raw_entries
    ):
        raise ValueError("Build function entry proofs must be objects")
    entries = cast(list[dict[str, Any]], raw_entries)
    if tuple(item.get("name") for item in entries) != FUNCTIONS:
        raise ValueError("Build function entry proof set/order mismatch")
    ppc64_elfv2 = (
        build_row.get("profile_id") in {"PPC64-LE", "PPC64-BE"}
        and build_row.get("mode") == "PPC64"
        and build_row.get("abi_id") == "elfv2-ppc64"
        and build_row.get("bitness") == 64
        and build_row.get("format") == "FMT-ELF"
        and build_row.get("platform_tag") == "linux"
        and (
            (
                build_row.get("profile_id") == "PPC64-LE"
                and build_row.get("data_endian") == "LE"
                and build_row.get("instruction_endian") == "LE"
                and build_row.get("processor") == "PPCL"
                and build_row.get("target_triple") == "powerpc64le-linux-gnu"
            )
            or (
                build_row.get("profile_id") == "PPC64-BE"
                and build_row.get("data_endian") == "BE"
                and build_row.get("instruction_endian") == "BE"
                and build_row.get("processor") == "PPC"
                and build_row.get("target_triple") == "powerpc64-linux-gnu"
            )
        )
    )
    header = build_row.get("binary_header")
    if (
        type(header) is not dict
        or header.get("kind") != "ELF"
        or type(header.get("image_base")) is not int
        or header["image_base"] < 0
    ):
        raise ValueError("ELF preferred image base missing")
    image_base = header["image_base"]
    thumb = (
        build_row.get("profile_id") in {"THUMB-LE", "THUMB-BE"}
        and build_row.get("mode") == "THUMB"
    )
    for entry in entries:
        _exact_keys(entry, FUNCTION_ENTRY_KEYS, "build function entry proof")
        logical_rva = entry["logical_rva"]
        symbol_value = entry["symbol_value"]
        symbol_size = entry["symbol_size"]
        symbol_other = entry["symbol_other"]
        if type(logical_rva) is not int or logical_rva < 0:
            raise ValueError("Invalid logical function RVA")
        if type(symbol_value) is not int or symbol_value < 0:
            raise ValueError("Invalid raw ELF symbol value")
        normalized_symbol_value = symbol_value & ~1 if thumb else symbol_value
        if normalized_symbol_value != image_base + logical_rva:
            raise ValueError("ELF symbol value/logical RVA/image-base mismatch")
        if type(symbol_size) is not int or symbol_size <= 0:
            raise ValueError("Invalid function symbol size")
        if type(symbol_other) is not int or not 0 <= symbol_other <= 0xFF:
            raise ValueError("Invalid raw ELF st_other")
        if entry["symbol_table"] != ".symtab":
            raise ValueError("Untrusted ELF symbol table")
        encoding = (symbol_other >> 5) & 0x7
        decoded_offset = 0 if encoding <= 1 else 1 << encoding
        expected_offset = decoded_offset if ppc64_elfv2 else 0
        expected_kind = "ppc64_elfv2_st_other" if ppc64_elfv2 else "elf_symbol"
        if (
            entry["proof_kind"] != expected_kind
            or type(entry["local_entry_offset"]) is not int
            or entry["local_entry_offset"] != expected_offset
            or type(entry["extraction_rva"]) is not int
            or entry["extraction_rva"] != logical_rva + expected_offset
            or not logical_rva <= entry["extraction_rva"] < logical_rva + symbol_size
        ):
            raise ValueError("Function extraction entry proof mismatch")
    if (
        header.get("entry")
        != entries[FUNCTIONS.index("isa_profile_entry")]["symbol_value"]
    ):
        raise ValueError("ELF function entry/load-bias binding mismatch")
    return tuple(entries)


def _semantic_entry_proofs(build_row: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    if build_row.get("format") == "FMT-ELF":
        return _function_entry_proofs(build_row)
    if (
        build_row.get("profile_id"),
        build_row.get("format"),
    ) not in FORMAT_VARIANT_KEYS:
        raise ValueError("Unsupported semantic format row")
    raw_selectors = build_row.get("function_selectors")
    if type(raw_selectors) is not list or not all(
        type(item) is dict for item in raw_selectors
    ):
        raise ValueError("Format semantic selectors must be objects")
    selectors = cast(list[dict[str, Any]], raw_selectors)
    if tuple(item.get("function") for item in selectors) != FUNCTIONS:
        raise ValueError("Format semantic selector set/order mismatch")
    proofs = []
    for selector in selectors:
        function = selector["function"]
        rva = selector.get("rva", selector.get("value"))
        if type(rva) is not int or rva < 0:
            raise ValueError("Invalid format function RVA")
        if build_row["format"] == "FMT-PE":
            _exact_keys(
                selector,
                {"function", "kind", "value", "rva"},
                "PE semantic selector",
            )
            if selector["kind"] != "export_name" or selector["value"] != function:
                raise ValueError("PE semantic export selector mismatch")
            proof_kind, extent_size = "pe_export_rva", None
        elif build_row["format"] == "FMT-RAW":
            _exact_keys(
                selector,
                {"function", "kind", "value", "size"},
                "raw semantic selector",
            )
            if (
                selector["kind"] != "raw_offset"
                or type(selector["size"]) is not int
                or selector["size"] <= 0
            ):
                raise ValueError("Raw semantic offset/size selector mismatch")
            proof_kind, extent_size = "raw_offset_size", selector["size"]
        else:
            _exact_keys(
                selector,
                {
                    "function",
                    "kind",
                    "value",
                    "rva",
                    "naming_convention",
                    "requires_companion",
                },
                "Mach-O semantic selector",
            )
            if (
                selector["kind"] != "ida_name"
                or selector["value"] != "_" + function
                or selector["requires_companion"] is not False
            ):
                raise ValueError("Mach-O semantic symbol selector mismatch")
            proof_kind, extent_size = "macho_external_symbol_rva", None
        proofs.append(
            {
                "name": function,
                "logical_rva": rva,
                "extraction_rva": rva,
                "proof_kind": proof_kind,
                "selector": selector,
                "extent_size": extent_size,
            }
        )
    header = build_row.get("binary_header")
    if build_row["format"] == "FMT-PE":
        if type(header) is not dict:
            raise ValueError("PE binary header missing")
        exports = header.get("exports")
        if type(exports) is not list or {
            item.get("name"): item.get("rva") for item in exports
        } != {item["name"]: item["logical_rva"] for item in proofs}:
            raise ValueError("PE export table/selector mismatch")
    elif build_row["format"] == "FMT-MACHO":
        if type(header) is not dict:
            raise ValueError("Mach-O binary header missing")
        symbols = header.get("semantic_symbols")
        if type(symbols) is not list or {
            item.get("name"): item.get("rva") for item in symbols
        } != {item["selector"]["value"]: item["logical_rva"] for item in proofs}:
            raise ValueError("Mach-O symbol table/selector mismatch")
    return tuple(proofs)


def _select_ida_extraction(
    proof: dict[str, Any], resolved_start_rva: int, resolved_end_rva: int
) -> dict[str, Any]:
    logical_rva = proof["logical_rva"]
    manifest_extraction_rva = proof["extraction_rva"]
    extent_size = proof.get("symbol_size", proof.get("extent_size"))
    if (
        type(resolved_start_rva) is not int
        or type(resolved_end_rva) is not int
        or resolved_start_rva >= resolved_end_rva
    ):
        raise ValueError("Invalid resolved IDA function bounds")
    if type(extent_size) is int and not (
        logical_rva
        <= resolved_start_rva
        < resolved_end_rva
        <= logical_rva + extent_size
    ):
        raise ValueError("Resolved IDA function escapes the manifest extent")
    if resolved_start_rva == manifest_extraction_rva:
        return {
            "manifest_extraction_rva": manifest_extraction_rva,
            "ida_extraction_rva": manifest_extraction_rva,
            "selection_kind": "exact_local_function",
        }
    local_entry_offset = proof.get("local_entry_offset", 0)
    if not (
        type(local_entry_offset) is int
        and local_entry_offset > 0
        and resolved_start_rva == logical_rva
        and resolved_start_rva < manifest_extraction_rva < resolved_end_rva
    ):
        raise ValueError(
            "Resolved IDA function is not an approved proven-local containment"
        )
    return {
        "manifest_extraction_rva": manifest_extraction_rva,
        "ida_extraction_rva": logical_rva,
        "selection_kind": "logical_function_contains_proven_local_entry",
    }


def _validate_normal_entry_selection(
    value: Any, proof: dict[str, Any], image_base: int
) -> None:
    _exact_keys(
        value,
        {
            "logical_rva",
            "manifest_extraction_rva",
            "ida_extraction_rva",
            "selection_kind",
            "proof_kind",
            "manifest_entry",
            "materialization",
            "named_ea",
            "named_rva",
            "logical_ida_bounds",
            "extraction_ida_bounds",
        },
        "normal entry selection",
    )
    if (
        value["logical_rva"] != proof["logical_rva"]
        or value["manifest_extraction_rva"] != proof["extraction_rva"]
        or value["proof_kind"] != proof["proof_kind"]
        or value["manifest_entry"] != proof
        or value["named_ea"] != image_base + proof["logical_rva"]
        or value["named_rva"] != proof["logical_rva"]
    ):
        raise ValueError("Entry selection/manifest proof mismatch")
    logical = value["logical_ida_bounds"]
    extraction = value["extraction_ida_bounds"]
    for bounds in (logical, extraction):
        _exact_keys(
            bounds,
            {"start_ea", "start_rva", "end_ea", "end_rva"},
            "normal IDA function bounds",
        )
        if not all(type(bounds[key]) is int for key in bounds) or (
            bounds["start_rva"] != bounds["start_ea"] - image_base
            or bounds["end_rva"] != bounds["end_ea"] - image_base
        ):
            raise ValueError("IDA function bound/image-base mismatch")
    extent_size = proof.get("symbol_size", proof.get("extent_size"))
    extent_end_rva = (
        proof["logical_rva"] + extent_size if type(extent_size) is int else None
    )
    if not (
        logical["start_rva"] == proof["logical_rva"]
        and logical["start_rva"] < logical["end_rva"]
        and (extent_end_rva is None or logical["end_rva"] <= extent_end_rva)
        and extraction["start_rva"] == value["ida_extraction_rva"]
        and extraction["start_rva"] < extraction["end_rva"]
        and (extent_end_rva is None or extraction["end_rva"] <= extent_end_rva)
    ):
        raise ValueError("IDA function bounds escape manifest entry")
    selection = _select_ida_extraction(
        proof, extraction["start_rva"], extraction["end_rva"]
    )
    if (
        value["ida_extraction_rva"] != selection["ida_extraction_rva"]
        or value["selection_kind"] != selection["selection_kind"]
    ):
        raise ValueError("IDA extraction selection contract mismatch")
    materialization = value["materialization"]
    if proof["proof_kind"] == "raw_offset_size":
        _exact_keys(
            materialization,
            {
                "kind",
                "requested_start_rva",
                "requested_end_rva",
                "observed_start_rva",
                "observed_end_rva",
                "add_func_called",
            },
            "raw function materialization",
        )
        if not (
            materialization["requested_start_rva"] == proof["logical_rva"]
            and materialization["requested_end_rva"]
            == proof["logical_rva"] + proof["extent_size"]
            and materialization["observed_start_rva"] == extraction["start_rva"]
            and materialization["observed_end_rva"] == extraction["end_rva"]
            and materialization["kind"]
            == (
                "manifest_add_func"
                if materialization["add_func_called"] is True
                else "preexisting_exact_start_within_manifest_extent"
            )
        ):
            raise ValueError("Raw function materialization proof mismatch")
    elif materialization is not None:
        raise ValueError("Unexpected non-raw materialization proof")
    if selection["selection_kind"] == "exact_local_function" and proof.get(
        "local_entry_offset", 0
    ):
        if logical["end_rva"] != extraction["start_rva"]:
            raise ValueError("IDA logical/local entry boundary mismatch")
    elif selection["selection_kind"] == "logical_function_contains_proven_local_entry":
        if not (
            logical == extraction
            and logical["start_rva"] < proof["extraction_rva"] < logical["end_rva"]
        ):
            raise ValueError("Containing logical function/local-entry mismatch")
    elif logical != extraction:
        raise ValueError("Exact logical entry bounds drifted")


def validate_normal_receipt(
    root: Path,
    receipt: dict[str, Any],
    build_row: dict[str, Any],
    oracle_profile: dict[str, Any],
) -> None:
    _exact_keys(
        receipt,
        {
            "schema_version",
            "profile_id",
            "abi_id",
            "bitness",
            "data_endian",
            "instruction_endian",
            "maturity",
            "evidence_path",
            "status",
            "binary_sha256",
            "build_evidence",
            "registry",
            "profile",
            "profile_digest",
            "environment",
            "image_base",
            "functions",
            "fresh_process_receipt_digests",
            "fresh_process_equal",
            "invocations",
            "implementation",
            "oracle_source",
            "oracle_digest",
            "isa_oracle_binding",
            "evaluation",
            "target_executed",
            "input_preserved",
            "registry_promoted",
            "service_promoted",
            "capabilities_promoted",
            "support_status",
            "receipt_digest",
        },
        "normal semantic receipt",
    )
    if receipt["schema_version"] != NORMAL_RECEIPT_SCHEMA:
        raise ValueError("Normal semantic receipt schema mismatch")
    unsigned = dict(receipt)
    observed_digest = unsigned.pop("receipt_digest")
    if observed_digest != digest(unsigned):
        raise ValueError("Normal semantic receipt digest mismatch")
    profile_id = build_row["profile_id"]
    if (
        receipt["profile_id"] != profile_id
        or receipt["binary_sha256"] != build_row["binary_sha256"]
    ):
        raise ValueError("Normal profile/binary mismatch")
    if {
        "abi_id": receipt["abi_id"],
        "bitness": receipt["bitness"],
        "data_endian": receipt["data_endian"],
        "instruction_endian": receipt["instruction_endian"],
    } != {
        "abi_id": build_row["abi_id"],
        "bitness": build_row["bitness"],
        "data_endian": build_row["data_endian"],
        "instruction_endian": build_row["instruction_endian"],
    }:
        raise ValueError("Normal ABI/profile facts mismatch")
    if (
        receipt["maturity"] != "MMAT_CALLS"
        or receipt["evidence_path"]
        != (
            "normal_microcode"
            if build_row["format"] == "FMT-ELF"
            else "format_microcode"
        )
        or receipt["status"] != "success"
    ):
        raise ValueError("Normal evidence path/status mismatch")
    if (
        receipt["target_executed"] is not False
        or receipt["input_preserved"] is not True
    ):
        raise ValueError("Normal target execution/input preservation mismatch")
    if receipt["support_status"] != "unverified_semantic_candidate_no_promotion":
        raise ValueError("Normal semantic receipt support claim mismatch")
    if (
        receipt["registry_promoted"] is not False
        or receipt["service_promoted"] is not False
        or receipt["capabilities_promoted"] is not False
    ):
        raise ValueError("Normal semantic receipt promoted support")
    if receipt["fresh_process_equal"] is not True:
        raise ValueError("Normal fresh-process semantic drift")
    if (
        type(receipt["fresh_process_receipt_digests"]) is not list
        or len(receipt["fresh_process_receipt_digests"]) != 2
        or len(set(receipt["fresh_process_receipt_digests"])) != 1
    ):
        raise ValueError("Normal fresh-process receipt digest mismatch")
    process_view = {
        "schema_version": "flow-profile-semantics-process/1",
        "registry": receipt["registry"],
        "profile": receipt["profile"],
        "profile_digest": receipt["profile_digest"],
        "binary_sha256": receipt["binary_sha256"],
        "image_base": receipt["image_base"],
        "environment": receipt["environment"],
        "functions": receipt["functions"],
        "implementation": receipt["implementation"],
        "target_executed": receipt["target_executed"],
        "input_preserved": receipt["input_preserved"],
    }
    expected_process_digest = digest(process_view)
    if receipt["fresh_process_receipt_digests"] != [
        expected_process_digest,
        expected_process_digest,
    ]:
        raise ValueError("Normal fresh-process receipt digest/payload mismatch")

    build_path = root / PROFILE_BUILD
    evidence = receipt["build_evidence"]
    _exact_keys(
        evidence,
        {
            "committed_manifest_sha256",
            "rebuilt_manifest_sha256",
            "build_row_digest",
            "rebuilt_profile_rows_equal",
            "binary_hash_equal",
            "binary_size_equal",
        },
        "normal build evidence",
    )
    if (
        evidence["committed_manifest_sha256"] != raw_sha256_file(build_path)
        or evidence["build_row_digest"] != digest(build_row)
        or evidence["rebuilt_profile_rows_equal"] is not True
        or evidence["binary_hash_equal"] is not True
        or evidence["binary_size_equal"] is not True
        or type(evidence["rebuilt_manifest_sha256"]) is not str
        or len(evidence["rebuilt_manifest_sha256"]) != 64
    ):
        raise ValueError("Normal build evidence mismatch")

    registry = cast(ProfileRegistry, ProfileRegistry.from_data(receipt["registry"]))
    if len(registry.profiles) != 17:
        raise ValueError("Ephemeral normal registry coverage mismatch")
    profile = receipt["profile"]
    measured = registry.get(profile_id).measured_receipt
    if measured is None:
        raise ValueError("Ephemeral normal registry profile is unmeasured")
    expected_provenance = {
        "kind": "measured_anchor_build",
        "manifest_sha256": evidence["committed_manifest_sha256"],
        "build_row_digest": digest(build_row),
        "binary_sha256": build_row["binary_sha256"],
        "p0_receipt": measured.file_name,
        "p0_mmat_calls_digest": measured.digest,
        "scope": "exact semantic-matrix fixture; not registry promotion",
    }
    if (
        profile["profile_id"] != profile_id
        or profile["version"] != build_row["profile_version"]
        or profile["mode"] != build_row["mode"]
        or profile["abi"] != build_row["abi_id"]
        or profile["maturity"] != "MMAT_CALLS"
        or profile["bitness"] != build_row["bitness"]
        or profile["data_endian"]
        != {"LE": "little", "BE": "big"}[build_row["data_endian"]]
        or profile["instruction_endian"]
        != {"LE": "little", "BE": "big"}[build_row["instruction_endian"]]
        or profile["processor"] != build_row["processor"]
        or profile["format_id"] != build_row["format"]
        or profile["platform_tag"] != build_row["platform_tag"]
        or profile["normal_status"] != "unverified"
        or profile["fallback_status"] != "unverified"
        or profile["receipt_status"] != "success"
        or profile["receipt_evidence"] != measured.to_data()
        or profile["registry_digest"] != digest(registry)
        or profile["required_features"]
        != ["scalar", "branch", "range_memory", "abi", "isa_specific_contract"]
        or profile["abi_provenance"] != expected_provenance
        or receipt["profile_digest"] != digest(profile)
    ):
        raise ValueError("Normal extraction profile mismatch")

    environment = receipt["environment"]
    expected_environment = {
        "processor": build_row["processor"],
        "abi": build_row["abi_id"],
        "bitness": build_row["bitness"],
        "data_endian": {"LE": "little", "BE": "big"}[build_row["data_endian"]],
        "instruction_endian": {"LE": "little", "BE": "big"}[
            build_row["instruction_endian"]
        ],
        "format_id": build_row["format"],
        "platform_tag": build_row["platform_tag"],
    }
    if type(environment) is not dict or not all(
        environment.get(key) == value for key, value in expected_environment.items()
    ):
        raise ValueError("Normal environment/oracle mismatch")

    functions = receipt["functions"]
    if [item.get("symbol") for item in functions] != RV32_FUNCTION_SYMBOLS:
        raise ValueError("Normal semantic functions incomplete")
    proofs = {item["name"]: item for item in _semantic_entry_proofs(build_row)}
    function_rvas = {item["symbol"]: item["function_rva"] for item in functions}
    functions_by_symbol = {item["symbol"]: item for item in functions}
    for symbol, item in functions_by_symbol.items():
        _validate_normal_entry_selection(
            item.get("entry_selection"), proofs[symbol], receipt["image_base"]
        )
        if item["function_rva"] != proofs[symbol]["logical_rva"]:
            raise ValueError("Function logical RVA/manifest proof mismatch")
    for item in functions:
        _exact_keys(
            item,
            {
                "symbol",
                "function_rva",
                "structural_identity",
                "entry_selection",
                "function_key",
                "call_target_resolutions",
                "snapshot",
                "snapshot_digest",
                "warmup_performed",
                "repeat_equal",
                "roundtrip_equal",
            },
            "normal semantic function",
        )
        snapshot = cast(Snapshot, Snapshot.from_data(item["snapshot"]))
        resolutions = item["call_target_resolutions"]
        calls = _normal_calls(snapshot)
        expected_symbols = NORMAL_EXPECTED_CALLS[item["symbol"]]
        if (
            type(resolutions) is not list
            or len(resolutions) != len(calls)
            or len(resolutions) != len(expected_symbols)
        ):
            raise ValueError("Normal call target resolution coverage mismatch")
        for resolution, call, expected_symbol in zip(
            resolutions, calls, expected_symbols, strict=True
        ):
            _exact_keys(
                resolution,
                {
                    "raw_target_ea",
                    "raw_target_rva",
                    "resolved_function_ea",
                    "resolved_function_rva",
                    "resolved_function_end_ea",
                    "resolved_function_end_rva",
                    "resolved_function_name",
                    "expected_symbol",
                    "expected_function_rva",
                    "expected_manifest_extraction_rva",
                    "expected_ida_extraction_rva",
                    "expected_selection_kind",
                    "expected_entry_proof_kind",
                    "expected_selected_entry_ea",
                    "expected_selected_end_ea",
                    "expected_selected_end_rva",
                    "resolution_kind",
                    "resolved_to_expected",
                },
                "normal call target resolution",
            )
            raw_target = call.callee_ea
            resolved_ea = resolution["resolved_function_ea"]
            expected_rva = function_rvas[expected_symbol]
            expected_selection = functions_by_symbol[expected_symbol]["entry_selection"]
            expected_manifest_extraction_rva = expected_selection[
                "manifest_extraction_rva"
            ]
            expected_ida_extraction_rva = expected_selection["ida_extraction_rva"]
            resolved_to_expected = (
                resolution["resolved_function_rva"] == expected_ida_extraction_rva
                and resolution["resolved_function_end_rva"]
                == expected_selection["extraction_ida_bounds"]["end_rva"]
            )
            expected_kind = (
                expected_selection["proof_kind"]
                if resolved_to_expected
                else "unresolved_or_mismatched"
            )
            if not (
                resolution["raw_target_ea"] == raw_target
                and resolution["raw_target_rva"]
                == (None if raw_target is None else raw_target - receipt["image_base"])
                and resolution["resolved_function_rva"]
                == (
                    None if resolved_ea is None else resolved_ea - receipt["image_base"]
                )
                and resolution["resolved_function_end_rva"]
                == (
                    None
                    if resolution["resolved_function_end_ea"] is None
                    else resolution["resolved_function_end_ea"] - receipt["image_base"]
                )
                and resolution["expected_symbol"] == expected_symbol
                and resolution["expected_function_rva"] == expected_rva
                and resolution["expected_manifest_extraction_rva"]
                == expected_manifest_extraction_rva
                and resolution["expected_ida_extraction_rva"]
                == expected_ida_extraction_rva
                and resolution["expected_selection_kind"]
                == expected_selection["selection_kind"]
                and resolution["expected_entry_proof_kind"]
                == expected_selection["proof_kind"]
                and resolution["expected_selected_entry_ea"]
                == receipt["image_base"] + expected_ida_extraction_rva
                and resolution["expected_selected_end_ea"]
                == expected_selection["extraction_ida_bounds"]["end_ea"]
                and resolution["expected_selected_end_rva"]
                == resolution["expected_selected_end_ea"] - receipt["image_base"]
                and resolution["resolution_kind"] == expected_kind
                and resolution["resolved_to_expected"] is resolved_to_expected
            ):
                raise ValueError("Normal call target resolution binding mismatch")
        expected_key = _structural_function_key(
            build_row["binary_sha256"], profile_id, item["function_rva"]
        )
        if (
            item["structural_identity"]
            != {
                "binary_sha256": build_row["binary_sha256"],
                "profile_id": profile_id,
                "function_rva": item["function_rva"],
            }
            or item["warmup_performed"] is not True
            or item["function_key"] != expected_key
            or snapshot.function.function_id != expected_key
            or item["snapshot_digest"] != digest(snapshot)
            or item["repeat_equal"] is not True
            or item["roundtrip_equal"] is not True
            or Snapshot.from_data(snapshot.to_data()) != snapshot
        ):
            raise ValueError("Normal function structural/replay mismatch")

    expected_implementation = {
        relative: raw_sha256_file(root / relative)
        for relative in (
            "scripts/flow_profile_semantics.py",
            "scripts/record_flow_profile_semantics.py",
            "src/ida_pro_mcp/flow_core/profile_semantics.py",
            "src/ida_pro_mcp/ida_mcp/flow/extractor.py",
        )
    }
    if receipt["implementation"] != expected_implementation:
        raise ValueError("Normal semantic implementation digest mismatch")
    invocations = receipt["invocations"]
    if type(invocations) is not list or len(invocations) != 2:
        raise ValueError("Normal invocation evidence mismatch")
    for invocation in invocations:
        if (
            invocation.get("target_executed") is not False
            or invocation.get("input_preserved") is not True
            or invocation.get("shell") is not False
            or invocation.get("arguments_shape")
            != [
                "-c",
                "-A",
                "-S<entry-script> <root> <output> <request>",
                "<disposable-copy>",
            ]
        ):
            raise ValueError("Normal static invocation evidence mismatch")

    oracle_path = root / ISA_ORACLE
    oracle = read_json(oracle_path)
    isa = oracle_profile["isa_specific_expectations"]
    if (
        receipt["oracle_source"] != ISA_ORACLE.as_posix()
        or receipt["oracle_digest"] != digest(oracle)
        or receipt["isa_oracle_binding"]
        != {
            "oracle_id": oracle_profile["oracle_id"],
            "integer_return_register": isa["integer_return_register"],
            "stack_pointer_register": isa["stack_pointer_register"],
            "call_instruction_family": isa["call_instruction_family"],
            "observation_status": "bound_hand_authored_expectation_not_serialized",
        }
        or isa["pointer_width_bits"] != environment["bitness"]
    ):
        raise ValueError("Normal ISA oracle binding mismatch")
    if receipt["evaluation"] != evaluate_normal_functions(
        functions, receipt["image_base"]
    ):
        raise ValueError("Normal semantic evaluation mismatch")


def build_complete_matrix_receipt(root: Path) -> dict[str, Any]:
    normal_dir = root / NORMAL_DIR
    normal_matrix = read_json(normal_dir / "matrix.json")
    unsigned_normal = dict(normal_matrix)
    normal_digest = unsigned_normal.pop("receipt_digest")
    if (
        normal_matrix.get("schema_version") != NORMAL_MATRIX_SCHEMA
        or normal_matrix.get("status") != "success"
        or normal_matrix.get("success_count") != len(NORMAL_PROFILE_IDS)
        or normal_matrix.get("failure_count") != 0
        or normal_matrix.get("target_executed") is not False
        or normal_matrix.get("input_preserved") is not True
        or normal_digest != digest(unsigned_normal)
    ):
        raise ValueError("Normal semantic matrix is incomplete")
    format_dir = root / FORMAT_DIR
    format_matrix = read_json(format_dir / "matrix.json")
    unsigned_format = dict(format_matrix)
    format_digest = unsigned_format.pop("receipt_digest")
    if (
        format_matrix.get("schema_version") != FORMAT_MATRIX_SCHEMA
        or format_matrix.get("status") != "success"
        or format_matrix.get("success_count") != len(FORMAT_VARIANT_KEYS)
        or format_matrix.get("failure_count") != 0
        or format_matrix.get("target_executed") is not False
        or format_matrix.get("input_preserved") is not True
        or format_digest != digest(unsigned_format)
    ):
        raise ValueError("Format semantic matrix is incomplete")
    build = read_json(root / PROFILE_BUILD)
    oracle = read_json(root / ISA_ORACLE)
    build_rows = {item["profile_id"]: item for item in build["profiles"]}
    oracle_rows = {item["profile_id"]: item for item in oracle["profiles"]}
    rows = []
    for profile_id in NORMAL_PROFILE_IDS:
        path = normal_dir / f"{profile_id.lower()}.json"
        receipt = read_json(path)
        validate_normal_receipt(
            root, receipt, build_rows[profile_id], oracle_rows[profile_id]
        )
        rows.append(
            {
                "profile_id": profile_id,
                "format": "FMT-ELF",
                "evidence_path": "normal",
                "status": "success_partial_with_named_limitations",
                "receipt_file": path.relative_to(root).as_posix(),
                "receipt_digest": receipt["receipt_digest"],
            }
        )
    format_rows = {
        (item["profile_id"], item["format"]): item for item in build["format_variants"]
    }
    matrix_rows = {
        (item["profile_id"], item["format"]): item for item in format_matrix["profiles"]
    }
    for key in FORMAT_VARIANT_KEYS:
        matrix_row = matrix_rows[key]
        path = format_dir / matrix_row["result_file"]
        receipt = read_json(path)
        validate_normal_receipt(root, receipt, format_rows[key], oracle_rows[key[0]])
        rows.append(
            {
                "profile_id": key[0],
                "format": key[1],
                "evidence_path": "format",
                "status": "success_partial_with_named_limitations",
                "receipt_file": path.relative_to(root).as_posix(),
                "receipt_digest": receipt["receipt_digest"],
            }
        )
    rv32_path = root / RV32_OUTPUT
    rv32 = read_json(rv32_path)
    validate_rv32_fallback_receipt(root, rv32)
    rows.append(
        {
            "profile_id": RV32_PROFILE_ID,
            "format": "FMT-ELF",
            "evidence_path": "fallback",
            "status": "accepted_candidate_partial_normal_failed",
            "receipt_file": rv32_path.relative_to(root).as_posix(),
            "receipt_digest": rv32["receipt_digest"],
        }
    )
    expected_rows = (
        {(profile_id, "FMT-ELF", "normal") for profile_id in NORMAL_PROFILE_IDS}
        | {
            (profile_id, binary_format, "format")
            for profile_id, binary_format in FORMAT_VARIANT_KEYS
        }
        | {(RV32_PROFILE_ID, "FMT-ELF", "fallback")}
    )
    if (
        len(rows) != len(expected_rows)
        or {
            (item["profile_id"], item["format"], item["evidence_path"]) for item in rows
        }
        != expected_rows
    ):
        raise ValueError("Semantic profile completeness mismatch")
    backend_counts = {
        evidence_path: sum(row["evidence_path"] == evidence_path for row in rows)
        for evidence_path in ("normal", "format", "fallback")
    }
    body = {
        "schema_version": COMPLETE_MATRIX_SCHEMA,
        "profile_count": len(build["profiles"]),
        "semantic_row_count": len(rows),
        "normal_success_count": backend_counts["normal"],
        "format_variant_count": len(build["format_variants"]),
        "format_success_count": backend_counts["format"],
        "rv32_normal_failure_count": backend_counts["fallback"],
        "rv32_fallback_count": backend_counts["fallback"],
        "profiles": rows,
        "build_manifest": PROFILE_BUILD.as_posix(),
        "build_manifest_digest": digest(build),
        "oracle_file": ISA_ORACLE.as_posix(),
        "oracle_digest": digest(oracle),
        "normal_matrix_file": (NORMAL_DIR / "matrix.json").as_posix(),
        "normal_matrix_digest": normal_matrix["receipt_digest"],
        "format_matrix_file": (FORMAT_DIR / "matrix.json").as_posix(),
        "format_matrix_digest": format_matrix["receipt_digest"],
        "target_executed": False,
        "input_preserved": True,
        "normal_fallback_separate": True,
        "registry_service_capabilities_promoted": False,
        "status": "accepted_candidate_partial_with_named_limitations",
    }
    return {**body, "receipt_digest": digest(body)}


def validate_complete_matrix_artifacts(root: Path, receipt: dict[str, Any]) -> None:
    """Validate the declared canonical rows without inferring backend by profile name."""

    validate_core_complete_matrix_receipt(receipt)
    root = root.resolve()

    def artifact(relative: Any, label: str) -> tuple[Path, dict[str, Any]]:
        if type(relative) is not str:
            raise ValueError(label + " path is invalid")
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError(label + " path escapes checkout")
        resolved = (root / path).resolve()
        resolved.relative_to(root)
        value = read_json(resolved)
        if type(value) is not dict:
            raise ValueError(label + " must be an object")
        return resolved, value

    _build_path, build = artifact(receipt["build_manifest"], "Build manifest")
    _oracle_path, oracle = artifact(receipt["oracle_file"], "ISA oracle")
    _normal_path, normal_matrix = artifact(
        receipt["normal_matrix_file"], "Normal semantic matrix"
    )
    _format_path, format_matrix = artifact(
        receipt["format_matrix_file"], "Format semantic matrix"
    )
    if (
        receipt["build_manifest_digest"] != digest(build)
        or receipt["oracle_digest"] != digest(oracle)
        or receipt["normal_matrix_digest"] != normal_matrix.get("receipt_digest")
        or receipt["format_matrix_digest"] != format_matrix.get("receipt_digest")
    ):
        raise ValueError("Complete semantic matrix source digest mismatch")
    for matrix, label in (
        (normal_matrix, "Normal semantic matrix"),
        (format_matrix, "Format semantic matrix"),
    ):
        unsigned = dict(matrix)
        matrix_digest = unsigned.pop("receipt_digest", None)
        profiles = matrix.get("profiles")
        if (
            matrix_digest != digest(unsigned)
            or type(profiles) is not list
            or matrix.get("success_count") != len(profiles)
            or matrix.get("failure_count") != 0
            or matrix.get("target_executed") is not False
            or matrix.get("input_preserved") is not True
            or matrix.get("status") != "success"
        ):
            raise ValueError(label + " is incomplete")

    build_profiles = {item["profile_id"]: item for item in build.get("profiles", [])}
    build_formats = {
        (item["profile_id"], item["format"]): item
        for item in build.get("format_variants", [])
    }
    oracle_profiles = {item["profile_id"]: item for item in oracle.get("profiles", [])}
    normal_sources = {item["profile_id"]: item for item in normal_matrix["profiles"]}
    format_sources = {
        (item["profile_id"], item["format"]): item for item in format_matrix["profiles"]
    }

    for row in receipt["profiles"]:
        evidence_path = row["evidence_path"]
        _path, value = artifact(row["receipt_file"], "Semantic receipt")
        if (
            value.get("profile_id") != row["profile_id"]
            or value.get("receipt_digest") != row["receipt_digest"]
        ):
            raise ValueError("Semantic matrix row/receipt mismatch")
        if evidence_path == "normal":
            source = normal_sources.get(row["profile_id"])
            build_row = build_profiles.get(row["profile_id"])
            oracle_row = oracle_profiles.get(row["profile_id"])
            if (
                source is None
                or source.get("receipt_digest") != row["receipt_digest"]
                or build_row is None
                or oracle_row is None
            ):
                raise ValueError("Normal semantic source row mismatch")
            validate_normal_receipt(root, value, build_row, oracle_row)
        elif evidence_path == "format":
            key = (row["profile_id"], row["format"])
            source = format_sources.get(key)
            build_row = build_formats.get(key)
            oracle_row = oracle_profiles.get(row["profile_id"])
            if (
                source is None
                or source.get("receipt_digest") != row["receipt_digest"]
                or build_row is None
                or oracle_row is None
            ):
                raise ValueError("Format semantic source row mismatch")
            validate_normal_receipt(root, value, build_row, oracle_row)
        elif evidence_path == "fallback":
            _validate_fallback_receipt(root, value)
        else:
            raise ValueError("Unknown semantic evidence path")


def _validate_fallback_receipt(root: Path, receipt: dict[str, Any]) -> None:
    """Dispatch only fallback schemas with artifact-backed deep validation."""

    schema = receipt.get("schema_version")
    if schema == RV32_RECEIPT_SCHEMA:
        validate_rv32_fallback_receipt(root, receipt)
        return
    raise ValueError("Unsupported fallback semantic receipt schema")


def validate_rv32_fallback_receipt(root: Path, receipt: dict[str, Any]) -> None:
    """Fail closed on any receipt, artifact, profile, or semantic mismatch."""

    validate_core_rv32_receipt(receipt)
    _exact_keys(
        receipt,
        {
            "schema_version",
            "profile_id",
            "abi_id",
            "evidence_path",
            "status",
            "candidate_status",
            "support_status",
            "normal_backend",
            "capture",
            "oracles",
            "implementation",
            "functions",
            "evaluation",
            "limitations",
            "input_preserved",
            "target_executed",
            "registry_promoted",
            "service_promoted",
            "receipt_digest",
        },
        "RV32 semantic receipt",
    )
    if receipt["schema_version"] != RV32_RECEIPT_SCHEMA:
        raise ValueError("Unsupported RV32 semantic receipt schema")
    if receipt["profile_id"] != RV32_PROFILE_ID or receipt["abi_id"] != RV32_ABI_ID:
        raise ValueError("RV32 semantic profile/ABI mismatch")
    if receipt["evidence_path"] != "fallback" or receipt["status"] != "partial":
        raise ValueError("RV32 fallback status mismatch")
    if receipt["candidate_status"] != "accepted_candidate":
        raise ValueError("RV32 fallback candidate status mismatch")
    if receipt["support_status"] != "unverified":
        raise ValueError("RV32 fallback cannot claim verified support")
    if (
        receipt["target_executed"] is not False
        or receipt["input_preserved"] is not True
    ):
        raise ValueError("RV32 fallback execution/input-preservation mismatch")
    if (
        receipt["registry_promoted"] is not False
        or receipt["service_promoted"] is not False
    ):
        raise ValueError("RV32 fallback cannot promote registry/service support")
    if receipt["limitations"] != RV32_LIMITATIONS:
        raise ValueError("RV32 fallback limitations mismatch")

    body = dict(receipt)
    receipt_digest = body.pop("receipt_digest")
    if receipt_digest != digest(body):
        raise ValueError("RV32 semantic receipt digest mismatch")

    normal_path, normal, normal_digest = _artifact(
        root, RV32_CAPTURE_ROOT / "normal_microcode_unavailable.json"
    )
    normal_summary = receipt["normal_backend"]
    _exact_keys(
        normal_summary,
        {
            "artifact",
            "artifact_digest",
            "schema_version",
            "probe_status",
            "support_status",
            "maturities",
            "probes",
            "target_executed",
        },
        "RV32 normal backend summary",
    )
    if normal_summary != {
        "artifact": normal_path.relative_to(root).as_posix(),
        "artifact_digest": normal_digest,
        "schema_version": normal["schema_version"],
        "probe_status": "failed",
        "support_status": "unverified",
        "maturities": ["MMAT_CALLS", "MMAT_GLBOPT3"],
        "probes": normal["probes"],
        "target_executed": False,
    }:
        raise ValueError("RV32 normal failure evidence mismatch")
    if normal["probes"] != [
        {
            "status": "failed",
            "failure_code": -23,
            "failure_ea": 70232,
            "maturity": "MMAT_CALLS",
            "repeat_equal": True,
        },
        {
            "status": "failed",
            "failure_code": -23,
            "failure_ea": 70232,
            "maturity": "MMAT_GLBOPT3",
            "repeat_equal": True,
        },
    ]:
        raise ValueError("RV32 normal backend failure changed")

    capture_path, capture_receipt, capture_receipt_digest = _artifact(
        root, RV32_CAPTURE_ROOT / "receipt.json"
    )
    first_path, first, first_digest = _artifact(
        root, RV32_CAPTURE_ROOT / "fresh-1/process-receipt.json"
    )
    second_path, second, second_digest = _artifact(
        root, RV32_CAPTURE_ROOT / "fresh-2/process-receipt.json"
    )
    capture_summary = receipt["capture"]
    _exact_keys(
        capture_summary,
        {
            "artifact",
            "artifact_digest",
            "process_artifacts",
            "capture_digest",
            "fresh_process_repeat_equal",
            "json_roundtrip_equal",
            "input_preserved",
            "target_executed",
        },
        "RV32 capture summary",
    )
    expected_process_artifacts = [
        {
            "artifact": first_path.relative_to(root).as_posix(),
            "artifact_digest": first_digest,
        },
        {
            "artifact": second_path.relative_to(root).as_posix(),
            "artifact_digest": second_digest,
        },
    ]
    if capture_summary != {
        "artifact": capture_path.relative_to(root).as_posix(),
        "artifact_digest": capture_receipt_digest,
        "process_artifacts": expected_process_artifacts,
        "capture_digest": first["capture_digest"],
        "fresh_process_repeat_equal": True,
        "json_roundtrip_equal": True,
        "input_preserved": True,
        "target_executed": False,
    }:
        raise ValueError("RV32 capture evidence mismatch")
    if first["capture_digest"] != second["capture_digest"]:
        raise ValueError("RV32 fresh-process capture mismatch")
    if first["capture"] != second["capture"]:
        raise ValueError("RV32 fresh-process capture payload mismatch")
    if capture_receipt["input_preserved"] is not True:
        raise ValueError("RV32 capture input was not preserved")
    for process in (first, second):
        if (
            process["target_executed"] is not False
            or process["support_status"] != "unverified"
            or process["in_session_repeat_equal"] is not True
            or process["json_roundtrip_equal"] is not True
        ):
            raise ValueError("RV32 process evidence mismatch")

    rv32_oracle_path, rv32_oracle, rv32_oracle_digest = _artifact(root, RV32_ORACLE)
    isa_oracle_path, isa_oracle, isa_oracle_digest = _artifact(root, ISA_ORACLE)
    oracle_summary = receipt["oracles"]
    _exact_keys(
        oracle_summary,
        {"rv32_artifact", "rv32_digest", "isa_artifact", "isa_digest"},
        "RV32 oracle summary",
    )
    if oracle_summary != {
        "rv32_artifact": rv32_oracle_path.relative_to(root).as_posix(),
        "rv32_digest": rv32_oracle_digest,
        "isa_artifact": isa_oracle_path.relative_to(root).as_posix(),
        "isa_digest": isa_oracle_digest,
    }:
        raise ValueError("RV32 semantic oracle mismatch")
    if rv32_oracle["capture_digest"] != first["capture_digest"]:
        raise ValueError("RV32 oracle capture mismatch")
    isa_profile = next(
        item for item in isa_oracle["profiles"] if item["profile_id"] == RV32_PROFILE_ID
    )
    if isa_profile["abi_id"] != RV32_ABI_ID:
        raise ValueError("RV32 ISA oracle ABI mismatch")

    functions = rv32_oracle["functions"]
    if [item["selector_ordinal"] for item in receipt["functions"]] != list(range(6)):
        raise ValueError("RV32 semantic functions are incomplete or reordered")
    if [item["symbol"] for item in receipt["functions"]] != RV32_FUNCTION_SYMBOLS:
        raise ValueError("RV32 semantic function symbols mismatch")
    for actual, expected in zip(receipt["functions"], functions):
        for key in ("oracle_id", "symbol", "selector_ordinal", "function_rva"):
            if actual[key] != expected[key]:
                raise ValueError(f"RV32 function {key} mismatch")

    snapshots = _snapshots_from_receipt(receipt)
    if len({item.snapshot_id for item in snapshots}) != 6:
        raise ValueError("RV32 snapshots must be unique")
    for snapshot in snapshots:
        environment = snapshot.identity.environment
        if (
            environment.backend_id != "ida-disasm-rv32"
            or environment.extraction_stage != "structured-disassembly"
            or environment.bitness != 32
            or environment.abi != RV32_ABI_ID
        ):
            raise ValueError("RV32 structured snapshot identity mismatch")
        if (
            StructuredSnapshot.from_json(
                json.dumps(snapshot.to_data(), sort_keys=True, separators=(",", ":"))
            )
            != snapshot
        ):
            raise ValueError("RV32 structured snapshot roundtrip mismatch")
    lowering_digests = {item.identity.lowering_rule_digest for item in snapshots}
    if len(lowering_digests) != 1:
        raise ValueError("RV32 lowering rule digest mismatch")
    implementation = receipt["implementation"]
    _exact_keys(
        implementation,
        {
            "capture_implementation_digest",
            "lowering_rule_digest",
            "lowering_artifact",
            "lowering_artifact_sha256",
            "evaluator_artifact",
            "evaluator_artifact_sha256",
        },
        "RV32 semantic implementation summary",
    )
    if implementation != {
        "capture_implementation_digest": first["capture"]["implementation_digest"],
        "lowering_rule_digest": next(iter(lowering_digests)),
        "lowering_artifact": LOWERING_IMPLEMENTATION.as_posix(),
        "lowering_artifact_sha256": sha256_file(root / LOWERING_IMPLEMENTATION),
        "evaluator_artifact": EVALUATOR_IMPLEMENTATION.as_posix(),
        "evaluator_artifact_sha256": sha256_file(root / EVALUATOR_IMPLEMENTATION),
    }:
        raise ValueError("RV32 semantic implementation digest mismatch")
    if receipt["evaluation"] != evaluate_rv32_snapshots(snapshots):
        raise ValueError("RV32 semantic evaluation mismatch")
    _validate_evaluation_against_oracle(receipt["evaluation"], rv32_oracle)


def build_rv32_fallback_receipt(root: Path) -> dict[str, Any]:
    """Build a deterministic replay receipt from committed static evidence."""

    root = root.resolve()
    capture_path, capture_receipt, capture_receipt_digest = _artifact(
        root, RV32_CAPTURE_ROOT / "receipt.json"
    )
    first_path = root / RV32_CAPTURE_ROOT / "fresh-1/process-receipt.json"
    second_path = root / RV32_CAPTURE_ROOT / "fresh-2/process-receipt.json"
    first_data = read_json(first_path)
    second_data = read_json(second_path)
    first = cast(ProcessReceipt, ProcessReceipt.from_json(first_path.read_text()))
    second = cast(ProcessReceipt, ProcessReceipt.from_json(second_path.read_text()))
    if first.capture != second.capture:
        raise ValueError("RV32 capture processes disagree")
    first_snapshots = lower_bundle(first.capture)
    second_snapshots = lower_bundle(second.capture)
    if first_snapshots != second_snapshots:
        raise ValueError("RV32 lowered snapshots are not deterministic")

    rv32_oracle_path, rv32_oracle, rv32_oracle_digest = _artifact(root, RV32_ORACLE)
    isa_oracle_path, _isa_oracle, isa_oracle_digest = _artifact(root, ISA_ORACLE)
    normal_path, normal, normal_digest = _artifact(
        root, RV32_CAPTURE_ROOT / "normal_microcode_unavailable.json"
    )
    functions = []
    for expected, snapshot in zip(rv32_oracle["functions"], first_snapshots):
        functions.append(
            {
                "oracle_id": expected["oracle_id"],
                "symbol": expected["symbol"],
                "selector_ordinal": expected["selector_ordinal"],
                "function_rva": expected["function_rva"],
                "snapshot_id": snapshot.snapshot_id,
                "snapshot_digest": digest(snapshot),
                "snapshot": snapshot.to_data(),
            }
        )

    body = {
        "schema_version": RV32_RECEIPT_SCHEMA,
        "profile_id": RV32_PROFILE_ID,
        "abi_id": RV32_ABI_ID,
        "evidence_path": "fallback",
        "status": "partial",
        "candidate_status": "accepted_candidate",
        "support_status": "unverified",
        "normal_backend": {
            "artifact": normal_path.relative_to(root).as_posix(),
            "artifact_digest": normal_digest,
            "schema_version": normal["schema_version"],
            "probe_status": normal["probe_status"],
            "support_status": normal["support_status"],
            "maturities": normal["request"]["probe"]["maturities"],
            "probes": normal["probes"],
            "target_executed": normal["target_executed"],
        },
        "capture": {
            "artifact": capture_path.relative_to(root).as_posix(),
            "artifact_digest": capture_receipt_digest,
            "process_artifacts": [
                {
                    "artifact": first_path.relative_to(root).as_posix(),
                    "artifact_digest": digest(first_data),
                },
                {
                    "artifact": second_path.relative_to(root).as_posix(),
                    "artifact_digest": digest(second_data),
                },
            ],
            "capture_digest": first_data["capture_digest"],
            "fresh_process_repeat_equal": first.capture == second.capture,
            "json_roundtrip_equal": (
                first_data["json_roundtrip_equal"]
                and second_data["json_roundtrip_equal"]
            ),
            "input_preserved": capture_receipt["input_preserved"],
            "target_executed": False,
        },
        "oracles": {
            "rv32_artifact": rv32_oracle_path.relative_to(root).as_posix(),
            "rv32_digest": rv32_oracle_digest,
            "isa_artifact": isa_oracle_path.relative_to(root).as_posix(),
            "isa_digest": isa_oracle_digest,
        },
        "implementation": {
            "capture_implementation_digest": first_data["capture"][
                "implementation_digest"
            ],
            "lowering_rule_digest": first_snapshots[0].identity.lowering_rule_digest,
            "lowering_artifact": LOWERING_IMPLEMENTATION.as_posix(),
            "lowering_artifact_sha256": sha256_file(root / LOWERING_IMPLEMENTATION),
            "evaluator_artifact": EVALUATOR_IMPLEMENTATION.as_posix(),
            "evaluator_artifact_sha256": sha256_file(root / EVALUATOR_IMPLEMENTATION),
        },
        "functions": functions,
        "evaluation": evaluate_rv32_snapshots(first_snapshots),
        "limitations": RV32_LIMITATIONS,
        "input_preserved": True,
        "target_executed": False,
        "registry_promoted": False,
        "service_promoted": False,
    }
    receipt = {**body, "receipt_digest": digest(body)}
    validate_rv32_fallback_receipt(root, receipt)
    return receipt


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--matrix-output", type=Path)
    parser.add_argument("--require-complete", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    output = (args.output or (root / RV32_OUTPUT)).resolve()
    receipt = build_rv32_fallback_receipt(root)
    write_json(output, receipt)
    validate_rv32_fallback_receipt(root, read_json(output))
    if args.matrix_output is not None or args.require_complete:
        matrix_path = (args.matrix_output or (root / MATRIX_OUTPUT)).resolve()
        matrix = build_complete_matrix_receipt(root)
        write_json(matrix_path, matrix)
        validate_complete_matrix_artifacts(root, read_json(matrix_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
