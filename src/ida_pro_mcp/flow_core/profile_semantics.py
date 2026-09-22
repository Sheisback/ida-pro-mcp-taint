"""Pure contracts and independent checks for the G012 semantic matrix.

This module deliberately does not alter the extraction-profile registry.  The
normal recorder supplies an exact, build-bound evidence profile to the existing
microcode extractor, then this module replays and validates the resulting pure
snapshots offline.  RV32 remains a separate structured-disassembly fallback.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import replace
from typing import Any, cast

from .contracts import CallInfo, Graph, Operand, Snapshot
from .memory_graph import build_memory_graph
from .profile_registry import (
    FormatId,
    REGISTRY,
    MeasuredReceipt,
    ProfileRegistry,
)
from .serialization import ContractError, canonical_json, digest
from .ssa import SSAProgram, build_ssa
from .states import require

NORMAL_PROFILE_IDS = (
    "X86-LE",
    "X64-LE",
    "ARM32-LE",
    "ARM32-BE",
    "THUMB-LE",
    "THUMB-BE",
    "A64-LE",
    "MIPS32-LE",
    "MIPS32-BE",
    "MIPS64-LE",
    "MIPS64-BE",
    "PPC32-LE",
    "PPC32-BE",
    "PPC64-LE",
    "PPC64-BE",
    "RV64-LE",
)
FORMAT_VARIANT_KEYS = (
    ("X64-LE", "FMT-PE"),
    ("ARM32-LE", "FMT-RAW"),
    ("X64-LE", "FMT-MACHO"),
    ("A64-LE", "FMT-MACHO"),
)
FUNCTIONS = (
    "isa_scalar",
    "isa_branch",
    "isa_load",
    "isa_store",
    "isa_call",
    "isa_profile_entry",
)
EXPECTED_CALLS = {
    "isa_scalar": (),
    "isa_branch": (),
    "isa_load": (),
    "isa_store": (),
    "isa_call": ("isa_scalar",),
    "isa_profile_entry": ("isa_load", "isa_call", "isa_branch", "isa_store"),
}
REQUIRED_FEATURES = (
    "scalar",
    "branch",
    "range_memory",
    "abi",
    "isa_specific_contract",
)

NORMAL_PROCESS_SCHEMA = "flow-profile-semantics-process/1"
NORMAL_RECEIPT_SCHEMA = "flow-profile-semantics-normal/1"
NORMAL_MATRIX_SCHEMA = "flow-profile-semantics-matrix/1"
FORMAT_MATRIX_SCHEMA = "flow-profile-semantics-format-matrix/1"


def _exact_keys(value: Any, expected: set[str], label: str) -> None:
    if type(value) is not dict:
        raise ContractError(label + " must be an object")
    actual = set(value)
    require(
        actual == expected,
        f"{label} keys mismatch; missing={sorted(expected - actual)!r}, "
        f"extra={sorted(actual - expected)!r}",
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def receipt_digest(value: dict[str, Any]) -> str:
    require("receipt_digest" not in value, "Digest input already has receipt digest")
    return digest(value)


def verify_receipt_digest(value: dict[str, Any]) -> None:
    try:
        observed = value["receipt_digest"]
    except KeyError as exc:
        raise ContractError("Receipt digest missing") from exc
    unsigned = {key: item for key, item in value.items() if key != "receipt_digest"}
    require(observed == receipt_digest(unsigned), "Receipt digest mismatch")


def structural_function_key(
    binary_sha256: str, profile_id: str, function_rva: int
) -> str:
    require(
        type(binary_sha256) is str
        and len(binary_sha256) == 64
        and all(char in "0123456789abcdef" for char in binary_sha256),
        "Invalid binary hash",
    )
    require(type(profile_id) is str and bool(profile_id), "Invalid profile id")
    require(type(function_rva) is int and function_rva >= 0, "Invalid function RVA")
    value = {
        "binary_sha256": binary_sha256,
        "profile_id": profile_id,
        "function_rva": function_rva,
    }
    return "g012-function-v1:" + digest(value).split(":", 1)[1]


FUNCTION_ENTRY_KEYS = {
    "name",
    "symbol_value",
    "logical_rva",
    "symbol_size",
    "symbol_other",
    "symbol_table",
    "proof_kind",
    "local_entry_offset",
    "extraction_rva",
}


def function_entry_proofs(build_row: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    """Validate binary-bound logical-to-extraction entry metadata.

    ELFv2 encodes the local-entry offset in the three high bits of ``st_other``.
    Encodings zero and one both denote the global entry; larger valid encodings
    denote a power-of-two byte offset.  No caller may infer an offset from a
    function name, adjacency, or a fixed ``+8`` convention.
    """

    raw_entries = build_row.get("function_entries")
    if type(raw_entries) is not list or not all(
        type(item) is dict for item in raw_entries
    ):
        raise ContractError("Build function entry proofs must be objects")
    entries = cast(list[dict[str, Any]], raw_entries)
    require(
        tuple(item.get("name") for item in entries) == FUNCTIONS,
        "Build function entry proof set/order mismatch",
    )
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
    header_value = build_row.get("binary_header")
    if type(header_value) is not dict:
        raise ContractError("ELF binary header missing")
    header = cast(dict[str, Any], header_value)
    image_base_value = header.get("image_base")
    if (
        header.get("kind") != "ELF"
        or type(image_base_value) is not int
        or image_base_value < 0
    ):
        raise ContractError("ELF preferred image base missing")
    image_base = image_base_value
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
        local_entry_offset = entry["local_entry_offset"]
        extraction_rva = entry["extraction_rva"]
        require(
            type(logical_rva) is int and logical_rva >= 0,
            "Invalid logical function RVA",
        )
        require(
            type(symbol_value) is int and symbol_value >= 0,
            "Invalid raw ELF symbol value",
        )
        normalized_symbol_value = symbol_value & ~1 if thumb else symbol_value
        require(
            normalized_symbol_value == image_base + logical_rva,
            "ELF symbol value/logical RVA/image-base mismatch",
        )
        require(
            type(symbol_size) is int and symbol_size > 0,
            "Invalid function symbol size",
        )
        require(
            type(symbol_other) is int and 0 <= symbol_other <= 0xFF,
            "Invalid raw ELF st_other",
        )
        require(entry["symbol_table"] == ".symtab", "Untrusted ELF symbol table")
        encoding = (symbol_other >> 5) & 0x7
        decoded_offset = 0 if encoding <= 1 else 1 << encoding
        expected_offset = decoded_offset if ppc64_elfv2 else 0
        expected_kind = "ppc64_elfv2_st_other" if ppc64_elfv2 else "elf_symbol"
        require(
            entry["proof_kind"] == expected_kind,
            "Function entry proof kind/profile mismatch",
        )
        require(
            type(local_entry_offset) is int and local_entry_offset == expected_offset,
            "ELF local-entry offset/st_other mismatch",
        )
        require(
            type(extraction_rva) is int
            and extraction_rva == logical_rva + expected_offset,
            "Extraction entry does not match the ELF proof",
        )
        require(
            logical_rva <= extraction_rva < logical_rva + symbol_size,
            "Extraction entry lies outside the exact ELF symbol",
        )
    require(
        header.get("entry")
        == entries[FUNCTIONS.index("isa_profile_entry")]["symbol_value"],
        "ELF entry point/profile-entry symbol mismatch",
    )
    return tuple(entries)


def semantic_entry_proofs(build_row: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    """Validate exact semantic entries for ELF and required format variants."""

    binary_format = build_row.get("format")
    if binary_format == "FMT-ELF":
        return function_entry_proofs(build_row)
    require(
        (build_row.get("profile_id"), binary_format) in FORMAT_VARIANT_KEYS,
        "Unsupported semantic format row",
    )
    selectors_value = build_row.get("function_selectors")
    if type(selectors_value) is not list or not all(
        type(item) is dict for item in selectors_value
    ):
        raise ContractError("Format semantic selectors must be objects")
    selectors = cast(list[dict[str, Any]], selectors_value)
    require(
        tuple(item.get("function") for item in selectors) == FUNCTIONS,
        "Format semantic selector set/order mismatch",
    )
    proofs = []
    for selector in selectors:
        function = selector["function"]
        rva = selector.get("rva", selector.get("value"))
        require(type(rva) is int and rva >= 0, "Invalid format function RVA")
        if binary_format == "FMT-PE":
            _exact_keys(
                selector,
                {"function", "kind", "value", "rva"},
                "PE semantic selector",
            )
            require(
                selector["kind"] == "export_name" and selector["value"] == function,
                "PE semantic export selector mismatch",
            )
            proof_kind = "pe_export_rva"
            extent_size = None
        elif binary_format == "FMT-RAW":
            _exact_keys(
                selector,
                {"function", "kind", "value", "size"},
                "raw semantic selector",
            )
            require(
                selector["kind"] == "raw_offset"
                and type(selector["size"]) is int
                and selector["size"] > 0,
                "Raw semantic offset/size selector mismatch",
            )
            proof_kind = "raw_offset_size"
            extent_size = selector["size"]
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
            require(
                selector["kind"] == "ida_name"
                and selector["value"] == "_" + function
                and selector["requires_companion"] is False,
                "Mach-O semantic symbol selector mismatch",
            )
            proof_kind = "macho_external_symbol_rva"
            extent_size = None
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
    if binary_format == "FMT-PE":
        if type(header) is not dict:
            raise ContractError("PE binary header missing")
        exports = header.get("exports")
        if type(exports) is not list or not all(type(item) is dict for item in exports):
            raise ContractError("PE export table missing")
        typed_exports = cast(list[dict[str, Any]], exports)
        require(
            {item.get("name"): item.get("rva") for item in typed_exports}
            == {item["name"]: item["logical_rva"] for item in proofs},
            "PE export table/selector mismatch",
        )
    elif binary_format == "FMT-MACHO":
        if type(header) is not dict:
            raise ContractError("Mach-O binary header missing")
        symbols = header.get("semantic_symbols")
        if type(symbols) is not list or not all(type(item) is dict for item in symbols):
            raise ContractError("Mach-O semantic symbol table missing")
        typed_symbols = cast(list[dict[str, Any]], symbols)
        require(
            {item.get("name"): item.get("rva") for item in typed_symbols}
            == {item["selector"]["value"]: item["logical_rva"] for item in proofs},
            "Mach-O symbol table/selector mismatch",
        )
    return tuple(proofs)


def select_ida_extraction(
    proof: dict[str, Any], resolved_start_rva: int, resolved_end_rva: int
) -> dict[str, Any]:
    """Select one of the two approved manifest-bound IDA extraction shapes."""

    logical_rva = proof["logical_rva"]
    manifest_extraction_rva = proof["extraction_rva"]
    extent_size = proof.get("symbol_size", proof.get("extent_size"))
    require(
        type(resolved_start_rva) is int
        and type(resolved_end_rva) is int
        and resolved_start_rva < resolved_end_rva,
        "Invalid resolved IDA function bounds",
    )
    if type(extent_size) is int:
        require(
            logical_rva
            <= resolved_start_rva
            < resolved_end_rva
            <= logical_rva + extent_size,
            "Resolved IDA function escapes the manifest extent",
        )
    if resolved_start_rva == manifest_extraction_rva:
        selection_kind = "exact_local_function"
        ida_extraction_rva = manifest_extraction_rva
    else:
        local_entry_offset = proof.get("local_entry_offset", 0)
        require(
            type(local_entry_offset) is int
            and local_entry_offset > 0
            and resolved_start_rva == logical_rva
            and resolved_start_rva < manifest_extraction_rva < resolved_end_rva,
            "Resolved IDA function is not an approved proven-local containment",
        )
        selection_kind = "logical_function_contains_proven_local_entry"
        ida_extraction_rva = logical_rva
    return {
        "manifest_extraction_rva": manifest_extraction_rva,
        "ida_extraction_rva": ida_extraction_rva,
        "selection_kind": selection_kind,
    }


def ephemeral_registry(
    build_row: dict[str, Any],
    p0_result: dict[str, Any],
    p0_receipt: dict[str, Any],
    p0_receipt_file: str,
) -> ProfileRegistry:
    """Admit one exact P0-measured static row without promoting support."""

    profile_id_value = build_row.get("profile_id")
    if type(profile_id_value) is not str:
        raise ContractError("Normal profile id must be a string")
    profile_id = profile_id_value
    require(profile_id in NORMAL_PROFILE_IDS, "Normal profile is not in the matrix")
    binary_format_value = build_row.get("format")
    if binary_format_value not in {"FMT-ELF", "FMT-PE", "FMT-RAW", "FMT-MACHO"}:
        raise ContractError("Unsupported static semantic format")
    binary_format = cast(FormatId, binary_format_value)
    observed_format = {
        "FMT-ELF": "ELF",
        "FMT-PE": "PE",
        "FMT-RAW": "RAW",
        "FMT-MACHO": "MACH-O",
    }.get(binary_format)
    require(
        p0_result.get("schema_version") == "flow-profile-receipt-run/1"
        and p0_result.get("profile_id") == profile_id
        and p0_result.get("format") == binary_format
        and p0_result.get("status") == "success"
        and p0_result.get("support_status") == "unverified"
        and p0_result.get("target_executed") is False,
        "P0 result did not accept the exact static row",
    )
    require(
        p0_result.get("binary")
        == {
            "manifest_path": build_row["binary"],
            "expected_sha256": build_row["binary_sha256"],
            "copied_sha256": build_row["binary_sha256"],
        },
        "P0 result/build evidence mismatch",
    )
    repeatability = p0_result.get("repeatability")
    require(
        type(repeatability) is dict
        and repeatability.get("performed") is True
        and repeatability.get("semantic_equal") is True,
        "P0 fresh-process repeat evidence missing",
    )
    expected_declared = {
        "profile_id": build_row["profile_id"],
        "profile_version": build_row["profile_version"],
        "mode": build_row["mode"],
        "processor": build_row["processor"],
        "bits": build_row["bitness"],
        "data_endian": build_row["data_endian"],
        "instruction_endian": build_row["instruction_endian"],
        "abi_id": build_row["abi_id"],
    }
    require(
        p0_result.get("declared_profile") == expected_declared,
        "P0 declared profile/build mismatch",
    )
    require(
        p0_receipt.get("schema_version") == "flow-p0-probe/2"
        and p0_receipt.get("target_executed") is False
        and p0_receipt.get("probe_status") == "success"
        and p0_receipt.get("support_status") == "unverified"
        and p0_receipt.get("initialization") is True
        and not p0_receipt.get("failures"),
        "P0 receipt status mismatch",
    )
    request = p0_receipt.get("request")
    if type(request) is not dict:
        raise ContractError("P0 request must be an object")
    request_binary = request.get("binary")
    if type(request_binary) is not dict:
        raise ContractError("P0 request binary must be an object")
    environment = p0_receipt.get("environment")
    if type(environment) is not dict:
        raise ContractError("P0 environment must be an object")
    require(
        request.get("profile") == expected_declared
        and request_binary.get("format") == observed_format
        and request_binary.get("sha256") == build_row["binary_sha256"],
        "P0 request/build mismatch",
    )
    require(
        environment.get("ida_version") == "9.3"
        and environment.get("processor") == build_row["processor"]
        and environment.get("bits") == build_row["bitness"]
        and environment.get("data_endian") == build_row["data_endian"]
        and environment.get("binary_sha256") == build_row["binary_sha256"]
        and environment.get("format") == observed_format,
        "P0 observed environment/build mismatch",
    )
    validation = p0_receipt.get("validation")
    if type(validation) is not dict:
        raise ContractError("P0 validation must be an object")
    require(
        validation.get("status") == "accepted",
        "P0 environment validation was not accepted",
    )
    lifetime = p0_receipt.get("lifetime")
    require(
        type(lifetime) is dict
        and lifetime.get("json_roundtrip") is True
        and lifetime.get("repeat_after_gc") is True,
        "P0 lifetime evidence mismatch",
    )
    raw_probes = p0_receipt.get("probes")
    if type(raw_probes) is not list:
        raise ContractError("P0 probes must be an array")
    probes: list[dict[str, Any]] = [
        probe
        for probe in raw_probes
        if type(probe) is dict and probe.get("maturity") == "MMAT_CALLS"
    ]
    require(
        len(probes) == 1
        and probes[0].get("status") == "success"
        and probes[0].get("repeat_equal") is True,
        "P0 MMAT_CALLS receipt mismatch",
    )
    measured = MeasuredReceipt(
        p0_receipt_file,
        "success",
        "MMAT_CALLS",
        "sha256-v1:" + probes[0]["digest"],
        True,
        True,
        False,
        build_row["processor"],
        build_row["abi_id"],
        binary_format,
        build_row["platform_tag"],
        "sha256-v1:" + build_row["binary_sha256"],
    )
    target = REGISTRY.get(profile_id)
    instruction_endian = {
        "LE": "little",
        "BE": "big",
    }[build_row["instruction_endian"]]
    updated = replace(
        target,
        instruction_endian=instruction_endian,
        format_ids=(binary_format,),
        receipt_status="success",
        maturity="MMAT_CALLS",
        measured_receipt=measured,
    )
    registry = ProfileRegistry(
        tuple(
            updated if row.profile_id == profile_id else row
            for row in REGISTRY.profiles
        )
    )
    require(
        all(
            row.normal_status == "unverified" and row.fallback_status == "unverified"
            for row in registry.profiles
        ),
        "Ephemeral registry promoted support",
    )
    return registry


def semantic_profile(
    build_row: dict[str, Any],
    manifest_sha256: str,
    registry: ProfileRegistry,
) -> dict[str, Any]:
    """Create an extraction-only profile bound to one pinned static build row."""

    profile_id_value = build_row.get("profile_id")
    if type(profile_id_value) is not str:
        raise ContractError("Normal profile id must be a string")
    profile_id = profile_id_value
    require(profile_id in NORMAL_PROFILE_IDS, "Normal profile is not in the matrix")
    require(
        build_row.get("format") == "FMT-ELF"
        or (profile_id, build_row.get("format")) in FORMAT_VARIANT_KEYS,
        "Unsupported semantic build row",
    )
    require(build_row.get("target_executed") is False, "Build executed the target")
    selectors = build_row.get("function_selectors")
    if type(selectors) is not list or not all(type(item) is dict for item in selectors):
        raise ContractError("Semantic function selectors must be objects")
    typed_selectors = cast(list[dict[str, Any]], selectors)
    logical_names = tuple(
        item.get("value")
        if build_row.get("format") == "FMT-ELF"
        else item.get("function")
        for item in typed_selectors
    )
    require(
        logical_names == FUNCTIONS,
        "Semantic fixture selector set mismatch",
    )
    entries = semantic_entry_proofs(build_row)
    require(
        tuple(item["name"] for item in entries) == logical_names,
        "Semantic selector/function-entry mismatch",
    )
    require(type(registry) is ProfileRegistry, "Expected exact ephemeral registry")
    profile = registry.measured_extraction_profile(profile_id)
    receipt = registry.get(profile_id).measured_receipt
    if receipt is None:
        raise ContractError("Ephemeral registry target remains unmeasured")
    require(
        (
            receipt.processor,
            receipt.abi,
            receipt.format_id,
            receipt.platform_tag,
            receipt.binary_digest,
        )
        == (
            build_row["processor"],
            build_row["abi_id"],
            build_row["format"],
            build_row["platform_tag"],
            "sha256-v1:" + build_row["binary_sha256"],
        ),
        "Ephemeral registry/build receipt mismatch",
    )
    profile["abi_provenance"] = {
        "kind": "measured_anchor_build",
        "manifest_sha256": manifest_sha256,
        "build_row_digest": digest(build_row),
        "binary_sha256": build_row["binary_sha256"],
        "p0_receipt": receipt.file_name,
        "p0_mmat_calls_digest": receipt.digest,
        "scope": "exact semantic-matrix fixture; not registry promotion",
    }
    registry.validate_extraction_profile(profile)
    return profile


def validate_semantic_profile(
    profile: Any,
    build_row: dict[str, Any],
    manifest_sha256: str,
    registry: ProfileRegistry,
) -> None:
    require(
        profile == semantic_profile(build_row, manifest_sha256, registry),
        "Profile mismatch",
    )


def validate_build_rows(
    committed: dict[str, Any], rebuilt: dict[str, Any]
) -> tuple[dict[str, Any], ...]:
    """Require exact reproducibility of the 17 ELF profile rows.

    Non-profile format variants may bind a host compiler through a different
    symlink.  The semantic matrix therefore requires exact equality of the
    profile rows whose binary hashes and commands are the acceptance surface.
    """

    require(
        committed.get("schema_version")
        == rebuilt.get("schema_version")
        == "flow-isa-profile-builds/1",
        "Unsupported build manifest",
    )
    expected_ids = NORMAL_PROFILE_IDS[:-1] + ("RV32-LE", NORMAL_PROFILE_IDS[-1])
    committed_rows_value = committed.get("profiles")
    rebuilt_rows_value = rebuilt.get("profiles")
    if type(committed_rows_value) is not list or not all(
        type(item) is dict for item in committed_rows_value
    ):
        raise ContractError("Missing committed build rows")
    if type(rebuilt_rows_value) is not list or not all(
        type(item) is dict for item in rebuilt_rows_value
    ):
        raise ContractError("Missing rebuilt build rows")
    committed_rows = cast(list[dict[str, Any]], committed_rows_value)
    rebuilt_rows = cast(list[dict[str, Any]], rebuilt_rows_value)
    require(committed_rows == rebuilt_rows, "Rebuilt profile rows differ from pin")
    require(
        tuple(row.get("profile_id") for row in committed_rows) == expected_ids,
        "Build profile order mismatch",
    )
    require(
        all(row.get("target_executed") is False for row in committed_rows),
        "Build manifest executed a target",
    )
    return tuple(committed_rows)


def validate_format_rows(
    committed: dict[str, Any], rebuilt: dict[str, Any]
) -> tuple[dict[str, Any], ...]:
    """Require exact reproducibility of the four required format variants."""

    require(
        committed.get("schema_version")
        == rebuilt.get("schema_version")
        == "flow-isa-profile-builds/1",
        "Unsupported build manifest",
    )
    committed_value = committed.get("format_variants")
    rebuilt_value = rebuilt.get("format_variants")
    if type(committed_value) is not list or not all(
        type(item) is dict for item in committed_value
    ):
        raise ContractError("Missing committed format rows")
    if type(rebuilt_value) is not list or not all(
        type(item) is dict for item in rebuilt_value
    ):
        raise ContractError("Missing rebuilt format rows")
    committed_rows = cast(list[dict[str, Any]], committed_value)
    rebuilt_rows = cast(list[dict[str, Any]], rebuilt_value)
    require(committed_rows == rebuilt_rows, "Rebuilt format rows differ from pin")
    require(
        tuple((row.get("profile_id"), row.get("format")) for row in committed_rows)
        == FORMAT_VARIANT_KEYS,
        "Build format row order mismatch",
    )
    require(
        all(row.get("target_executed") is False for row in committed_rows),
        "Build manifest executed a format target",
    )
    for row in committed_rows:
        semantic_entry_proofs(row)
    return tuple(committed_rows)


def _nodes(program: SSAProgram, kind: str) -> tuple[Any, ...]:
    return tuple(node for node in program.graph.nodes if node.kind == kind)


def _predecessors(graph: Graph) -> dict[str, tuple[str, ...]]:
    result: dict[str, tuple[str, ...]] = {}
    for node in graph.nodes:
        result[node.node_id] = node.inputs + tuple(
            item.node_id for item in node.phi_inputs
        )
    return result


def _depends_on(graph: Graph, target: str, source: str) -> bool:
    predecessors = _predecessors(graph)
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


def _constant_input(program: SSAProgram, node: Any, value: int) -> bool:
    by_id = {item.node_id: item for item in program.graph.nodes}
    return any(
        by_id[item].kind == "Constant" and by_id[item].constant == value
        for item in node.inputs
    )


def _binary_with_constant(
    program: SSAProgram, operation: str, value: int
) -> tuple[Any, ...]:
    return tuple(
        node
        for node in program.graph.nodes
        if node.kind == "Binary"
        and node.operation == operation
        and _constant_input(program, node, value)
    )


def _walk_operand(value: Operand) -> Iterable[Operand]:
    yield value
    for child in value.children:
        yield from _walk_operand(child)
    if value.call is not None:
        for child in value.call.arguments + value.call.return_operands:
            yield from _walk_operand(child)


def snapshot_calls(snapshot: Snapshot) -> tuple[CallInfo, ...]:
    found: list[CallInfo] = []
    for block in snapshot.function.blocks:
        for instruction in block.instructions:
            for root in instruction.operands:
                for operand in _walk_operand(root):
                    if operand.call is not None:
                        found.append(operand.call)
    return tuple(found)


def _observed_limitations(program: SSAProgram) -> list[str]:
    limitations = set(program.diagnostics)
    if not _nodes(program, "Return"):
        limitations.add("normal_terminal_return_not_serialized")
    if any(node.kind == "UnknownValue" for node in program.graph.nodes):
        limitations.add("opaque_graph_nodes_retained")
    return sorted(limitations)


def evaluate_normal_snapshots(
    functions: list[dict[str, Any]], image_base: int
) -> dict[str, Any]:
    """Apply source-authored semantic checks to six normal snapshots."""

    require(
        tuple(item.get("symbol") for item in functions) == FUNCTIONS,
        "Normal function set/order mismatch",
    )
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
    require(
        all(all(item.values()) for item in replay.values()),
        "Offline graph replay drift",
    )

    scalar = programs["isa_scalar"]
    adds = tuple(
        node
        for node in scalar.graph.nodes
        if node.kind == "Binary" and node.operation == "add"
    )
    xors = _binary_with_constant(scalar, "xor", 0x013579BD)
    require(bool(adds) and bool(xors), "Scalar add/xor relation missing")
    require(
        any(
            any(_depends_on(scalar.graph, xor.node_id, add.node_id) for add in adds)
            for xor in xors
        ),
        "Scalar xor does not depend on add",
    )

    branch = programs["isa_branch"]
    split = any(
        len(block.successors) == 2 for block in snapshots["isa_branch"].function.blocks
    )
    merge = any(
        len(block.predecessors) == 2
        for block in snapshots["isa_branch"].function.blocks
    )
    require(
        split and merge and bool(_nodes(branch, "Branch")),
        "Branch CFG relation missing",
    )
    require(bool(_binary_with_constant(branch, "add", 3)), "Branch add arm missing")
    require(bool(_binary_with_constant(branch, "xor", 5)), "Branch xor arm missing")

    load = programs["isa_load"]
    loads = _nodes(load, "Load")
    require(len(loads) == 1 and loads[0].width_bits == 32, "Load is not exact 4-byte")
    require(
        loads[0].memory_operands is not None
        and loads[0].memory_operands.address in loads[0].inputs,
        "Load address role missing",
    )

    store = programs["isa_store"]
    stores = _nodes(store, "Store")
    require(
        len(stores) == 1 and stores[0].width_bits == 32,
        "Store is not exact 4-byte",
    )
    store_roles = stores[0].memory_operands
    require(
        store_roles is not None
        and store_roles.address != store_roles.data
        and store_roles.address in stores[0].inputs
        and store_roles.data in stores[0].inputs,
        "Store address/content separation missing",
    )

    rvas = {item["symbol"]: item["function_rva"] for item in functions}
    calls = snapshot_calls(snapshots["isa_call"])
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

    entry_calls = snapshot_calls(snapshots["isa_profile_entry"])
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
            for limitation in _observed_limitations(program)
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
                cast(int, call.callee_ea) - image_base
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


def _validate_entry_selection(
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
    require(
        value["logical_rva"] == proof["logical_rva"]
        and value["manifest_extraction_rva"] == proof["extraction_rva"]
        and value["proof_kind"] == proof["proof_kind"]
        and value["manifest_entry"] == proof,
        "Entry selection/manifest proof mismatch",
    )
    require(
        value["named_ea"] == image_base + proof["logical_rva"]
        and value["named_rva"] == proof["logical_rva"],
        "IDA selector did not match the logical manifest entry",
    )
    logical = value["logical_ida_bounds"]
    extraction = value["extraction_ida_bounds"]
    for bounds, label in (
        (logical, "logical IDA function bounds"),
        (extraction, "extraction IDA function bounds"),
    ):
        _exact_keys(bounds, {"start_ea", "start_rva", "end_ea", "end_rva"}, label)
        require(
            all(type(bounds[key]) is int for key in bounds),
            label + " must contain integers",
        )
        require(
            bounds["start_rva"] == bounds["start_ea"] - image_base
            and bounds["end_rva"] == bounds["end_ea"] - image_base,
            label + " image-base binding mismatch",
        )
    extent_size = proof.get("symbol_size", proof.get("extent_size"))
    extent_end_rva = (
        proof["logical_rva"] + extent_size if type(extent_size) is int else None
    )
    require(
        logical["start_rva"] == proof["logical_rva"]
        and logical["start_rva"] < logical["end_rva"]
        and (extent_end_rva is None or logical["end_rva"] <= extent_end_rva),
        "Logical IDA function bounds escape the manifest entry",
    )
    require(
        extraction["start_rva"] == value["ida_extraction_rva"]
        and extraction["start_rva"] < extraction["end_rva"]
        and (extent_end_rva is None or extraction["end_rva"] <= extent_end_rva),
        "Extraction IDA function bounds escape the manifest entry",
    )
    selection = select_ida_extraction(
        proof, extraction["start_rva"], extraction["end_rva"]
    )
    require(
        value["ida_extraction_rva"] == selection["ida_extraction_rva"]
        and value["selection_kind"] == selection["selection_kind"],
        "IDA extraction selection contract mismatch",
    )
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
        require(
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
            ),
            "Raw function materialization proof mismatch",
        )
    else:
        require(materialization is None, "Unexpected non-raw materialization proof")
    if selection["selection_kind"] == "exact_local_function" and proof.get(
        "local_entry_offset", 0
    ):
        require(
            logical["end_rva"] == extraction["start_rva"],
            "IDA logical/local entry boundary mismatch",
        )
    elif selection["selection_kind"] == "logical_function_contains_proven_local_entry":
        require(
            logical == extraction
            and logical["start_rva"] < proof["extraction_rva"] < logical["end_rva"],
            "Containing logical function/local-entry mismatch",
        )
    else:
        require(logical == extraction, "Exact logical entry bounds drifted")


def validate_normal_process(
    value: dict[str, Any], build_row: dict[str, Any], manifest_sha256: str
) -> None:
    _exact_keys(
        value,
        {
            "schema_version",
            "registry",
            "profile",
            "profile_digest",
            "binary_sha256",
            "image_base",
            "environment",
            "functions",
            "implementation",
            "target_executed",
            "input_preserved",
            "receipt_digest",
        },
        "normal process receipt",
    )
    require(value["schema_version"] == NORMAL_PROCESS_SCHEMA, "Process schema mismatch")
    registry = cast(ProfileRegistry, ProfileRegistry.from_data(value["registry"]))
    validate_semantic_profile(value["profile"], build_row, manifest_sha256, registry)
    require(
        value["profile_digest"] == digest(value["profile"]), "Profile digest mismatch"
    )
    require(value["binary_sha256"] == build_row["binary_sha256"], "Binary mismatch")
    require(value["target_executed"] is False, "Process executed target")
    require(value["input_preserved"] is True, "Process did not preserve input")
    require(
        type(value["image_base"]) is int and value["image_base"] >= 0,
        "Invalid image base",
    )
    require(
        tuple(item.get("symbol") for item in value["functions"]) == FUNCTIONS,
        "Process function set mismatch",
    )
    proofs = {item["name"]: item for item in semantic_entry_proofs(build_row)}
    function_rvas = {
        item["symbol"]: item["function_rva"] for item in value["functions"]
    }
    functions = {item["symbol"]: item for item in value["functions"]}
    for symbol, item in functions.items():
        _validate_entry_selection(
            item.get("entry_selection"), proofs[symbol], value["image_base"]
        )
        require(
            item["function_rva"] == proofs[symbol]["logical_rva"],
            "Function logical RVA/manifest proof mismatch",
        )
    for item in value["functions"]:
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
            "normal process function",
        )
        snapshot = cast(Snapshot, Snapshot.from_data(item["snapshot"]))
        resolutions = item["call_target_resolutions"]
        require(type(resolutions) is list, "Call target resolutions must be an array")
        calls = snapshot_calls(snapshot)
        expected_symbols = EXPECTED_CALLS[item["symbol"]]
        require(
            len(resolutions) == len(calls) == len(expected_symbols),
            "Call target resolution coverage mismatch",
        )
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
                "call target resolution",
            )
            raw_target = call.callee_ea
            resolved_ea = resolution["resolved_function_ea"]
            expected_rva = function_rvas[expected_symbol]
            expected_selection = functions[expected_symbol]["entry_selection"]
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
            require(
                resolution["raw_target_ea"] == raw_target
                and resolution["raw_target_rva"]
                == (None if raw_target is None else raw_target - value["image_base"])
                and resolution["resolved_function_rva"]
                == (None if resolved_ea is None else resolved_ea - value["image_base"])
                and resolution["resolved_function_end_rva"]
                == (
                    None
                    if resolution["resolved_function_end_ea"] is None
                    else resolution["resolved_function_end_ea"] - value["image_base"]
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
                == value["image_base"] + expected_ida_extraction_rva
                and resolution["expected_selected_end_ea"]
                == expected_selection["extraction_ida_bounds"]["end_ea"]
                and resolution["expected_selected_end_rva"]
                == resolution["expected_selected_end_ea"] - value["image_base"]
                and resolution["resolution_kind"] == expected_kind
                and resolution["resolved_to_expected"] is resolved_to_expected,
                "Call target resolution binding mismatch",
            )
        require(
            item["structural_identity"]
            == {
                "binary_sha256": build_row["binary_sha256"],
                "profile_id": build_row["profile_id"],
                "function_rva": item["function_rva"],
            },
            "Function structural identity tuple mismatch",
        )
        require(
            item["function_key"]
            == structural_function_key(
                build_row["binary_sha256"],
                build_row["profile_id"],
                item["function_rva"],
            ),
            "Function structural identity mismatch",
        )
        require(
            snapshot.function.function_id == item["function_key"],
            "Snapshot function mismatch",
        )
        require(item["snapshot_digest"] == digest(snapshot), "Snapshot digest mismatch")
        require(item["warmup_performed"] is True, "Snapshot warmup evidence missing")
        require(item["repeat_equal"] is True, "In-process repeat drift")
        require(item["roundtrip_equal"] is True, "Snapshot roundtrip drift")
        require(
            Snapshot.from_json(canonical_json(snapshot)) == snapshot,
            "Snapshot strict replay drift",
        )
    verify_receipt_digest(value)


def validate_normal_receipt(
    value: dict[str, Any], build_row: dict[str, Any], oracle_profile: dict[str, Any]
) -> None:
    require(
        value.get("schema_version") == NORMAL_RECEIPT_SCHEMA,
        "Normal receipt schema mismatch",
    )
    verify_receipt_digest(value)
    require(
        value.get("profile_id") == build_row["profile_id"], "Normal profile mismatch"
    )
    require(
        {
            "abi_id": value.get("abi_id"),
            "bitness": value.get("bitness"),
            "data_endian": value.get("data_endian"),
            "instruction_endian": value.get("instruction_endian"),
        }
        == {
            "abi_id": build_row["abi_id"],
            "bitness": build_row["bitness"],
            "data_endian": build_row["data_endian"],
            "instruction_endian": build_row["instruction_endian"],
        },
        "Normal ABI/profile facts mismatch",
    )
    require(
        value.get("maturity") == "MMAT_CALLS"
        and value.get("evidence_path")
        == (
            "normal_microcode"
            if build_row["format"] == "FMT-ELF"
            else "format_microcode"
        )
        and value.get("status") == "success"
        and value.get("support_status") == "unverified_semantic_candidate_no_promotion",
        "Normal evidence/support status mismatch",
    )
    require(
        value.get("binary_sha256") == build_row["binary_sha256"],
        "Normal binary mismatch",
    )
    require(value.get("target_executed") is False, "Normal receipt executed target")
    require(value.get("input_preserved") is True, "Normal receipt changed input")
    require(
        value.get("registry_promoted") is False
        and value.get("service_promoted") is False
        and value.get("capabilities_promoted") is False,
        "Normal evidence promoted a capability",
    )
    require(value.get("fresh_process_equal") is True, "Fresh-process semantics drift")
    registry = cast(ProfileRegistry, ProfileRegistry.from_data(value.get("registry")))
    validate_semantic_profile(
        value.get("profile"),
        build_row,
        value["build_evidence"]["committed_manifest_sha256"],
        registry,
    )
    process_view = {
        "schema_version": NORMAL_PROCESS_SCHEMA,
        "registry": value["registry"],
        "profile": value["profile"],
        "profile_digest": value["profile_digest"],
        "binary_sha256": value["binary_sha256"],
        "image_base": value["image_base"],
        "environment": value["environment"],
        "functions": value["functions"],
        "implementation": value["implementation"],
        "target_executed": value["target_executed"],
        "input_preserved": value["input_preserved"],
    }
    process_view["receipt_digest"] = receipt_digest(process_view)
    validate_normal_process(
        process_view,
        build_row,
        value["build_evidence"]["committed_manifest_sha256"],
    )
    environment = value.get("environment")
    if type(environment) is not dict:
        raise ContractError("Normal environment missing")
    expected = {
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
    require(
        all(environment.get(key) == item for key, item in expected.items()),
        "Normal environment/oracle mismatch",
    )
    evaluation = evaluate_normal_snapshots(value["functions"], value["image_base"])
    require(value.get("evaluation") == evaluation, "Normal evaluation mismatch")
    isa = oracle_profile["isa_specific_expectations"]
    require(
        isa["pointer_width_bits"] == environment["bitness"],
        "Pointer-width oracle mismatch",
    )
    require(
        value.get("isa_oracle_binding")
        == {
            "oracle_id": oracle_profile["oracle_id"],
            "integer_return_register": isa["integer_return_register"],
            "stack_pointer_register": isa["stack_pointer_register"],
            "call_instruction_family": isa["call_instruction_family"],
            "observation_status": "bound_hand_authored_expectation_not_serialized",
        },
        "ISA oracle binding mismatch",
    )


__all__ = [
    "FORMAT_MATRIX_SCHEMA",
    "FORMAT_VARIANT_KEYS",
    "FUNCTIONS",
    "EXPECTED_CALLS",
    "NORMAL_MATRIX_SCHEMA",
    "NORMAL_PROCESS_SCHEMA",
    "NORMAL_PROFILE_IDS",
    "NORMAL_RECEIPT_SCHEMA",
    "evaluate_normal_snapshots",
    "ephemeral_registry",
    "function_entry_proofs",
    "receipt_digest",
    "select_ida_extraction",
    "semantic_entry_proofs",
    "semantic_profile",
    "sha256_bytes",
    "snapshot_calls",
    "structural_function_key",
    "validate_build_rows",
    "validate_format_rows",
    "validate_normal_process",
    "validate_normal_receipt",
    "validate_semantic_profile",
    "verify_receipt_digest",
]
