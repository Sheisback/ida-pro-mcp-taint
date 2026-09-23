#!/usr/bin/env python3
"""Record fail-closed static IDA receipts for the G012 profile matrix.

The target binaries are never executed.  Every IDA invocation receives a
disposable copy and uses ``-c -A`` with the repository's bounded P0 probe.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

MATRIX_SCHEMA = "flow-profile-receipt-matrix/1"
ROW_SCHEMA = "flow-profile-receipt-run/1"
BUILD_SCHEMA = "flow-isa-profile-builds/1"
BOOTSTRAP_FILETYPE = "__bootstrap_observation_required__"
FORMATS = {"FMT-ELF": "ELF", "FMT-PE": "PE", "FMT-MACHO": "MACH-O"}
MATURITIES = ["MMAT_CALLS", "MMAT_GLBOPT3"]
SEMANTIC_IGNORED_FIELDS: list[str] = []
RAW_PROFILE = {
    "profile_id": "ARM32-LE",
    "profile_version": 1,
    "mode": "ARM32",
    "processor": "ARM",
    "bits": 32,
    "data_endian": "LE",
    "instruction_endian": "LE",
    "abi_id": "aapcs32",
}
RAW_CONFIGURATION_KEYS = {
    "processor",
    "bitness",
    "data_endian",
    "instruction_endian",
    "mode",
    "load_address",
    "entry_offset",
    "entry_point",
    "source_section",
    "function_selector",
}
RAW_ADDRESS_LIMIT = 1 << 32


class RowFailure(RuntimeError):
    """A bounded row failure that must become a retained result receipt."""

    def __init__(self, kind: str, message: str, **details: Any) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.details = details


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _reject_json_constant(value: str) -> None:
    raise ValueError("Non-finite JSON constant: " + value)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(), parse_constant=_reject_json_constant)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    detached = json.loads(json.dumps(value, allow_nan=False))
    path.write_text(json.dumps(detached, indent=2, sort_keys=True) + "\n")


def _exact_keys(value: Any, expected: set[str], label: str) -> None:
    if type(value) is not dict:
        raise ValueError(label + " must be an object")
    actual = set(value)
    if actual != expected:
        raise ValueError(
            f"{label} keys mismatch; missing={sorted(expected - actual)!r}, "
            f"extra={sorted(actual - expected)!r}"
        )


def _safe_relative(value: Any, label: str) -> Path:
    if type(value) is not str or not value:
        raise RowFailure("invalid_manifest", label + " must be a non-empty string")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise RowFailure(
            "unsafe_manifest_path", label + " must be a safe relative path", value=value
        )
    return path


def _inside(base: Path, relative: Path, label: str) -> Path:
    candidate = (base / relative).resolve()
    try:
        candidate.relative_to(base.resolve())
    except ValueError as exc:
        raise RowFailure(
            "unsafe_manifest_path", label + " escapes its declared root"
        ) from exc
    return candidate


def _row_format(row: dict[str, Any]) -> str:
    value = row.get("format")
    if value == "FMT-RAW":
        return "RAW"
    if value not in FORMATS:
        raise RowFailure("invalid_manifest", "Unsupported row format", format=value)
    return FORMATS[value]


def _declared_profile(row: dict[str, Any]) -> dict[str, Any]:
    try:
        profile = {
            "profile_id": row["profile_id"],
            "profile_version": row["profile_version"],
            "mode": row["mode"],
            "processor": row["processor"],
            "bits": row["bitness"],
            "data_endian": row["data_endian"],
            "instruction_endian": row["instruction_endian"],
            "abi_id": row["abi_id"],
        }
    except KeyError as exc:
        raise RowFailure(
            "invalid_manifest", "Profile row is missing " + str(exc)
        ) from exc
    if type(profile["profile_id"]) is not str or not profile["profile_id"]:
        raise RowFailure("invalid_manifest", "profile_id must be non-empty")
    return profile


def _entry_value(row: dict[str, Any]) -> str:
    selector = row.get("function_selector")
    if selector is None:
        selectors = row.get("function_selectors")
        if type(selectors) is not list:
            raise RowFailure("invalid_manifest", "Missing function selector")
        selector = next(
            (
                item
                for item in selectors
                if type(item) is dict and item.get("value") == "isa_profile_entry"
            ),
            None,
        )
    if type(selector) is not dict or selector.get("kind") not in {
        "debug_or_symbol_name",
        "export_name",
        "ida_name",
    }:
        raise RowFailure("invalid_manifest", "Unsupported function selector")
    value = selector.get("value")
    if type(value) is not str or not value:
        raise RowFailure("invalid_manifest", "Function selector must name an entry")
    return value


def _raw_configuration(
    row: dict[str, Any], *, binary_size: int | None = None
) -> dict[str, Any]:
    """Validate the only reviewed raw-loader profile without accepting flags."""

    if _row_format(row) != "RAW" or _declared_profile(row) != RAW_PROFILE:
        raise RowFailure(
            "unsupported_raw_configuration",
            "Only the reviewed ARM32-LE raw profile is supported",
        )
    config = row.get("raw_configuration")
    if type(config) is not dict or set(config) != RAW_CONFIGURATION_KEYS:
        raise RowFailure(
            "unsupported_raw_configuration",
            "Raw configuration keys do not match the reviewed contract",
        )
    expected_identity = {
        "processor": "ARM",
        "bitness": 32,
        "data_endian": "LE",
        "instruction_endian": "LE",
        "mode": "ARM32",
        "source_section": ".text",
    }
    identity_mismatches = {
        key: {"expected": value, "observed": config.get(key)}
        for key, value in expected_identity.items()
        if config.get(key) != value
    }
    if identity_mismatches:
        raise RowFailure(
            "unsupported_raw_configuration",
            "Raw configuration identity is not the reviewed ARMv7-A row",
            mismatches=identity_mismatches,
        )

    load_address = config.get("load_address")
    entry_offset = config.get("entry_offset")
    entry_point = config.get("entry_point")
    if any(
        type(value) is not int for value in (load_address, entry_offset, entry_point)
    ):
        raise RowFailure(
            "unsupported_raw_configuration",
            "Raw load and entry fields must be integers",
        )
    if load_address != 0x10000 or load_address % 16:
        raise RowFailure(
            "unsupported_raw_configuration",
            "Raw load address must be the reviewed paragraph-aligned 0x10000",
            load_address=load_address,
        )
    if entry_offset != 0 or entry_point != load_address:
        raise RowFailure(
            "unsupported_raw_configuration",
            "Raw entry must select stable isa_scalar at offset zero",
            load_address=load_address,
            entry_offset=entry_offset,
            entry_point=entry_point,
        )
    if config.get("function_selector") != {"kind": "raw_offset", "value": 0}:
        raise RowFailure(
            "unsupported_raw_configuration",
            "Raw function selector must select stable offset zero",
        )
    if binary_size is not None:
        if type(binary_size) is not int or binary_size <= 0:
            raise RowFailure(
                "unsupported_raw_configuration", "Raw input must not be empty"
            )
        if load_address + binary_size > RAW_ADDRESS_LIMIT:
            raise RowFailure(
                "unsupported_raw_configuration",
                "Raw input exceeds the ARM32 address space",
            )
        if not load_address <= entry_point < load_address + binary_size:
            raise RowFailure(
                "unsupported_raw_configuration",
                "Raw entry lies outside the copied input range",
            )
    return json.loads(json.dumps(config, allow_nan=False))


def _row_id(row: dict[str, Any]) -> str:
    profile = str(row.get("profile_id", "unknown"))
    binary_format = str(row.get("format", "unknown")).removeprefix("FMT-")
    binary_hash = str(row.get("binary_sha256", "missing"))[:12]
    raw = f"{profile}--{binary_format}--{binary_hash}".lower()
    return re.sub(r"[^a-z0-9_.-]+", "-", raw).strip("-") or "unknown-row"


def _load_probe_module(root: Path) -> Any:
    path = root / "src/ida_pro_mcp/ida_mcp/flow/p0_probe.py"
    if not path.is_file():
        raise ValueError("Missing P0 probe contract: " + str(path))
    spec = importlib.util.spec_from_file_location("g012_profile_probe_contract", path)
    if spec is None or spec.loader is None:
        raise ValueError("Cannot load P0 probe contract: " + str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bootstrap_request(
    row: dict[str, Any], *, binary_size: int | None = None
) -> dict[str, Any]:
    binary_format = _row_format(row)
    request = {
        "schema_version": "flow-p0-probe-request/1",
        "profile": _declared_profile(row),
        "binary": {
            "format": binary_format,
            "filetype": BOOTSTRAP_FILETYPE,
            "sha256": row["binary_sha256"],
        },
        "probe": {"maturities": list(MATURITIES)},
    }
    if binary_format == "RAW":
        config = _raw_configuration(row, binary_size=binary_size)
        request["load"] = {
            "kind": "raw",
            "file_offset": 0,
            "load_address": config["load_address"],
        }
        request["entry"] = {"kind": "address", "value": config["entry_point"]}
    else:
        request["load"] = {"kind": "loader", "image_base": 0}
        request["entry"] = {"kind": "name", "value": _entry_value(row)}
    return request


def _final_request(
    bootstrap: dict[str, Any], observation: dict[str, Any]
) -> dict[str, Any]:
    result = json.loads(json.dumps(bootstrap, allow_nan=False))
    result["binary"]["filetype"] = observation["filetype"]
    if result["load"]["kind"] == "loader":
        result["load"] = {
            "kind": "loader",
            "image_base": observation["image_base"],
        }
        result["entry"] = {"kind": "address", "value": observation["entry_ea"]}
    return result


def _empty_stage() -> dict[str, Any]:
    return {
        "status": "not_run",
        "request_file": None,
        "receipt_file": None,
        "exit_code": None,
        "stdout_file": None,
        "stderr_file": None,
    }


def _base_result(row: dict[str, Any], repeat_final: bool) -> dict[str, Any]:
    return {
        "schema_version": ROW_SCHEMA,
        "row_id": _row_id(row),
        "profile_id": row.get("profile_id"),
        "format": row.get("format"),
        "declared_profile": _declared_profile(row),
        "binary": {
            "manifest_path": row.get("binary"),
            "expected_sha256": row.get("binary_sha256"),
            "copied_sha256": None,
        },
        "status": "failed",
        "support_status": "unverified",
        "target_executed": False,
        "stages": {
            "bootstrap": _empty_stage(),
            "final": _empty_stage(),
            "repeat": _empty_stage(),
        },
        "repeatability": {
            "requested": repeat_final,
            "performed": False,
            "semantic_equal": None,
            "ignored_fields": list(SEMANTIC_IGNORED_FIELDS),
        },
        "failures": [],
        "receipt_digest": None,
    }


def _failure(result: dict[str, Any], error: RowFailure) -> None:
    result["failures"].append(
        {"kind": error.kind, "message": error.message, "details": error.details}
    )


def _finish_result(path: Path, result: dict[str, Any]) -> dict[str, Any]:
    result["receipt_digest"] = digest(
        {key: value for key, value in result.items() if key != "receipt_digest"}
    )
    validate_row_result(result)
    write_json(path, result)
    return result


def validate_row_result(result: dict[str, Any]) -> None:
    _exact_keys(
        result,
        {
            "schema_version",
            "row_id",
            "profile_id",
            "format",
            "declared_profile",
            "binary",
            "status",
            "support_status",
            "target_executed",
            "stages",
            "repeatability",
            "failures",
            "receipt_digest",
        },
        "row result",
    )
    _exact_keys(
        result["binary"],
        {"manifest_path", "expected_sha256", "copied_sha256"},
        "row result binary",
    )
    _exact_keys(result["stages"], {"bootstrap", "final", "repeat"}, "row result stages")
    for name, stage in result["stages"].items():
        _exact_keys(
            stage,
            {
                "status",
                "request_file",
                "receipt_file",
                "exit_code",
                "stdout_file",
                "stderr_file",
            },
            "row result stage " + name,
        )
    _exact_keys(
        result["repeatability"],
        {"requested", "performed", "semantic_equal", "ignored_fields"},
        "row result repeatability",
    )
    if result["schema_version"] != ROW_SCHEMA:
        raise ValueError("Unsupported row result schema")
    if result["status"] not in {"success", "failed", "blocked"}:
        raise ValueError("Invalid row result status")
    if result["support_status"] != "unverified":
        raise ValueError("Runner may not promote support status")
    if result["target_executed"] is not False:
        raise ValueError("Runner receipt must state target_executed false")
    expected = digest(
        {key: value for key, value in result.items() if key != "receipt_digest"}
    )
    if result["receipt_digest"] != expected:
        raise ValueError("Invalid row result receipt digest")


def _load_reference(
    root: Path, manifest_path: Path, row: dict[str, Any]
) -> tuple[Path, list[tuple[Path, Path]]]:
    relative = _safe_relative(row["binary"], "binary")
    primary = _inside(manifest_path.parent, relative, "binary")
    if primary.is_file():
        companions = []
        for item in row.get("companion_artifacts", []):
            item_relative = _safe_relative(item.get("path"), "companion path")
            source = _inside(manifest_path.parent, item_relative, "companion path")
            companions.append((source, item_relative))
        return primary, companions

    reference_value = row.get("reference_manifest")
    if reference_value is None:
        raise RowFailure(
            "binary_missing", "Build output binary does not exist", binary=row["binary"]
        )
    reference_relative = _safe_relative(reference_value, "reference_manifest")
    reference = _inside(root, reference_relative, "reference_manifest")
    if not reference.is_file():
        raise RowFailure(
            "reference_manifest_missing", "Reference manifest does not exist"
        )
    expected_reference_hash = row.get("reference_manifest_sha256")
    if sha256(reference) != expected_reference_hash:
        raise RowFailure(
            "reference_manifest_hash_mismatch",
            "Reference manifest hash does not match the build row",
        )
    reference_rows = read_json(reference)
    if type(reference_rows) is not list:
        raise RowFailure("invalid_manifest", "Reference manifest must contain a list")
    match = next(
        (
            item
            for item in reference_rows
            if type(item) is dict
            and item.get("binary") == row.get("binary")
            and item.get("binary_sha256") == row.get("binary_sha256")
        ),
        None,
    )
    if match is None:
        raise RowFailure("reference_row_missing", "Referenced binary row was not found")
    source = _inside(reference.parent, relative, "referenced binary")
    if not source.is_file():
        raise RowFailure(
            "binary_missing", "Referenced build output binary does not exist"
        )
    companions = []
    for item in match.get("companion_artifacts", []):
        item_relative = _safe_relative(item.get("path"), "companion path")
        companion = _inside(reference.parent, item_relative, "companion path")
        if not companion.is_file():
            raise RowFailure("companion_missing", "Required companion is missing")
        if sha256(companion) != item.get("sha256"):
            raise RowFailure(
                "companion_hash_mismatch", "Required companion hash does not match"
            )
        companions.append((companion, item_relative))
    return source, companions


def _validate_probe_receipt(
    receipt: Any, request: dict[str, Any], probe: Any
) -> dict[str, Any]:
    if type(receipt) is not dict:
        raise RowFailure("invalid_probe_receipt", "Probe receipt must be an object")
    if receipt.get("schema_version") != probe.RECEIPT_SCHEMA:
        raise RowFailure(
            "invalid_probe_receipt", "Probe receipt schema version is invalid"
        )
    if receipt.get("target_executed") is not False:
        raise RowFailure(
            "target_execution_claimed", "Probe receipt did not preserve no-execution"
        )
    if receipt.get("support_status") != "unverified":
        raise RowFailure(
            "support_status_promoted", "Probe receipt promoted support status"
        )
    if receipt.get("request") != request:
        raise RowFailure(
            "request_mismatch", "Probe receipt request differs from written request"
        )
    request_digest = probe.request_digest(request)
    if receipt.get("request_digest") != request_digest:
        raise RowFailure("request_digest_mismatch", "Probe request digest is invalid")
    payload = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    if receipt.get("receipt_digest") != probe.digest(payload):
        raise RowFailure("receipt_digest_mismatch", "Probe receipt digest is invalid")
    validation = receipt.get("validation")
    if (
        type(validation) is not dict
        or validation.get("request_digest") != request_digest
    ):
        raise RowFailure(
            "validation_digest_mismatch", "Validation did not bind the exact request"
        )
    return receipt


def _declared_observation_check(
    row: dict[str, Any], receipt: dict[str, Any]
) -> dict[str, Any]:
    environment = receipt.get("environment")
    if type(environment) is not dict:
        raise RowFailure(
            "observation_missing", "Probe receipt has no runtime observation"
        )
    expected = {
        "binary_sha256": row["binary_sha256"],
        "format": _row_format(row),
        "processor": row["processor"],
        "bits": row["bitness"],
        "data_endian": row["data_endian"],
    }
    mismatches = {
        field: {"expected": value, "observed": environment.get(field)}
        for field, value in expected.items()
        if environment.get(field) != value
    }
    observed_instruction = environment.get("instruction_endian")
    if (
        observed_instruction is not None
        and observed_instruction != row["instruction_endian"]
    ):
        mismatches["instruction_endian"] = {
            "expected": row["instruction_endian"],
            "observed": observed_instruction,
        }
    if mismatches:
        raise RowFailure(
            "declared_profile_mismatch",
            "Runtime observation differs from declared profile fields",
            mismatches=mismatches,
        )
    if type(environment.get("filetype")) is not str or not environment["filetype"]:
        raise RowFailure("observation_missing", "Observed filetype is missing")
    if type(environment.get("image_base")) is not int:
        raise RowFailure("observation_missing", "Observed image base is missing")
    if type(environment.get("entry_ea")) is not int:
        raise RowFailure("entry_missing", "IDA did not resolve the requested entry")
    if _row_format(row) == "RAW":
        config = _raw_configuration(row)
        address_mismatches = {
            "load_address": {
                "expected": config["load_address"],
                "observed": environment["image_base"],
            },
            "entry_point": {
                "expected": config["entry_point"],
                "observed": environment["entry_ea"],
            },
        }
        address_mismatches = {
            key: value
            for key, value in address_mismatches.items()
            if value["expected"] != value["observed"]
        }
        if address_mismatches:
            raise RowFailure(
                "raw_setup_mismatch",
                "Observed raw load or entry differs from reviewed configuration",
                mismatches=address_mismatches,
            )
    return environment


def _validate_bootstrap(receipt: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    validation = receipt.get("validation")
    if type(validation) is not dict:
        raise RowFailure("validation_missing", "Bootstrap validation is missing")
    mismatches = validation.get("mismatches")
    rejected_as_expected = validation.get("status") == "mismatch" and (
        mismatches == ["binary.filetype"]
        if _row_format(row) == "RAW"
        else type(mismatches) is list and "binary.filetype" in mismatches
    )
    if not rejected_as_expected:
        raise RowFailure(
            "bootstrap_not_rejected",
            "Bootstrap request was not rejected by the expected filetype mismatch",
        )
    if receipt.get("initialization") is not None or receipt.get("probes") != []:
        raise RowFailure(
            "bootstrap_probed",
            "Bootstrap request initialized Hex-Rays or emitted probe results",
        )
    return _declared_observation_check(row, receipt)


def _validate_final(
    receipt: dict[str, Any], row: dict[str, Any], stable: dict[str, Any]
) -> None:
    validation = receipt.get("validation")
    if type(validation) is not dict:
        raise RowFailure("validation_missing", "Final validation is missing")
    if validation.get("status") != "accepted":
        raise RowFailure(
            "final_request_rejected",
            "Exact final request did not pass runtime validation",
            validation_status=validation.get("status"),
            mismatches=validation.get("mismatches"),
        )
    if _row_format(row) == "RAW" and (
        type(validation.get("raw_setup")) is not dict
        or validation["raw_setup"].get("status") != "verified_observable_fields"
    ):
        raise RowFailure(
            "raw_setup_unverified",
            "Final raw request did not verify the external loader setup",
        )
    environment = _declared_observation_check(row, receipt)
    stable_fields = ("filetype", "image_base", "entry_ea")
    drift = {
        field: {"bootstrap": stable[field], "final": environment.get(field)}
        for field in stable_fields
        if environment.get(field) != stable[field]
    }
    if drift:
        raise RowFailure(
            "runtime_observation_drift",
            "Final runtime observation differs from bootstrap",
            mismatches=drift,
        )
    if receipt.get("initialization") is not True:
        raise RowFailure(
            "hexrays_initialization", "Hex-Rays initialization did not succeed"
        )
    probes = receipt.get("probes")
    if (
        type(probes) is not list
        or [item.get("maturity") for item in probes] != MATURITIES
    ):
        raise RowFailure(
            "maturities_missing", "Final receipt does not contain both maturities"
        )
    for item in probes:
        if type(item.get("repeat_equal")) is not bool:
            raise RowFailure(
                "repeatability_missing", "A maturity did not record repeatability"
            )
        if item.get("status") != "success" or item["repeat_equal"] is not True:
            raise RowFailure("probe_failure", "A maturity failed or was not repeatable")
    if receipt.get("probe_status") != "success":
        raise RowFailure("probe_failure", "Final probe status is not success")
    lifetime = receipt.get("lifetime")
    if type(lifetime) is not dict or lifetime.get("repeat_after_gc") is not True:
        raise RowFailure(
            "repeatability_failure", "Final receipt failed repeat-after-GC"
        )


def semantic_receipts_equal(left: Any, right: Any) -> bool:
    """Compare path- and timestamp-free probe receipts without exclusions."""

    return left == right


def _run_stage(
    *,
    name: str,
    root: Path,
    ida_executable: Path,
    disposable: Path,
    binary: Path,
    row_dir: Path,
    request: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    request_name = f"request-{name}.json"
    receipt_name = f"receipt-{name}.json"
    stdout_name = f"{name}.stdout.log"
    stderr_name = f"{name}.stderr.log"
    request_path = row_dir / request_name
    receipt_path = row_dir / receipt_name
    stdout_path = row_dir / stdout_name
    stderr_path = row_dir / stderr_name
    write_json(request_path, request)
    receipt_path.unlink(missing_ok=True)
    probe_script = root / "scripts/flow_p0_probe.py"
    script_option = "-S" + shlex.join(
        [str(probe_script), str(root), str(receipt_path), str(request_path)]
    )
    loader_options: list[str] = []
    if request["load"]["kind"] == "raw":
        if request["profile"] != RAW_PROFILE or request["binary"]["format"] != "RAW":
            raise RowFailure(
                "unsupported_raw_configuration",
                "Raw IDA invocation requires the reviewed ARM32-LE profile",
            )
        load_address = request["load"].get("load_address")
        file_offset = request["load"].get("file_offset")
        entry_point = request["entry"].get("value")
        if (
            type(load_address) is not int
            or type(entry_point) is not int
            or file_offset != 0
            or load_address != 0x10000
            or load_address % 16
            or entry_point != load_address
            or entry_point >= load_address + binary.stat().st_size
            or load_address + binary.stat().st_size > RAW_ADDRESS_LIMIT
        ):
            raise RowFailure(
                "unsupported_raw_configuration",
                "Raw IDA invocation addresses are invalid",
            )
        loader_options = [
            "-TBinary",
            "-parm:ARMv7-A",
            f"-b{load_address // 16:x}",
            f"-i{entry_point:x}",
        ]
    command = [
        str(ida_executable),
        "-c",
        "-A",
        *loader_options,
        script_option,
        str(binary),
    ]
    completed = subprocess.run(
        command,
        cwd=disposable,
        check=False,
        capture_output=True,
        text=True,
        shell=False,
    )
    stdout_path.write_text(completed.stdout or "")
    stderr_path.write_text(completed.stderr or "")
    stage = {
        "status": "completed" if completed.returncode == 0 else "failed",
        "request_file": request_name,
        "receipt_file": receipt_name if receipt_path.is_file() else None,
        "exit_code": completed.returncode,
        "stdout_file": stdout_name,
        "stderr_file": stderr_name,
    }
    if completed.returncode != 0:
        raise RowFailure(
            "ida_process_failed",
            "IDA exited unsuccessfully during " + name,
            stage=name,
            exit_code=completed.returncode,
        )
    if not receipt_path.is_file():
        raise RowFailure(
            "probe_receipt_missing",
            "IDA did not create a probe receipt during " + name,
            stage=name,
        )
    return stage, read_json(receipt_path)


def _record_row(
    *,
    root: Path,
    manifest_path: Path,
    row: dict[str, Any],
    output_dir: Path,
    ida_executable: Path,
    repeat_final: bool,
    probe: Any,
) -> dict[str, Any]:
    row_id = _row_id(row)
    row_dir = output_dir / row_id
    row_dir.mkdir(parents=True, exist_ok=True)
    result_path = row_dir / "result.json"
    try:
        result = _base_result(row, repeat_final)
    except RowFailure as error:
        result = {
            "schema_version": ROW_SCHEMA,
            "row_id": row_id,
            "profile_id": row.get("profile_id"),
            "format": row.get("format"),
            "declared_profile": {},
            "binary": {
                "manifest_path": row.get("binary"),
                "expected_sha256": row.get("binary_sha256"),
                "copied_sha256": None,
            },
            "status": "failed",
            "support_status": "unverified",
            "target_executed": False,
            "stages": {
                "bootstrap": _empty_stage(),
                "final": _empty_stage(),
                "repeat": _empty_stage(),
            },
            "repeatability": {
                "requested": repeat_final,
                "performed": False,
                "semantic_equal": None,
                "ignored_fields": [],
            },
            "failures": [],
            "receipt_digest": None,
        }
        _failure(result, error)
        return _finish_result(result_path, result)

    try:
        if row.get("target_executed") is not False:
            raise RowFailure(
                "target_execution_not_disclaimed",
                "Build row must state target_executed false",
            )
        _row_format(row)
        source, companions = _load_reference(root, manifest_path, row)
        expected_hash = row.get("binary_sha256")
        if type(expected_hash) is not str or not re.fullmatch(
            r"[0-9a-f]{64}", expected_hash
        ):
            raise RowFailure(
                "invalid_manifest", "binary_sha256 must be lowercase SHA-256"
            )
        actual_hash = sha256(source)
        if actual_hash != expected_hash:
            raise RowFailure(
                "binary_hash_mismatch",
                "Build output hash does not match the manifest",
                expected=expected_hash,
                observed=actual_hash,
            )

        with tempfile.TemporaryDirectory(
            prefix=row_id + "-", dir=output_dir
        ) as temporary:
            disposable = Path(temporary)
            binary = disposable / source.name
            shutil.copy2(source, binary)
            for companion, relative in companions:
                destination = disposable / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(companion, destination)
            copied_hash = sha256(binary)
            result["binary"]["copied_sha256"] = copied_hash
            if copied_hash != expected_hash:
                raise RowFailure(
                    "disposable_copy_hash_mismatch",
                    "Disposable binary copy changed the input hash",
                )

            bootstrap_request = _bootstrap_request(
                row, binary_size=binary.stat().st_size
            )
            probe.validate_request(bootstrap_request)
            try:
                stage, bootstrap_receipt = _run_stage(
                    name="bootstrap",
                    root=root,
                    ida_executable=ida_executable,
                    disposable=disposable,
                    binary=binary,
                    row_dir=row_dir,
                    request=bootstrap_request,
                )
                result["stages"]["bootstrap"] = stage
            except RowFailure as error:
                if (row_dir / "request-bootstrap.json").is_file():
                    result["stages"]["bootstrap"]["request_file"] = (
                        "request-bootstrap.json"
                    )
                if (row_dir / "receipt-bootstrap.json").is_file():
                    result["stages"]["bootstrap"]["receipt_file"] = (
                        "receipt-bootstrap.json"
                    )
                raise error
            bootstrap_receipt = _validate_probe_receipt(
                bootstrap_receipt, bootstrap_request, probe
            )
            observation = _validate_bootstrap(bootstrap_receipt, row)

            final_request = _final_request(bootstrap_request, observation)
            probe.validate_request(final_request)
            try:
                stage, final_receipt = _run_stage(
                    name="final",
                    root=root,
                    ida_executable=ida_executable,
                    disposable=disposable,
                    binary=binary,
                    row_dir=row_dir,
                    request=final_request,
                )
                result["stages"]["final"] = stage
            except RowFailure as error:
                if (row_dir / "request-final.json").is_file():
                    result["stages"]["final"]["request_file"] = "request-final.json"
                if (row_dir / "receipt-final.json").is_file():
                    result["stages"]["final"]["receipt_file"] = "receipt-final.json"
                raise error
            final_receipt = _validate_probe_receipt(final_receipt, final_request, probe)
            _validate_final(final_receipt, row, observation)

            if repeat_final:
                try:
                    stage, repeat_receipt = _run_stage(
                        name="repeat",
                        root=root,
                        ida_executable=ida_executable,
                        disposable=disposable,
                        binary=binary,
                        row_dir=row_dir,
                        request=final_request,
                    )
                    result["stages"]["repeat"] = stage
                except RowFailure as error:
                    if (row_dir / "request-repeat.json").is_file():
                        result["stages"]["repeat"]["request_file"] = (
                            "request-repeat.json"
                        )
                    if (row_dir / "receipt-repeat.json").is_file():
                        result["stages"]["repeat"]["receipt_file"] = (
                            "receipt-repeat.json"
                        )
                    raise error
                repeat_receipt = _validate_probe_receipt(
                    repeat_receipt, final_request, probe
                )
                _validate_final(repeat_receipt, row, observation)
                equal = semantic_receipts_equal(final_receipt, repeat_receipt)
                result["repeatability"].update(
                    {"performed": True, "semantic_equal": equal}
                )
                if not equal:
                    raise RowFailure(
                        "semantic_repeat_mismatch",
                        "Repeated final receipts are not semantically identical",
                    )
            result["status"] = "success"
    except RowFailure as error:
        _failure(result, error)
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        _failure(
            result,
            RowFailure("runner_exception", f"{type(error).__name__}: {error}"),
        )
    return _finish_result(result_path, result)


def _manifest_rows(
    manifest: Any, profile_filter: set[str] | None
) -> list[dict[str, Any]]:
    if type(manifest) is not dict:
        raise ValueError("Build manifest must be an object")
    if manifest.get("schema_version") != BUILD_SCHEMA:
        raise ValueError("Unsupported build manifest schema")
    if manifest.get("target_executed") is not False:
        raise ValueError("Build manifest must state target_executed false")
    profiles = manifest.get("profiles")
    variants = manifest.get("format_variants")
    if type(profiles) is not list or type(variants) is not list:
        raise ValueError("Build manifest rows must be lists")
    rows = profiles + variants
    if any(type(row) is not dict for row in rows):
        raise ValueError("Every build manifest row must be an object")
    if profile_filter is not None:
        rows = [row for row in rows if row.get("profile_id") in profile_filter]
        found = {row.get("profile_id") for row in rows}
        missing = sorted(profile_filter - found)
        if missing:
            raise ValueError("Unknown profile filter(s): " + ", ".join(missing))
    identifiers = [_row_id(row) for row in rows]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Build manifest contains duplicate receipt row identities")
    return rows


def validate_matrix_result(result: dict[str, Any]) -> None:
    _exact_keys(
        result,
        {
            "schema_version",
            "build_manifest_sha256",
            "profile_filter",
            "repeat_final",
            "row_count",
            "status_counts",
            "status",
            "support_status",
            "target_executed",
            "rows",
            "receipt_digest",
        },
        "matrix result",
    )
    _exact_keys(
        result["status_counts"], {"success", "failed", "blocked"}, "status counts"
    )
    for row in result["rows"]:
        _exact_keys(
            row,
            {
                "row_id",
                "profile_id",
                "format",
                "status",
                "result_file",
                "receipt_digest",
            },
            "matrix row",
        )
    if result["schema_version"] != MATRIX_SCHEMA:
        raise ValueError("Unsupported matrix result schema")
    if result["support_status"] != "unverified":
        raise ValueError("Matrix may not promote support status")
    if result["target_executed"] is not False:
        raise ValueError("Matrix must state target_executed false")
    if result["row_count"] != len(result["rows"]):
        raise ValueError("Matrix row count is inconsistent")
    expected = digest(
        {key: value for key, value in result.items() if key != "receipt_digest"}
    )
    if result["receipt_digest"] != expected:
        raise ValueError("Invalid matrix receipt digest")


def run_matrix(
    *,
    root: Path,
    build_manifest: Path,
    output_dir: Path,
    ida_executable: Path,
    profile_filter: set[str] | None = None,
    repeat_final: bool = False,
) -> dict[str, Any]:
    root = root.resolve()
    build_manifest = build_manifest.resolve()
    output_dir = output_dir.resolve()
    ida_executable = ida_executable.resolve()
    if not root.is_dir():
        raise ValueError("Repository root does not exist")
    if not build_manifest.is_file():
        raise ValueError("Build manifest does not exist")
    if not ida_executable.is_file() or not os.access(ida_executable, os.X_OK):
        raise ValueError("IDA executable is missing or not executable")
    if ida_executable.name not in {"idat", "idat64"}:
        raise ValueError("IDA executable must be the headless idat or idat64 binary")
    if not (root / "scripts/flow_p0_probe.py").is_file():
        raise ValueError("Repository P0 probe runner is missing")
    manifest = read_json(build_manifest)
    rows = _manifest_rows(manifest, profile_filter)
    output_dir.mkdir(parents=True, exist_ok=True)
    probe = _load_probe_module(root)
    receipts = [
        _record_row(
            root=root,
            manifest_path=build_manifest,
            row=row,
            output_dir=output_dir,
            ida_executable=ida_executable,
            repeat_final=repeat_final,
            probe=probe,
        )
        for row in rows
    ]
    counts = {
        status: sum(receipt["status"] == status for receipt in receipts)
        for status in ("success", "failed", "blocked")
    }
    if counts["failed"] == 0 and counts["blocked"] == 0:
        status = "success"
    elif counts["success"]:
        status = "partial"
    else:
        status = "failed"
    result = {
        "schema_version": MATRIX_SCHEMA,
        "build_manifest_sha256": sha256(build_manifest),
        "profile_filter": sorted(profile_filter) if profile_filter else [],
        "repeat_final": repeat_final,
        "row_count": len(receipts),
        "status_counts": counts,
        "status": status,
        "support_status": "unverified",
        "target_executed": False,
        "rows": [
            {
                "row_id": receipt["row_id"],
                "profile_id": receipt["profile_id"],
                "format": receipt["format"],
                "status": receipt["status"],
                "result_file": receipt["row_id"] + "/result.json",
                "receipt_digest": receipt["receipt_digest"],
            }
            for receipt in receipts
        ],
        "receipt_digest": None,
    }
    result["receipt_digest"] = digest(
        {key: value for key, value in result.items() if key != "receipt_digest"}
    )
    validate_matrix_result(result)
    write_json(output_dir / "matrix.json", result)
    return result


def release_scope_accepted(matrix: dict[str, Any], scope: dict[str, Any]) -> bool:
    """Allow optional P0 failures without concealing a failed required row."""
    validate_matrix_result(matrix)
    _exact_keys(
        scope,
        {"schema_version", "decision", "required_profile_ids", "optional_profile_ids"},
        "release scope",
    )
    if scope["schema_version"] != "flow-release-scope/1":
        raise ValueError("Unsupported release scope schema")
    if type(scope["decision"]) is not str or not scope["decision"]:
        raise ValueError("Release scope decision missing")
    required = scope["required_profile_ids"]
    optional = scope["optional_profile_ids"]
    for label, values in (("required", required), ("optional", optional)):
        if (
            type(values) is not list
            or any(type(value) is not str or not value for value in values)
            or len(values) != len(set(values))
        ):
            raise ValueError(f"Invalid {label} release profiles")
    required_ids, optional_ids = set(required), set(optional)
    if not required_ids or required_ids & optional_ids:
        raise ValueError("Release profiles are empty or overlap")
    if matrix["repeat_final"] is not True:
        raise ValueError("Release scope requires P0 fresh-process repeat evidence")
    if matrix["profile_filter"] != []:
        raise ValueError("Release scope requires an unfiltered P0 matrix")
    rows = matrix["rows"]
    if {row["profile_id"] for row in rows} != required_ids | optional_ids:
        raise ValueError("Release scope does not match P0 profile inventory")
    return all(
        row["status"] == "success" for row in rows if row["profile_id"] in required_ids
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--build-manifest", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--ida-executable", type=Path, required=True)
    parser.add_argument(
        "--profile",
        action="append",
        default=[],
        help="Run only this profile_id; may be specified more than once",
    )
    parser.add_argument(
        "--repeat-final",
        action="store_true",
        help="Run each accepted final request twice and require exact semantics",
    )
    parser.add_argument(
        "--release-scope",
        type=Path,
        help="Keep optional failures in the matrix but exit successfully only if every required profile succeeds",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.release_scope is not None and args.profile:
        raise ValueError("Release scope cannot be combined with a profile filter")
    result = run_matrix(
        root=args.root,
        build_manifest=args.build_manifest,
        output_dir=args.output_dir,
        ida_executable=args.ida_executable,
        profile_filter=set(args.profile) or None,
        repeat_final=args.repeat_final,
    )
    print(json.dumps(result, sort_keys=True))
    if args.release_scope is not None:
        return int(not release_scope_accepted(result, read_json(args.release_scope)))
    return 0 if result["status"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
