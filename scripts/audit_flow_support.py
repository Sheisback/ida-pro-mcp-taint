"""Audit committed flow support receipts without loading IDA or a target."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

from ida_pro_mcp.flow_core.serialization import canonical_json
from ida_pro_mcp.flow_core.support_receipts import (
    build_support_receipt_manifest,
    validate_support_receipt_manifest,
)

INVENTORY = Path("tests/flow_fixtures/manifests/p0_inventory.json")
P0_ROOT = Path("tests/flow_fixtures/manifests/profiles/actual-p0")
SEMANTIC_MATRIX = Path("tests/flow_fixtures/manifests/profile_semantics/matrix.json")


def _load_validator_script(name: str) -> ModuleType:
    path = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location("flow_support_" + name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load receipt validator: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROFILE_RECEIPTS = _load_validator_script("record_flow_profile_receipts")
SEMANTIC_RECEIPTS = _load_validator_script("evaluate_flow_profile_semantics")


def _reject_constant(value: str) -> None:
    raise ValueError(f"Non-finite JSON constant: {value}")


def _object_pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(
        path.read_text(),
        object_pairs_hook=_object_pairs,
        parse_constant=_reject_constant,
    )
    if type(value) is not dict:
        raise ValueError(f"Expected object in {path}")
    return value


def _under(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError("Receipt path escapes repository root") from exc
    if not candidate.is_file():
        raise ValueError(f"Missing receipt: {candidate}")
    return candidate


def validate_referenced_receipts(
    root: Path, p0_matrix: dict[str, Any], semantic_matrix: dict[str, Any]
) -> None:
    PROFILE_RECEIPTS.validate_matrix_result(p0_matrix)
    p0_root = (root / P0_ROOT).resolve()
    for row in p0_matrix["rows"]:
        result = read_json(_under(p0_root, row["result_file"]))
        PROFILE_RECEIPTS.validate_row_result(result)
        if result.get("receipt_digest") != row["receipt_digest"]:
            raise ValueError("P0 result digest mismatch")
        if result.get("profile_id") != row["profile_id"]:
            raise ValueError("P0 result profile mismatch")
        if result.get("format") != row["format"]:
            raise ValueError("P0 result format mismatch")
        if result.get("status") != row["status"]:
            raise ValueError("P0 result status mismatch")
        if result.get("target_executed") is not False:
            raise ValueError("P0 result executed target")
        if result.get("support_status") != "unverified":
            raise ValueError("P0 result promoted support")

    # Rebuild the complete semantic matrix from every referenced normal,
    # format, and RV32 fallback body.  This invokes the same receipt-specific
    # validators used when the evidence was recorded, rather than trusting a
    # copied digest label in the summary matrix.
    SEMANTIC_RECEIPTS.validate_complete_matrix_artifacts(root, semantic_matrix)


def build(root: Path) -> dict[str, Any]:
    root = root.resolve()
    inventory = read_json(root / INVENTORY)
    p0_matrix = read_json(root / P0_ROOT / "matrix.json")
    semantic_matrix = read_json(root / SEMANTIC_MATRIX)
    validate_referenced_receipts(root, p0_matrix, semantic_matrix)
    return build_support_receipt_manifest(inventory, p0_matrix, semantic_matrix)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--check", type=Path)
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(argv)
    result = build(arguments.root)
    if arguments.check is not None:
        committed = read_json(arguments.check)
        validate_support_receipt_manifest(committed)
        if committed != result:
            raise ValueError("Committed support receipt manifest is stale")
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    elif arguments.check is None:
        print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
