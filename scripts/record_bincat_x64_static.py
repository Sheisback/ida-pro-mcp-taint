#!/usr/bin/env python3
"""Run an allowlisted static IDA command for the pinned BinCAT x64 PE."""

from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ACQUIRE_SCRIPT = ROOT / "scripts/acquire_bincat_x64.py"
IDA_SCRIPT = ROOT / "scripts/ida_bincat_x64_snapshot.py"
DEFAULT_MANIFEST = ROOT / "tests/flow_fixtures/public/bincat_x64/provenance.json"
LEGACY_X86_TUTORIAL_ANALYSIS_EP = 0x93B
EXPECTED_SELECTORS = {
    "custom_crc32": (
        0x10EC,
        "472993ced058d918374b769e90107b5bd4a311a514dd8118231551916fafb33a",
    ),
    "compute_hash": (
        0x1134,
        "7ce5d96c4a91a9c05dbb29df928263502bb68f1ceca22951373ce2e42188fae2",
    ),
    "main": (
        0x1258,
        "e08a3a0888347c90d8a6950513ce5c26ce12b4e3e8d60ff3870ecbd20a846530",
    ),
}


def _load_acquisition_module():
    spec = importlib.util.spec_from_file_location(
        "bincat_x64_acquisition", ACQUIRE_SCRIPT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load the BinCAT acquisition module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_snapshot_receipt(receipt: dict) -> None:
    if receipt.get("schema_version") != "bincat-x64-ida-static/1":
        raise ValueError("Unexpected BinCAT IDA receipt schema")
    if receipt.get("target_executed") is not False:
        raise ValueError("BinCAT target execution is forbidden")
    if receipt.get("debugger_attached") is not False:
        raise ValueError("BinCAT debugger attachment is forbidden")
    if receipt.get("bitness") != 64 or receipt.get("processor") != "metapc":
        raise ValueError("BinCAT receipt is not the x64 snapshot")
    functions = receipt.get("functions")
    if type(functions) is not list:
        raise ValueError("Missing BinCAT function selectors")
    observed = {
        row.get("name"): (row.get("rva"), row.get("bytes_sha256"))
        for row in functions
        if type(row) is dict
    }
    if any(
        rva == LEGACY_X86_TUTORIAL_ANALYSIS_EP for rva, _digest in observed.values()
    ):
        raise ValueError("Rejected BinCAT x86 tutorial address for the x64 PE")
    if observed != EXPECTED_SELECTORS:
        raise ValueError("BinCAT snapshot-local selector inventory mismatch")


def record(*, cache_root: Path, output: Path, ida: Path, manifest_path: Path) -> dict:
    acquisition = _load_acquisition_module()
    manifest = acquisition.load_manifest(manifest_path)
    acquisition.verify_cache(manifest, cache_root)
    identity = acquisition.identity_report(cache_root)
    if identity["binary_pdb_correspondence"]["status"] != "proven":
        raise RuntimeError("Refusing PDB selectors without proven PE/PDB identity")

    binary = cache_root / "doc/get_key/get_key_x64_win.exe"
    pdb = cache_root / "doc/get_key/get_key_x64_win.pdb"
    if not ida.is_file() or ida.name != "idat":
        raise RuntimeError(
            "The static recorder requires the IDA text executable 'idat'"
        )
    before = acquisition.sha256_file(binary)
    with tempfile.TemporaryDirectory(prefix="bincat-x64-static-") as temporary:
        isolated = Path(temporary)
        isolated_binary = isolated / binary.name
        isolated_pdb = isolated / pdb.name
        pdb_alias = isolated / "Bincat_get_key.pdb"
        raw_receipt = isolated / "receipt.json"
        database = isolated / "bincat.i64"
        shutil.copy2(binary, isolated_binary)
        shutil.copy2(pdb, isolated_pdb)
        shutil.copy2(pdb, pdb_alias)
        command = [
            str(ida),
            "-A",
            f"-S{IDA_SCRIPT} {raw_receipt}",
            f"-o{database}",
            str(isolated_binary),
        ]
        process = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )
        receipt = json.loads(raw_receipt.read_text())
        validate_snapshot_receipt(receipt)
        isolated_after = acquisition.sha256_file(isolated_binary)
        if isolated_after != before:
            raise RuntimeError("IDA modified the isolated PE input")
        receipt.update(
            {
                "command": [
                    "idat",
                    "-A",
                    "-Sscripts/ida_bincat_x64_snapshot.py <receipt>",
                    "-o<isolated>/bincat.i64",
                    "<isolated>/get_key_x64_win.exe",
                ],
                "command_kind": "static_ida_load_and_snapshot",
                "ida_exit_code": process.returncode,
                "input_preserved": True,
                "pdb_alias_sha256": acquisition.sha256_file(pdb_alias),
                "identity": identity,
            }
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--ida", type=Path, required=True)
    arguments = parser.parse_args()
    record(
        cache_root=arguments.cache_root.resolve(),
        output=arguments.output.resolve(),
        ida=arguments.ida.resolve(),
        manifest_path=arguments.manifest.resolve(),
    )


if __name__ == "__main__":
    main()
