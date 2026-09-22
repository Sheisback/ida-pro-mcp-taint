#!/usr/bin/env python3
"""Acquire the pinned BinCAT Windows x64 corpus without executing it."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import tempfile
import urllib.request
import uuid
from pathlib import Path
from typing import Any


PINNED_REPOSITORY = "https://github.com/airbus-seclab/bincat"
PINNED_COMMIT = "5d0ee3b56867059427eb0f4123c4d9de0b8059dd"
RAW_PREFIX = f"https://raw.githubusercontent.com/airbus-seclab/bincat/{PINNED_COMMIT}/"
PINNED_FILES = {
    "README.md": (
        4829,
        "e8391e9e5b2f910a3c9de49456fde146ca5aae5cae311fd076247343135d7c5b",
    ),
    "doc/Apache-license-2.0": (
        11358,
        "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30",
    ),
    "doc/COPYING": (
        34520,
        "57c8ff33c9c0cfc3ef00e650a1cc910d7ee479a8bc509f6c9209a7c2a11399d6",
    ),
    "doc/get_key/Makefile": (
        820,
        "8cf3ffc8203ab3da830e6466f70778d57f22cc5953eb757881875f5246b54db5",
    ),
    "doc/get_key/get_key.c": (
        2701,
        "5419d21aa987bb32ebbedf96f0eb6d96296ea9964c75bf984dd4d4a359388122",
    ),
    "doc/get_key/get_key_x64_win.exe": (
        17408,
        "687a36f98a8b62fc0411e0e9e8d09c42608f201a7fe68d2e3ea4272b98fe0a70",
    ),
    "doc/get_key/get_key_x64_win.pdb": (
        397312,
        "dde5e815e9c7c25f7b73319b9a491aa9ac2c860317164fbe067353993ab0563d",
    ),
    "doc/get_key/sha1.c": (
        11654,
        "332577f44b1d1045f4e131f8eba5f1a86067c5874d0f8fd2cf045066b189711d",
    ),
    "doc/get_key/sha1.h": (
        3330,
        "031bc4dfb72788d01fb9c74e69c9216c7b656a0e913787ba7ad04b901a003118",
    ),
}
MSF7_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"


class CorpusError(ValueError):
    """The pinned corpus contract was not satisfied."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if type(value) is not dict:
        raise CorpusError("BinCAT manifest must be an object")
    return value


def validate_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("schema_version") != "bincat-x64-provenance/1":
        raise CorpusError("Unexpected BinCAT manifest schema")
    upstream = manifest.get("upstream")
    if type(upstream) is not dict:
        raise CorpusError("Missing BinCAT upstream identity")
    if upstream.get("repository") != PINNED_REPOSITORY:
        raise CorpusError("BinCAT repository URL is not allowlisted")
    if upstream.get("commit") != PINNED_COMMIT:
        raise CorpusError("BinCAT commit does not match the compiled pin")

    files = manifest.get("files")
    if type(files) is not list or len(files) != len(PINNED_FILES):
        raise CorpusError("BinCAT selected-file inventory mismatch")
    observed: dict[str, tuple[int, str]] = {}
    for row in files:
        if type(row) is not dict:
            raise CorpusError("BinCAT file row must be an object")
        relative = row.get("path")
        if type(relative) is not str or relative not in PINNED_FILES:
            raise CorpusError("BinCAT file path is not allowlisted")
        if row.get("url") != RAW_PREFIX + relative:
            raise CorpusError(f"BinCAT URL mismatch for {relative}")
        size = row.get("size")
        digest = row.get("sha256")
        if (
            type(size) is not int
            or type(digest) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise CorpusError(f"Invalid BinCAT size/hash for {relative}")
        observed[relative] = (size, digest)
    if observed != PINNED_FILES:
        raise CorpusError("BinCAT size/hash allowlist mismatch")

    evidence = manifest.get("license_evidence")
    if type(evidence) is not list or not evidence:
        raise CorpusError("BinCAT license evidence is missing")
    evidence_paths = {row.get("path") for row in evidence if type(row) is dict}
    if evidence_paths != {
        "README.md",
        "doc/COPYING",
        "doc/Apache-license-2.0",
        "doc/get_key/sha1.c",
        "doc/get_key/sha1.h",
    }:
        raise CorpusError("BinCAT license evidence inventory mismatch")


def verify_file(path: Path, expected_size: int, expected_sha256: str) -> None:
    if not path.is_file():
        raise CorpusError(f"Missing pinned file: {path}")
    if path.stat().st_size != expected_size:
        raise CorpusError(f"Size mismatch for {path}")
    if sha256_file(path) != expected_sha256:
        raise CorpusError(f"SHA-256 mismatch for {path}")


def verify_cache(manifest: dict[str, Any], cache_root: Path) -> None:
    validate_manifest(manifest)
    for row in manifest["files"]:
        verify_file(cache_root / row["path"], row["size"], row["sha256"])


def _u16(data: bytes, offset: int) -> int:
    try:
        return struct.unpack_from("<H", data, offset)[0]
    except struct.error as exc:
        raise CorpusError("Truncated PE/PDB structure") from exc


def _u32(data: bytes, offset: int) -> int:
    try:
        return struct.unpack_from("<I", data, offset)[0]
    except struct.error as exc:
        raise CorpusError("Truncated PE/PDB structure") from exc


def _rva_to_offset(rva: int, sections: list[tuple[int, int, int, int]]) -> int:
    for virtual_address, virtual_size, raw_offset, raw_size in sections:
        if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
            return raw_offset + rva - virtual_address
    raise CorpusError(f"PE RVA 0x{rva:x} is not file-backed")


def parse_pe_identity(data: bytes) -> dict[str, Any]:
    if data[:2] != b"MZ":
        raise CorpusError("BinCAT binary is not an MZ image")
    pe_offset = _u32(data, 0x3C)
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise CorpusError("BinCAT binary has no PE signature")
    coff = pe_offset + 4
    machine = _u16(data, coff)
    section_count = _u16(data, coff + 2)
    timestamp = _u32(data, coff + 4)
    optional_size = _u16(data, coff + 16)
    optional = coff + 20
    if machine != 0x8664 or _u16(data, optional) != 0x20B:
        raise CorpusError("BinCAT binary is not PE32+ x86-64")
    entry_rva = _u32(data, optional + 16)
    image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    image_size = _u32(data, optional + 56)
    directory_count = _u32(data, optional + 108)
    if directory_count <= 6:
        raise CorpusError("BinCAT PE has no debug directory slot")
    debug_rva = _u32(data, optional + 112 + 6 * 8)
    debug_size = _u32(data, optional + 112 + 6 * 8 + 4)

    sections = []
    section_table = optional + optional_size
    for index in range(section_count):
        row = section_table + 40 * index
        virtual_size = _u32(data, row + 8)
        virtual_address = _u32(data, row + 12)
        raw_size = _u32(data, row + 16)
        raw_offset = _u32(data, row + 20)
        sections.append((virtual_address, virtual_size, raw_offset, raw_size))
    debug_offset = _rva_to_offset(debug_rva, sections)

    records = []
    for offset in range(debug_offset, debug_offset + debug_size, 28):
        if offset + 28 > len(data):
            raise CorpusError("Truncated PE debug directory")
        debug_type = _u32(data, offset + 12)
        size = _u32(data, offset + 16)
        raw_offset = _u32(data, offset + 24)
        if debug_type != 2:
            continue
        codeview = data[raw_offset : raw_offset + size]
        if not codeview.startswith(b"RSDS") or len(codeview) < 25:
            continue
        terminator = codeview.find(b"\x00", 24)
        if terminator < 0:
            raise CorpusError("Unterminated PE CodeView path")
        records.append(
            {
                "guid": str(uuid.UUID(bytes_le=codeview[4:20])),
                "age": _u32(codeview, 20),
                "pdb_path": codeview[24:terminator].decode("utf-8", "strict"),
                "record_file_offset": raw_offset,
            }
        )
    if len(records) != 1:
        raise CorpusError("Expected exactly one PE RSDS CodeView record")
    return {
        "format": "PE32+",
        "machine": "x86_64",
        "coff_timestamp": timestamp,
        "image_base": image_base,
        "image_size": image_size,
        "entry_rva": entry_rva,
        "codeview": records[0],
    }


def _slice_block(data: bytes, block_size: int, block: int) -> bytes:
    start = block_size * block
    end = start + block_size
    if start < 0 or end > len(data):
        raise CorpusError("PDB block points outside the file")
    return data[start:end]


def parse_pdb_identity(data: bytes) -> dict[str, Any]:
    if not data.startswith(MSF7_MAGIC):
        raise CorpusError("BinCAT PDB is not an MSF 7.00 database")
    try:
        block_size, _free_map, block_count, directory_size, _unknown, block_map = (
            struct.unpack_from("<6I", data, 32)
        )
    except struct.error as exc:
        raise CorpusError("Truncated PDB superblock") from exc
    if block_size < 512 or block_size & (block_size - 1):
        raise CorpusError("Invalid PDB block size")
    if block_count * block_size > len(data):
        raise CorpusError("PDB block count exceeds file size")
    directory_block_count = (directory_size + block_size - 1) // block_size
    block_map_data = _slice_block(data, block_size, block_map)
    try:
        directory_blocks = struct.unpack_from(
            f"<{directory_block_count}I", block_map_data
        )
    except struct.error as exc:
        raise CorpusError("Truncated PDB directory block map") from exc
    directory = b"".join(
        _slice_block(data, block_size, block) for block in directory_blocks
    )[:directory_size]
    stream_count = _u32(directory, 0)
    try:
        stream_sizes = struct.unpack_from(f"<{stream_count}I", directory, 4)
    except struct.error as exc:
        raise CorpusError("Truncated PDB stream inventory") from exc
    offset = 4 + 4 * stream_count
    streams: list[bytes | None] = []
    for size in stream_sizes:
        if size == 0xFFFFFFFF:
            streams.append(None)
            continue
        count = (size + block_size - 1) // block_size
        try:
            blocks = struct.unpack_from(f"<{count}I", directory, offset)
        except struct.error as exc:
            raise CorpusError("Truncated PDB stream block inventory") from exc
        offset += 4 * count
        streams.append(
            b"".join(_slice_block(data, block_size, block) for block in blocks)[:size]
        )
    if len(streams) < 2 or streams[1] is None or len(streams[1]) < 28:
        raise CorpusError("PDB info stream is missing")
    info = streams[1]
    version, signature, age = struct.unpack_from("<III", info, 0)
    return {
        "format": "MSF 7.00",
        "version": version,
        "signature": signature,
        "age": age,
        "guid": str(uuid.UUID(bytes_le=info[12:28])),
        "block_size": block_size,
        "stream_count": stream_count,
    }


def compare_identities(pe: dict[str, Any], pdb: dict[str, Any]) -> dict[str, Any]:
    codeview = pe.get("codeview")
    if type(codeview) is not dict:
        return {
            "status": "unproven",
            "reason": "PE CodeView identity is unavailable",
            "pdb_authority": "reference_only",
        }
    if codeview.get("guid") != pdb.get("guid") or codeview.get("age") != pdb.get("age"):
        return {
            "status": "mismatched",
            "reason": "PE CodeView GUID-age does not match PDB info-stream GUID-age",
            "pdb_authority": "reference_only",
        }
    return {
        "status": "proven",
        "reason": "PE CodeView and PDB info stream have identical GUID-age",
        "pdb_authority": "symbol_identity_for_this_binary",
    }


def identity_report(cache_root: Path) -> dict[str, Any]:
    binary = cache_root / "doc/get_key/get_key_x64_win.exe"
    pdb = cache_root / "doc/get_key/get_key_x64_win.pdb"
    pe_identity = parse_pe_identity(binary.read_bytes())
    pdb_identity = parse_pdb_identity(pdb.read_bytes())
    return {
        "schema_version": "bincat-x64-identity/1",
        "binary": {
            "path": "doc/get_key/get_key_x64_win.exe",
            "size": binary.stat().st_size,
            "sha256": sha256_file(binary),
            **pe_identity,
        },
        "pdb": {
            "path": "doc/get_key/get_key_x64_win.pdb",
            "size": pdb.stat().st_size,
            "sha256": sha256_file(pdb),
            **pdb_identity,
        },
        "binary_pdb_correspondence": compare_identities(pe_identity, pdb_identity),
        "source_correspondence": {
            "status": "unproven",
            "reason": (
                "upstream supplies no Windows build command, compiler manifest, "
                "or source digest embedded in the PE/PDB"
            ),
            "source_authority": "reference_only",
            "binary_observations": "authoritative",
        },
    }


def _download(url: str) -> bytes:
    request = urllib.request.Request(
        url, headers={"User-Agent": "ida-pro-mcp-corpus/1"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def acquire(manifest_path: Path, output_root: Path) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    validate_manifest(manifest)
    if output_root.is_symlink():
        raise CorpusError("Acquisition output root must not be a symlink")
    if output_root.exists() and any(output_root.iterdir()):
        raise CorpusError("Acquisition output root must be empty")
    output_root.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(
        tempfile.mkdtemp(prefix=output_root.name + ".tmp-", dir=output_root.parent)
    )
    try:
        for row in manifest["files"]:
            data = _download(row["url"])
            if len(data) != row["size"] or sha256_bytes(data) != row["sha256"]:
                raise CorpusError(f"Downloaded content mismatch for {row['path']}")
            destination = stage / row["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        verify_cache(manifest, stage)
        report = identity_report(stage)
        receipt = {
            "schema_version": "bincat-x64-acquisition-receipt/1",
            "manifest_sha256": sha256_file(manifest_path),
            "repository": PINNED_REPOSITORY,
            "commit": PINNED_COMMIT,
            "verified_files": [
                {
                    "path": row["path"],
                    "size": row["size"],
                    "sha256": row["sha256"],
                }
                for row in manifest["files"]
            ],
            "identity": report,
            "target_executed": False,
        }
        (stage / "acquisition_receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        )
        if output_root.exists():
            output_root.rmdir()
        os.replace(stage, output_root)
        return receipt
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("tests/flow_fixtures/public/bincat_x64/provenance.json"),
    )
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    acquire(arguments.manifest.resolve(), arguments.output.resolve())


if __name__ == "__main__":
    main()
