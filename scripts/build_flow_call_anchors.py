#!/usr/bin/env python3
"""Build static G011 call/heap fixtures twice; never execute the targets.

Apple clang, the macOS SDK and dsymutil are required. Output is disposable and
contains build artifacts plus a build-only manifest; it contains no IDA receipt.
"""

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path("tests/flow_fixtures/call_heap_anchor.c")
ARCHITECTURES = (
    ("x86_64", "darwin-x86_64-sysv-derived"),
    ("arm64", "darwin-aarch64"),
)
FUNCTIONS = (
    "call_identity",
    "call_copy",
    "call_fill",
    "call_output",
    "call_global",
    "call_alloc",
    "call_free",
    "call_context_left",
    "call_context_right",
    "call_recursive",
    "call_candidate_increment",
    "call_indirect",
    "call_heap_h01",
    "call_heap_h02",
    "call_heap_h03",
    "call_heap_h04",
)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalized(command, output):
    return [part.replace(str(output), "$OUTPUT") for part in command]


def build_once(arch, output, environment):
    output.mkdir(parents=True)
    binary = output / ("call_heap_" + arch)
    obj = binary.with_suffix(".o")
    compile_command = [
        "clang",
        "-arch",
        arch,
        "-O0",
        "-g",
        "-fno-stack-protector",
        "-fno-omit-frame-pointer",
        "-fno-optimize-sibling-calls",
        "-fno-builtin",
        "-fdebug-compilation-dir=.",
        "-ffile-prefix-map=" + str(ROOT) + "=.",
        "-c",
        str(SOURCE),
        "-o",
        str(obj),
    ]
    subprocess.run(compile_command, cwd=ROOT, env=environment, check=True)
    os.utime(obj, (0, 0))
    link_command = [
        "clang",
        "-arch",
        arch,
        "-g",
        "-Wl,-no_uuid",
        "-Wl,-oso_prefix," + str(output) + "/",
        str(obj),
        "-o",
        str(binary),
    ]
    subprocess.run(link_command, cwd=ROOT, env=environment, check=True)
    dsym_command = [
        "dsymutil",
        "--oso-prepend-path",
        str(output),
        str(binary),
    ]
    subprocess.run(dsym_command, cwd=ROOT, env=environment, check=True)
    dwarf = output / (binary.name + ".dSYM") / "Contents/Resources/DWARF" / binary.name
    if not dwarf.is_file():
        raise RuntimeError(f"Required debug companion missing: {dwarf}")
    return {
        "binary": binary,
        "dwarf": dwarf,
        "compile_command": compile_command,
        "link_command": link_command,
        "dsym_command": dsym_command,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    compiler = subprocess.check_output(["clang", "--version"], text=True).strip()
    sdk_version = subprocess.check_output(
        ["xcrun", "--show-sdk-version"], text=True
    ).strip()
    environment = dict(os.environ, SOURCE_DATE_EPOCH="0")
    rows = []
    for arch, abi in ARCHITECTURES:
        builds = [
            build_once(
                arch, args.output.resolve() / f"fresh-{index}" / arch, environment
            )
            for index in (1, 2)
        ]
        binary_hashes = [sha256(build["binary"]) for build in builds]
        dwarf_hashes = [sha256(build["dwarf"]) for build in builds]
        if len(set(binary_hashes)) != 1 or len(set(dwarf_hashes)) != 1:
            raise RuntimeError(f"Non-reproducible {arch} call/heap fixture build")
        primary = builds[0]
        rows.append(
            {
                "arch": arch,
                "abi_id": abi,
                "format": "FMT-MACHO",
                "manifest_kind": "build_only",
                "source": str(SOURCE),
                "source_sha256": sha256(ROOT / SOURCE),
                "builder_sha256": sha256(Path(__file__)),
                "binary": primary["binary"].name,
                "binary_sha256": binary_hashes[0],
                "companion_artifacts": [
                    {
                        "path": (
                            primary["binary"].name
                            + ".dSYM/Contents/Resources/DWARF/"
                            + primary["binary"].name
                        ),
                        "bundle": primary["binary"].name + ".dSYM",
                        "placement": "sibling_of_binary",
                        "sha256": dwarf_hashes[0],
                        "required": True,
                        "purpose": "function/source mapping",
                    }
                ],
                "functions": list(FUNCTIONS),
                "compiler": compiler,
                "sdk_version": sdk_version,
                "compile_command": normalized(
                    primary["compile_command"], primary["binary"].parent
                ),
                "link_command": normalized(
                    primary["link_command"], primary["binary"].parent
                ),
                "dsym_command": normalized(
                    primary["dsym_command"], primary["binary"].parent
                ),
                "environment": {"SOURCE_DATE_EPOCH": "0"},
                "object_mtime": 0,
                "source_types": {
                    "u8": 8,
                    "u32": 32,
                    "usize": 64,
                    "pointer": 64,
                },
                "reproducibility": {
                    "fresh_builds": 2,
                    "binary_sha256_equal": True,
                    "dwarf_sha256_equal": True,
                },
                "target_executed": False,
                "ida_receipt_recorded": False,
            }
        )
    (args.output / "build.json").write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
