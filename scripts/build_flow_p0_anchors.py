#!/usr/bin/env python3
"""Build static P0 fixtures only; never execute the produced programs.

Apple clang and the macOS SDK are required. Output must be disposable.
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source = Path("tests/flow_fixtures/p0_anchor.c")
    compiler = subprocess.check_output(["clang", "--version"], text=True).strip()
    sdk_version = subprocess.check_output(
        ["xcrun", "--show-sdk-version"], text=True
    ).strip()
    rows = []
    for arch, abi in [
        ("x86_64", "darwin-x86_64-sysv-derived"),
        ("arm64", "darwin-aarch64"),
    ]:
        output = args.output.resolve() / ("p0_" + arch)
        command = [
            "clang",
            "-arch",
            arch,
            "-O0",
            "-g",
            "-fno-stack-protector",
            str(source),
            "-o",
            str(output),
        ]
        subprocess.run(command, cwd=ROOT, check=True)
        dwarf = (
            output.parent
            / (output.name + ".dSYM")
            / "Contents/Resources/DWARF"
            / output.name
        )
        if not dwarf.is_file():
            raise RuntimeError(f"Required debug companion missing: {dwarf}")
        rows.append(
            {
                "arch": arch,
                "abi_id": abi,
                "format": "FMT-MACHO",
                "source": str(source),
                "source_sha256": hashlib.sha256(
                    (ROOT / source).read_bytes()
                ).hexdigest(),
                "binary": output.name,
                "binary_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                "companion_artifacts": [
                    {
                        "path": dwarf.relative_to(output.parent).as_posix(),
                        "bundle": output.name + ".dSYM",
                        "placement": "sibling_of_binary",
                        "sha256": hashlib.sha256(dwarf.read_bytes()).hexdigest(),
                        "required": True,
                        "purpose": "function/source mapping",
                    }
                ],
                "function_selector": {
                    "kind": "ida_name",
                    "value": "p0_anchor",
                    "naming_convention": "DWARF C function name without Mach-O underscore prefix",
                    "requires_companion": True,
                },
                "compiler": compiler,
                "sdk_version": sdk_version,
                "command": command[:-1] + ["$OUTPUT/" + output.name],
                "source_types": {"u32": 32, "unsigned_long_long": 64, "pointer": 64},
                "target_executed": False,
            }
        )
    (args.output / "build.json").write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
