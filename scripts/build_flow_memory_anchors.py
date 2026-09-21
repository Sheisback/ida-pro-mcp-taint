#!/usr/bin/env python3
"""Build static G007 memory fixtures only; never execute the produced programs.

Apple clang and the macOS SDK are required. Output must be disposable.
"""

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source = Path("tests/flow_fixtures/memory_anchor.c")
    compiler = subprocess.check_output(["clang", "--version"], text=True).strip()
    sdk_version = subprocess.check_output(
        ["xcrun", "--show-sdk-version"], text=True
    ).strip()
    rows = []
    for arch, abi in [
        ("x86_64", "darwin-x86_64-sysv-derived"),
        ("arm64", "darwin-aarch64"),
    ]:
        output = args.output.resolve() / ("memory_" + arch)
        command = [
            "clang",
            "-arch",
            arch,
            "-O0",
            "-g",
            "-fno-stack-protector",
            "-Wl,-no_uuid",
            "-fdebug-compilation-dir=.",
            "-ffile-prefix-map=" + str(ROOT) + "=.",
            str(source),
            "-o",
            str(output),
        ]
        # Stable intermediate path/mtime removes randomized temporary .o paths
        # from Mach-O OSO debug records. Outputs remain static analysis inputs.
        obj = output.with_suffix(".o")
        compile_command = command[: command.index(str(source))] + [
            "-c",
            str(source),
            "-o",
            str(obj),
        ]
        compile_command = [x for x in compile_command if x != "-Wl,-no_uuid"]
        environment = dict(os.environ, SOURCE_DATE_EPOCH="0")
        subprocess.run(compile_command, cwd=ROOT, env=environment, check=True)
        os.utime(obj, (0, 0))
        link_command = [
            "clang",
            "-arch",
            arch,
            "-g",
            "-Wl,-no_uuid",
            "-Wl,-oso_prefix," + str(output.parent) + "/",
            str(obj),
            "-o",
            str(output),
        ]
        subprocess.run(link_command, cwd=ROOT, env=environment, check=True)
        subprocess.run(
            ["dsymutil", "--oso-prepend-path", str(output.parent), str(output)],
            cwd=ROOT,
            env=environment,
            check=True,
        )
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
                "builder_sha256": hashlib.sha256(
                    Path(__file__).read_bytes()
                ).hexdigest(),
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
                "functions": [
                    "memory_before_after",
                    "memory_alias",
                    "memory_global_roundtrip",
                    "memory_stack_roundtrip",
                ],
                "function_selector": {
                    "kind": "ida_name",
                    "value": "memory_before_after",
                    "naming_convention": "DWARF C function name without Mach-O underscore prefix",
                    "requires_companion": True,
                },
                "compiler": compiler,
                "sdk_version": sdk_version,
                "command": [
                    x.replace(str(output.parent), "$OUTPUT") for x in link_command
                ],
                "compile_command": [
                    x.replace(str(output.parent), "$OUTPUT") for x in compile_command
                ],
                "link_command": [
                    x.replace(str(output.parent), "$OUTPUT") for x in link_command
                ],
                "dsym_command": [
                    "dsymutil",
                    "--oso-prepend-path",
                    "$OUTPUT",
                    "$OUTPUT/" + output.name,
                ],
                "environment": {"SOURCE_DATE_EPOCH": "0"},
                "object_mtime": 0,
                "source_types": {"u8": 8, "u32": 32, "pointer": 64},
                "target_executed": False,
            }
        )
    (args.output / "build.json").write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
