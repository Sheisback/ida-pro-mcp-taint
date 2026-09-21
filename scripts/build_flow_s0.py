#!/usr/bin/env python3
"""Build static-only MinGW PE fixtures; never run the target executable."""

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPILER = "x86_64-w64-mingw32-gcc"
SOURCES = ("tests/typed_fixture.c", "tests/flow_fixtures/s0.c")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    version = subprocess.check_output([COMPILER, "--version"], text=True).strip()
    compiler_path = subprocess.check_output(
        ["/usr/bin/which", COMPILER], text=True
    ).strip()
    layout_source = "tests/flow_fixtures/typed_layout_check.c"
    layout_command = [COMPILER, "-fsyntax-only", layout_source]
    subprocess.run(layout_command, cwd=ROOT, check=True)
    rows = []
    for source in SOURCES:
        name = Path(source).stem + "_x64.exe"
        flags = [
            "-O0",
            "-g",
            "-fno-ident",
            "-frandom-seed=flow-s0",
            f"-ffile-prefix-map={ROOT}=.",
            f"-fdebug-prefix-map={ROOT}=.",
            "-Wl,--no-insert-timestamp",
        ]
        command = [COMPILER, *flags, source, "-o", str(output / name)]
        env = dict(os.environ, SOURCE_DATE_EPOCH="0")
        subprocess.run(command, cwd=ROOT, env=env, check=True)
        rows.append(
            {
                "source": source,
                "source_sha256": sha(ROOT / source),
                "binary": name,
                "binary_sha256": sha(output / name),
                "format": "PE32+",
                "isa": "x86_64",
                "abi": "windows-x64",
                "compiler": version,
                "compiler_sha256": sha(Path(compiler_path)),
                "command": [
                    part.replace(str(ROOT), "$ROOT").replace(str(output), "$OUTPUT")
                    for part in command
                ],
                "environment": {"SOURCE_DATE_EPOCH": "0"},
                "debug_info": "embedded DWARF; no PDB",
                "companion_artifacts": [],
                "layout_check": {
                    "command": layout_command,
                    "source_sha256": sha(ROOT / layout_source),
                    "status": "passed",
                }
                if source == "tests/typed_fixture.c"
                else None,
                "target_executed": False,
            }
        )
    (output / "build.json").write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
