#!/usr/bin/env python3
"""Acquire and build the pinned G015 SVF/Juliet corpus without running targets.

Acquisition is optional and networked. Building consumes already-acquired,
exactly pinned inputs and only invokes the compiler/linker. Upstream sources
and native binaries remain in the caller-provided isolated output directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROVENANCE = ROOT / "tests/flow_fixtures/public_samples/provenance.json"
SVF_URL = "https://github.com/SVF-tools/Test-Suite.git"
SVF_COMMIT = "9c6e5d5fb6c783fb66529e189b44bd5b76ee7a59"
JULIET_URL = (
    "https://samate.nist.gov/SARD/downloads/test-suites/"
    "2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"
)
JULIET_SHA256 = "ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb"
JULIET_SIZE = 152_957_342

SVF_FILES = {
    "aliascheck.h": "ea4a480d786efa35f98783547e94c7dbb16032f317d34956573ea38aa3b5a0ab",
    "src/basic_c_tests/global-simple.c": "3fc6be8d0069d23fff7dacd7ed33ab2ead368c39dd657d243aa2f13c743ea11c",
    "src/basic_c_tests/ptr-dereference2.c": "57b58ca0d9ad55f329ec8cb2359bf879fb8533533a6ecbc3ad2968bbf9536e2b",
    "src/fs_tests/struct_1.c": "6fee1a76b3fd3991c6c281356521fd429b2f4e2bda8bcba796f4b217fc32e3be",
    "src/cs_tests/cs0.c": "ace7937bcfdae75206409030dccdb7e55f7a17b853082803cccf692cf4a82dc8",
}
SVF_CASES = {
    "svf-pointer-copy": "src/basic_c_tests/global-simple.c",
    "svf-pointer-store-load": "src/basic_c_tests/ptr-dereference2.c",
    "svf-field-sensitivity": "src/fs_tests/struct_1.c",
    "svf-context-call": "src/cs_tests/cs0.c",
}

JULIET_BASE = "C/testcases/CWE789_Uncontrolled_Mem_Alloc/s01"
JULIET_FILES = {
    "C/testcasesupport/std_testcase.h": "a78aaf3a54a6210260ad70123c09c3c283c6edf7808b6244205e00b8f2d9b8d0",
    "C/testcasesupport/std_testcase_io.h": "6459df50d22697bb61619e2effd688ebb98915db25f7eb1bdbb767f888066fb6",
    "C/testcasesupport/io.c": "50ace91d0f9cd9f281d5d8ff3a9ca879ee2779d737030ae84e8e4be3df5b299c",
    f"{JULIET_BASE}/CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_31.c": "c0cbfe0ae9ee7d31fe5b077414abd27b13199931d746e06cb8028017ce88ca01",
    f"{JULIET_BASE}/CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_32.c": "918d535668f53d7bdc3d74d14bb277d1eeb60f639b4a12a7ff0fc3b387b9d4bb",
    f"{JULIET_BASE}/CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_33.cpp": "39093a83b06551b449dcbadb1e7929f688b19c34c7ccd4bc7aaf1687e398c52f",
    f"{JULIET_BASE}/CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_34.c": "038cdc37b8bb21fd9df1dcacbf2c7f748d32111651f5603140b50635eaa5ad1b",
    f"{JULIET_BASE}/CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_41.c": "5fa56d120b566c5d6aa3779ee01085be4ed64b3ecef6b54961abadc14cf50508",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def require_equal(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        raise ValueError(f"{label} mismatch: expected {expected!r}, got {actual!r}")


def load_and_validate_provenance(path: Path = PROVENANCE) -> dict:
    value = json.loads(path.read_text())
    require_equal(value.get("schema_version"), "public-sample-provenance/1", "schema")
    svf = value.get("svf", {})
    require_equal(svf.get("upstream_url"), SVF_URL, "SVF URL")
    require_equal(svf.get("commit"), SVF_COMMIT, "SVF commit")
    require_equal(svf.get("selected_files"), SVF_FILES, "SVF selected hashes")
    license_data = svf.get("license", {})
    require_equal(license_data.get("status"), "unproven", "SVF license status")
    require_equal(license_data.get("redistribution"), False, "SVF redistribution")
    juliet = value.get("juliet", {})
    require_equal(juliet.get("archive_url"), JULIET_URL, "Juliet URL")
    require_equal(juliet.get("archive_sha256"), JULIET_SHA256, "Juliet hash")
    require_equal(juliet.get("archive_size"), JULIET_SIZE, "Juliet size")
    require_equal(juliet.get("selected_files"), JULIET_FILES, "Juliet selected hashes")
    require_equal(juliet.get("license", {}).get("spdx"), "CC0-1.0", "Juliet license")
    return value


def git_output(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def verify_svf(repo: Path) -> dict[str, bytes]:
    require_equal(
        git_output(repo, "remote", "get-url", "origin"), SVF_URL, "SVF remote"
    )
    require_equal(git_output(repo, "rev-parse", "HEAD"), SVF_COMMIT, "SVF HEAD")
    selected = {}
    for name, expected in SVF_FILES.items():
        data = subprocess.check_output(
            ["git", "-C", str(repo), "show", f"{SVF_COMMIT}:{name}"]
        )
        require_equal(sha256_bytes(data), expected, f"SVF {name} hash")
        selected[name] = data
    return selected


def verify_juliet(archive: Path) -> dict[str, bytes]:
    require_equal(archive.stat().st_size, JULIET_SIZE, "Juliet archive size")
    require_equal(sha256_path(archive), JULIET_SHA256, "Juliet archive hash")
    selected = {}
    with zipfile.ZipFile(archive) as handle:
        names = handle.namelist()
        for name, expected in JULIET_FILES.items():
            require_equal(names.count(name), 1, f"Juliet {name} multiplicity")
            data = handle.read(name)
            require_equal(sha256_bytes(data), expected, f"Juliet {name} hash")
            selected[name] = data
    return selected


def fetch_inputs(output: Path) -> None:
    load_and_validate_provenance()
    output.mkdir(parents=True, exist_ok=False)
    repo = output / "svf-test-suite"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "remote", "add", "origin", SVF_URL], check=True
    )
    subprocess.run(
        ["git", "-C", str(repo), "fetch", "-q", "--depth=1", "origin", SVF_COMMIT],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "checkout", "-q", "--detach", "FETCH_HEAD"],
        check=True,
    )
    verify_svf(repo)
    archive = output / "juliet-test-suite-c-cplusplus-1.3.zip"
    with urllib.request.urlopen(JULIET_URL) as response, archive.open("wb") as target:
        shutil.copyfileobj(response, target)
    verify_juliet(archive)
    (output / "acquisition.json").write_text(
        json.dumps(
            {
                "schema_version": "public-sample-acquisition/1",
                "svf_url": SVF_URL,
                "svf_commit": SVF_COMMIT,
                "juliet_url": JULIET_URL,
                "juliet_sha256": JULIET_SHA256,
                "target_executed": False,
            },
            indent=2,
        )
        + "\n"
    )


def write_sources(fresh: Path, svf: dict[str, bytes], juliet: dict[str, bytes]) -> None:
    svf_dir = fresh / "sources/svf"
    juliet_dir = fresh / "sources/juliet"
    svf_dir.mkdir(parents=True)
    juliet_dir.mkdir(parents=True)
    (svf_dir / "aliascheck.h").write_bytes(svf["aliascheck.h"])
    for case_id, upstream in SVF_CASES.items():
        (svf_dir / f"{case_id}.c").write_bytes(svf[upstream])
    for upstream, data in juliet.items():
        (juliet_dir / Path(upstream).name).write_bytes(data)


COMMON_FLAGS = [
    "-arch",
    "x86_64",
    "-O0",
    "-g",
    "-fno-stack-protector",
    "-fno-omit-frame-pointer",
    "-fno-optimize-sibling-calls",
    "-fno-builtin",
    "-fdebug-compilation-dir=.",
]


def run(command: list[str], cwd: Path, environment: dict[str, str]) -> None:
    subprocess.run(command, cwd=cwd, env=environment, check=True)


def normalized(command: list[str], fresh: Path) -> list[str]:
    return [part.replace(str(fresh.resolve()), "$OUTPUT") for part in command]


def build_fresh(
    fresh: Path,
    svf: dict[str, bytes],
    juliet: dict[str, bytes],
    environment: dict[str, str],
) -> list[dict]:
    write_sources(fresh, svf, juliet)
    objects = fresh / "objects"
    binaries = fresh / "binaries"
    objects.mkdir()
    binaries.mkdir()
    rows = []
    prefix = f"-ffile-prefix-map={fresh.resolve()}=."
    for case_id, upstream in SVF_CASES.items():
        source = f"sources/svf/{case_id}.c"
        obj = f"objects/{case_id}.o"
        binary = f"binaries/{case_id}"
        compile_command = [
            "clang",
            *COMMON_FLAGS,
            prefix,
            "-I",
            "sources/svf",
            "-c",
            source,
            "-o",
            obj,
        ]
        link_command = [
            "clang",
            "-arch",
            "x86_64",
            "-Wl,-no_uuid",
            f"-Wl,-oso_prefix,{fresh.resolve()}/",
            obj,
            "-o",
            binary,
        ]
        run(compile_command, fresh, environment)
        os.utime(fresh / obj, (0, 0))
        run(link_command, fresh, environment)
        rows.append(
            {
                "corpus": "svf-test-suite",
                "case_id": case_id,
                "upstream_source": upstream,
                "source_sha256": SVF_FILES[upstream],
                "support_sha256": {"aliascheck.h": SVF_FILES["aliascheck.h"]},
                "binary": case_id,
                "compile_command": normalized(compile_command, fresh),
                "link_command": normalized(link_command, fresh),
            }
        )
    juliet_dir = "sources/juliet"
    io_compile = [
        "clang",
        *COMMON_FLAGS,
        prefix,
        "-I",
        juliet_dir,
        "-c",
        f"{juliet_dir}/io.c",
        "-o",
        "objects/juliet-io.o",
    ]
    run(io_compile, fresh, environment)
    os.utime(fresh / "objects/juliet-io.o", (0, 0))
    for variant in (31, 32, 33, 34, 41):
        extension = "cpp" if variant == 33 else "c"
        case_id = f"juliet-cwe789-{variant}"
        filename = (
            f"CWE789_Uncontrolled_Mem_Alloc__malloc_char_fgets_{variant}.{extension}"
        )
        upstream = f"{JULIET_BASE}/{filename}"
        compiler = "clang++" if extension == "cpp" else "clang"
        source = f"{juliet_dir}/{filename}"
        obj = f"objects/{case_id}.o"
        binary = f"binaries/{case_id}"
        compile_command = [
            compiler,
            *COMMON_FLAGS,
            prefix,
            "-DINCLUDEMAIN",
            "-I",
            juliet_dir,
            "-c",
            source,
            "-o",
            obj,
        ]
        link_command = [
            compiler,
            "-arch",
            "x86_64",
            "-Wl,-no_uuid",
            f"-Wl,-oso_prefix,{fresh.resolve()}/",
            obj,
            "objects/juliet-io.o",
            "-o",
            binary,
        ]
        run(compile_command, fresh, environment)
        os.utime(fresh / obj, (0, 0))
        run(link_command, fresh, environment)
        rows.append(
            {
                "corpus": "nist-juliet-c-cpp-1.3",
                "case_id": case_id,
                "flow_variant": variant,
                "upstream_source": upstream,
                "source_sha256": JULIET_FILES[upstream],
                "support_sha256": {
                    name: JULIET_FILES[f"C/testcasesupport/{name}"]
                    for name in ("std_testcase.h", "std_testcase_io.h", "io.c")
                },
                "binary": case_id,
                "compile_command": normalized(compile_command, fresh),
                "support_compile_command": normalized(io_compile, fresh),
                "link_command": normalized(link_command, fresh),
            }
        )
    return rows


def build_inputs(svf_repo: Path, juliet_archive: Path, output: Path) -> None:
    load_and_validate_provenance()
    svf = verify_svf(svf_repo)
    juliet = verify_juliet(juliet_archive)
    output.mkdir(parents=True, exist_ok=False)
    compiler = subprocess.check_output(["clang", "--version"], text=True).strip()
    sdk_version = subprocess.check_output(
        ["xcrun", "--show-sdk-version"], text=True
    ).strip()
    environment = dict(os.environ, SOURCE_DATE_EPOCH="0")
    builds = [
        build_fresh(output / f"fresh-{index}", svf, juliet, environment)
        for index in (1, 2)
    ]
    rows = []
    for first, second in zip(*builds, strict=True):
        require_equal(first["case_id"], second["case_id"], "build case order")
        hashes = [
            sha256_path(output / f"fresh-{index}/binaries/{first['binary']}")
            for index in (1, 2)
        ]
        require_equal(hashes[0], hashes[1], f"{first['case_id']} reproducibility")
        rows.append(
            {
                **first,
                "schema_version": "public-sample-build/1",
                "format": "FMT-MACHO",
                "architecture": "x86_64",
                "abi_id": "darwin-x86_64-sysv-derived",
                "binary_sha256": hashes[0],
                "builder_sha256": sha256_path(Path(__file__)),
                "compiler": compiler,
                "sdk_version": sdk_version,
                "environment": {"SOURCE_DATE_EPOCH": "0"},
                "object_mtime": 0,
                "reproducibility": {"fresh_builds": 2, "binary_sha256_equal": True},
                "target_executed": False,
                "ida_receipt_recorded": False,
            }
        )
    (output / "build.json").write_text(json.dumps(rows, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    fetch = subparsers.add_parser("fetch")
    fetch.add_argument("output", type=Path)
    build = subparsers.add_parser("build")
    build.add_argument("--svf-repo", type=Path, required=True)
    build.add_argument("--juliet-archive", type=Path, required=True)
    build.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.command == "fetch":
        fetch_inputs(args.output)
    else:
        build_inputs(args.svf_repo, args.juliet_archive, args.output)


if __name__ == "__main__":
    main()
