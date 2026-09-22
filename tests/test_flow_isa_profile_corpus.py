"""Independent checks for the build-only G012 ISA/ABI fixture corpus."""

import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "tests/flow_fixtures"
SOURCE = BASE / "isa_profile_anchor.c"
MACHO_SOURCE = SOURCE
BUILDER = ROOT / "scripts/build_flow_isa_profiles.py"
MANIFEST = BASE / "manifests/profiles/build.json"
ORACLE = BASE / "oracles/isa_profiles.json"

EXPECTED = {
    "X86-LE": ("x86-linux-gnu", "sysv-i386", 32, "LE", "LE", "X86", "metapc"),
    "X64-LE": ("x86_64-linux-gnu", "sysv-amd64", 64, "LE", "LE", "X64", "metapc"),
    "ARM32-LE": ("arm-linux-gnueabi", "aapcs32", 32, "LE", "LE", "ARM32", "ARM"),
    "ARM32-BE": ("armeb-linux-gnueabi", "aapcs32", 32, "BE", "LE", "ARM32", "ARMB"),
    "THUMB-LE": ("thumb-linux-musleabi", "aapcs32", 32, "LE", "LE", "THUMB", "ARM"),
    "THUMB-BE": ("thumbeb-linux-musleabi", "aapcs32", 32, "BE", "LE", "THUMB", "ARMB"),
    "A64-LE": ("aarch64-linux-gnu", "aapcs64", 64, "LE", "LE", "A64", "ARM"),
    "MIPS32-LE": ("mipsel-linux-gnu", "mips-o32", 32, "LE", "LE", "MIPS32", "mipsl"),
    "MIPS32-BE": ("mips-linux-gnu", "mips-o32", 32, "BE", "BE", "MIPS32", "mipsb"),
    "MIPS64-LE": (
        "mips64el-linux-gnuabi64",
        "mips-n64",
        64,
        "LE",
        "LE",
        "MIPS64",
        "mipsl",
    ),
    "MIPS64-BE": (
        "mips64-linux-gnuabi64",
        "mips-n64",
        64,
        "BE",
        "BE",
        "MIPS64",
        "mipsb",
    ),
    "PPC32-LE": ("powerpcle-linux-gnu", "sysv-ppc32", 32, "LE", "LE", "PPC32", "PPCL"),
    "PPC32-BE": ("powerpc-linux-gnu", "sysv-ppc32", 32, "BE", "BE", "PPC32", "PPC"),
    "PPC64-LE": (
        "powerpc64le-linux-gnu",
        "elfv2-ppc64",
        64,
        "LE",
        "LE",
        "PPC64",
        "PPCL",
    ),
    "PPC64-BE": ("powerpc64-linux-gnu", "elfv2-ppc64", 64, "BE", "BE", "PPC64", "PPC"),
    "RV32-LE": ("riscv32-linux-gnu", "riscv-ilp32", 32, "LE", "LE", "RV32", "riscv"),
    "RV64-LE": ("riscv64-linux-gnu", "riscv-lp64", 64, "LE", "LE", "RV64", "riscv"),
}
EXACT_ENDIAN_PROCESSORS = {
    "ARM32-BE": "ARMB",
    "THUMB-BE": "ARMB",
    "MIPS32-LE": "mipsl",
    "MIPS32-BE": "mipsb",
    "MIPS64-LE": "mipsl",
    "MIPS64-BE": "mipsb",
    "PPC32-LE": "PPCL",
    "PPC32-BE": "PPC",
    "PPC64-LE": "PPCL",
    "PPC64-BE": "PPC",
}
FUNCTIONS = {
    "isa_scalar",
    "isa_branch",
    "isa_load",
    "isa_store",
    "isa_call",
    "isa_profile_entry",
}
ORDERED_FUNCTIONS = (
    "isa_scalar",
    "isa_branch",
    "isa_load",
    "isa_store",
    "isa_call",
    "isa_profile_entry",
)
MACHO_SYMBOLS = {f"_{name}" for name in ORDERED_FUNCTIONS}
STABLE_CAPABILITY_SELECTOR = {
    "kind": "debug_or_symbol_name",
    "value": "isa_scalar",
}
SEMANTIC_FUNCTION_SELECTORS = [
    {"kind": "debug_or_symbol_name", "value": name} for name in ORDERED_FUNCTIONS
]
MACHO_EXPECTED = {
    "X64-LE": (
        "x86_64",
        "x86_64-apple-darwin",
        "darwin-x86_64-sysv-derived",
        "X64",
        "metapc",
        0x01000007,
    ),
    "A64-LE": (
        "arm64",
        "arm64-apple-darwin",
        "darwin-aarch64",
        "A64",
        "ARM",
        0x0100000C,
    ),
}
MACHO_ROW_KEYS = {
    "profile_id",
    "profile_version",
    "target_triple",
    "abi_id",
    "bitness",
    "data_endian",
    "instruction_endian",
    "mode",
    "processor",
    "format",
    "platform_tag",
    "source",
    "source_sha256",
    "binary",
    "binary_sha256",
    "binary_size",
    "binary_header",
    "compiler",
    "command",
    "command_sha256",
    "function_selector",
    "function_selectors",
    "companion_artifacts",
    "debug_info",
    "reproducibility",
    "target_executed",
    "ida_receipt_recorded",
    "support_status",
}


def read(path):
    return json.loads(path.read_text())


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_builder():
    spec = importlib.util.spec_from_file_location("isa_profile_builder_test", BUILDER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def fresh_macho_corpus(tmp_path_factory):
    if sys.platform != "darwin":
        pytest.skip("real Apple-clang Mach-O integration requires Darwin")
    builder = load_builder()
    output = tmp_path_factory.mktemp("fresh-macho-corpus")
    clang, version = builder.resolve_apple_clang(None)
    environment = dict(
        os.environ,
        LC_ALL="C",
        SOURCE_DATE_EPOCH="0",
        ZERO_AR_DATE="1",
    )
    rows = {
        profile[0]: builder.build_macho(clang, version, output, profile, environment)
        for profile in builder.MACHO_PROFILES
    }
    return builder, output, rows


def test_source_and_hand_authored_oracle_cover_required_operations():
    defined = set(
        re.findall(r"KEEP\s+(?:void|u32)\s+(isa_[a-z_]+)\(", SOURCE.read_text())
    )
    assert defined == FUNCTIONS
    oracle = read(ORACLE)
    assert oracle["schema_version"] == "flow-isa-profile-oracles/1"
    assert "hand-authored" in oracle["oracle_origin"]
    assert "not_engine_validation" in oracle["status"]
    assert "not_support_advertisement" in oracle["status"]
    cases = oracle["generic_cases"]
    assert {case["operation"] for case in cases} == {
        "scalar",
        "branch",
        "load",
        "store",
        "call",
    }
    assert {case["function"] for case in cases} == FUNCTIONS - {"isa_profile_entry"}
    for case in cases:
        assert case["inputs"]
        assert case["expected_relations"]
        assert case["forbidden_relations"]


def test_oracle_has_independent_expectation_for_every_profile():
    profiles = read(ORACLE)["profiles"]
    assert {row["profile_id"] for row in profiles} == set(EXPECTED)
    assert len(profiles) == 17
    for row in profiles:
        expected = EXPECTED[row["profile_id"]]
        actual = (
            row["abi_id"],
            row["bitness"],
            row["data_endian"],
            row["instruction_endian"],
            row["mode"],
            row["processor"],
        )
        assert actual == expected[1:]
        isa = row["isa_specific_expectations"]
        assert isa["integer_return_register"]
        assert isa["stack_pointer_register"]
        assert isa["call_instruction_family"]
        assert isa["pointer_width_bits"] == row["bitness"]
        assert row["status"] == "hand-authored_expectation_not_engine_validation"


def test_family_and_endian_specific_ida_processor_names_are_exact():
    builder_processors = {row[0]: row[7] for row in load_builder().PROFILES}
    oracle_processors = {
        row["profile_id"]: row["processor"] for row in read(ORACLE)["profiles"]
    }
    manifest_processors = {
        row["profile_id"]: row["processor"] for row in read(MANIFEST)["profiles"]
    }

    for profile_id, processor in EXACT_ENDIAN_PROCESSORS.items():
        assert builder_processors[profile_id] == processor
        assert oracle_processors[profile_id] == processor
        assert manifest_processors[profile_id] == processor


def test_build_manifest_pins_exact_reproducible_17_row_corpus():
    manifest = read(MANIFEST)
    assert manifest["schema_version"] == "flow-isa-profile-builds/1"
    assert manifest["manifest_kind"] == "build_only"
    assert manifest["profile_count"] == 17
    assert manifest["source_sha256"] == sha256(SOURCE)
    assert manifest["builder_sha256"] == sha256(BUILDER)
    assert manifest["compiler"]["version"].startswith("0.16.")
    assert re.fullmatch(r"[0-9a-f]{64}", manifest["compiler"]["sha256"])
    assert manifest["environment"] == {
        "LC_ALL": "C",
        "SOURCE_DATE_EPOCH": "0",
        "ZERO_AR_DATE": "1",
    }
    assert manifest["target_executed"] is False
    assert manifest["new_profiles_advertised"] == []
    rows = manifest["profiles"]
    assert {row["profile_id"] for row in rows} == set(EXPECTED)
    assert len(rows) == 17
    for row in rows:
        expected = EXPECTED[row["profile_id"]]
        actual = (
            row["target_triple"],
            row["abi_id"],
            row["bitness"],
            row["data_endian"],
            row["instruction_endian"],
            row["mode"],
            row["processor"],
        )
        assert actual == expected
        assert row["format"] == "FMT-ELF"
        assert row["binary_header"]["kind"] == "ELF"
        assert row["binary_header"]["bits"] == row["bitness"]
        assert row["binary_header"]["endian"] == row["data_endian"]
        assert row["binary_header"]["image_base"] >= 0
        assert row["binary_size"] > 0
        assert re.fullmatch(r"[0-9a-f]{64}", row["binary_sha256"])
        assert re.fullmatch(r"[0-9a-f]{64}", row["command_sha256"])
        assert row["command"][0] == "$ZIG" and row["command"][1] == "cc"
        assert row["function_selector"] == STABLE_CAPABILITY_SELECTOR
        assert row["function_selectors"] == SEMANTIC_FUNCTION_SELECTORS
        assert row["function_selector"] in row["function_selectors"]
        entries = row["function_entries"]
        assert [entry["name"] for entry in entries] == list(ORDERED_FUNCTIONS)
        assert len({entry["logical_rva"] for entry in entries}) == len(entries)
        is_ppc64_elfv2 = row["profile_id"].startswith("PPC64-")
        expected_local_offsets = {
            name: 8
            if is_ppc64_elfv2 and name in {"isa_call", "isa_profile_entry"}
            else 0
            for name in ORDERED_FUNCTIONS
        }
        if is_ppc64_elfv2:
            assert int(row["binary_header"]["flags_hex"], 16) & 0x3 == 0x2
            assert "-mabi=elfv2" in row["command"]
        for entry in entries:
            assert list(entry) == [
                "name",
                "symbol_value",
                "symbol_size",
                "symbol_other",
                "symbol_table",
                "logical_rva",
                "local_entry_offset",
                "extraction_rva",
                "proof_kind",
            ]
            assert entry["symbol_size"] > 0
            assert entry["symbol_table"] == ".symtab"
            code_value = (
                entry["symbol_value"] & ~1
                if row["mode"] == "THUMB"
                else entry["symbol_value"]
            )
            assert code_value == (
                row["binary_header"]["image_base"] + entry["logical_rva"]
            )
            assert entry["local_entry_offset"] == expected_local_offsets[entry["name"]]
            assert entry["extraction_rva"] == (
                entry["logical_rva"] + entry["local_entry_offset"]
            )
            assert 0 <= entry["local_entry_offset"] < entry["symbol_size"]
            assert entry["proof_kind"] == (
                "ppc64_elfv2_st_other" if is_ppc64_elfv2 else "elf_symbol"
            )
            encoding = (entry["symbol_other"] >> 5) & 0x7
            decoded = 0 if encoding <= 1 else 1 << encoding
            assert entry["local_entry_offset"] == (decoded if is_ppc64_elfv2 else 0)
        profile_entry = next(
            entry for entry in entries if entry["name"] == "isa_profile_entry"
        )
        assert profile_entry["symbol_value"] == row["binary_header"]["entry"]
        if is_ppc64_elfv2:
            assert profile_entry["logical_rva"] < row["binary_header"]["image_base"]
        assert row["reproducibility"] == {
            "fresh_builds": 2,
            "binary_sha256_equal": True,
            "binary_sha256s": [row["binary_sha256"], row["binary_sha256"]],
        }
        assert row["target_executed"] is False
        assert row["ida_receipt_recorded"] is False
        assert row["support_status"] == "build_only_unmeasured"


def test_required_pe_macho_and_raw_format_rows_are_honest():
    variants = read(MANIFEST)["format_variants"]
    assert {(row["profile_id"], row["format"]) for row in variants} == {
        ("X64-LE", "FMT-PE"),
        ("X64-LE", "FMT-MACHO"),
        ("A64-LE", "FMT-MACHO"),
        ("ARM32-LE", "FMT-RAW"),
    }
    pe = next(row for row in variants if row["format"] == "FMT-PE")
    header = pe["binary_header"]
    assert {
        key: header[key] for key in ("kind", "bits", "endian", "machine", "timestamp")
    } == {
        "kind": "PE",
        "bits": 64,
        "endian": "LE",
        "machine": 0x8664,
        "timestamp": 0,
    }
    exports = {item["name"]: item["rva"] for item in header["exports"]}
    assert set(exports) == FUNCTIONS
    assert header["entry_rva"] == exports["isa_profile_entry"]
    assert pe["reproducibility"]["binary_sha256_equal"] is True
    assert pe["debug_info"] == "stripped for deterministic PE; no PDB required"
    assert pe["function_selector"] == {
        "kind": "export_name",
        "value": "isa_scalar",
    }
    assert pe["function_selectors"] == [
        {
            "function": name,
            "kind": "export_name",
            "value": name,
            "rva": exports[name],
        }
        for name in ORDERED_FUNCTIONS
    ]
    assert len(set(exports.values())) == len(exports)
    raw = next(row for row in variants if row["format"] == "FMT-RAW")
    config = raw["raw_configuration"]
    assert config["processor"] == "ARM"
    assert config["mode"] == "ARM32"
    assert config["load_address"] == 0x10000
    assert config["entry_offset"] == 0
    assert config["entry_point"] == config["load_address"] == 0x10000
    assert config["function_selector"] == {
        "kind": "raw_offset",
        "value": 0,
    }
    selectors = raw["function_selectors"]
    assert [item["function"] for item in selectors] == list(ORDERED_FUNCTIONS)
    assert raw["derived_from_sha256"] == next(
        row["binary_sha256"]
        for row in read(MANIFEST)["profiles"]
        if row["profile_id"] == "ARM32-LE"
    )
    by_offset = sorted(selectors, key=lambda item: item["value"])
    for item in selectors:
        assert item["kind"] == "raw_offset"
        assert 0 <= item["value"] < raw["binary_size"]
        assert 0 < item["size"] <= raw["binary_size"] - item["value"]
    for current, following in zip(by_offset, by_offset[1:]):
        assert current["value"] + current["size"] <= following["value"]
    for row in variants:
        assert row["target_executed"] is False
        assert row["support_status"] == "build_only_unmeasured"


def raw_elf_info(*, scalar_offset=0, scalar_count=1, overlapping=False):
    text_address = 0x20000
    offsets = {
        "isa_scalar": scalar_offset,
        "isa_branch": 4,
        "isa_load": 8,
        "isa_store": 12,
        "isa_call": 12 if overlapping else 16,
        "isa_profile_entry": 20,
    }
    symbols = []
    for name in ORDERED_FUNCTIONS:
        count = scalar_count if name == "isa_scalar" else 1
        symbols.extend(
            {
                "name": name,
                "value": text_address + offsets[name],
                "size": 4,
                "binding": 1,
                "type": 2,
                "section": ".text",
                "symbol_table": ".symtab",
            }
            for _ in range(count)
        )
    return {
        "text": {"address": text_address, "offset": 0, "size": 32},
        "symbols": symbols,
    }


@pytest.mark.parametrize(
    "info,match",
    [
        (raw_elf_info(scalar_count=0), "exactly one"),
        (raw_elf_info(scalar_count=2), "exactly one"),
        (raw_elf_info(scalar_offset=32), "outside .text"),
    ],
)
def test_raw_scalar_symbol_must_be_unique_defined_text_function(info, match):
    builder = load_builder()
    with pytest.raises(RuntimeError, match=match):
        builder.elf_text_function_offset(info, "isa_scalar")


@pytest.mark.parametrize(
    ("symbol_other", "offset"),
    [(0x00, 0), (0x20, 0), (0x40, 4), (0x60, 8), (0x80, 16)],
)
def test_ppc64_elfv2_local_entry_offset_is_decoded_from_st_other(symbol_other, offset):
    assert load_builder().ppc64_elfv2_local_entry_offset(symbol_other) == offset


def test_raw_builder_rejects_nonzero_scalar_offset(monkeypatch, tmp_path):
    builder = load_builder()
    output = tmp_path / "corpus"
    relative = Path("profiles/ARM32-LE/arm32_le.elf")
    for fresh in (1, 2):
        elf = output / f"fresh-{fresh}" / relative
        elf.parent.mkdir(parents=True)
        elf.write_bytes(bytes(range(32)))

    def fake_run(command, _environment):
        source, destination = map(Path, command[-2:])
        destination.write_bytes(source.read_bytes())

    monkeypatch.setattr(builder, "run", fake_run)
    monkeypatch.setattr(
        builder, "elf_info", lambda _path: raw_elf_info(scalar_offset=4)
    )
    with pytest.raises(RuntimeError, match="offset zero"):
        builder.build_raw(
            Path("/tool/zig"),
            output,
            {"binary": "fresh-1/" + relative.as_posix()},
            {},
        )


def test_raw_builder_rejects_overlapping_semantic_functions(monkeypatch, tmp_path):
    builder = load_builder()
    output = tmp_path / "corpus"
    relative = Path("profiles/ARM32-LE/arm32_le.elf")
    for fresh in (1, 2):
        elf = output / f"fresh-{fresh}" / relative
        elf.parent.mkdir(parents=True)
        elf.write_bytes(bytes(range(32)))

    def fake_run(command, _environment):
        source, destination = map(Path, command[-2:])
        destination.write_bytes(source.read_bytes())

    monkeypatch.setattr(builder, "run", fake_run)
    monkeypatch.setattr(
        builder, "elf_info", lambda _path: raw_elf_info(overlapping=True)
    )
    with pytest.raises(RuntimeError, match="functions overlap"):
        builder.build_raw(
            Path("/tool/zig"),
            output,
            {
                "binary": "fresh-1/" + relative.as_posix(),
                "binary_sha256": "0" * 64,
            },
            {},
        )


def test_recorded_macho_rows_have_exact_self_contained_build_schema():
    builder = load_builder()
    rows = {
        row["profile_id"]: row
        for row in read(MANIFEST)["format_variants"]
        if row["format"] == "FMT-MACHO"
    }
    assert set(rows) == set(MACHO_EXPECTED)
    for profile_id, row in rows.items():
        arch, target, abi, mode, processor, cpu_type = MACHO_EXPECTED[profile_id]
        assert set(row) == MACHO_ROW_KEYS
        assert (
            row["target_triple"],
            row["abi_id"],
            row["bitness"],
            row["data_endian"],
            row["instruction_endian"],
            row["mode"],
            row["processor"],
        ) == (target, abi, 64, "LE", "LE", mode, processor)
        assert row["binary"] == f"fresh-1/formats/{profile_id}/isa_profile_anchor"
        assert row["binary_size"] > 0
        assert re.fullmatch(r"[0-9a-f]{64}", row["binary_sha256"])
        header = row["binary_header"]
        assert {
            key: header[key]
            for key in ("kind", "bits", "endian", "cpu_type", "file_type")
        } == {
            "kind": "MACH-O",
            "bits": 64,
            "endian": "LE",
            "cpu_type": cpu_type,
            "file_type": 2,
        }
        assert header["image_base"] > 0
        assert header["selected_symbol"] == "_isa_scalar"
        symbol_rvas = {item["name"]: item["rva"] for item in header["semantic_symbols"]}
        assert set(symbol_rvas) == MACHO_SYMBOLS
        assert len(set(symbol_rvas.values())) == len(symbol_rvas)
        assert row["source"] == "tests/flow_fixtures/isa_profile_anchor.c"
        assert row["source_sha256"] == sha256(MACHO_SOURCE)
        assert row["compiler"]["command"] == "$APPLE_CLANG"
        assert row["compiler"]["version"].startswith("Apple clang version")
        assert re.fullmatch(r"[0-9a-f]{64}", row["compiler"]["sha256"])
        assert row["command"] == [
            "$APPLE_CLANG",
            "-arch",
            arch,
            "-O0",
            "-fno-stack-protector",
            "-Wl,-no_uuid",
            "-Wl,-no_adhoc_codesign",
            "-Wl,-e,_isa_profile_entry",
            "tests/flow_fixtures/isa_profile_anchor.c",
            "-o",
            f"$OUTPUT/fresh-1/formats/{profile_id}/isa_profile_anchor",
        ]
        assert row["command_sha256"] == builder.command_hash(row["command"])
        assert row["function_selector"] == {
            "kind": "ida_name",
            "value": "_isa_scalar",
            "naming_convention": (
                "Mach-O external symbol with the object-format underscore prefix"
            ),
            "requires_companion": False,
        }
        assert row["function_selectors"] == [
            {
                "function": name,
                "kind": "ida_name",
                "value": f"_{name}",
                "rva": symbol_rvas[f"_{name}"],
                "naming_convention": (
                    "Mach-O external symbol with the object-format underscore prefix"
                ),
                "requires_companion": False,
            }
            for name in ORDERED_FUNCTIONS
        ]
        assert row["companion_artifacts"] == []
        assert row["debug_info"] == (
            "no debug info; global symbol retained; no dSYM required"
        )
        assert row["reproducibility"] == {
            "fresh_builds": 2,
            "binary_sha256_equal": True,
            "binary_sha256s": [row["binary_sha256"], row["binary_sha256"]],
        }
        assert row["target_executed"] is False
        assert row["ida_receipt_recorded"] is False
        assert row["support_status"] == "build_only_unmeasured"
        assert "reference_manifest" not in row


def test_fresh_macho_builds_are_self_contained_identical_and_keep_global_symbol(
    fresh_macho_corpus,
):
    builder, output, rows = fresh_macho_corpus
    assert set(rows) == set(MACHO_EXPECTED)
    assert not list(output.rglob("*.dSYM"))
    for profile_id, row in rows.items():
        primary = output / row["binary"]
        repeat = output / row["binary"].replace("fresh-1", "fresh-2")
        assert primary.is_file() and repeat.is_file()
        assert primary.read_bytes() == repeat.read_bytes()
        assert sha256(primary) == row["binary_sha256"] == sha256(repeat)
        for binary in (primary, repeat):
            info = builder.macho_info(binary)
            assert info["cpu_type"] == MACHO_EXPECTED[profile_id][-1]
            assert MACHO_SYMBOLS.issubset(info["defined_external_symbols"])
        assert row["target_executed"] is False
        assert row["ida_receipt_recorded"] is False
        assert row["companion_artifacts"] == []


def test_builder_only_allows_zig_and_configured_apple_clang_tools(monkeypatch):
    builder = load_builder()
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))

    monkeypatch.setattr(builder.subprocess, "run", fake_run)
    environment = {"SOURCE_DATE_EPOCH": "0"}
    builder.run(["/tool/zig", "cc", "source.c", "-o", "/tmp/out"], environment)
    builder.run(["/tool/zig", "objcopy", "in", "out"], environment)
    clang_command = [
        "/tool/apple-clang",
        "-arch",
        "x86_64",
        "-O0",
        "-fno-stack-protector",
        "-Wl,-no_uuid",
        "-Wl,-no_adhoc_codesign",
        "-Wl,-e,_isa_profile_entry",
        "tests/flow_fixtures/isa_profile_anchor.c",
        "-o",
        "/tmp/out",
    ]
    builder.run_apple_clang(clang_command, environment, Path("/tool/apple-clang"))
    assert [call[0][1] for call in calls] == ["cc", "objcopy", "-arch"]
    assert all(call[1]["cwd"] == ROOT for call in calls)
    assert all(call[1]["check"] is True for call in calls)
    with pytest.raises(RuntimeError, match="only Zig"):
        builder.run(["/tmp/generated-target"], environment)
    with pytest.raises(RuntimeError, match="only configured Apple clang"):
        builder.run_apple_clang(
            ["/tmp/generated-target", *clang_command[1:]],
            environment,
            Path("/tool/apple-clang"),
        )


def test_macho_output_rejects_symlink_escape(tmp_path):
    builder = load_builder()
    output = tmp_path / "output"
    outside = tmp_path / "outside"
    output.mkdir()
    outside.mkdir()
    (output / "fresh-1").symlink_to(outside, target_is_directory=True)
    with pytest.raises(RuntimeError, match="may not traverse a symlink"):
        builder.contained_output(
            output, Path("fresh-1/formats/X64-LE/isa_profile_anchor")
        )


def test_macho_info_rejects_malformed_header(tmp_path):
    builder = load_builder()
    truncated = tmp_path / "truncated-macho"
    truncated.write_bytes(b"\xcf\xfa\xed\xfe")
    with pytest.raises(RuntimeError, match="Truncated Mach-O header"):
        builder.macho_info(truncated)


@pytest.mark.parametrize(
    ("cpu_type", "symbols"),
    [
        (0x0100000C, sorted(MACHO_SYMBOLS)),
        (0x01000007, sorted(MACHO_SYMBOLS - {"_isa_scalar"})),
        (0x01000007, ["_isa_scalar"]),
        (0x01000007, ["_main"]),
    ],
)
def test_macho_build_rejects_wrong_identity_or_missing_symbol(
    monkeypatch, tmp_path, cpu_type, symbols
):
    builder = load_builder()

    def fake_run(command, environment, clang):
        del environment, clang
        Path(command[command.index("-o") + 1]).write_bytes(b"not-executed")

    monkeypatch.setattr(builder, "run_apple_clang", fake_run)
    monkeypatch.setattr(
        builder,
        "macho_info",
        lambda path: {
            "kind": "MACH-O",
            "bits": 64,
            "endian": "LE",
            "cpu_type": cpu_type,
            "file_type": 2,
            "image_base": 0x100000000,
            "defined_external_symbols": symbols,
            "defined_external_symbol_entries": [
                {"name": name, "rva": 0x1000 + index * 0x10}
                for index, name in enumerate(symbols)
            ],
        },
    )
    with pytest.raises(RuntimeError, match="Unexpected Mach-O identity"):
        builder.build_macho(
            Path("/tool/apple-clang"),
            "Apple clang version test",
            tmp_path,
            builder.MACHO_PROFILES[0],
            {},
        )


def test_macho_build_rejects_unequal_fresh_builds(monkeypatch, tmp_path):
    builder = load_builder()

    def fake_run(command, environment, clang):
        del environment, clang
        output = Path(command[command.index("-o") + 1])
        output.write_bytes(output.parts[-4].encode())

    monkeypatch.setattr(builder, "run_apple_clang", fake_run)
    monkeypatch.setattr(
        builder,
        "macho_info",
        lambda path: {
            "kind": "MACH-O",
            "bits": 64,
            "endian": "LE",
            "cpu_type": 0x01000007,
            "file_type": 2,
            "image_base": 0x100000000,
            "defined_external_symbols": sorted(MACHO_SYMBOLS),
            "defined_external_symbol_entries": [
                {"name": name, "rva": 0x1000 + index * 0x10}
                for index, name in enumerate(sorted(MACHO_SYMBOLS))
            ],
        },
    )
    with pytest.raises(RuntimeError, match="Non-reproducible Mach-O fixture"):
        builder.build_macho(
            Path("/tool/apple-clang"),
            "Apple clang version test",
            tmp_path,
            builder.MACHO_PROFILES[0],
            {},
        )


def test_commands_keep_all_explicit_outputs_below_requested_directory():
    manifest = read(MANIFEST)
    commands = [row["command"] for row in manifest["profiles"]]
    commands.extend(
        row["command"] for row in manifest["format_variants"] if "command" in row
    )
    for command in commands:
        assert "-.o" not in command and "-.obj" not in command
        if "-o" in command:
            output = command[command.index("-o") + 1]
            assert output.startswith("$OUTPUT/")
        else:
            assert command[-1].startswith("$OUTPUT/")
