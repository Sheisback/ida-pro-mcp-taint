#!/usr/bin/env python3
"""Build the G012 ISA/ABI corpus twice without executing any target."""

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path("tests/flow_fixtures/isa_profile_anchor.c")
MACHO_SOURCE = SOURCE
FUNCTIONS = (
    "isa_scalar",
    "isa_branch",
    "isa_load",
    "isa_store",
    "isa_call",
    "isa_profile_entry",
)

# profile, triple, ABI, bits, data endian, instruction endian, mode, processor,
# ELF e_machine, extra compiler arguments
PROFILES = (
    ("X86-LE", "x86-linux-gnu", "sysv-i386", 32, "LE", "LE", "X86", "metapc", 3, ()),
    (
        "X64-LE",
        "x86_64-linux-gnu",
        "sysv-amd64",
        64,
        "LE",
        "LE",
        "X64",
        "metapc",
        62,
        (),
    ),
    (
        "ARM32-LE",
        "arm-linux-gnueabi",
        "aapcs32",
        32,
        "LE",
        "LE",
        "ARM32",
        "ARM",
        40,
        (),
    ),
    (
        "ARM32-BE",
        "armeb-linux-gnueabi",
        "aapcs32",
        32,
        "BE",
        "LE",
        "ARM32",
        "ARMB",
        40,
        (),
    ),
    (
        "THUMB-LE",
        "thumb-linux-musleabi",
        "aapcs32",
        32,
        "LE",
        "LE",
        "THUMB",
        "ARM",
        40,
        (),
    ),
    (
        "THUMB-BE",
        "thumbeb-linux-musleabi",
        "aapcs32",
        32,
        "BE",
        "LE",
        "THUMB",
        "ARMB",
        40,
        (),
    ),
    ("A64-LE", "aarch64-linux-gnu", "aapcs64", 64, "LE", "LE", "A64", "ARM", 183, ()),
    (
        "MIPS32-LE",
        "mipsel-linux-gnu",
        "mips-o32",
        32,
        "LE",
        "LE",
        "MIPS32",
        "mipsl",
        8,
        ("-mabi=o32",),
    ),
    (
        "MIPS32-BE",
        "mips-linux-gnu",
        "mips-o32",
        32,
        "BE",
        "BE",
        "MIPS32",
        "mipsb",
        8,
        ("-mabi=o32",),
    ),
    (
        "MIPS64-LE",
        "mips64el-linux-gnuabi64",
        "mips-n64",
        64,
        "LE",
        "LE",
        "MIPS64",
        "mipsl",
        8,
        ("-mabi=n64",),
    ),
    (
        "MIPS64-BE",
        "mips64-linux-gnuabi64",
        "mips-n64",
        64,
        "BE",
        "BE",
        "MIPS64",
        "mipsb",
        8,
        ("-mabi=n64",),
    ),
    (
        "PPC32-LE",
        "powerpcle-linux-gnu",
        "sysv-ppc32",
        32,
        "LE",
        "LE",
        "PPC32",
        "PPCL",
        20,
        (),
    ),
    (
        "PPC32-BE",
        "powerpc-linux-gnu",
        "sysv-ppc32",
        32,
        "BE",
        "BE",
        "PPC32",
        "PPC",
        20,
        (),
    ),
    (
        "PPC64-LE",
        "powerpc64le-linux-gnu",
        "elfv2-ppc64",
        64,
        "LE",
        "LE",
        "PPC64",
        "PPCL",
        21,
        ("-mabi=elfv2",),
    ),
    (
        "PPC64-BE",
        "powerpc64-linux-gnu",
        "elfv2-ppc64",
        64,
        "BE",
        "BE",
        "PPC64",
        "PPC",
        21,
        ("-mabi=elfv2",),
    ),
    (
        "RV32-LE",
        "riscv32-linux-gnu",
        "riscv-ilp32",
        32,
        "LE",
        "LE",
        "RV32",
        "riscv",
        243,
        ("-mabi=ilp32",),
    ),
    (
        "RV64-LE",
        "riscv64-linux-gnu",
        "riscv-lp64",
        64,
        "LE",
        "LE",
        "RV64",
        "riscv",
        243,
        ("-mabi=lp64",),
    ),
)

# profile, clang architecture, target triple, ABI, mode, processor, Mach-O CPU type
MACHO_PROFILES = (
    (
        "X64-LE",
        "x86_64",
        "x86_64-apple-darwin",
        "darwin-x86_64-sysv-derived",
        "X64",
        "metapc",
        0x01000007,
    ),
    (
        "A64-LE",
        "arm64",
        "arm64-apple-darwin",
        "darwin-aarch64",
        "A64",
        "ARM",
        0x0100000C,
    ),
)


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256(path):
    return sha256_bytes(path.read_bytes())


def command_hash(command):
    return sha256_bytes(
        json.dumps(command, ensure_ascii=True, separators=(",", ":")).encode()
    )


def resolve_zig(explicit):
    candidates = []
    if explicit is not None:
        candidates.append(explicit)
    if os.environ.get("ZIG"):
        candidates.append(Path(os.environ["ZIG"]))
    found = shutil.which("zig")
    if found:
        candidates.append(Path(found))
    candidates.extend(
        sorted(Path.home().glob(".local/share/cmux-zig/zig-*/zig"), reverse=True)
    )
    for candidate in candidates:
        candidate = candidate.expanduser().resolve()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise RuntimeError("Zig compiler not found; pass --zig or set ZIG")


def resolve_apple_clang(explicit):
    candidates = []
    if explicit is not None:
        candidates.append(explicit)
    if os.environ.get("APPLE_CLANG"):
        candidates.append(Path(os.environ["APPLE_CLANG"]))
    candidates.append(Path("/usr/bin/clang"))
    found = shutil.which("clang")
    if found:
        candidates.append(Path(found))
    for candidate in candidates:
        candidate = candidate.expanduser().resolve()
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        version = subprocess.check_output(
            [str(candidate), "--version"], cwd=ROOT, text=True
        ).strip()
        if version.startswith("Apple clang version"):
            return candidate, version
    raise RuntimeError("Apple clang not found; pass --apple-clang or set APPLE_CLANG")


def normalize(command, output, tool, tool_variable="$ZIG"):
    replacements = (
        (str(output), "$OUTPUT"),
        (str(tool), tool_variable),
        (str(ROOT), "$ROOT"),
    )
    result = []
    for value in command:
        for old, new in replacements:
            value = value.replace(old, new)
        result.append(value)
    return result


def run(command, environment):
    if Path(command[0]).name != "zig" or command[1] not in {"cc", "objcopy"}:
        raise RuntimeError("Builder may invoke only Zig compilation tools")
    subprocess.run(command, cwd=ROOT, env=environment, check=True)


def run_apple_clang(command, environment, clang):
    required = {
        "-O0",
        "-fno-stack-protector",
        "-Wl,-no_uuid",
        "-Wl,-no_adhoc_codesign",
        "-Wl,-e,_isa_profile_entry",
        str(MACHO_SOURCE),
    }
    if (
        not command
        or len(command) < 3
        or Path(command[0]).resolve() != clang.resolve()
        or command[1:2] != ["-arch"]
        or command[2] not in {"x86_64", "arm64"}
        or not required.issubset(command)
        or "-o" not in command
    ):
        raise RuntimeError("Builder may invoke only configured Apple clang builds")
    subprocess.run(command, cwd=ROOT, env=environment, check=True)


def contained_output(output, relative):
    base = output.resolve()
    relative = Path(relative)
    if relative.is_absolute() or ".." in relative.parts or not relative.name:
        raise RuntimeError(f"Output path escapes requested directory: {relative}")
    parent = base
    for part in relative.parts[:-1]:
        parent /= part
        if parent.is_symlink():
            raise RuntimeError(f"Output path may not traverse a symlink: {relative}")
        if parent.exists() and not parent.is_dir():
            raise RuntimeError(f"Output parent is not a directory: {relative}")
        parent.mkdir(exist_ok=True)
    candidate = parent / relative.name
    if candidate.is_symlink():
        raise RuntimeError(f"Output path may not be a symlink: {relative}")
    return candidate


def elf_info(path):
    data = path.read_bytes()
    if (
        len(data) < 16
        or data[:4] != b"\x7fELF"
        or data[4] not in (1, 2)
        or data[5] not in (1, 2)
    ):
        raise RuntimeError(f"Not a supported ELF file: {path}")
    bits = 32 if data[4] == 1 else 64
    byteorder = "little" if data[5] == 1 else "big"
    endian = "LE" if byteorder == "little" else "BE"
    header_size = 52 if bits == 32 else 64
    if len(data) < header_size:
        raise RuntimeError(f"Truncated ELF header: {path}")
    machine = int.from_bytes(data[18:20], byteorder)
    if bits == 32:
        entry = int.from_bytes(data[24:28], byteorder)
        program_offset = int.from_bytes(data[28:32], byteorder)
        program_size = int.from_bytes(data[42:44], byteorder)
        program_count = int.from_bytes(data[44:46], byteorder)
        program_format = "IIIIIIII"
        flags = int.from_bytes(data[36:40], byteorder)
        section_offset = int.from_bytes(data[32:36], byteorder)
        section_size = int.from_bytes(data[46:48], byteorder)
        section_count = int.from_bytes(data[48:50], byteorder)
        names_index = int.from_bytes(data[50:52], byteorder)
        section_format = "IIIIIIIIII"
    else:
        entry = int.from_bytes(data[24:32], byteorder)
        program_offset = int.from_bytes(data[32:40], byteorder)
        program_size = int.from_bytes(data[54:56], byteorder)
        program_count = int.from_bytes(data[56:58], byteorder)
        program_format = "IIQQQQQQ"
        flags = int.from_bytes(data[48:52], byteorder)
        section_offset = int.from_bytes(data[40:48], byteorder)
        section_size = int.from_bytes(data[58:60], byteorder)
        section_count = int.from_bytes(data[60:62], byteorder)
        names_index = int.from_bytes(data[62:64], byteorder)
        section_format = "IIQQQQIIQQ"
    prefix = "<" if byteorder == "little" else ">"
    standard_program_size = struct.calcsize(prefix + program_format)
    if (
        program_count == 0
        or program_size < standard_program_size
        or program_offset + program_count * program_size > len(data)
    ):
        raise RuntimeError(f"Invalid ELF program table: {path}")
    load_addresses = []
    for index in range(program_count):
        start = program_offset + index * program_size
        fields = struct.unpack_from(prefix + program_format, data, start)
        if fields[0] != 1:  # PT_LOAD
            continue
        if bits == 32:
            file_offset, virtual_address, file_size = fields[1], fields[2], fields[4]
        else:
            file_offset, virtual_address, file_size = fields[2], fields[3], fields[5]
        if file_offset + file_size > len(data):
            raise RuntimeError(f"Truncated ELF load segment: {path}")
        load_addresses.append(virtual_address)
    if not load_addresses:
        raise RuntimeError(f"ELF file lacks a load segment: {path}")
    image_base = min(load_addresses)
    standard_section_size = struct.calcsize(prefix + section_format)
    if (
        section_count == 0
        or names_index >= section_count
        or section_size < standard_section_size
        or section_offset + section_count * section_size > len(data)
    ):
        raise RuntimeError(f"Invalid ELF section table: {path}")
    sections = []
    for index in range(section_count):
        start = section_offset + index * section_size
        sections.append(struct.unpack_from(prefix + section_format, data, start))
    names = sections[names_index]
    names_offset = names[4]
    names_size = names[5]
    if names_offset + names_size > len(data):
        raise RuntimeError(f"Truncated ELF section names: {path}")
    names_data = data[names_offset : names_offset + names_size]
    section_names = []
    parsed = {}
    for section in sections:
        name_offset = section[0]
        if name_offset >= len(names_data):
            raise RuntimeError(f"Invalid ELF section name offset: {path}")
        end = names_data.find(b"\0", name_offset)
        if end < 0:
            raise RuntimeError(f"Unterminated ELF section name: {path}")
        name = names_data[name_offset:end].decode()
        section_names.append(name)
        address = section[3]
        offset = section[4]
        size = section[5]
        if section[1] != 8 and offset + size > len(data):
            raise RuntimeError(f"Truncated ELF section {name!r}: {path}")
        parsed[name] = {"address": address, "offset": offset, "size": size}
    if ".text" not in parsed:
        raise RuntimeError(f"ELF file lacks .text: {path}")

    symbol_format = "IIIBBH" if bits == 32 else "IBBHQQ"
    symbol_size = struct.calcsize(prefix + symbol_format)
    symbols = []
    for section_index, section in enumerate(sections):
        if section[1] != 2:  # SHT_SYMTAB; dynamic symbols are not build proof.
            continue
        offset, size, strings_index, entry_size = (
            section[4],
            section[5],
            section[6],
            section[9],
        )
        if (
            entry_size != symbol_size
            or size % entry_size
            or strings_index >= len(sections)
            or sections[strings_index][1] != 3
        ):
            raise RuntimeError(f"Invalid ELF symbol table: {path}")
        strings = sections[strings_index]
        strings_offset, strings_size = strings[4], strings[5]
        if strings_offset + strings_size > len(data):
            raise RuntimeError(f"Truncated ELF symbol strings: {path}")
        strings_data = data[strings_offset : strings_offset + strings_size]
        for symbol_offset in range(offset, offset + size, entry_size):
            fields = struct.unpack_from(prefix + symbol_format, data, symbol_offset)
            if bits == 32:
                name_offset, value, symbol_bytes, info, other, symbol_section = fields
            else:
                name_offset, info, other, symbol_section, value, symbol_bytes = fields
            if name_offset >= len(strings_data):
                raise RuntimeError(f"Invalid ELF symbol name offset: {path}")
            end = strings_data.find(b"\0", name_offset)
            if end < 0:
                raise RuntimeError(f"Unterminated ELF symbol name: {path}")
            name = strings_data[name_offset:end].decode()
            if not name:
                continue
            symbols.append(
                {
                    "name": name,
                    "value": value,
                    "size": symbol_bytes,
                    "binding": info >> 4,
                    "type": info & 0xF,
                    "other": other,
                    "section": (
                        section_names[symbol_section]
                        if 0 < symbol_section < len(section_names)
                        else None
                    ),
                    "symbol_table": section_names[section_index],
                }
            )
    return {
        "kind": "ELF",
        "bits": bits,
        "endian": endian,
        "machine": machine,
        "entry": entry,
        "image_base": image_base,
        "flags": flags,
        "text": parsed[".text"],
        "symbols": symbols,
    }


def elf_text_function_offset(info, name):
    """Return one defined .text function offset from parsed ELF metadata."""

    return elf_text_function(info, name)["text_offset"]


def elf_text_function(info, name):
    """Return exact defined .text function metadata from the static symbol table."""

    matches = [
        symbol
        for symbol in info["symbols"]
        if symbol["name"] == name
        and symbol["section"] == ".text"
        and symbol["type"] == 2  # STT_FUNC
        and symbol["binding"] in (1, 2)  # STB_GLOBAL or STB_WEAK
    ]
    if len(matches) != 1:
        raise RuntimeError(f"ELF must define exactly one .text function {name}")
    symbol = matches[0]
    text = info["text"]
    code_value = (
        symbol["value"] & ~1
        if info.get("machine") == 40 and symbol["value"] & 1
        else symbol["value"]
    )
    offset = code_value - text["address"]
    if symbol["size"] <= 0 or offset < 0 or offset + symbol["size"] > text["size"]:
        raise RuntimeError(f"ELF function {name} lies outside .text")
    return {**symbol, "code_value": code_value, "text_offset": offset}


def ppc64_elfv2_local_entry_offset(symbol_other):
    """Decode the ELFv2 local-entry offset encoded in PPC64 ``st_other``."""

    if type(symbol_other) is not int or not 0 <= symbol_other <= 0xFF:
        raise RuntimeError("Invalid PPC64 ELF symbol st_other")
    encoded = (symbol_other & 0xE0) >> 5
    return 0 if encoded <= 1 else 1 << encoded


def elf_function_entries(info, profile_id, abi):
    """Describe logical and proven extraction entries for all semantic functions."""

    is_ppc64_elfv2 = profile_id.startswith("PPC64-") and abi == "elfv2-ppc64"
    if is_ppc64_elfv2 and (
        info["machine"] != 21 or info["bits"] != 64 or info["flags"] & 0x3 != 0x2
    ):
        raise RuntimeError(f"Invalid PPC64 ELFv2 identity for {profile_id}")
    entries = []
    for name in FUNCTIONS:
        symbol = elf_text_function(info, name)
        logical_rva = symbol["code_value"] - info["image_base"]
        if logical_rva < 0:
            raise RuntimeError(f"ELF function {name} lies below the image base")
        local_entry_offset = (
            ppc64_elfv2_local_entry_offset(symbol["other"]) if is_ppc64_elfv2 else 0
        )
        if local_entry_offset >= symbol["size"] and local_entry_offset != 0:
            raise RuntimeError(f"ELF local entry lies outside function {name}")
        entries.append(
            {
                "name": name,
                "symbol_value": symbol["value"],
                "symbol_size": symbol["size"],
                "symbol_other": symbol["other"],
                "symbol_table": symbol["symbol_table"],
                "logical_rva": logical_rva,
                "local_entry_offset": local_entry_offset,
                "extraction_rva": logical_rva + local_entry_offset,
                "proof_kind": (
                    "ppc64_elfv2_st_other" if is_ppc64_elfv2 else "elf_symbol"
                ),
            }
        )
    if (
        next(item for item in entries if item["name"] == "isa_profile_entry")[
            "symbol_value"
        ]
        != info["entry"]
    ):
        raise RuntimeError("ELF entry point does not match isa_profile_entry")
    return entries


def pe_info(path):
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise RuntimeError(f"Not a PE file: {path}")
    header = int.from_bytes(data[0x3C:0x40], "little")
    if header + 24 > len(data) or data[header : header + 4] != b"PE\0\0":
        raise RuntimeError(f"Missing PE signature: {path}")
    section_count = int.from_bytes(data[header + 6 : header + 8], "little")
    optional_size = int.from_bytes(data[header + 20 : header + 22], "little")
    optional = header + 24
    if optional + optional_size > len(data):
        raise RuntimeError(f"Truncated PE optional header: {path}")
    magic = int.from_bytes(data[optional : optional + 2], "little")
    if magic not in (0x10B, 0x20B):
        raise RuntimeError(f"Unsupported PE optional header: {path}")
    bits = 64 if magic == 0x20B else 32
    directory_count_offset = optional + (108 if bits == 64 else 92)
    directories_offset = optional + (112 if bits == 64 else 96)
    if directory_count_offset + 4 > optional + optional_size:
        raise RuntimeError(f"Truncated PE data directories: {path}")
    directory_count = int.from_bytes(
        data[directory_count_offset : directory_count_offset + 4], "little"
    )
    if directory_count < 1 or directories_offset + 8 > optional + optional_size:
        raise RuntimeError(f"PE file lacks an export directory: {path}")
    export_rva = int.from_bytes(
        data[directories_offset : directories_offset + 4], "little"
    )
    export_size = int.from_bytes(
        data[directories_offset + 4 : directories_offset + 8], "little"
    )
    section_table = optional + optional_size
    if section_table + section_count * 40 > len(data):
        raise RuntimeError(f"Truncated PE section table: {path}")
    sections = []
    for index in range(section_count):
        offset = section_table + index * 40
        virtual_size = int.from_bytes(data[offset + 8 : offset + 12], "little")
        virtual_address = int.from_bytes(data[offset + 12 : offset + 16], "little")
        raw_size = int.from_bytes(data[offset + 16 : offset + 20], "little")
        raw_offset = int.from_bytes(data[offset + 20 : offset + 24], "little")
        if raw_offset + raw_size > len(data):
            raise RuntimeError(f"Truncated PE section data: {path}")
        sections.append((virtual_address, virtual_size, raw_offset, raw_size))

    def rva_offset(rva, size):
        for virtual_address, virtual_size, raw_offset, raw_size in sections:
            relative = rva - virtual_address
            if 0 <= relative and relative + size <= raw_size:
                if relative + size <= max(virtual_size, raw_size):
                    return raw_offset + relative
        raise RuntimeError(f"PE RVA lies outside file-backed sections: {path}")

    def c_string(rva):
        offset = rva_offset(rva, 1)
        end = data.find(b"\0", offset)
        if end < 0:
            raise RuntimeError(f"Unterminated PE export name: {path}")
        return data[offset:end].decode()

    if export_rva == 0 or export_size < 40:
        raise RuntimeError(f"PE file lacks exported functions: {path}")
    export_offset = rva_offset(export_rva, 40)
    function_count = int.from_bytes(
        data[export_offset + 20 : export_offset + 24], "little"
    )
    name_count = int.from_bytes(data[export_offset + 24 : export_offset + 28], "little")
    function_table_rva = int.from_bytes(
        data[export_offset + 28 : export_offset + 32], "little"
    )
    name_table_rva = int.from_bytes(
        data[export_offset + 32 : export_offset + 36], "little"
    )
    ordinal_table_rva = int.from_bytes(
        data[export_offset + 36 : export_offset + 40], "little"
    )
    function_table = rva_offset(function_table_rva, function_count * 4)
    name_table = rva_offset(name_table_rva, name_count * 4)
    ordinal_table = rva_offset(ordinal_table_rva, name_count * 2)
    exports = []
    for index in range(name_count):
        name_rva = int.from_bytes(
            data[name_table + index * 4 : name_table + index * 4 + 4], "little"
        )
        ordinal = int.from_bytes(
            data[ordinal_table + index * 2 : ordinal_table + index * 2 + 2],
            "little",
        )
        if ordinal >= function_count:
            raise RuntimeError(f"Invalid PE export ordinal: {path}")
        function_rva = int.from_bytes(
            data[function_table + ordinal * 4 : function_table + ordinal * 4 + 4],
            "little",
        )
        if function_rva == 0 or export_rva <= function_rva < export_rva + export_size:
            raise RuntimeError(f"PE export is null or forwarded: {path}")
        rva_offset(function_rva, 1)
        exports.append({"name": c_string(name_rva), "rva": function_rva})
    if len({item["name"] for item in exports}) != len(exports):
        raise RuntimeError(f"PE export names are not unique: {path}")
    return {
        "kind": "PE",
        "bits": bits,
        "endian": "LE",
        "machine": int.from_bytes(data[header + 4 : header + 6], "little"),
        "timestamp": int.from_bytes(data[header + 8 : header + 12], "little"),
        "entry_rva": int.from_bytes(data[optional + 16 : optional + 20], "little"),
        "exports": sorted(exports, key=lambda item: item["name"]),
    }


def macho_info(path):
    data = path.read_bytes()
    if len(data) < 32:
        raise RuntimeError(f"Truncated Mach-O header: {path}")
    header = struct.unpack_from("<IIIIIIII", data)
    magic, cpu_type, _, file_type, command_count, command_size, _, _ = header
    if magic != 0xFEEDFACF:
        raise RuntimeError(f"Not a supported 64-bit little-endian Mach-O file: {path}")
    commands_end = 32 + command_size
    if commands_end > len(data):
        raise RuntimeError(f"Truncated Mach-O load commands: {path}")
    symtab = None
    image_base = None
    offset = 32
    for _ in range(command_count):
        if offset + 8 > commands_end:
            raise RuntimeError(f"Truncated Mach-O load command: {path}")
        command, size = struct.unpack_from("<II", data, offset)
        if size < 8 or offset + size > commands_end:
            raise RuntimeError(f"Invalid Mach-O load command: {path}")
        if command == 0x2:
            if size < 24:
                raise RuntimeError(f"Invalid Mach-O symbol table command: {path}")
            symtab = struct.unpack_from("<IIII", data, offset + 8)
        if command == 0x19:
            if size < 72:
                raise RuntimeError(f"Invalid Mach-O segment command: {path}")
            segment_name = data[offset + 8 : offset + 24].rstrip(b"\0")
            if segment_name == b"__TEXT":
                if image_base is not None:
                    raise RuntimeError(f"Duplicate Mach-O __TEXT segment: {path}")
                image_base = struct.unpack_from("<Q", data, offset + 24)[0]
        offset += size
    if offset != commands_end or symtab is None or image_base is None:
        raise RuntimeError(f"Mach-O file lacks a valid symbol table: {path}")
    symbol_offset, symbol_count, strings_offset, strings_size = symtab
    symbol_end = symbol_offset + symbol_count * 16
    strings_end = strings_offset + strings_size
    if symbol_end > len(data) or strings_end > len(data):
        raise RuntimeError(f"Truncated Mach-O symbol table: {path}")
    strings = data[strings_offset:strings_end]
    defined_external_symbols = []
    defined_external_symbol_entries = []
    for index in range(symbol_count):
        name_offset, symbol_type, _, _, value = struct.unpack_from(
            "<IBBHQ", data, symbol_offset + index * 16
        )
        if symbol_type & 0xE0 or not symbol_type & 0x01 or symbol_type & 0x0E == 0:
            continue
        if name_offset >= len(strings):
            raise RuntimeError(f"Invalid Mach-O symbol name offset: {path}")
        end = strings.find(b"\0", name_offset)
        if end < 0:
            raise RuntimeError(f"Unterminated Mach-O symbol name: {path}")
        name = strings[name_offset:end].decode()
        if value < image_base:
            raise RuntimeError(f"Mach-O symbol lies below __TEXT: {path}")
        defined_external_symbols.append(name)
        defined_external_symbol_entries.append(
            {"name": name, "rva": value - image_base}
        )
    return {
        "kind": "MACH-O",
        "bits": 64,
        "endian": "LE",
        "cpu_type": cpu_type,
        "file_type": file_type,
        "image_base": image_base,
        "defined_external_symbols": sorted(defined_external_symbols),
        "defined_external_symbol_entries": sorted(
            defined_external_symbol_entries, key=lambda item: item["name"]
        ),
    }


def common_command(zig, target):
    return [
        str(zig),
        "cc",
        "-target",
        target,
        "-std=c11",
        "-O0",
        "-g",
        "-fno-sanitize=all",
        "-ffreestanding",
        "-fno-stack-protector",
        "-fno-builtin",
        "-fdebug-compilation-dir=.",
        f"-ffile-prefix-map={ROOT}=.",
        "-nostdlib",
    ]


def build_elf(zig, output, profile, environment):
    (
        profile_id,
        target,
        abi,
        bits,
        data_endian,
        instruction_endian,
        mode,
        processor,
        machine,
        extra,
    ) = profile
    filename = profile_id.lower().replace("-", "_") + ".elf"
    commands = []
    artifacts = []
    for fresh in (1, 2):
        binary = output / f"fresh-{fresh}" / "profiles" / profile_id / filename
        binary.parent.mkdir(parents=True, exist_ok=True)
        command = (
            common_command(zig, target)
            + list(extra)
            + [
                "-Wl,--build-id=none",
                "-Wl,-e,isa_profile_entry",
                str(SOURCE),
                "-o",
                str(binary),
            ]
        )
        run(command, environment)
        info = elf_info(binary)
        if (info["bits"], info["endian"], info["machine"]) != (
            bits,
            data_endian,
            machine,
        ):
            raise RuntimeError(f"Unexpected ELF identity for {profile_id}: {info}")
        entries = elf_function_entries(info, profile_id, abi)
        commands.append(normalize(command, output, zig))
        artifacts.append((binary, info, entries))
    hashes = [sha256(binary) for binary, _, _ in artifacts]
    if len(set(hashes)) != 1:
        raise RuntimeError(f"Non-reproducible ELF fixture: {profile_id}")
    primary, info, function_entries = artifacts[0]
    if any(entries != function_entries for _, _, entries in artifacts[1:]):
        raise RuntimeError(f"Non-reproducible ELF function metadata: {profile_id}")
    normalized = commands[0]
    return {
        "profile_id": profile_id,
        "profile_version": 1,
        "target_triple": target,
        "abi_id": abi,
        "bitness": bits,
        "data_endian": data_endian,
        "instruction_endian": instruction_endian,
        "mode": mode,
        "processor": processor,
        "format": "FMT-ELF",
        "platform_tag": "linux",
        "binary": primary.relative_to(output).as_posix(),
        "binary_sha256": hashes[0],
        "binary_size": primary.stat().st_size,
        "binary_header": {
            "kind": info["kind"],
            "bits": info["bits"],
            "endian": info["endian"],
            "machine": info["machine"],
            "entry": info["entry"],
            "image_base": info["image_base"],
            "flags_hex": hex(info["flags"]),
        },
        "command": normalized,
        "command_sha256": command_hash(normalized),
        # Keep the stable capability probe separate from the full semantic
        # selector inventory used by later oracle coverage.
        "function_selector": {
            "kind": "debug_or_symbol_name",
            "value": "isa_scalar",
        },
        "function_selectors": [
            {"kind": "debug_or_symbol_name", "value": name} for name in FUNCTIONS
        ],
        "function_entries": function_entries,
        "reproducibility": {
            "fresh_builds": 2,
            "binary_sha256_equal": True,
            "binary_sha256s": hashes,
        },
        "target_executed": False,
        "ida_receipt_recorded": False,
        "support_status": "build_only_unmeasured",
    }


def build_pe(zig, output, environment):
    target = "x86_64-windows-gnu"
    commands = []
    artifacts = []
    for fresh in (1, 2):
        binary = output / f"fresh-{fresh}" / "formats" / "X64-LE" / "x64_pe.exe"
        binary.parent.mkdir(parents=True, exist_ok=True)
        command = common_command(zig, target) + [
            "-s",
            "-Wl,--entry,isa_profile_entry",
            "-Wl,--subsystem,console",
            str(SOURCE),
            "-o",
            str(binary),
        ]
        run(command, environment)
        info = pe_info(binary)
        exports = {item["name"]: item["rva"] for item in info["exports"]}
        if (
            (info["bits"], info["machine"], info["timestamp"]) != (64, 0x8664, 0)
            or set(exports) != set(FUNCTIONS)
            or len(set(exports.values())) != len(FUNCTIONS)
        ):
            raise RuntimeError(f"Unexpected PE identity: {info}")
        commands.append(normalize(command, output, zig))
        artifacts.append((binary, info, exports))
    hashes = [sha256(binary) for binary, _, _ in artifacts]
    if len(set(hashes)) != 1:
        raise RuntimeError("Non-reproducible X64 PE fixture")
    primary, info, exports = artifacts[0]
    if any(other_exports != exports for _, _, other_exports in artifacts[1:]):
        raise RuntimeError("Non-reproducible X64 PE export metadata")
    normalized = commands[0]
    return {
        "profile_id": "X64-LE",
        "profile_version": 1,
        "target_triple": target,
        "abi_id": "windows-x64",
        "bitness": 64,
        "data_endian": "LE",
        "instruction_endian": "LE",
        "mode": "X64",
        "processor": "metapc",
        "format": "FMT-PE",
        "platform_tag": "windows",
        "binary": primary.relative_to(output).as_posix(),
        "binary_sha256": hashes[0],
        "binary_size": primary.stat().st_size,
        "binary_header": info,
        "command": normalized,
        "command_sha256": command_hash(normalized),
        "function_selector": {
            "kind": "export_name",
            "value": "isa_scalar",
        },
        "function_selectors": [
            {
                "function": name,
                "kind": "export_name",
                "value": name,
                "rva": exports[name],
            }
            for name in FUNCTIONS
        ],
        "debug_info": "stripped for deterministic PE; no PDB required",
        "reproducibility": {
            "fresh_builds": 2,
            "binary_sha256_equal": True,
            "binary_sha256s": hashes,
        },
        "target_executed": False,
        "ida_receipt_recorded": False,
        "support_status": "build_only_unmeasured",
    }


def build_raw(zig, output, arm_row, environment):
    raws = []
    commands = []
    for fresh in (1, 2):
        elf = output / arm_row["binary"].replace("fresh-1", f"fresh-{fresh}")
        raw = output / f"fresh-{fresh}" / "formats" / "ARM32-LE" / "arm32_le.raw"
        raw.parent.mkdir(parents=True, exist_ok=True)
        command = [
            str(zig),
            "objcopy",
            "-O",
            "binary",
            "-j",
            ".text",
            str(elf),
            str(raw),
        ]
        run(command, environment)
        info = elf_info(elf)
        text = info["text"]
        functions = [elf_text_function(info, name) for name in FUNCTIONS]
        selectors = [
            {
                "function": function["name"],
                "kind": "raw_offset",
                "value": function["text_offset"],
                "size": function["size"],
            }
            for function in functions
        ]
        scalar_offset = selectors[0]["value"]
        if scalar_offset != 0:
            raise RuntimeError("ARM32 raw isa_scalar must start at .text offset zero")
        by_offset = sorted(selectors, key=lambda item: item["value"])
        for current, following in zip(by_offset, by_offset[1:]):
            if current["value"] + current["size"] > following["value"]:
                raise RuntimeError("ARM32 raw semantic functions overlap")
        expected = elf.read_bytes()[text["offset"] : text["offset"] + text["size"]]
        if raw.read_bytes() != expected:
            raise RuntimeError("ARM raw extraction does not equal ELF .text")
        commands.append(normalize(command, output, zig))
        raws.append((raw, info, scalar_offset, selectors))
    hashes = [sha256(raw) for raw, _, _, _ in raws]
    if len(set(hashes)) != 1:
        raise RuntimeError("Non-reproducible ARM32 raw fixture")
    primary, _info, entry_offset, function_selectors = raws[0]
    if any(
        (offset, selectors) != (entry_offset, function_selectors)
        for _, _, offset, selectors in raws[1:]
    ):
        raise RuntimeError("ARM32 raw function metadata is not reproducible")
    load_address = 0x10000
    normalized = commands[0]
    return {
        "profile_id": "ARM32-LE",
        "profile_version": 1,
        "abi_id": "aapcs32",
        "bitness": 32,
        "data_endian": "LE",
        "instruction_endian": "LE",
        "mode": "ARM32",
        "processor": "ARM",
        "format": "FMT-RAW",
        "platform_tag": "bare",
        "derived_from": arm_row["binary"],
        "derived_from_sha256": arm_row["binary_sha256"],
        "binary": primary.relative_to(output).as_posix(),
        "binary_sha256": hashes[0],
        "binary_size": primary.stat().st_size,
        "command": normalized,
        "command_sha256": command_hash(normalized),
        "raw_configuration": {
            "processor": "ARM",
            "bitness": 32,
            "data_endian": "LE",
            "instruction_endian": "LE",
            "mode": "ARM32",
            "load_address": load_address,
            "entry_offset": entry_offset,
            "entry_point": load_address + entry_offset,
            "source_section": ".text",
            "function_selector": {"kind": "raw_offset", "value": entry_offset},
        },
        "function_selectors": function_selectors,
        "reproducibility": {
            "fresh_builds": 2,
            "binary_sha256_equal": True,
            "binary_sha256s": hashes,
        },
        "target_executed": False,
        "ida_receipt_recorded": False,
        "support_status": "build_only_unmeasured",
    }


def build_macho(clang, clang_version, output, profile, environment):
    profile_id, arch, target, abi, mode, processor, cpu_type = profile
    commands = []
    artifacts = []
    for fresh in (1, 2):
        relative = (
            Path(f"fresh-{fresh}") / "formats" / profile_id / "isa_profile_anchor"
        )
        binary = contained_output(output, relative)
        command = [
            str(clang),
            "-arch",
            arch,
            "-O0",
            "-fno-stack-protector",
            "-Wl,-no_uuid",
            "-Wl,-no_adhoc_codesign",
            "-Wl,-e,_isa_profile_entry",
            str(MACHO_SOURCE),
            "-o",
            str(binary),
        ]
        run_apple_clang(command, environment, clang)
        info = macho_info(binary)
        required_symbols = {f"_{name}" for name in FUNCTIONS}
        symbol_rvas = {
            item["name"]: item["rva"]
            for item in info["defined_external_symbol_entries"]
        }
        if (
            (
                info["bits"],
                info["endian"],
                info["cpu_type"],
                info["file_type"],
            )
            != (64, "LE", cpu_type, 2)
            or not required_symbols.issubset(info["defined_external_symbols"])
            or len({symbol_rvas[name] for name in required_symbols})
            != len(required_symbols)
        ):
            raise RuntimeError(f"Unexpected Mach-O identity for {profile_id}: {info}")
        commands.append(normalize(command, output, clang, "$APPLE_CLANG"))
        artifacts.append((binary, info, symbol_rvas, sha256(binary)))
    resolved = [binary.resolve() for binary, _, _, _ in artifacts]
    if len(set(resolved)) != len(resolved):
        raise RuntimeError(f"Mach-O fresh-build paths alias: {profile_id}")
    hashes = [binary_hash for _, _, _, binary_hash in artifacts]
    if len(set(hashes)) != 1:
        raise RuntimeError(f"Non-reproducible Mach-O fixture: {profile_id}")
    primary, info, symbol_rvas, _ = artifacts[0]
    if any(other_rvas != symbol_rvas for _, _, other_rvas, _ in artifacts[1:]):
        raise RuntimeError(f"Non-reproducible Mach-O symbol metadata: {profile_id}")
    normalized = commands[0]
    return {
        "profile_id": profile_id,
        "profile_version": 1,
        "target_triple": target,
        "abi_id": abi,
        "bitness": 64,
        "data_endian": "LE",
        "instruction_endian": "LE",
        "mode": mode,
        "processor": processor,
        "format": "FMT-MACHO",
        "platform_tag": "darwin",
        "source": str(MACHO_SOURCE),
        "source_sha256": sha256(ROOT / MACHO_SOURCE),
        "binary": primary.relative_to(output).as_posix(),
        "binary_sha256": hashes[0],
        "binary_size": primary.stat().st_size,
        "binary_header": {
            "kind": info["kind"],
            "bits": info["bits"],
            "endian": info["endian"],
            "cpu_type": info["cpu_type"],
            "file_type": info["file_type"],
            "image_base": info["image_base"],
            "selected_symbol": "_isa_scalar",
            "semantic_symbols": [
                {"name": f"_{name}", "rva": symbol_rvas[f"_{name}"]}
                for name in FUNCTIONS
            ],
        },
        "compiler": {
            "command": "$APPLE_CLANG",
            "resolved_path": str(clang).replace(str(Path.home()), "~", 1),
            "version": clang_version,
            "sha256": sha256(clang),
        },
        "command": normalized,
        "command_sha256": command_hash(normalized),
        "function_selector": {
            "kind": "ida_name",
            "value": "_isa_scalar",
            "naming_convention": (
                "Mach-O external symbol with the object-format underscore prefix"
            ),
            "requires_companion": False,
        },
        "function_selectors": [
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
            for name in FUNCTIONS
        ],
        "companion_artifacts": [],
        "debug_info": "no debug info; global symbol retained; no dSYM required",
        "reproducibility": {
            "fresh_builds": 2,
            "binary_sha256_equal": True,
            "binary_sha256s": hashes,
        },
        "target_executed": False,
        "ida_receipt_recorded": False,
        "support_status": "build_only_unmeasured",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--zig", type=Path)
    parser.add_argument("--apple-clang", type=Path)
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    zig = resolve_zig(args.zig)
    version = subprocess.check_output([str(zig), "version"], text=True).strip()
    if not version.startswith("0.16."):
        raise RuntimeError(f"Expected Zig 0.16.x, got {version}")
    apple_clang, apple_clang_version = resolve_apple_clang(args.apple_clang)
    environment = dict(
        os.environ,
        LC_ALL="C",
        SOURCE_DATE_EPOCH="0",
        ZERO_AR_DATE="1",
    )
    rows = [build_elf(zig, output, profile, environment) for profile in PROFILES]
    arm_row = next(row for row in rows if row["profile_id"] == "ARM32-LE")
    variants = [
        build_pe(zig, output, environment),
        build_raw(zig, output, arm_row, environment),
    ]
    variants.extend(
        build_macho(
            apple_clang,
            apple_clang_version,
            output,
            profile,
            environment,
        )
        for profile in MACHO_PROFILES
    )
    manifest = {
        "schema_version": "flow-isa-profile-builds/1",
        "manifest_kind": "build_only",
        "source": str(SOURCE),
        "source_sha256": sha256(ROOT / SOURCE),
        "builder": Path(__file__).resolve().relative_to(ROOT).as_posix(),
        "builder_sha256": sha256(Path(__file__).resolve()),
        "compiler": {
            "command": "$ZIG",
            "resolved_path": str(zig).replace(str(Path.home()), "~", 1),
            "version": version,
            "sha256": sha256(zig),
        },
        "environment": {
            "LC_ALL": "C",
            "SOURCE_DATE_EPOCH": "0",
            "ZERO_AR_DATE": "1",
        },
        "profile_count": len(rows),
        "profiles": rows,
        "format_variants": variants,
        "target_executed": False,
        "new_profiles_advertised": [],
        "status": "builds_only_not_engine_validation",
    }
    (output / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
