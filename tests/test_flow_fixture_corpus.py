"""Independent fixture-oracle and static receipt integrity checks."""

import hashlib
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "tests/flow_fixtures"


def read(path):
    return json.loads((BASE / path).read_text())


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def test_oracle_coverage_and_nonempty_contracts():
    cases = read("oracles/s0.json")["cases"]
    expected = {
        "s0_" + x
        for x in (
            "scalar",
            "phi",
            "overwrite",
            "partial",
            "alias",
            "merge",
            "output",
            "unknown",
        )
    }
    assert {c["function_id"] for c in cases} == expected
    assert (
        set(re.findall(r"KEEP \w+ (s0_\w+)\(", (BASE / "s0.c").read_text())) == expected
    )
    all_cases = cases + [read("oracles/sum_point.json")]
    assert len({c["oracle_id"] for c in all_cases}) == 9
    for case in all_cases:
        for key in (
            "preconditions",
            "expected_relations",
            "forbidden_relations",
            "widths",
            "seeds",
        ):
            assert case[key]
        assert "hand-authored" in case["oracle_origin"]


def test_sum_point_byte_range_oracle():
    oracle = read("oracles/sum_point.json")
    assert oracle["layout"]["fields"] == {"x": [0, 4], "y": [4, 8], "tag": [8, 9]}
    assert oracle["layout"]["padding"] == [[9, 12]]
    assert oracle["seeds"] == {"arg0.memory[0,4)": "X"}
    assert "not_engine_validation" in oracle["status"]


def test_build_receipts_and_no_target_execution():
    for row in read("manifests/s0_build.json"):
        assert (
            row["source_sha256"]
            == hashlib.sha256((ROOT / row["source"]).read_bytes()).hexdigest()
        )
        assert row["command"][0] == "x86_64-w64-mingw32-gcc"
        assert "-Wl,--no-insert-timestamp" in row["command"]
        assert "-frandom-seed=flow-s0" in row["command"]
        assert row["environment"] == {"SOURCE_DATE_EPOCH": "0"}
        assert row["reproducibility"]["fresh_builds"] == 2
        assert row["reproducibility"]["binary_sha256_equal"] is True
        assert row["target_executed"] is False
        assert row["debug_info"] == "embedded DWARF; no PDB"
        assert row["companion_artifacts"] == []
        if row["source"] == "tests/typed_fixture.c":
            check = row["layout_check"]
            assert check["status"] == "passed" and "-fsyntax-only" in check["command"]
            assert (
                check["source_sha256"]
                == hashlib.sha256(
                    (ROOT / check["command"][-1]).read_bytes()
                ).hexdigest()
            )
    elf = read("manifests/typed_elf.json")
    for path_key, hash_key in [
        ("source", "source_sha256"),
        ("binary", "binary_sha256"),
    ]:
        assert (
            elf[hash_key]
            == hashlib.sha256((ROOT / elf[path_key]).read_bytes()).hexdigest()
        )


def test_actual_sum_point_receipts_have_three_field_loads():
    probe_path = ROOT / "src/ida_pro_mcp/ida_mcp/flow/p0_probe.py"
    spec = importlib.util.spec_from_file_location("s0_receipt_probe", probe_path)
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    builds = read("manifests/s0_build.json")
    for inspection in read("manifests/sum_point_inspection.json"):
        receipt = read("manifests/" + inspection["probe_receipt"])
        assert receipt["implementation_sha256"] == probe.LEGACY_IMPLEMENTATION_SHA256
        for entry in receipt["probes"]:
            payload = {
                k: v for k, v in entry.items() if k not in ("digest", "repeat_equal")
            }
            assert entry["digest"] == probe.digest(payload)
        assert receipt["binary"]["sha256"] == inspection["binary_sha256"]
        expected_hash = (
            read("manifests/typed_elf.json")["binary_sha256"]
            if inspection["format"] == "elf"
            else next(
                b["binary_sha256"]
                for b in builds
                if b["source"] == "tests/typed_fixture.c"
            )
        )
        assert receipt["binary"]["sha256"] == expected_hash
        assert receipt["function_name"] == "sum_point"
        assert receipt["target_executed"] is False
        p = receipt["probes"][0]
        assert p["maturity"] == "MMAT_CALLS" and p["status"] == "success"
        assert p["repeat_equal"] is True and p["warnings"] == []
        loads = {
            node["ea"]: node
            for node in walk(p["blocks"])
            if node.get("opcode") == "m_ldx"
        }
        assert len(loads) == 3
        assert [
            (s["offset_bytes"], s["width_bytes"]) for s in inspection["load_sites"]
        ] == [(0, 4), (4, 4), (8, 1)]
        for site in inspection["load_sites"]:
            assert loads[site["ea"]]["operands"][2]["size"] == site["width_bytes"]
            assert site["ea"] is not None
        assert p["source_map"]["top_level_with_ea"] > 0


def test_builder_invokes_compiler_only(monkeypatch, tmp_path):
    import sys

    spec = importlib.util.spec_from_file_location(
        "s0_builder_test", ROOT / "scripts/build_flow_s0.py"
    )
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    compiler = tmp_path / "compiler"
    compiler.write_bytes(b"mock compiler")
    calls = []

    def check_output(command, **kwargs):
        assert command in (
            [builder.COMPILER, "--version"],
            ["/usr/bin/which", builder.COMPILER],
        )
        return "test compiler" if command[-1] == "--version" else str(compiler)

    def run(command, **kwargs):
        assert command[0] == builder.COMPILER
        assert kwargs["check"] is True
        assert kwargs["cwd"] == ROOT
        if "-fsyntax-only" in command:
            calls.append(command)
            return
        assert kwargs["env"]["SOURCE_DATE_EPOCH"] == "0"
        assert command[-2] == "-o"
        Path(command[-1]).write_bytes(b"mock PE, never executable")
        calls.append(command)

    monkeypatch.setattr(builder.subprocess, "check_output", check_output)
    monkeypatch.setattr(builder.subprocess, "run", run)
    monkeypatch.setattr(sys, "argv", ["builder", str(tmp_path / "output")])
    builder.main()
    assert len(calls) == 3
    result = json.loads((tmp_path / "output/build.json").read_text())
    assert len(result) == 2 and all(r["target_executed"] is False for r in result)
