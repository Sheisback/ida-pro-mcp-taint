"""Static IDA 9.3 pointee-byte and typed Store evidence integration probe.

PYTHONPATH=src:. uv run python tests/flow_core/native_pointee_store_probe.py OUTPUT
Never executes the fixture. dSYM/IDB type correctness is an analyst assumption.
This diagnostic does not promote any platform to release-supported status.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from ida_pro_mcp import idalib_supervisor as sm
from ida_pro_mcp.flow_core.build_identity import BUILD_ID
from native_taint_scenarios import Client
from native_typed_macho_smoke import ROOT, sha

SOURCE = ROOT / "tests/flow_fixtures/pointee_store.c"
LABEL = {
    "explicit": ["BUFFER"],
    "control": [],
    "unknown_provenance": False,
    "any_explicit_source": False,
    "any_control_source": False,
}


def build(directory, arch):
    directory.mkdir(parents=True)
    obj, binary = directory / "pointee_store.o", directory / "pointee_store"
    flags = [
        "-arch",
        arch,
        "-O1",
        "-g",
        "-fno-builtin",
        "-fno-stack-protector",
        "-fdebug-compilation-dir=.",
        f"-ffile-prefix-map={ROOT}=.",
    ]
    subprocess.run(["clang", *flags, "-c", str(SOURCE), "-o", str(obj)], check=True)
    os.utime(obj, (0, 0))
    subprocess.run(
        [
            "clang",
            "-arch",
            arch,
            "-g",
            "-Wl,-no_uuid",
            f"-Wl,-oso_prefix,{directory}/",
            str(obj),
            "-o",
            str(binary),
        ],
        check=True,
    )
    subprocess.run(
        ["dsymutil", "--oso-prepend-path", str(directory), str(binary)], check=True
    )
    dwarf = Path(str(binary) + ".dSYM/Contents/Resources/DWARF/" + binary.name)
    assert dwarf.is_file()
    return binary, dwarf, flags


def snapshot(client, function, profile, abi):
    result = client.wait(
        client.call(
            "flow_create_snapshot",
            function=function,
            profile=profile,
            abi=abi,
            routing_mode="analyst_selected",
            request_key=function,
        )
    )
    assert result["target_executed"] is False
    nodes, metadata = client.pages(
        "flow_get_function_ssa", artifact_id=result["ssa_artifact"]
    )
    return {
        "function": function,
        "snapshot": result,
        "nodes": nodes,
        "ssa_metadata": metadata,
    }


def pointee(client, row):
    nodes = row["nodes"]
    loads = [n for n in nodes if n["kind"] == "Load"]
    # The fixture has precisely one pointer Load before its Store and final data Load.
    assert len(loads) == 2, loads
    stores = [n for n in nodes if n["kind"] == "Store"]
    assert len(stores) == 1
    pointer = next(
        n for n in loads if n["node_id"] == stores[0]["memory_operands"]["address"]
    )
    seed = {
        "kind": "pointee_range",
        "schema_version": 1,
        "pointer_node_id": pointer["node_id"],
        "interval": {"start": 0, "end": 8},
        "labels": LABEL,
        "binding_mode": "analyst_assumed_exact",
        "point": "after_pointer_definition",
    }
    row["seed"] = seed
    result = client.wait(
        client.call(
            "flow_create_implicit_analysis",
            ssa_artifact=row["snapshot"]["ssa_artifact"],
            seeds=[seed],
            request_key="pointee",
        )
    )
    row["implicit_result"] = result
    facts, metadata = client.pages(
        "flow_get_implicit_analysis", artifact_id=result["implicit_artifact"]
    )
    row["implicit_items"], row["implicit_metadata"] = facts, metadata
    items, meta = client.pages(
        "flow_get_pointee_evidence", artifact_id=result["pointee_certificate_artifact"]
    )
    row["certificate_items"], row["certificate_metadata"] = items, meta
    observed = [n for n in nodes if n["kind"] == "Return"]
    assert len(observed) == 1
    target = observed[0]["node_id"]
    items, meta = client.pages(
        "flow_explain_implicit_analysis",
        artifact_id=result["implicit_artifact"],
        observation_node_id=target,
    )
    row["explanation_items"], row["explanation_metadata"] = items, meta
    data_load = next(n for n in loads if n["node_id"] != pointer["node_id"])
    for name, node_id in (("return_fact", target), ("load_fact", data_load["node_id"])):
        fact = next(f for f in facts if f["type"] == "fact" and f["node_id"] == node_id)
        row[name] = fact
        assert fact["labels"]["explicit"] == ["BUFFER"], fact
        assert [
            (r["bit_offset"], r["width_bits"]) for r in fact["explicit_bit_ranges"]
        ] == [(32, 32)], fact
    # Unknown provenance is retained: precise explicit byte ranges alone do not
    # establish absence of alias or other unresolved memory effects.


def store(client, row):
    stores = [n for n in row["nodes"] if n["kind"] == "Store"]
    assert len(stores) == 1, stores
    binding = next(
        b for b in row["ssa_metadata"]["argument_bindings"] if b["argument_index"] == 0
    )
    assert len(binding["entry_node_ids"]) == 1, binding
    result = client.wait(
        client.call(
            "flow_check_store",
            ssa_artifact=row["snapshot"]["ssa_artifact"],
            store_node_id=stores[0]["node_id"],
            base_node_id=binding["entry_node_ids"][0],
            byte_offset=120,
            target_function="callback_target",
            member_path=["slots", 14],
            request_key="proof-" + row["function"],
        )
    )
    row["store_result"] = result
    items, meta = client.pages(
        "flow_check_store", artifact_id=result["store_evidence_artifact"]
    )
    row["store_items"], row["store_metadata"] = items, meta
    observation = next(item for item in items if item["type"] == "observation")
    assert observation["function_observation"]["exact_entry"] is True
    layout = observation["layout_observation"]
    assert layout["status"] == "observed", layout
    assert (layout["byte_offset"], layout["width_bits"]) == (120, 64), layout
    expected_status, expected_reason = {
        "register_callback": ("proven_in_scope", None),
        "register_truncated": ("unknown", "non_pointer_width_expression"),
        "register_changed": ("mismatch", "observed_relation_differs_from_request"),
    }[row["function"]]
    assert result["status"] == expected_status, (result, items[:2])
    proof = next(item for item in items if item["type"] == "proof")
    assert proof["reasons"] == ([] if expected_reason is None else [expected_reason]), (
        proof
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--arch", choices=("x86_64", "arm64"), action="append")
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix="flow-pointee-store-", dir="/private/tmp"))
    os.environ["IDA_MCP_FLOW_STATE_ROOT"] = str(work / "state")
    supervisor = sm.IdalibSupervisor(
        sm.mcp,
        max_workers=1,
        worker_args=["--profile", str(ROOT / "profiles/flow-readonly.txt")],
    )
    sm.supervisor = supervisor
    report = {
        "schema_version": "flow-pointee-store-probe/1",
        "target_executed": False,
        "build_id": BUILD_ID,
        "source_sha256": sha(SOURCE),
        "runner_sha256": sha(__file__),
        "compiler": subprocess.check_output(["clang", "--version"], text=True).strip(),
        "sdk_version": subprocess.check_output(
            ["xcrun", "--show-sdk-version"], text=True
        ).strip(),
        "work_directory": str(work),
        "runs": [],
        "assumptions": [
            "current IDB/dSYM types are analyst assumptions",
            "pointee binding is analyst_assumed_exact",
        ],
        "limitations": [
            "Store site if reached, not path feasibility or final callback registration",
            "Darwin Mach-O fixture is not Windows driver validation",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        for arch in args.arch or ["x86_64", "arm64"]:
            profile, abi = (
                ("X64-LE", "darwin-x86_64-sysv-derived")
                if arch == "x86_64"
                else ("A64-LE", "darwin-aarch64")
            )
            built, dwarf, flags = build(work / arch, arch)
            analysis = work / "analysis" / arch
            analysis.mkdir(parents=True)
            binary = analysis / built.name
            shutil.copy2(built, binary)
            shutil.copytree(str(built) + ".dSYM", str(binary) + ".dSYM")
            row = {
                "arch": arch,
                "optimization": "O1",
                "profile": profile,
                "abi": abi,
                "format": "FMT-MACHO",
                "binary_sha256": sha(built),
                "dwarf_sha256": sha(dwarf),
                "compiler_flags": flags,
                "functions": [],
            }
            report["runs"].append(row)
            session = supervisor.open_session(str(binary), mode="force_headless")
            try:
                client = Client(sm, session.session_id, 0)
                caps = client.call("flow_get_capabilities")
                row["environment"], row["worker_build_id"] = (
                    caps["environment"],
                    caps["build_id"],
                )
                assert caps["build_id"] == BUILD_ID
                assert caps["environment"]["ida_version"] == "9.3"
                for function in (
                    "pointee_partial_clear",
                    "register_callback",
                    "register_truncated",
                    "register_changed",
                ):
                    case = snapshot(client, function, profile, abi)
                    row["functions"].append(case)
                    try:
                        (pointee if function == "pointee_partial_clear" else store)(
                            client, case
                        )
                        case["passed"] = True
                    except AssertionError as exc:
                        case["passed"] = False
                        case["error"] = repr(exc)
                    print(
                        arch, function, "PASS" if case["passed"] else "FAIL", flush=True
                    )
            finally:
                supervisor.close_session(session.session_id, save=False)
                row["closed_save_false"] = True
                row["input_preserved"] = sha(binary) == sha(built)
                assert row["input_preserved"]
        report["passed"] = all(
            case["passed"] for row in report["runs"] for case in row["functions"]
        )
        assert report["passed"], "Native feature assertions failed; see receipt"
    except Exception as exc:
        report["error"] = repr(exc)
        raise
    finally:
        for database in list(supervisor.sessions):
            supervisor.close_session(database, save=False)
        supervisor.shutdown()
        args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
