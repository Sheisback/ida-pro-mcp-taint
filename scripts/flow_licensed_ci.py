"""Record one fresh, non-executing licensed-IDA CI receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


SHA1 = re.compile(r"[0-9a-f]{40}")
PROFILE_ID = re.compile(r"[A-Z0-9]+(?:-[A-Z0-9]+)+")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(
    fixture: Path,
    output: Path,
    checkout_sha: str,
    *,
    profile_id: str,
    abi_id: str,
    format_id: str,
    maturity: str,
) -> dict[str, object]:
    if not fixture.is_file():
        raise ValueError("Fixture does not exist")
    if SHA1.fullmatch(checkout_sha) is None:
        raise ValueError("checkout_sha must be a full lowercase commit SHA")
    if PROFILE_ID.fullmatch(profile_id) is None:
        raise ValueError("profile_id must be a canonical profile identifier")
    if not abi_id or format_id not in {"FMT-ELF", "FMT-PE", "FMT-MACHO", "FMT-RAW"}:
        raise ValueError("abi_id and format_id must identify the expected row")
    if maturity != "MMAT_CALLS":
        raise ValueError("licensed release evidence requires MMAT_CALLS")
    before = sha256(fixture)

    # idapro initializes the standalone IDAPython runtime.  Importing SDK
    # modules before it is unsupported and fails outside an IDA-launched Python.
    import idapro  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    import ida_auto  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    import ida_kernwin  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    import ida_nalt  # pyright: ignore[reportMissingImports, reportMissingModuleSource]

    sdk_file = Path(ida_kernwin.__file__).resolve()
    ida_executable = sdk_file.parent.parent / "idat"
    if not ida_executable.is_file():
        raise RuntimeError("Loaded IDA runtime has no matching idat executable")

    if idapro.open_database(str(fixture), run_auto_analysis=True):
        raise RuntimeError("IDA failed to open the fixture")
    try:
        ida_auto.auto_wait()
        from ida_pro_mcp.flow_core.serialization import digest
        from ida_pro_mcp.ida_mcp import api_flow

        capabilities = api_flow.flow_get_capabilities()
        ida_input = bytes(ida_nalt.retrieve_input_file_sha256()).hex()
        if ida_input != before:
            raise RuntimeError("IDA opened different input bytes")
        supported_profiles = capabilities["supported_profiles"]
        # Discovery alone cannot prove a normal microcode row. A strict release
        # may accept ``pass`` only from a producer that ran that mandatory row.
        normal_status = "unknown"
        receipt: dict[str, object] = {
            "schema_version": "flow-licensed-ci/2",
            "checkout_sha": checkout_sha,
            "fixture": fixture.name,
            "fixture_sha256": before,
            "ida_input_sha256": ida_input,
            "profile_id": profile_id,
            "abi_id": abi_id,
            "format_id": format_id,
            "maturity": maturity,
            "normal_status": normal_status,
            "ida_build": ida_kernwin.get_kernel_version(),
            "ida_executable_sha256": sha256(ida_executable),
            "hexrays_build": capabilities["environment"]["hexrays_version"],
            "flow_build_id": capabilities["build_id"],
            "capabilities": capabilities,
            "capabilities_digest": digest(capabilities),
            "environment": capabilities["environment"],
            "supported_profiles": supported_profiles,
            "input_preserved": True,
            "target_executed": False,
            "debugger_attached": False,
        }
    finally:
        idapro.close_database()

    if sha256(fixture) != before:
        raise RuntimeError("Licensed CI changed the owned fixture")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checkout-sha", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--abi", required=True)
    parser.add_argument("--format", required=True, dest="format_id")
    parser.add_argument("--maturity", default="MMAT_CALLS")
    arguments = parser.parse_args()
    receipt = record(
        arguments.fixture.resolve(),
        arguments.output.resolve(),
        arguments.checkout_sha,
        profile_id=arguments.profile,
        abi_id=arguments.abi,
        format_id=arguments.format_id,
        maturity=arguments.maturity,
    )
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
