"""Record one fresh, non-executing licensed-IDA CI receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


SHA1 = re.compile(r"[0-9a-f]{40}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(fixture: Path, output: Path, checkout_sha: str) -> dict[str, object]:
    if not fixture.is_file():
        raise ValueError("Fixture does not exist")
    if SHA1.fullmatch(checkout_sha) is None:
        raise ValueError("checkout_sha must be a full lowercase commit SHA")
    before = sha256(fixture)

    import ida_auto  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    import ida_kernwin  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    import ida_nalt  # pyright: ignore[reportMissingImports, reportMissingModuleSource]
    import idapro  # pyright: ignore[reportMissingImports, reportMissingModuleSource]

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
        receipt: dict[str, object] = {
            "schema_version": "flow-licensed-ci/1",
            "checkout_sha": checkout_sha,
            "fixture": fixture.name,
            "fixture_sha256": before,
            "ida_input_sha256": ida_input,
            "ida_version": ida_kernwin.get_kernel_version(),
            "flow_build_id": capabilities["build_id"],
            "capabilities_digest": digest(capabilities),
            "environment": capabilities["environment"],
            "supported_profiles": capabilities["supported_profiles"],
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
    arguments = parser.parse_args()
    receipt = record(
        arguments.fixture.resolve(),
        arguments.output.resolve(),
        arguments.checkout_sha,
    )
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
