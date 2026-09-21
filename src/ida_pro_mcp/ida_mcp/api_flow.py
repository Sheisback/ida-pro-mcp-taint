"""Read-only flow capability discovery; no analysis tools are exposed yet."""

import hashlib
import platform
from pathlib import Path
from typing import TypedDict

import ida_hexrays
import ida_ida
import ida_kernwin

from .rpc import tool
from .sync import idasync

SCHEMA_VERSION = "flow-capabilities/1"
# Content identity works in both installed GUI packages and wheels, without git.
BUILD_ID = "flow-p0-sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


class FlowFeature(TypedDict):
    status: str
    reason: str


class FlowEnvironment(TypedDict):
    ida_version: str
    python_version: str
    processor: str
    bits: int
    endian: str
    hexrays_version: str | None
    hexrays_initialization: FlowFeature


class FlowCapabilities(TypedDict):
    schema_version: str
    build_id: str
    build_scope: str
    environment: FlowEnvironment
    features: dict[str, FlowFeature]
    supported_profiles: list[str]
    limitations: list[str]


@tool
@idasync
def flow_get_capabilities() -> FlowCapabilities:
    """Report this worker's flow extension build, runtime facts, and analysis limits.

    Hex-Rays initialization is probed without decompiling or running the target.
    Initialization does not prove a license or microcode support for any ISA.
    The tool does not edit program data, but MCP call tracing can write a working
    IDB netnode and the host's close/save policy can persist it. Use disposable
    working copies when original IDBs must remain unchanged.
    """
    version = None
    try:
        ready = bool(ida_hexrays.init_hexrays_plugin())
        probe: FlowFeature = {
            "status": "available" if ready else "unavailable",
            "reason": "init_hexrays_plugin returned " + str(ready),
        }
        if ready:
            version = ida_hexrays.get_hexrays_version()
    except Exception as exc:
        probe = {"status": "unverified", "reason": f"Hex-Rays probe failed: {exc}"}
    features: dict[str, FlowFeature] = {
        name: {"status": "unavailable", "reason": "Not implemented in this build"}
        for name in (
            "snapshot", "value_ssa", "memory_ssa", "taint", "interprocedural",
            "implicit_flow", "path_proof", "durable_jobs",
        )
    }
    features["capability_discovery"] = {
        "status": "available", "reason": "This read-only discovery tool is registered"
    }
    features["microcode_extraction"] = {
        "status": "unverified", "reason": "No gen_microcode or maturity probe performed"
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "build_id": BUILD_ID,
        "build_scope": "api_flow.py source bytes; not an upstream or core build digest",
        "environment": {
            "ida_version": ida_kernwin.get_kernel_version(),
            "python_version": platform.python_version(),
            "processor": ida_ida.inf_get_procname(),
            "bits": 64 if ida_ida.inf_is_64bit() else 32 if ida_ida.inf_is_32bit_exactly() else 16,
            "endian": "big" if ida_ida.inf_is_be() else "little",
            "hexrays_version": version,
            "hexrays_initialization": probe,
        },
        "features": features,
        "supported_profiles": [],
        "limitations": [
            "No ISA, ABI, maturity, or decompiler entitlement has been validated by this tool.",
            "No SSA, taint, snapshot, path proof, or target execution is performed.",
            "MCP tools/call tracing can write the working IDB netnode; host close/save policy may persist it.",
            "Read-only describes program-analysis operations, not a byte-immutable IDB session; use working copies.",
        ],
    }
