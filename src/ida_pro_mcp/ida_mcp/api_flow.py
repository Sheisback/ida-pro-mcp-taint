"""Experimental bounded value/memory graph tools; no implicit/path/interprocedural APIs."""

import functools
import os
import platform
from typing import Literal, TypedDict

import ida_hexrays
import ida_ida
import ida_kernwin

from ida_pro_mcp.flow_core.build_identity import BUILD_ID, BUILD_SCOPE

from .rpc import tool
from .sync import idasync

SCHEMA_VERSION = "flow-capabilities/1"


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


class FlowErrorDetail(TypedDict):
    code: str


class FlowError(TypedDict):
    schema_version: Literal["flow-error/1"]
    error: FlowErrorDetail


class FlowJobSubmission(TypedDict):
    schema_version: Literal["flow-job/1"]
    job_id: str
    experimental: bool


class FlowJob(TypedDict):
    schema_version: Literal["flow-job/1"]
    id: str
    state: str
    revision: int
    progress: dict
    budget: dict
    error: dict | None
    result: dict | None


class FlowArtifactPage(TypedDict):
    schema_version: Literal["flow-page/1"]
    artifact_id: str
    section: str
    metadata: dict
    items: list[dict]
    next_cursor: str | None


class FlowTracePage(TypedDict):
    schema_version: Literal["flow-trace-page/1"]
    trace_id: str
    revision: int
    cursor: str
    items: list[dict]
    status: str
    frontier_remaining: int
    pending_remaining: int
    unresolved_count: int


class FlowByteRangeSpec(TypedDict):
    start: int
    end: int


class FlowMemoryReferenceSpec(TypedDict):
    object_id: str
    version_id: str
    address_space: str
    interval: FlowByteRangeSpec
    endian: Literal["little", "big"]


class FlowValueSourceSpec(TypedDict):
    kind: Literal["value"]
    node_id: str


class FlowMemorySourceSpec(TypedDict):
    kind: Literal["memory"]
    reference: FlowMemoryReferenceSpec


FlowSourceSpec = FlowValueSourceSpec | FlowMemorySourceSpec


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
    ready = False
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
    processor = ida_ida.inf_get_procname()
    bits = (
        64 if ida_ida.inf_is_64bit() else 32 if ida_ida.inf_is_32bit_exactly() else 16
    )
    endian = "big" if ida_ida.inf_is_be() else "little"
    try:
        target_supported = (
            os.name == "posix"
            and ready
            and ida_ida.inf_get_filetype() == ida_ida.f_MACHO
            and bits == 64
            and endian == "little"
            and processor in {"metapc", "ARM"}
        )
    except Exception:
        target_supported = False
    profile = "X64-LE" if processor == "metapc" else "A64-LE"
    support_status = (
        "available"
        if target_supported
        else "unverified"
        if probe["status"] == "unverified"
        else "unavailable"
    )
    support_reason = (
        f"Experimental {profile} Darwin Mach-O MMAT_CALLS scope for this open database"
        if target_supported
        else "Current database, host permission model, or Hex-Rays probe is outside the experimental X64-LE/A64-LE Darwin Mach-O scope"
    )
    features: dict[str, FlowFeature] = {
        name: {"status": "unavailable", "reason": "Not implemented in this build"}
        for name in (
            "snapshot",
            "value_ssa",
            "memory_ssa",
            "taint",
            "interprocedural",
            "implicit_flow",
            "path_proof",
            "durable_jobs",
        )
    }
    features["capability_discovery"] = {
        "status": "available",
        "reason": "This read-only discovery tool is registered",
    }
    features["microcode_extraction"] = {
        "status": "unverified",
        "reason": "No gen_microcode or maturity probe performed",
    }
    for name in (
        "snapshot",
        "value_ssa",
        "memory_ssa",
        "taint",
        "durable_jobs",
        "microcode_extraction",
    ):
        features[name] = {
            "status": support_status,
            "reason": support_reason,
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "build_id": BUILD_ID,
        "build_scope": BUILD_SCOPE,
        "environment": {
            "ida_version": ida_kernwin.get_kernel_version(),
            "python_version": platform.python_version(),
            "processor": processor,
            "bits": bits,
            "endian": endian,
            "hexrays_version": version,
            "hexrays_initialization": probe,
        },
        "features": features,
        "supported_profiles": [profile] if target_supported else [],
        "limitations": [
            "No ISA, ABI, maturity, or decompiler entitlement has been validated by this tool.",
            "This capability query performs no snapshot, SSA, taint, path proof, or target execution.",
            "Published traces include conservative intra-function byte-range memory dependencies; no call-summary, implicit-flow, or path-proof completeness is implied.",
            "Supported-anchor memory edges model successful flat user-space accesses; TLS/MMIO and null/fault path feasibility remain unresolved.",
            "MCP tools/call tracing can write the working IDB netnode; host close/save policy may persist it.",
            "Read-only describes program-analysis operations, not a byte-immutable IDB session; use working copies.",
        ],
    }


def _flow_api(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        from ida_pro_mcp.flow_core.serialization import ContractError

        try:
            return function(*args, **kwargs)
        except (ContractError, ValueError, OSError) as exc:
            code = str(exc)[:300]
            if code == "not_found":
                code = "wrong_database_or_unknown_id"
            return {"schema_version": "flow-error/1", "error": {"code": code}}

    return wrapped


def _service():
    # Import lazily: tools/list and discovery need neither an open IDB nor storage.
    from .flow import service

    return service


@tool
@_flow_api
def flow_create_snapshot(
    function: str, profile: str, request_key: str
) -> FlowJobSubmission | FlowError:
    """Queue an experimental MMAT_CALLS scalar snapshot for an exact function entry.

    Profiles: X64-LE or A64-LE, Darwin Mach-O only. No target execution or ABI
    argument inference. Reuse request_key only for the identical request.
    """
    return _service().create(function, profile, request_key)


@tool
@_flow_api
def flow_get_job(job_id: str) -> FlowJob | FlowError:
    """Read durable flow job state and artifact IDs in the current database."""
    return _service().job(job_id)


@tool
@_flow_api
def flow_cancel_job(job_id: str) -> FlowJob | FlowError:
    """Request cooperative cancellation; native extraction is not preemptible."""
    return _service().job(job_id, cancel=True)


@tool
@_flow_api
def flow_get_function_ssa(
    artifact_id: str, cursor: str | None = None, limit: int = 50
) -> FlowArtifactPage | FlowError:
    """Page SSA nodes and exposed logical memory references from a completed job."""
    return _service().page(artifact_id, "ssa", cursor, limit)


@tool
@_flow_api
def flow_get_cfg(
    artifact_id: str, cursor: str | None = None, limit: int = 50
) -> FlowArtifactPage | FlowError:
    """Page recovered CFG dominance records from the completed job's ssa_artifact."""
    return _service().page(artifact_id, "cfg", cursor, limit)


@tool
@_flow_api
def flow_get_graph(
    artifact_id: str, cursor: str | None = None, limit: int = 50
) -> FlowArtifactPage | FlowError:
    """Page immutable typed nodes and edges from the job's graph_artifact."""
    return _service().page(artifact_id, "graph", cursor, limit)


@tool
@_flow_api
def flow_get_evidence(
    artifact_id: str,
    evidence_ids: list[str] | None = None,
    cursor: str | None = None,
    limit: int = 50,
) -> FlowArtifactPage | FlowError:
    """Page graph evidence; unknown requested IDs are explicitly marked missing."""
    return _service().page(artifact_id, "evidence", cursor, limit, evidence_ids)


@tool
@_flow_api
def flow_trace_forward(
    snapshot_artifact: str,
    graph_artifact: str,
    source: FlowSourceSpec,
    request_key: str,
    edge_kinds: list[str] | None = None,
    budget: int = 10000,
    limit: int = 50,
) -> FlowTracePage | FlowError:
    """Forward typed value and byte-memory dependency reachability, not path proof.

    source is tagged: {kind: value, node_id: ...}; memory additionally requires
    an exposed graph memory reference. Unknown alias effects remain opaque/partial.
    """
    return _service().trace(
        snapshot_artifact,
        graph_artifact,
        source,
        "forward",
        request_key,
        edge_kinds
        if edge_kinds is not None
        else ["memory_data_dependency", "phi_input", "value_dependency"],
        budget,
        limit,
    )


@tool
@_flow_api
def flow_trace_backward(
    snapshot_artifact: str,
    graph_artifact: str,
    source: FlowSourceSpec,
    request_key: str,
    edge_kinds: list[str] | None = None,
    budget: int = 10000,
    limit: int = 50,
) -> FlowTracePage | FlowError:
    """Backward structural dependency reachability with explicit Unknown boundaries."""
    return _service().trace(
        snapshot_artifact,
        graph_artifact,
        source,
        "backward",
        request_key,
        edge_kinds
        if edge_kinds is not None
        else ["memory_data_dependency", "phi_input", "value_dependency"],
        budget,
        limit,
    )


@tool
@_flow_api
def flow_continue_trace(
    trace_id: str,
    expected_revision: int,
    cursor: str,
    request_key: str,
    limit: int = 50,
) -> FlowTracePage | FlowError:
    """Atomically continue/replay a durable trace page; stale revisions conflict."""
    return _service().continue_trace(
        trace_id, expected_revision, cursor, request_key, limit
    )


@tool
@_flow_api
def flow_cancel_trace(
    trace_id: str, expected_revision: int, cursor: str, request_key: str
) -> FlowTracePage | FlowError:
    """Revision-safe durable trace cancellation; completed traces are immutable."""
    return _service().continue_trace(
        trace_id, expected_revision, cursor, request_key, cancel=True
    )
