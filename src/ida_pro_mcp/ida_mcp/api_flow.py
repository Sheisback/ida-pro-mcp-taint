"""Experimental static flow-analysis tools with explicit boundedness contracts."""

import functools
import os
import platform
from typing import Any, Literal, TypedDict, cast

import ida_hexrays
import ida_ida
import ida_kernwin
import ida_loader
import ida_nalt

from ida_pro_mcp.flow_core.build_identity import BUILD_ID, BUILD_SCOPE
from .flow.profile_routing import observe_open_database
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


class FlowRouting(TypedDict):
    mode: str | None
    profile_id: str | None
    abi_id: str | None
    binary_digest: str | None


class FlowCapabilities(TypedDict):
    schema_version: str
    build_id: str
    build_scope: str
    environment: FlowEnvironment
    routing: FlowRouting
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


class FlowLabelSpec(TypedDict):
    explicit: list[str]
    control: list[str]
    unknown_provenance: bool
    any_explicit_source: bool
    any_control_source: bool


class FlowImplicitSeedSpec(TypedDict):
    node_id: str
    labels: FlowLabelSpec


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
    except Exception as exc:  # noqa: BLE001 - discovery must report arbitrary SDK failure.
        probe = {"status": "unverified", "reason": f"Hex-Rays probe failed: {exc}"}
    processor = ida_ida.inf_get_procname()
    bits = (
        64 if ida_ida.inf_is_64bit() else 32 if ida_ida.inf_is_32bit_exactly() else 16
    )
    endian = "big" if ida_ida.inf_is_be() else "little"
    resolved: dict[str, str] | None = None
    route_format: str | None = None
    route_error = "Hex-Rays initialization unavailable"
    try:
        if os.name == "posix" and ready:
            if version is None:
                raise RuntimeError("Hex-Rays version unavailable after initialization")
            observed = observe_open_database(
                ida_ida,
                ida_nalt,
                ida_build=ida_kernwin.get_kernel_version(),
                hexrays_build=version,
            )
            info = _service().resolve_observed_context(
                ida_loader.get_path(ida_loader.PATH_TYPE_IDB),
                observed,
                ida_ida.inf_get_database_change_count(),
            )
            resolved = cast(dict[str, str], info["routing"])
            route_format = observed.format_id
            target_supported = True
        else:
            target_supported = False
    except Exception as exc:  # noqa: BLE001 - discovery must fail closed, not abort.
        target_supported = False
        route_error = str(exc)
    support_status = (
        "available"
        if target_supported
        else "unverified"
        if probe["status"] == "unverified"
        else "unavailable"
    )
    if resolved is not None:
        assert route_format is not None
        if resolved["routing_mode"] == "analyst_selected":
            support_reason = (
                "Validated active analyst-selected route for "
                f"{resolved['profile_id']}/{resolved['abi_id']}/{route_format} at "
                "MMAT_CALLS; "
                "selection is bound to this database snapshot and runtime build"
            )
        else:
            support_reason = (
                "Experimental exact static-evidence route for "
                f"{resolved['profile_id']}/{resolved['abi_id']}/{route_format} at "
                "MMAT_CALLS"
            )
        supported_profiles = [resolved["profile_id"]]
        routing: FlowRouting = {
            "mode": resolved["routing_mode"],
            "profile_id": resolved["profile_id"],
            "abi_id": resolved["abi_id"],
            "binary_digest": resolved["binary_digest"],
        }
    else:
        support_reason = (
            "Current database has no validated active normal-profile route: "
            + route_error
        )
        supported_profiles = []
        routing = {
            "mode": None,
            "profile_id": None,
            "abi_id": None,
            "binary_digest": None,
        }
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
        "interprocedural",
        "implicit_flow",
        "path_proof",
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
        "routing": routing,
        "features": features,
        "supported_profiles": supported_profiles,
        "limitations": [
            "No ISA, ABI, maturity, or decompiler entitlement has been validated by this tool.",
            "This capability query performs no snapshot, SSA, taint, proof, call composition, or target execution.",
            "Implicit results publish explicit partial/frontier evidence; bounded proof results apply only to the artifact-bound declared constraint model.",
            "Interprocedural call compositions preserve unknown remainders; the default runtime summary catalog is empty and never implies whole-program completeness.",
            "No flow tool emits an automatic vulnerability or safety verdict.",
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


def _service() -> Any:
    # Import lazily: tools/list and discovery need neither an open IDB nor storage.
    from .flow import service

    return service


@tool
@_flow_api
def flow_create_snapshot(
    function: str,
    profile: str,
    request_key: str,
    abi: str | None = None,
    routing_mode: str = "exact_fixture",
) -> FlowJobSubmission | FlowError:
    """Queue an experimental MMAT_CALLS snapshot for an exact function entry.

    ``exact_fixture`` requires the open input to match frozen static semantic
    evidence. ``analyst_selected`` accepts another binary only when ``profile``
    and ``abi`` are explicit and its observed processor, bitness, endianness,
    format, and exact IDA/Hex-Rays builds match reviewed normal evidence. The
    current binary digest scopes all runtime state; selection never promotes
    support or infers an ABI. RV32 has no normal route and is rejected. Reuse
    ``request_key`` only for the identical request.
    """
    return _service().create(function, profile, request_key, abi, routing_mode)


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
def flow_create_implicit_analysis(
    ssa_artifact: str,
    seeds: list[FlowImplicitSeedSpec],
    request_key: str,
    max_evaluations: int = 100000,
) -> FlowJobSubmission | FlowError:
    """Queue seeded explicit-plus-control propagation over an owned SSA artifact.

    Control provenance remains distinct from explicit provenance. Partial CFG or
    budget coverage is returned as partial with a concrete frontier; it is never
    interpreted as evidence that no implicit flow exists.
    """
    return _service().create_implicit(ssa_artifact, seeds, request_key, max_evaluations)


@tool
@_flow_api
def flow_create_path_proof(
    graph_artifact: str, query: dict, request_key: str
) -> FlowJobSubmission | FlowError:
    """Queue an artifact-bound finite proof of a declared bounded constraint model.

    Exact SAT requires independent witness replay; only exhaustive exact bounded
    UNSAT can become infeasible. Sound-overapproximate or incomplete evidence is
    Unknown. Results are constraint-model facts, never vulnerability verdicts.
    """
    return _service().create_path_proof(graph_artifact, query, request_key)


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
def flow_get_implicit_analysis(
    artifact_id: str, cursor: str | None = None, limit: int = 50
) -> FlowArtifactPage | FlowError:
    """Page implicit facts, control relations, and any unresolved frontier."""
    return _service().analysis_page(artifact_id, "implicit", cursor, limit)


@tool
@_flow_api
def flow_get_path_proof(
    artifact_id: str, cursor: str | None = None, limit: int = 50
) -> FlowArtifactPage | FlowError:
    """Page a bounded proof result with exact/overapprox/incomplete distinctions."""
    return _service().analysis_page(artifact_id, "path_proof", cursor, limit)


@tool
@_flow_api
def flow_get_call_compositions(
    artifact_id: str, cursor: str | None = None, limit: int = 50
) -> FlowArtifactPage | FlowError:
    """Page bounded call bindings/compositions, including unknown remainders."""
    return _service().analysis_page(artifact_id, "interprocedural", cursor, limit)


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
