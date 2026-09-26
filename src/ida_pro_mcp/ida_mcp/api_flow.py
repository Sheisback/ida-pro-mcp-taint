"""Experimental static flow-analysis tools with explicit boundedness contracts."""

import functools
import os
import platform
from typing import Any, Literal, NotRequired, TypedDict, cast

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
    supported_profiles: list[str]  # Excludes unverified analyst-selected routes.
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


FlowTaggedInt = TypedDict("FlowTaggedInt", {"$int": str})
FlowWireInt = int | FlowTaggedInt


class FlowJob(TypedDict):
    schema_version: Literal["flow-job/1"]
    id: str
    state: str
    revision: FlowWireInt
    progress: dict
    budget: dict
    error: dict | None
    result: dict | None
    wire_version: NotRequired[Literal["flow-wire/2"]]


class FlowArtifactPage(TypedDict):
    schema_version: Literal["flow-page/1"]
    artifact_id: str
    section: str
    metadata: dict
    items: list[dict]
    next_cursor: str | None


class FlowGraphBytesPage(TypedDict):
    schema_version: Literal["flow-graph-bytes/1"]
    artifact_id: str
    snapshot_id: str
    graph_digest: str
    identity_version: int
    build_id: str
    total_bytes: int
    offset: int
    byte_count: int
    chunk_base64url: str
    next_cursor: str | None


class FlowTracePage(TypedDict):
    schema_version: Literal["flow-trace-page/1"]
    trace_id: str
    revision: FlowWireInt
    cursor: str
    items: list[dict]
    status: str
    frontier_remaining: FlowWireInt
    pending_remaining: FlowWireInt
    unresolved_count: FlowWireInt
    wire_version: NotRequired[Literal["flow-wire/2"]]
    snapshot_id: NotRequired[str]


class FlowByteRangeSpec(TypedDict):
    start: FlowWireInt
    end: FlowWireInt


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


class FlowImplicitBitSeedSpec(TypedDict):
    kind: Literal["bit_range"]
    schema_version: Literal[1] | FlowTaggedInt
    node_id: str
    labels: FlowLabelSpec
    bit_offset: FlowWireInt
    width_bits: FlowWireInt


class FlowPointeeSeedSpec(TypedDict):
    kind: Literal["pointee_range"]
    schema_version: Literal[1] | FlowTaggedInt
    pointer_node_id: str
    interval: FlowByteRangeSpec
    labels: FlowLabelSpec
    binding_mode: Literal["analyst_assumed_exact", "require_program_derived_exact"]
    point: Literal["after_pointer_definition"]


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
    reviewed_calls = False
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
            reviewed_calls = bool(_service().reviewed_catalog(info).summaries)
            route_format = observed.format_id
            route_ready = True
        else:
            route_ready = False
    except Exception as exc:  # noqa: BLE001 - discovery must fail closed, not abort.
        route_ready = False
        route_error = str(exc)
    analyst_route_only = (
        resolved is not None and resolved["routing_mode"] == "analyst_selected"
    )
    if analyst_route_only:
        support_status = "unverified"
    elif route_ready:
        support_status = "available"
    elif probe["status"] == "unverified":
        support_status = "unverified"
    else:
        support_status = "unavailable"
    if resolved is not None:
        assert route_format is not None
        if resolved["routing_mode"] == "analyst_selected":
            support_reason = (
                "Matched active analyst-selected route for "
                f"{resolved['profile_id']}/{resolved['abi_id']}/{route_format} at "
                "MMAT_CALLS; "
                "selection is bound to this database snapshot and runtime build, "
                "but no current-binary extraction is proven by this query; "
                "inspect a completed flow_get_job result"
            )
        else:
            support_reason = (
                "Experimental exact static-evidence route for "
                f"{resolved['profile_id']}/{resolved['abi_id']}/{route_format} at "
                "MMAT_CALLS"
            )
        supported_profiles = [] if analyst_route_only else [resolved["profile_id"]]
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
    features["interprocedural"] = {
        "status": (
            "unverified"
            if analyst_route_only and reviewed_calls
            else "available"
            if route_ready and reviewed_calls
            else "unavailable"
        ),
        "reason": (
            "Packaged reviewed summaries match this route, but current-binary "
            "extraction remains unverified; inspect a completed flow_get_job result"
            if analyst_route_only and reviewed_calls
            else "Packaged owned-fixture reviewed summaries with fresh full-identity "
            "callee checks and bounded closure; unresolved remainders stay partial"
            if route_ready and reviewed_calls
            else "No reviewed summary catalog for this runtime scope; call observations "
            "remain available as conservative Unknown compositions"
        ),
    }
    try:
        from ida_pro_mcp.flow_core.angr_client import sidecar_from_environment

        solver_ready = sidecar_from_environment().probe() is None
    except Exception:  # noqa: BLE001 - discovery must fail closed, not abort.
        solver_ready = False
    features["symbolic_refinement"] = {
        "status": (
            "available"
            if route_ready and solver_ready
            else "unavailable"
        ),
        "reason": (
            "Opt-in angr path refinement over v1 proofs; sidecar runs "
            "only when an explicit refinement tier requests it"
            if route_ready and solver_ready
            else "Refinement unavailable: "
            + (
                "no validated route"
                if not route_ready
                else "angr sidecar not configured (IDA_MCP_ANGR_PYTHON)"
            )
            + "; v1 proofs remain available and engine-free"
        ),
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
            "An analyst-selected route is configuration eligibility, not current-binary extraction success; only a completed flow_get_job result supplies that evidence.",
            "Implicit results publish explicit partial/frontier evidence; bounded proof results apply only to program-derived CFG-prefix constraints; unsupported correspondence remains Unknown.",
            "Reviewed call effects are restricted to packaged owned fixtures; arbitrary libraries and unresolved callees remain Unknown, never whole-program completeness.",
            "No flow tool emits an automatic vulnerability or safety verdict.",
            "Supported-anchor memory edges model successful flat user-space accesses; TLS/MMIO and null/fault path feasibility remain unresolved.",
            "MCP tools/call tracing can write the working IDB netnode; host close/save policy may persist it.",
            "Read-only describes program-analysis operations, not a byte-immutable IDB session; use working copies.",
        ],
    }


def _flow_api(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        from ida_pro_mcp.flow_core.serialization import (
            ContractError,
            ensure_wire_v1_safe,
            to_wire_v2,
        )
        from ida_pro_mcp.flow_core.wire_contracts import (
            validate_model_wire_v2,
            wire_v2_scope,
        )

        try:
            # Incoming control numbers are JSON numbers only in the bounded v1
            # request shape. v2 graph payload integers are tagged on export.
            ensure_wire_v1_safe([list(args), kwargs])
            response = function(*args, **kwargs)
            if function.__name__ == "flow_get_graph_digest_bytes":
                return response  # Offset/length are bounded envelope numbers.
            if wire_v2_scope(response)[0]:
                validate_model_wire_v2(response, 64)
                return to_wire_v2(response)
            ensure_wire_v1_safe(response)
            return response
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
    wire_version: str = "flow-wire/1",
) -> FlowJobSubmission | FlowError:
    """Queue an experimental MMAT_CALLS snapshot for an exact function entry.

    ``exact_fixture`` requires the open input to match frozen static semantic
    evidence. ``analyst_selected`` accepts another binary only when ``profile``
    and ``abi`` are explicit and its observed processor, bitness, endianness,
    format, and exact IDA/Hex-Rays builds match reviewed normal evidence. The
    current binary digest scopes all runtime state; selection never promotes
    support or infers an ABI. RV32 has no normal route and is rejected. Reuse
    ``request_key`` only for the identical request. Opt into ``flow-wire/2``
    for tagged integers and separate v2 snapshot/graph identities; omitted
    ``wire_version`` preserves v1.
    """
    if wire_version == "flow-wire/1":
        return _service().create(function, profile, request_key, abi, routing_mode)
    return _service().create(
        function, profile, request_key, abi, routing_mode, wire_version
    )


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
    seeds: list[FlowImplicitSeedSpec | FlowImplicitBitSeedSpec | FlowPointeeSeedSpec],
    request_key: str,
    max_evaluations: int = 100000,
) -> FlowJobSubmission | FlowError:
    """Queue explicit-plus-control taint from analyst-chosen SSA nodes.

    A whole-value seed ``{node_id, labels}`` marks the value read at that
    node, not all bytes of the pointer's pointee. The caller must establish
    input status. Control labels stay separate from explicit labels;
    unresolved alias, call, CFG, or budget effects stay partial/unknown,
    never safe or vulnerable.

    A ``kind=bit_range`` seed selects ``InputValue`` bytes; exact
    Store/Load replay preserves source bits while weak effects widen.

    A ``kind=pointee_range`` seed labels [start,end) bytes after an entry
    value or acyclic full-width pointer Load. binding_mode must choose a
    derived exact pointer or an analyst-assumed nonnull singleton; neither
    proves OS input status. Results add a bound SSA/graph and certificate.
    """
    return _service().create_implicit(ssa_artifact, seeds, request_key, max_evaluations)


@tool
@_flow_api
def flow_get_pointee_evidence(
    artifact_id: str, cursor: str | None = None, limit: int = 50
) -> FlowArtifactPage | FlowError:
    """Replay and page a pointee source certificate, including analyst assumptions."""
    return _service().analysis_page(artifact_id, "pointee", cursor, limit)


@tool
@_flow_api
def flow_check_store(
    ssa_artifact: str | None = None,
    store_node_id: str | None = None,
    base_node_id: str | None = None,
    byte_offset: FlowWireInt | None = None,
    target_function: str | None = None,
    request_key: str | None = None,
    member_path: list[str | int] | None = None,
    artifact_id: str | None = None,
    cursor: str | None = None,
    limit: int = 50,
) -> FlowJobSubmission | FlowArtifactPage | FlowError:
    """Prove a pointer-width Store(base+offset, function-entry), or page its evidence.

    This is a bounded Store-site relation, conditional on reaching that Store,
    not path feasibility or final callback registration. An optional member_path
    (field names / array indices) checks the exact entry argument's current IDB
    type layout without OS hardcoding; type correctness remains an assumption.
    Submit with request_key, poll flow_get_job, then page store_evidence_artifact.
    Truncation, unresolved loads/aliases and differing joins remain unknown.
    """
    if artifact_id is not None:
        if any(
            value is not None
            for value in (
                ssa_artifact,
                store_node_id,
                base_node_id,
                byte_offset,
                target_function,
                request_key,
                member_path,
            )
        ):
            raise ValueError("mixed_store_request")
        return _service().analysis_page(artifact_id, "store_proof", cursor, limit)
    if (
        any(
            value is None
            for value in (
                ssa_artifact,
                store_node_id,
                base_node_id,
                byte_offset,
                target_function,
                request_key,
            )
        )
        or cursor is not None
        or limit != 50
    ):
        raise ValueError("invalid_store_submission")
    return _service().create_store_proof(
        ssa_artifact,
        store_node_id,
        base_node_id,
        byte_offset,
        target_function,
        request_key,
        member_path or [],
    )


@tool
@_flow_api
def flow_check_path(
    graph_artifact: str | None = None,
    path: dict | None = None,
    request_key: str | None = None,
    artifact_id: str | None = None,
    cursor: str | None = None,
    limit: int = 50,
) -> FlowJobSubmission | FlowArtifactPage | FlowError:
    """Submit a program-derived CFG-prefix proof OR page its immutable evidence.

    Submit with graph_artifact, path, request_key. path contains bindings
    (snapshot/graph/profile/ruleset/summary digests), entry-rooted blocks, and
    required schema_version=1. The final block is reached, not executed.
    Caller equations are rejected; unsupported semantics yield Unknown.
    Poll flow_get_job; page its path_proof_artifact with artifact_id/cursor/limit.
    Submission and paging arguments are mutually exclusive. No target execution
    or automatic vulnerability verdict occurs.
    """
    if artifact_id is not None:
        if any(value is not None for value in (graph_artifact, path, request_key)):
            raise ValueError("mixed_path_request")
        return _service().analysis_page(artifact_id, "path_proof", cursor, limit)
    if (
        graph_artifact is None
        or path is None
        or request_key is None
        or cursor is not None
        or limit != 50
    ):
        raise ValueError("invalid_path_submission")
    return _service().create_path_proof(graph_artifact, path, request_key)


@_flow_api
def _flow_create_path_proof(
    graph_artifact: str, query: dict, request_key: str
) -> FlowJobSubmission | FlowError:
    """Unregistered compatibility helper; accepts selectors, not caller equations."""
    return _service().create_path_proof(graph_artifact, query, request_key)


@tool
@_flow_api
def flow_refine_path_proof(
    graph_artifact: str | None = None,
    path: dict | None = None,
    refinement: dict | None = None,
    request_key: str | None = None,
    proof_artifact: str | None = None,
    artifact_id: str | None = None,
    cursor: str | None = None,
    limit: int = 50,
) -> FlowJobSubmission | FlowArtifactPage | FlowError:
    """Refine a v1 path proof with the opt-in angr tier, OR page the result.

    Submit with graph_artifact, path, refinement, request_key. ``refinement``
    explicitly opts into the angr sidecar tier (symbolic_angr,
    solver_timeout_ms, loop_bound); an all-off refinement replays the v1
    baseline verbatim and never runs the engine. Optional proof_artifact
    cross-checks a quoted v1 original. The sidecar needs IDA_MCP_ANGR_PYTHON
    pointing at an angr-capable interpreter; without it the tier reports
    angr_not_configured. Poll flow_get_job; page its refined artifact with
    artifact_id/cursor/limit. Submission and paging arguments are mutually
    exclusive. Static only; no target execution or automatic vulnerability
    verdict occurs.
    """
    if artifact_id is not None:
        if any(
            value is not None
            for value in (
                graph_artifact,
                path,
                refinement,
                request_key,
                proof_artifact,
            )
        ):
            raise ValueError("mixed_refine_request")
        return _service().analysis_page(artifact_id, "refined_path_proof", cursor, limit)
    if (
        graph_artifact is None
        or path is None
        or refinement is None
        or request_key is None
        or cursor is not None
        or limit != 50
    ):
        raise ValueError("invalid_refine_submission")
    return _service().create_path_refinement(
        graph_artifact, path, refinement, request_key, proof_artifact
    )


@tool
@_flow_api
def flow_refine_memory_proof(
    ssa_artifact: str | None = None,
    memory_plan_artifact: str | None = None,
    memory_result_artifact: str | None = None,
    path: dict | None = None,
    load_id: str | None = None,
    store_id: str | None = None,
    refinement: dict | None = None,
    request_key: str | None = None,
    artifact_id: str | None = None,
    cursor: str | None = None,
    limit: int = 50,
) -> FlowJobSubmission | FlowArtifactPage | FlowError:
    """Replay a v1 memory pair verdict, OR page a recorded replay.

    Submit with ssa_artifact, memory_plan_artifact, memory_result_artifact,
    path, load_id, store_id, refinement, request_key. The call quotes the v1
    pair facts verbatim; there is intentionally no alias-narrowing tier
    (the refined section carries `evidence_only`), because narrowing an
    alias unknown is the analyst's judgement call on that evidence.
    Poll flow_get_job; page its refined artifact with artifact_id/cursor/limit.
    Submission and paging arguments are mutually exclusive. Static only; no
    target execution or automatic vulnerability verdict occurs.
    """
    if artifact_id is not None:
        if any(
            value is not None
            for value in (
                ssa_artifact,
                memory_plan_artifact,
                memory_result_artifact,
                path,
                load_id,
                store_id,
                refinement,
                request_key,
            )
        ):
            raise ValueError("mixed_refine_request")
        return _service().analysis_page(
            artifact_id, "refined_memory_proof", cursor, limit
        )
    if (
        ssa_artifact is None
        or memory_plan_artifact is None
        or memory_result_artifact is None
        or path is None
        or load_id is None
        or store_id is None
        or refinement is None
        or request_key is None
        or cursor is not None
        or limit != 50
    ):
        raise ValueError("invalid_refine_submission")
    return _service().create_memory_refinement(
        ssa_artifact,
        memory_plan_artifact,
        memory_result_artifact,
        path,
        load_id,
        store_id,
        refinement,
        request_key,
    )


@tool
@_flow_api
def flow_get_function_ssa(
    artifact_id: str, cursor: str | None = None, limit: int = 50
) -> FlowArtifactPage | FlowError:
    """Page SSA nodes and exposed logical memory references from a completed job.

    Select a ``Load`` value only after identifying the actual input read.
    Seeding a pointer value is not the same as seeding its pointee contents.
    """
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
def flow_get_graph_digest_bytes(
    artifact_id: str, cursor: str | None = None
) -> FlowGraphBytesPage | FlowError:
    """Page the completed graph's canonical digest bytes as unpadded base64url.

    Concatenate decoded chunks in offset order and hash before JSON parsing.
    Pages contain at most 16 KiB; exports above 16 MiB fail without truncation.
    Completion requires next_cursor=null and offset+byte_count=total_bytes.
    For identity_version=2, bytes include the graph domain/version wrapper.
    """
    return _service().graph_digest_bytes(artifact_id, cursor)


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
    """Page per-node labels, control relations, and unresolved frontier.

    Inspect ``explicit``, ``control``, and ``unknown_provenance`` separately.
    Function-wide ``partial`` does not decide a particular observation.
    """
    return _service().analysis_page(artifact_id, "implicit", cursor, limit)


@tool
@_flow_api
def flow_explain_implicit_analysis(
    artifact_id: str,
    observation_node_id: str,
    cursor: str | None = None,
    limit: int = 50,
    max_nodes: int = 2048,
    max_causes: int = 256,
) -> FlowArtifactPage | FlowError:
    """Page bounded candidate causes for one owned implicit-analysis fact.

    Local structural predecessors and function-wide partial diagnostics are
    separate items. A candidate is not proof of path feasibility, definite
    source-to-sink flow, or a vulnerability verdict. For an untyped input
    pointer versus the current frame, ``alias_boundary`` reports that
    no-alias is unproven and possible taint remains unknown.
    """
    return _service().explain_implicit(
        artifact_id,
        observation_node_id,
        cursor,
        limit,
        max_nodes,
        max_causes,
    )


@tool
@_flow_api
def flow_get_memory_analysis(
    artifact_id: str, cursor: str | None = None, limit: int = 50
) -> FlowArtifactPage | FlowError:
    """Page owned byte-memory accesses, candidate ranges, facts and reasons.

    Use the ``memory_result_artifact`` from a completed snapshot job. An access
    marked may_alias or opaque is not a definite data-flow or safety verdict.
    ``alias_boundary`` names an untyped-input/current-frame no-alias proof gap;
    metadata also states the conditional typed-pointer policy. Pages are
    bounded and scoped to the current database session.
    """
    return _service().analysis_page(artifact_id, "memory", cursor, limit)


@tool
@_flow_api
def flow_get_derived_call_evidence(
    artifact_id: str, cursor: str | None = None, limit: int = 50
) -> FlowArtifactPage | FlowError:
    """Page a bound unreviewed return or single-write certificate.

    Use an artifact ID from ``derived_call_evidence`` or
    ``derived_call_memory_evidence`` in a completed snapshot job. A write may
    be a proven typed output-pointer write or one fixed-global write. Each
    page rechecks the claimed scope; unrelated call effects remain unresolved.
    """
    return _service().analysis_page(artifact_id, "derived_call", cursor, limit)


@_flow_api
def _flow_get_path_proof(
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
    expected_revision: FlowWireInt,
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
    trace_id: str, expected_revision: FlowWireInt, cursor: str, request_key: str
) -> FlowTracePage | FlowError:
    """Revision-safe durable trace cancellation; completed traces are immutable."""
    return _service().continue_trace(
        trace_id, expected_revision, cursor, request_key, cancel=True
    )
