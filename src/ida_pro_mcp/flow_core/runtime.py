"""Trusted callable registry and cooperative in-process reference executor."""

from dataclasses import dataclass
from contextlib import contextmanager
import sqlite3
import threading
import time
import uuid
from types import MappingProxyType

from .persistence import PersistenceError, Store, require
from .runtime_contracts import TERMINAL
from .serialization import ContractError


class JobCancelled(Exception):
    pass


class JobDeadline(Exception):
    pass


_CONTRACT_REASONS = {
    "SSA node budget exceeded": "ssa_node_budget_exceeded",
    "SSA block budget exceeded": "ssa_block_budget_exceeded",
    "SDK register set exceeds extraction budget": "extractor_register_budget_exceeded",
    "Bit-range source budget exceeded": "source_budget_exceeded",
    "Bit-range label budget exceeded": "source_label_budget_exceeded",
    "Seeded memory plan drift": "memory_plan_drift",
    "Seeded memory object drift": "memory_object_drift",
    "Seeded memory dependency drift": "memory_dependency_drift",
    "Stored memory dependency replay mismatch": "memory_dependency_drift",
    "Stored memory plan replay mismatch": "memory_plan_drift",
    "Explanation graph mismatch": "artifact_graph_mismatch",
    "stale_database": "stale_database",
    "stale_profile_evidence": "stale_profile_evidence",
    "stale_summary_catalog": "stale_summary_catalog",
    "stale_context": "stale_context",
    "stale_profile_selection": "stale_profile_selection",
    "function_entry_required": "function_entry_required",
    "Select a function entry": "function_entry_required",
    "hexrays_unavailable": "hexrays_unavailable",
}

_PERSISTENCE_REASONS = {
    "stale_database": "stale_database",
    "stale_context": "stale_context",
    "wrong_database": "wrong_database",
    "not_found": "owned_artifact_unavailable",
    "store_busy": "storage_busy",
}

_RUNTIME_REASONS = {
    "Microcode extraction requires the IDA main thread": "ida_main_thread_required",
    "Hex-Rays initialization unavailable": "hexrays_unavailable",
    "IDA image-base API unavailable": "image_base_unavailable",
}

_EXTRACT_STAGES = frozenset(
    {
        "preflight",
        "gen_microcode",
        "microcode_walk",
        "typed_argloc",
        "input_digest",
        "snapshot_serialize",
        "callee_closure",
        "derived_closure",
    }
)
_SNAPSHOT_STAGES = frozenset({"snapshot_serialize"})
_CLOSURE_STAGES = frozenset({"callee_closure", "derived_closure"})
_INPUT_DIGEST_STAGES = frozenset({"input_digest"})

# IDA-layer exception identities as (module, qualname) pairs. Matched by MRO
# walk so this layer needs no ida_mcp import and subclassing still classifies.
# Identities only select static allowlisted reasons; they are never serialized.
_IDA_TIMEOUT_NAMES = frozenset({("ida_pro_mcp.ida_mcp.sync", "IDASyncError")})
_IDA_CANCELLED_NAMES = frozenset(
    {
        ("ida_pro_mcp.ida_mcp.zeromcp.jsonrpc", "RequestCancelledError"),
        ("ida_pro_mcp.ida_mcp.sync", "CancelledError"),
    }
)
_IDA_PUMP_BUSY_NAMES = frozenset(
    {
        ("ida_pro_mcp.ida_mcp.mainthread", "PumpBusyError"),
        ("ida_pro_mcp.ida_mcp.sync", "IDAError"),
        ("ida_pro_mcp.ida_mcp.zeromcp.mcp", "McpToolError"),
    }
)
_TOOL_TIMEOUT_PREFIX = "Tool timed out after "
_PUMP_BUSY_MARK = "main thread is busy"


def _stage_default_reason(stage):
    if stage in _SNAPSHOT_STAGES:
        return "snapshot_serialization_failed"
    if stage in _CLOSURE_STAGES:
        return "derived_closure_failed"
    return None


def _failure_error(
    exc: BaseException, phase: str, *, stage=None
) -> dict[str, str]:
    """Only static allowlisted fields cross the durable job boundary.

    Neither arbitrary exception messages, class names, native EAs, nor host
    paths are serialized. An unclassified failure stays explicitly internal.
    Classification is isinstance-based: subclasses keep their family's typed
    reason instead of collapsing to internal_error. The extract stage only
    refines extract-phase failures; allowlisted reasons always win over it.
    """
    phase = phase if phase in {"setup", "extract", "analyze", "commit"} else "unknown"
    if type(stage) is not str or stage not in _EXTRACT_STAGES or phase != "extract":
        stage = None
    message = exc.args[0] if len(exc.args) == 1 and type(exc.args[0]) is str else None
    names = {(cls.__module__, cls.__qualname__) for cls in type(exc).__mro__}
    if names & _IDA_CANCELLED_NAMES:
        kind = "InternalError"
        reason = "ida_request_cancelled"
    elif names & _IDA_TIMEOUT_NAMES:
        kind = "InternalError"
        reason = (
            "ida_tool_timeout"
            if message is not None and message.startswith(_TOOL_TIMEOUT_PREFIX)
            else "internal_error"
        )
    elif names & _IDA_PUMP_BUSY_NAMES:
        kind = "InternalError"
        reason = (
            "ida_pump_busy"
            if ("ida_pro_mcp.ida_mcp.mainthread", "PumpBusyError") in names
            or (message is not None and _PUMP_BUSY_MARK in message)
            else "internal_error"
        )
        if reason == "ida_pump_busy" and isinstance(exc, RuntimeError):
            kind = "RuntimeError"
    elif isinstance(exc, PersistenceError):
        kind = "PersistenceError"
        reason = _PERSISTENCE_REASONS.get(message or "", "storage_boundary")
    elif isinstance(exc, ContractError):
        kind = "ContractError"
        reason = _CONTRACT_REASONS.get(message or "")
        if reason is None:
            reason = _stage_default_reason(stage)
            if reason is None:
                reason = (
                    "contract_subclass"
                    if type(exc) is not ContractError
                    else "contract_rejected"
                )
    elif isinstance(exc, TimeoutError):
        kind = "TimeoutError"
        reason = "handler_timeout"
    elif isinstance(exc, InterruptedError):
        kind = "InternalError"
        reason = "extraction_cancelled"
    elif isinstance(exc, RuntimeError):
        kind = "RuntimeError"
        if message is not None and message.startswith("gen_microcode failed:"):
            reason = "microcode_generation_failed"
        else:
            reason = _RUNTIME_REASONS.get(message or "")
            if reason is None:
                reason = _stage_default_reason(stage) or "runtime_boundary"
    elif isinstance(exc, ValueError):
        staged = _stage_default_reason(stage)
        kind = "ValueError"
        reason = staged if staged is not None else "invalid_handler_value"
    elif isinstance(exc, OSError):
        kind = "InternalError"
        if stage in _INPUT_DIGEST_STAGES:
            reason = "input_digest_unavailable"
        else:
            reason = _stage_default_reason(stage) or "internal_error"
    elif (
        isinstance(exc, (AttributeError, TypeError, LookupError))
        and stage is not None
        and stage not in _SNAPSHOT_STAGES
        and stage not in _CLOSURE_STAGES
    ):
        kind = "InternalError"
        reason = "sdk_shape_mismatch"
    else:
        kind = "InternalError"
        reason = _stage_default_reason(stage) or "internal_error"
    return {
        "code": "handler_failed",
        "phase": phase,
        "reason": reason,
        "type": kind,
    }


@dataclass(frozen=True)
class Handler:
    extract: object
    analyze: object

    def __post_init__(self):
        require(callable(self.extract) and callable(self.analyze), "invalid_handler")


class JobContext:
    def __init__(self, cancel, deadline, clock, report, runtime=None):
        self.cancel = cancel
        self.deadline = deadline
        self.clock = clock
        self._report = report
        # The Runtime that admitted this job is its durable Store authority.
        # Worker callbacks must reuse it instead of re-entering the global
        # database-switch admission gate from parallel analyze threads.
        self.runtime = runtime
        self.budget = MappingProxyType({})
        self._extract_stage = None

    def report(self, progress, checkpoint=None):
        self.check()
        revision, deadline = self._report(progress, checkpoint)
        self.deadline = deadline
        return revision

    def note_extract_stage(self, stage):
        # Instrumentation only: never raises, never blocks. The runtime
        # validates against the stage allowlist before recording or routing.
        self._extract_stage = stage

    def check(self):
        if self.cancel.is_set():
            raise JobCancelled()
        if self.clock() >= self.deadline:
            raise JobDeadline()


class Runtime:
    """Host registers callables, never request-selected modules/commands.

    Extraction callables needing IDA must be host-wrapped for the main-thread
    pump. This executor itself imports no SDK and cannot preempt native code.
    """

    def __init__(
        self,
        store: Store,
        handlers: dict[str, Handler],
        *,
        clock=time.monotonic,
        admission=None,
    ):
        require(type(store) is Store, "invalid_store")
        require(store._lease is not None, "runtime_requires_owner_lease")
        require(
            all(
                type(name) is str and type(handler) is Handler
                for name, handler in handlers.items()
            ),
            "invalid_handler_registry",
        )
        self.store = store
        self.handlers = MappingProxyType(dict(handlers))
        self.owner = "executor_" + uuid.uuid4().hex
        self.clock = clock
        self._lock = threading.RLock()
        self._submit_gate = threading.Lock()
        self._admission = admission or self._local_admission
        self._closing_event = threading.Event()
        self._jobs = {}
        self._retired = set()
        self._pending_finish = {}
        self._finish_failures = {}
        self._closing = False

    @contextmanager
    def _local_admission(self):
        require(self._submit_gate.acquire(blocking=False), "job_admission_busy")
        try:
            yield
        finally:
            self._submit_gate.release()

    def submit(
        self,
        handler,
        input_value,
        request_key,
        *,
        timeout=60.0,
        budget=None,
        retry_of=None,
    ):
        require(
            type(timeout) in (int, float) and 0 < timeout <= 86400, "invalid_timeout"
        )
        with self._admission():
            with self._lock:
                require(not self._closing_event.is_set(), "runtime_closing")
                require(handler in self.handlers, "unknown_handler")
            # Do not hold the runtime lock across SQLite/Store locks: close must
            # be able to signal cancellation even when publication is blocked.
            identifier = self.store.create_job(
                handler, input_value, request_key, budget=budget, retry_of=retry_of
            )
            state = self.store.job(identifier)["state"]
            with self._lock:
                closing = self._closing_event.is_set()
                if not closing and (identifier in self._jobs or state != "queued"):
                    return identifier
                if not closing:
                    cancel = threading.Event()
                    done = threading.Event()
                    deadline = self.clock() + timeout
                    thread = threading.Thread(
                        target=self._run,
                        args=(
                            identifier,
                            self.handlers[handler],
                            cancel,
                            done,
                            deadline,
                            timeout,
                        ),
                        daemon=True,
                        name="flow-" + identifier,
                    )
                    self._jobs[identifier] = (thread, cancel, done, deadline)
                    thread.start()
                    return identifier
            self._finish(
                identifier,
                "interrupted",
                {"code": "closed_during_admission"},
                nonblocking=True,
            )
            raise PersistenceError("runtime_closing")

    @staticmethod
    def _retryable_finish_error(exc):
        if str(exc) in {"store_busy", "job_conflict"}:
            return True
        cause = exc.__cause__
        code = getattr(cause, "sqlite_errorcode", 0)
        return (
            str(exc) == "sqlite_failure"
            and isinstance(cause, sqlite3.OperationalError)
            and code & 0xFF in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}
        )

    def _finish(self, identifier, state, error=None, *, nonblocking=False):
        # Preserve the terminal intent if contention outlasts this bounded try.
        # Status/wait/cancel can reconcile it after the worker has exited.
        with self._lock:
            if identifier in self._finish_failures:
                return
            state, error = self._pending_finish.setdefault(identifier, (state, error))
        attempts = 1 if nonblocking or self._closing else 3
        for attempt in range(attempts):
            busy = 0 if nonblocking or self._closing else 50
            try:
                row = self.store.job(identifier, _busy_timeout_ms=busy)
                if row["state"] not in TERMINAL:
                    require(row["owner"] in (None, self.owner), "wrong_job_owner")
                    target = state
                    if target == "cancelled" and row["state"] != "cancel_requested":
                        self.store.transition_job(
                            identifier,
                            row["state"],
                            "cancel_requested",
                            owner=self.owner,
                            _busy_timeout_ms=busy,
                        )
                        row = self.store.job(identifier, _busy_timeout_ms=busy)
                    if row["state"] not in TERMINAL:
                        if row["state"] == "cancel_requested" and target not in {
                            "interrupted",
                            "stale",
                        }:
                            target = "cancelled"
                        self.store.transition_job(
                            identifier,
                            row["state"],
                            target,
                            owner=self.owner,
                            error=error,
                            _busy_timeout_ms=busy,
                        )
            except PersistenceError as exc:
                if self._retryable_finish_error(exc):
                    if attempt + 1 < attempts:
                        self._closing_event.wait(0.05)
                    continue
                with self._lock:
                    self._finish_failures[identifier] = str(exc)
                # Closed/invalidated scopes and ownership failures are not
                # contention: never bypass Store checks or retry into a new DB.
            with self._lock:
                self._pending_finish.pop(identifier, None)
            return

    def _recover_finishes(self, identifier=None):
        with self._lock:
            pending = tuple(self._pending_finish.items())
        for job_id, (state, error) in pending:
            if identifier is None or job_id == identifier:
                self._finish(job_id, state, error, nonblocking=True)

    def _check_finish_failure(self, identifier):
        with self._lock:
            failure = self._finish_failures.get(identifier)
        if failure is not None:
            raise PersistenceError(failure)

    def status(self, identifier):
        """Reconcile terminal intent, then return the authoritative stored row.

        Storage failures propagate; a finished thread alone is not evidence of a
        durable terminal state. Pending contention never fabricates completion.
        """
        self._recover_finishes(identifier)
        self._check_finish_failure(identifier)
        return self.store.job(identifier)

    def _checkpoint(self, identifier, progress, checkpoint, timeout):
        renewed_deadline = self.clock() + timeout
        with self._lock:
            job = self._jobs.get(identifier)
            if job is None or identifier in self._retired or job[2].is_set():
                raise JobDeadline()
            thread, cancel, done, _ = job
            if cancel.is_set() or self._closing_event.is_set():
                raise JobCancelled()
            # Publish the in-process renewal before Store I/O so the idle/busy
            # observer cannot retire a job while its Host progress checkpoint
            # is being committed. Store failure still raises into the handler
            # and the ordinary terminal path records the failure.
            self._jobs[identifier] = (thread, cancel, done, renewed_deadline)
        revision = self.store.checkpoint_job(
            identifier,
            self.owner,
            progress,
            checkpoint,
            deadline=time.time() + timeout,
        )
        return revision, renewed_deadline

    def _run(self, identifier, handler, cancel, done, deadline, timeout):
        phase = "setup"
        spans: dict[str, int] = {}
        mark = self.clock()
        extract_start = None
        context = JobContext(
            cancel,
            deadline,
            self.clock,
            lambda progress, checkpoint: self._checkpoint(
                identifier,
                progress,
                checkpoint,
                timeout,
            ),
            self,
        )

        def record(span):
            nonlocal mark
            now = self.clock()
            spans[span] = int(round((now - mark) * 1000))
            mark = now

        def publish_spans():
            # Best-effort diagnostics: never block terminal completion on
            # a contended store.
            try:
                progress = {
                    "phase_times_ms": dict(spans),
                    "failed_phase": phase,
                }
                stage = getattr(context, "_extract_stage", None)
                if type(stage) is str and stage in _EXTRACT_STAGES:
                    progress["extract_stage"] = stage
                if extract_start is not None:
                    progress["extract_elapsed_ms"] = int(
                        round((self.clock() - extract_start) * 1000)
                    )
                self.store.checkpoint_job(
                    identifier,
                    self.owner,
                    progress,
                    _busy_timeout_ms=0,
                )
            except PersistenceError:
                pass

        try:
            context.check()
            row = self.store.job(identifier)
            context.budget = MappingProxyType(row["budget"])
            self.store.transition_job(
                identifier,
                "queued",
                "extracting",
                owner=self.owner,
                deadline=time.time() + max(0, deadline - self.clock()),
            )
            phase = "extract"
            extract_start = self.clock()
            record("setup_ms")
            extracted = handler.extract(context, row["input"])
            context.check()
            self.store.transition_job(
                identifier, "extracting", "analyzing", owner=self.owner
            )
            record("extract_ms")
            phase = "analyze"
            result = handler.analyze(context, extracted)
            context.check()
            record("analyze_ms")
            phase = "commit"
            self.store.transition_job(
                identifier, "analyzing", "committing", owner=self.owner
            )
            context.check()
            self.store.transition_job(
                identifier,
                "committing",
                "complete",
                owner=self.owner,
                result=result,
                progress={"phase_times_ms": dict(spans)},
            )
        except JobCancelled:
            publish_spans()
            self._finish(
                identifier,
                "cancelled",
                {"code": "cancelled", "phase": phase, "reason": "cancelled"},
            )
        except JobDeadline:
            publish_spans()
            self._finish(
                identifier,
                "interrupted",
                {
                    "code": "lease_expired",
                    "phase": phase,
                    "reason": "deadline_exceeded",
                },
                nonblocking=True,
            )
        except BaseException as exc:
            publish_spans()
            stage = getattr(context, "_extract_stage", None)
            if type(stage) is not str or stage not in _EXTRACT_STAGES:
                stage = None
            self._finish(
                identifier,
                "failed",
                _failure_error(exc, phase, stage=stage),
            )
        finally:
            done.set()

    def cancel(self, identifier):
        with self._lock:
            job = self._jobs.get(identifier)
            if job is not None:
                job[1].set()
        # A late cancellation must not replace an already-computed terminal
        # outcome merely because its persistence was temporarily blocked.
        self._recover_finishes(identifier)
        self._check_finish_failure(identifier)
        # Cooperative signalling is immediate. Persistence may win, conflict or
        # fail; propagate that actual outcome rather than inventing an ack.
        state = self.store.request_cancel(identifier)
        if job is not None and job[2].is_set() and state not in TERMINAL:
            with self._lock:
                intent = self._pending_finish.get(identifier)
            if intent is None:
                intent = ("cancelled", {"code": "cancelled"})
            self._finish(identifier, *intent)
            self._check_finish_failure(identifier)
            state = self.store.job(identifier)["state"]
        return state

    @property
    def inflight_job_count(self):
        # Database switching cannot assume an expired daemon callback has stopped
        # touching SDK state merely because its keepalive lease was retired.
        with self._lock:
            return sum(not done.is_set() for _, _, done, _ in self._jobs.values())

    @property
    def active_job_count(self):
        self._recover_finishes()
        now = self.clock()
        expired = []
        with self._lock:
            active = 0
            for identifier, (_, cancel, done, deadline) in self._jobs.items():
                if done.is_set() or identifier in self._retired:
                    continue
                if now >= deadline:
                    cancel.set()
                    self._retired.add(identifier)
                    expired.append(identifier)
                else:
                    active += 1
        for identifier in expired:
            self._finish(
                identifier, "interrupted", {"code": "lease_expired"}, nonblocking=True
            )
        return active

    def begin_close(self):
        # Closing and thread publication share this short mutex. No Store I/O
        # occurs here, so publication cannot race past the closing decision.
        with self._lock:
            self._closing_event.set()
            self._closing = True
            identifiers = []
            for identifier, (_, cancel, done, _) in self._jobs.items():
                if not done.is_set():
                    cancel.set()
                    identifiers.append(identifier)
        for identifier in identifiers:
            try:
                self.store.request_cancel(identifier, _busy_timeout_ms=0)
            except PersistenceError:
                # Reopen recovery marks remaining nonterminal rows interrupted.
                pass

    def shutdown(self, timeout=2.0):
        require(
            type(timeout) in (int, float) and 0 <= timeout <= 60,
            "invalid_shutdown_timeout",
        )
        self.begin_close()
        end = time.monotonic() + timeout
        with self._lock:
            jobs = list(self._jobs.items())
        for _, (thread, _, _, _) in jobs:
            if thread is not threading.current_thread():
                thread.join(max(0, end - time.monotonic()))
        interrupted = []
        for identifier, (_, _, done, _) in jobs:
            if not done.is_set():
                self._finish(identifier, "interrupted", {"code": "shutdown_deadline"})
                interrupted.append(identifier)
                with self._lock:
                    self._retired.add(identifier)
        return tuple(sorted(interrupted))

    def wait(self, identifier, timeout=5.0):
        with self._lock:
            job = self._jobs.get(identifier)
        if job is None:
            return self.store.job(identifier)["state"] in TERMINAL
        if not job[2].wait(timeout):
            return False
        self._recover_finishes(identifier)
        self._check_finish_failure(identifier)
        with self._lock:
            return identifier not in self._pending_finish
