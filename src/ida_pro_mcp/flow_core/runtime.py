"""Trusted callable registry and cooperative in-process reference executor."""

from dataclasses import dataclass
from contextlib import contextmanager
import threading
import time
import uuid
from types import MappingProxyType

from .persistence import PersistenceError, Store, require
from .runtime_contracts import TERMINAL


class JobCancelled(Exception):
    pass


class JobDeadline(Exception):
    pass


@dataclass(frozen=True)
class Handler:
    extract: object
    analyze: object

    def __post_init__(self):
        require(callable(self.extract) and callable(self.analyze), "invalid_handler")


class JobContext:
    def __init__(self, cancel, deadline, clock, report):
        self.cancel = cancel
        self.deadline = deadline
        self.clock = clock
        self._report = report
        self.budget = MappingProxyType({})

    def report(self, progress, checkpoint=None):
        self.check()
        return self._report(progress, checkpoint)

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

    def _finish(self, identifier, state, error=None, *, nonblocking=False):
        busy = 0 if nonblocking or self._closing else 5000
        try:
            row = self.store.job(identifier, _busy_timeout_ms=busy)
            if row["state"] in TERMINAL:
                return
            target = state
            if target == "cancelled" and row["state"] != "cancel_requested":
                self.store.request_cancel(identifier, _busy_timeout_ms=busy)
                row = self.store.job(identifier, _busy_timeout_ms=busy)
                if row["state"] in TERMINAL:
                    return
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
        except PersistenceError:
            # Another terminal transition, invalidated scope, or closed runtime
            # won. Never retry by mutating a terminal row or a different DB.
            return

    def _run(self, identifier, handler, cancel, done, deadline):
        context = JobContext(
            cancel,
            deadline,
            self.clock,
            lambda progress, checkpoint: self.store.checkpoint_job(
                identifier, self.owner, progress, checkpoint
            ),
        )
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
            extracted = handler.extract(context, row["input"])
            context.check()
            self.store.transition_job(
                identifier, "extracting", "analyzing", owner=self.owner
            )
            result = handler.analyze(context, extracted)
            context.check()
            self.store.transition_job(
                identifier, "analyzing", "committing", owner=self.owner
            )
            context.check()
            self.store.transition_job(
                identifier, "committing", "complete", owner=self.owner, result=result
            )
        except JobCancelled:
            self._finish(identifier, "cancelled", {"code": "cancelled"})
        except JobDeadline:
            self._finish(
                identifier, "interrupted", {"code": "lease_expired"}, nonblocking=True
            )
        except BaseException as exc:
            self._finish(
                identifier,
                "failed",
                {"code": "handler_failed", "type": type(exc).__name__},
            )
        finally:
            done.set()

    def cancel(self, identifier):
        with self._lock:
            job = self._jobs.get(identifier)
            if job is not None:
                job[1].set()
        # Cooperative signalling is immediate. Persistence may win, conflict or
        # fail; propagate that actual outcome rather than inventing an ack.
        return self.store.request_cancel(identifier)

    @property
    def inflight_job_count(self):
        # Database switching cannot assume an expired daemon callback has stopped
        # touching SDK state merely because its keepalive lease was retired.
        with self._lock:
            return sum(not done.is_set() for _, _, done, _ in self._jobs.values())

    @property
    def active_job_count(self):
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
        return job[2].wait(timeout)
