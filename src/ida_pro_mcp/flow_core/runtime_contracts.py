"""Internal durable runtime envelopes. No SDK objects, executables or import paths."""

from dataclasses import dataclass
from typing import Literal

from .serialization import Model, digest
from .states import canonical_set, check_digest, check_id, nonempty, require

JobState = Literal[
    "queued",
    "extracting",
    "analyzing",
    "committing",
    "complete",
    "cancel_requested",
    "cancelled",
    "failed",
    "stale",
    "interrupted",
]
TERMINAL = frozenset({"complete", "cancelled", "failed", "stale", "interrupted"})
TRANSITIONS = {
    "queued": {"extracting", "cancel_requested", "failed", "stale", "interrupted"},
    "extracting": {"analyzing", "cancel_requested", "failed", "stale", "interrupted"},
    "analyzing": {"committing", "cancel_requested", "failed", "stale", "interrupted"},
    "committing": {"complete", "cancel_requested", "failed", "stale", "interrupted"},
    "cancel_requested": {"cancelled", "stale", "interrupted"},
}


@dataclass(frozen=True)
class RuntimeScope(Model):
    namespace: str
    fingerprint: str
    binary_digest: str
    profile_digest: str
    rule_digest: str
    summary_digest: str
    policy_digest: str
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.namespace)
        for value in (
            self.fingerprint,
            self.binary_digest,
            self.profile_digest,
            self.rule_digest,
            self.summary_digest,
            self.policy_digest,
        ):
            check_digest(value)

    @property
    def scope_digest(self):
        return digest(self)


@dataclass(frozen=True)
class TraceSpec(Model):
    snapshot_artifact: str
    policy_digest: str
    source_digest: str
    query_scope: str
    direction: Literal["forward", "backward"]
    edge_kinds: tuple[str, ...]
    graph_artifact: str
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.snapshot_artifact)
        nonempty(self.graph_artifact)
        nonempty(self.query_scope)
        check_digest(self.policy_digest)
        check_digest(self.source_digest)
        canonical_set(self.edge_kinds)
        allowed = {
            "value_dependency",
            "memory_data_dependency",
            "memory_order",
            "phi_input",
            "address_dependency",
            "control_dependency",
            "call_argument",
            "call_return",
            "summary_effect",
            "opaque_effect",
        }
        require(
            bool(self.edge_kinds) and set(self.edge_kinds) <= allowed,
            "Invalid trace edge filter",
        )


@dataclass(frozen=True)
class TraceState(Model):
    frontier: tuple[str, ...] = ()
    visited: tuple[str, ...] = ()
    emitted: tuple[str, ...] = ()
    pending: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()
    budget_remaining: int = 10000
    status: Literal["active", "frontier_exhausted", "budget_exceeded", "cancelled"] = (
        "active"
    )
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        for values in (self.visited, self.emitted, self.unresolved):
            canonical_set(values)
        for values in (self.frontier, self.pending):
            require(len(set(values)) == len(values), "Duplicate trace queue entries")
        for values in (
            self.frontier,
            self.visited,
            self.emitted,
            self.pending,
            self.unresolved,
        ):
            for value in values:
                check_id(value, "node")
        require(
            set(self.emitted) <= set(self.visited), "Emitted IDs must have been visited"
        )
        require(self.budget_remaining >= 0, "Negative trace budget")
        require(
            self.status != "frontier_exhausted"
            or (not self.frontier and not self.pending),
            "Unfinished trace marked exhausted",
        )
