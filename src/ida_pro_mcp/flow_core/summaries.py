"""Reviewed, versioned function-summary contracts.

Summary selection is intentionally exact: names are display metadata and never a
lookup key.  Return, memory, and lifetime effects have separate fields so a
memory output cannot silently become a return-value dependency.
"""

import re
from dataclasses import dataclass
from typing import Literal

from .serialization import Model, canonical_json, digest
from .states import check_digest, check_id, nonempty, require, width

SummaryKind = Literal["identity", "copy", "fill", "output", "global", "alloc", "free"]
ReturnSource = Literal["argument", "constant", "global", "allocation", "unknown"]
MemoryOperation = Literal["copy", "fill", "output", "global_write"]
MemoryTarget = Literal["argument", "global"]
MemorySource = Literal["argument", "argument_memory", "constant", "global", "unknown"]
LifetimeOperation = Literal["allocate", "free"]


def _optional_index(value: int | None, label: str):
    require(value is None or value >= 0, f"Invalid {label} index")


@dataclass(frozen=True)
class SummaryIdentity(Model):
    """Full reviewed-summary lookup key; a function name is deliberately absent."""

    binary_sha256: str
    callee_rva: int
    callee_snapshot_id: str
    profile_digest: str
    calling_convention: str
    signature_digest: str
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        require(
            re.fullmatch(r"[0-9a-f]{64}", self.binary_sha256) is not None,
            "Invalid binary SHA-256",
        )
        require(self.callee_rva >= 0, "Negative callee RVA")
        check_id(self.callee_snapshot_id, "snapshot")
        check_digest(self.profile_digest)
        nonempty(self.calling_convention)
        check_digest(self.signature_digest)

    @property
    def sort_key(self) -> tuple[str, int, str, str, str, str]:
        return (
            self.binary_sha256,
            self.callee_rva,
            self.callee_snapshot_id,
            self.profile_digest,
            self.calling_convention,
            self.signature_digest,
        )

    @property
    def identity_digest(self) -> str:
        return digest(self)


@dataclass(frozen=True)
class MemoryExtent(Model):
    """A positive fixed extent or a byte count supplied by a call argument."""

    fixed_bytes: int | None = None
    argument_index: int | None = None

    def __post_init__(self):
        super().__post_init__()
        require(
            (self.fixed_bytes is None) != (self.argument_index is None),
            "Memory extent needs exactly one fixed or argument size",
        )
        require(
            self.fixed_bytes is None or self.fixed_bytes > 0,
            "Fixed memory extent must be positive",
        )
        _optional_index(self.argument_index, "extent argument")


@dataclass(frozen=True)
class ReturnEffect(Model):
    source: ReturnSource
    width_bits: int
    argument_index: int | None = None
    global_rva: int | None = None
    constant: int | None = None

    def __post_init__(self):
        super().__post_init__()
        width(self.width_bits)
        _optional_index(self.argument_index, "return source argument")
        require(self.global_rva is None or self.global_rva >= 0, "Negative global RVA")
        require(
            self.constant is None or self.constant >= 0, "Negative bit-vector constant"
        )
        require(
            (self.argument_index is not None) == (self.source == "argument"),
            "Argument return-source payload mismatch",
        )
        require(
            (self.global_rva is not None) == (self.source == "global"),
            "Global return-source payload mismatch",
        )
        require(
            (self.constant is not None) == (self.source == "constant"),
            "Constant return-source payload mismatch",
        )
        if self.constant is not None:
            require(
                self.constant.bit_length() <= self.width_bits,
                "Return constant outside width",
            )


@dataclass(frozen=True)
class MemoryEffect(Model):
    operation: MemoryOperation
    target: MemoryTarget
    source: MemorySource
    extent: MemoryExtent
    target_index: int | None = None
    target_rva: int | None = None
    source_index: int | None = None
    source_rva: int | None = None
    constant: int | None = None

    def __post_init__(self):
        super().__post_init__()
        for value, label in (
            (self.target_index, "memory target"),
            (self.source_index, "memory source"),
        ):
            _optional_index(value, label)
        require(self.target_rva is None or self.target_rva >= 0, "Negative target RVA")
        require(self.source_rva is None or self.source_rva >= 0, "Negative source RVA")
        require(self.constant is None or self.constant >= 0, "Negative fill constant")
        require(
            (self.target_index is not None) == (self.target == "argument"),
            "Argument memory-target payload mismatch",
        )
        require(
            (self.target_rva is not None) == (self.target == "global"),
            "Global memory-target payload mismatch",
        )
        require(
            (self.source_index is not None)
            == (self.source in {"argument", "argument_memory"}),
            "Argument memory-source payload mismatch",
        )
        require(
            (self.source_rva is not None) == (self.source == "global"),
            "Global memory-source payload mismatch",
        )
        require(
            (self.constant is not None) == (self.source == "constant"),
            "Constant memory-source payload mismatch",
        )
        if self.operation == "copy":
            require(
                self.source in {"argument_memory", "global", "unknown"},
                "Copy needs a memory source",
            )
        if self.operation == "fill":
            require(
                self.source in {"argument", "constant", "unknown"},
                "Fill needs a scalar source",
            )
        if self.operation == "global_write":
            require(self.target == "global", "Global write needs a global target")


@dataclass(frozen=True)
class LifetimeEffect(Model):
    operation: LifetimeOperation
    pointer_argument_index: int | None = None
    size_argument_index: int | None = None
    nullable: bool = True

    def __post_init__(self):
        super().__post_init__()
        _optional_index(self.pointer_argument_index, "lifetime pointer")
        _optional_index(self.size_argument_index, "allocation size")
        if self.operation == "allocate":
            require(
                self.pointer_argument_index is None,
                "Allocation identity is returned, not supplied by an argument",
            )
        else:
            require(
                self.pointer_argument_index is not None
                and self.size_argument_index is None,
                "Free needs one pointer argument and no allocation size",
            )


def _canonical_effects(values: tuple[Model, ...], label: str):
    encoded = tuple(canonical_json(value) for value in values)
    require(
        encoded == tuple(sorted(set(encoded))), f"{label} must be sorted and unique"
    )


@dataclass(frozen=True)
class ReviewedSummary(Model):
    identity: SummaryIdentity
    display_name: str
    kind: SummaryKind
    return_effects: tuple[ReturnEffect, ...]
    memory_effects: tuple[MemoryEffect, ...]
    lifetime_effects: tuple[LifetimeEffect, ...]
    reviewer: str
    review_digest: str
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.display_name)
        nonempty(self.reviewer)
        check_digest(self.review_digest)
        _canonical_effects(self.return_effects, "Return effects")
        _canonical_effects(self.memory_effects, "Memory effects")
        _canonical_effects(self.lifetime_effects, "Lifetime effects")
        if self.kind == "identity":
            require(
                any(effect.source == "argument" for effect in self.return_effects),
                "Identity summary needs an argument return effect",
            )
        elif self.kind in {"copy", "fill", "output"}:
            require(
                any(effect.operation == self.kind for effect in self.memory_effects),
                f"{self.kind.title()} summary needs its memory effect",
            )
        elif self.kind == "global":
            require(
                any(effect.source == "global" for effect in self.return_effects)
                or any(effect.target == "global" for effect in self.memory_effects),
                "Global summary needs a global effect",
            )
        elif self.kind == "alloc":
            require(
                any(effect.source == "allocation" for effect in self.return_effects)
                and any(
                    effect.operation == "allocate" for effect in self.lifetime_effects
                ),
                "Allocation summary needs return and lifetime effects",
            )
        elif self.kind == "free":
            require(
                not self.return_effects
                and any(effect.operation == "free" for effect in self.lifetime_effects),
                "Free summary needs a lifetime effect and no data return",
            )

    @property
    def summary_digest(self) -> str:
        return digest(self)


@dataclass(frozen=True)
class SummaryCatalog(Model):
    """An immutable collection containing reviewed summaries only."""

    summaries: tuple[ReviewedSummary, ...]
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        identities = tuple(summary.identity.sort_key for summary in self.summaries)
        require(
            identities == tuple(sorted(set(identities))),
            "Catalog summaries must have sorted unique pinned identities",
        )

    @property
    def catalog_digest(self) -> str:
        return digest(self)

    def lookup(self, identity: SummaryIdentity) -> ReviewedSummary | None:
        """Return only an exact six-field identity match."""

        for summary in self.summaries:
            if summary.identity == identity:
                return summary
        return None
