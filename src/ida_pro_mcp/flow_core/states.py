"""Immutable abstract domains. Transfer, alias and widening algorithms are not here."""

from dataclasses import dataclass
import re
from typing import Literal

from .serialization import ContractError, Model

Endian = Literal["little", "big"]
Escape = Literal["local", "escaped", "unknown"]
Liveness = Literal["not_allocated", "live", "freed"]


def require(condition: bool, message: str):
    if not condition:
        raise ContractError(message)


def nonempty(value: str):
    require(bool(value) and not value.isspace(), "Empty identifier")


def check_digest(value: str):
    require(
        re.fullmatch(r"sha256-v[12]:[0-9a-f]{64}", value) is not None, "Invalid digest"
    )


def check_id(value: str, kind: str):
    require(
        re.fullmatch(rf"{kind}-v[12]:[0-9a-f]{{64}}", value) is not None,
        f"Invalid {kind} ID",
    )


def unique(values):
    require(len(set(values)) == len(values), "Duplicate entries")


def canonical_set(values):
    require(values == tuple(sorted(set(values))), "Expected sorted unique set")


def width(value: int):
    require(value > 0, "Width must be positive")


@dataclass(frozen=True)
class BitValue(Model):
    width_bits: int
    value: int | None = None  # None is Top, never zero or an untainted assertion.

    def __post_init__(self):
        super().__post_init__()
        width(self.width_bits)
        if self.value is not None:
            require(
                self.value >= 0 and self.value.bit_length() <= self.width_bits,
                "Constant outside width",
            )

    def join(self, other: "BitValue") -> "BitValue":
        require(self.width_bits == other.width_bits, "Cannot join unlike widths")
        return self if self == other else BitValue(self.width_bits)


@dataclass(frozen=True)
class Labels(Model):
    explicit: tuple[str, ...] = ()
    control: tuple[str, ...] = ()
    unknown_provenance: bool = False
    any_explicit_source: bool = False
    any_control_source: bool = False

    def __post_init__(self):
        super().__post_init__()
        for labels in (self.explicit, self.control):
            require(
                labels == tuple(sorted(set(labels))),
                "Labels must be sorted unique sets",
            )
            for label in labels:
                nonempty(label)

    def join(self, other: "Labels") -> "Labels":
        return Labels(
            tuple(sorted(set(self.explicit) | set(other.explicit))),
            tuple(sorted(set(self.control) | set(other.control))),
            self.unknown_provenance or other.unknown_provenance,
            self.any_explicit_source or other.any_explicit_source,
            self.any_control_source or other.any_control_source,
        )


@dataclass(frozen=True)
class ByteRange(Model):
    start: int
    end: int

    def __post_init__(self):
        super().__post_init__()
        require(0 <= self.start < self.end, "Expected nonempty nonnegative [start,end)")


@dataclass(frozen=True)
class StorageLocation(Model):
    address_space: str
    name: str
    bit_offset: int
    width_bits: int

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.address_space)
        nonempty(self.name)
        require(self.bit_offset >= 0, "Negative bit offset")
        width(self.width_bits)


@dataclass(frozen=True)
class PointerCandidate(Model):
    object_id: str
    offset: (
        int | None
    )  # None is an unknown object-relative offset; signed displacement is legal; access bounds are a later analysis.

    def __post_init__(self):
        super().__post_init__()
        check_id(self.object_id, "object")


@dataclass(frozen=True)
class PointerValue(Model):
    address_space: str
    width_bits: int
    candidates: tuple[PointerCandidate, ...] = ()
    any_compatible_location: bool = False
    may_be_null: bool = False

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.address_space)
        width(self.width_bits)
        require(
            self.candidates
            == tuple(
                sorted(
                    set(self.candidates),
                    key=lambda p: (p.object_id, p.offset is None, p.offset or 0),
                )
            ),
            "Pointer candidates must be sorted and unique",
        )
        require(
            not self.any_compatible_location or not self.candidates,
            "Top pointer cannot also enumerate candidates",
        )
        require(
            self.any_compatible_location or self.may_be_null or bool(self.candidates),
            "Empty pointer is not a null/unknown pointer",
        )

    def join(self, other: "PointerValue") -> "PointerValue":
        require(
            (self.address_space, self.width_bits)
            == (other.address_space, other.width_bits),
            "Incompatible pointer domains",
        )
        top = self.any_compatible_location or other.any_compatible_location
        candidates = (
            ()
            if top
            else tuple(
                sorted(
                    set(self.candidates) | set(other.candidates),
                    key=lambda p: (p.object_id, p.offset is None, p.offset or 0),
                )
            )
        )
        return PointerValue(
            self.address_space,
            self.width_bits,
            candidates,
            top,
            self.may_be_null or other.may_be_null,
        )


@dataclass(frozen=True)
class Lifetime(Model):
    possible: tuple[Liveness, ...] = ("live",)
    escape: Escape = "local"

    def __post_init__(self):
        super().__post_init__()
        require(
            bool(self.possible) and self.possible == tuple(sorted(set(self.possible))),
            "Liveness must be a nonempty sorted set",
        )

    def join(self, other: "Lifetime") -> "Lifetime":
        return Lifetime(
            tuple(sorted(set(self.possible) | set(other.possible))),
            self.escape if self.escape == other.escape else "unknown",
        )


@dataclass(frozen=True)
class MemoryReference(Model):
    object_id: str
    version_id: str
    address_space: str
    interval: ByteRange
    endian: Endian

    def __post_init__(self):
        super().__post_init__()
        check_id(self.object_id, "object")
        check_id(self.version_id, "memory")
        nonempty(self.address_space)


@dataclass(frozen=True)
class MemoryCell(Model):
    reference: MemoryReference
    value: BitValue | PointerValue
    labels: Labels
    reaching_definitions: tuple[str, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        require(
            self.value.width_bits
            == 8 * (self.reference.interval.end - self.reference.interval.start),
            "Memory value width differs from byte range",
        )
        canonical_set(self.reaching_definitions)
        for node in self.reaching_definitions:
            check_id(node, "node")


@dataclass(frozen=True)
class MemoryState(Model):
    """Disjoint materialized intervals, not a transfer function or MemorySSA builder."""

    cells: tuple[MemoryCell, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        keys = tuple(
            (
                c.reference.object_id,
                c.reference.version_id,
                c.reference.address_space,
                c.reference.interval.start,
                c.reference.interval.end,
            )
            for c in self.cells
        )
        canonical_set(keys)
        intervals = {}
        for cell in self.cells:
            ref = cell.reference
            key = (ref.object_id, ref.version_id, ref.address_space)
            intervals.setdefault(key, []).append(ref.interval)
        for ranges in intervals.values():
            ranges.sort(key=lambda r: r.start)
            require(
                all(a.end <= b.start for a, b in zip(ranges, ranges[1:])),
                "Overlapping materialized memory cells",
            )
