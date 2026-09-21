"""Hand-authored reviewed-summary contract examples."""

from dataclasses import replace

import pytest

from ida_pro_mcp.flow_core import ContractError, canonical_json, digest, stable_id
from ida_pro_mcp.flow_core.summaries import (
    LifetimeEffect,
    MemoryEffect,
    MemoryExtent,
    ReturnEffect,
    ReviewedSummary,
    SummaryCatalog,
    SummaryIdentity,
)


def summary_identity(name: str, rva: int) -> SummaryIdentity:
    return SummaryIdentity(
        digest(name).split(":", 1)[1],
        rva,
        stable_id("snapshot", {"callee": name, "rva": rva}),
        digest("profile-v1"),
        "darwin-aarch64",
        digest({"signature": "u32(u32)", "name": name}),
    )


def reviewed_identity(name: str, rva: int) -> ReviewedSummary:
    return ReviewedSummary(
        summary_identity(name, rva),
        name,
        "identity",
        (ReturnEffect("argument", 32, argument_index=0),),
        (),
        (),
        "fixture-review",
        digest({"review": name, "rva": rva}),
    )


def catalog(*summaries: ReviewedSummary) -> SummaryCatalog:
    return SummaryCatalog(
        tuple(sorted(summaries, key=lambda summary: summary.identity.sort_key))
    )


def test_reviewed_catalog_uses_full_pinned_identity_not_name():
    first = reviewed_identity("same_display_name", 0x100)
    second = reviewed_identity("same_display_name", 0x200)
    summaries = catalog(second, first)
    assert summaries.lookup(first.identity) == first
    assert summaries.lookup(second.identity) == second
    assert summaries.lookup(replace(first.identity, callee_rva=0x101)) is None
    assert first.display_name == second.display_name
    assert not hasattr(summaries, "lookup_name")


def test_catalog_digest_and_roundtrip_pin_reviewed_contents():
    first = reviewed_identity("call_identity", 0x100)
    summaries = catalog(first)
    assert SummaryCatalog.from_json(canonical_json(summaries)) == summaries
    assert SummaryCatalog.from_json(canonical_json(summaries)).catalog_digest == (
        summaries.catalog_digest
    )
    changed = catalog(replace(first, reviewer="second-reviewer"))
    assert changed.catalog_digest != summaries.catalog_digest
    with pytest.raises(ContractError, match="sorted unique pinned identities"):
        SummaryCatalog((first, first))


def test_return_memory_and_lifetime_effects_remain_distinct():
    output = ReviewedSummary(
        summary_identity("call_output", 0x120),
        "call_output",
        "output",
        (),
        (
            MemoryEffect(
                "output",
                "argument",
                "argument",
                MemoryExtent(fixed_bytes=4),
                target_index=0,
                source_index=1,
            ),
        ),
        (),
        "fixture-review",
        digest("call_output-review"),
    )
    allocation = ReviewedSummary(
        summary_identity("call_alloc", 0x140),
        "call_alloc",
        "alloc",
        (ReturnEffect("allocation", 64),),
        (),
        (LifetimeEffect("allocate", size_argument_index=0),),
        "fixture-review",
        digest("call_alloc-review"),
    )
    free = ReviewedSummary(
        summary_identity("call_free", 0x160),
        "call_free",
        "free",
        (),
        (),
        (LifetimeEffect("free", pointer_argument_index=0),),
        "fixture-review",
        digest("call_free-review"),
    )
    assert not output.return_effects and output.memory_effects
    assert allocation.return_effects and allocation.lifetime_effects
    assert not free.return_effects and free.lifetime_effects
    assert len({item.summary_digest for item in (output, allocation, free)}) == 3


def test_copy_fill_and_global_ranges_are_explicit():
    copy = MemoryEffect(
        "copy",
        "argument",
        "argument_memory",
        MemoryExtent(argument_index=2),
        target_index=0,
        source_index=1,
    )
    fill = MemoryEffect(
        "fill",
        "argument",
        "argument",
        MemoryExtent(argument_index=2),
        target_index=0,
        source_index=1,
    )
    global_write = MemoryEffect(
        "global_write",
        "global",
        "argument",
        MemoryExtent(fixed_bytes=4),
        target_rva=0x4000,
        source_index=0,
    )
    assert copy.extent.argument_index == fill.extent.argument_index == 2
    assert global_write.target_rva == 0x4000
    with pytest.raises(ContractError, match="exactly one"):
        MemoryExtent()
    with pytest.raises(ContractError, match="memory source"):
        replace(copy, source="argument")


@pytest.mark.parametrize(
    "change",
    [
        {"binary_sha256": "not-a-hash"},
        {"callee_rva": -1},
        {"callee_snapshot_id": "snapshot-by-name"},
        {"calling_convention": ""},
        {"signature_digest": digest("sig")[:-1]},
    ],
)
def test_invalid_pinned_identity_rejected(change):
    with pytest.raises(ContractError):
        replace(summary_identity("callee", 0x100), **change)
