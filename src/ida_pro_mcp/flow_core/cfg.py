"""Deterministic dominance on a recovered CFG; no native control-flow recovery."""

from dataclasses import dataclass

from .contracts import FunctionInput
from .serialization import Model
from .states import canonical_set, require


@dataclass(frozen=True)
class BlockDominance(Model):
    block: int
    dominators: tuple[int, ...]
    immediate: int | None
    frontier: tuple[int, ...]


@dataclass(frozen=True)
class Dominance(Model):
    reachable: tuple[int, ...]
    unreachable: tuple[int, ...]
    blocks: tuple[BlockDominance, ...]

    def __post_init__(self):
        super().__post_init__()
        canonical_set(self.reachable)
        canonical_set(self.unreachable)
        require(
            tuple(b.block for b in self.blocks) == self.reachable,
            "Dominance block mismatch",
        )


def dominance(function: FunctionInput) -> Dominance:
    successors = {b.index: [] for b in function.blocks}
    for block in function.blocks:
        for pred in block.predecessors:
            successors[pred].append(block.index)
    entry = function.entry_block
    reachable, pending = set(), [entry]
    while pending:
        block = pending.pop()
        if block not in reachable:
            reachable.add(block)
            pending.extend(successors[block])
    dom = {b: ({b} if b == entry else set(reachable)) for b in reachable}
    changed = True
    while changed:
        changed = False
        for b in sorted(reachable - {entry}):
            preds = set(function.blocks[b].predecessors) & reachable
            value = {b} | set.intersection(*(dom[p] for p in preds))
            if value != dom[b]:
                dom[b], changed = value, True
    immediate = {entry: None}
    for b in sorted(reachable - {entry}):
        strict = dom[b] - {b}
        immediate[b] = max(strict, key=lambda d: len(dom[d]))
    frontier = {b: set() for b in reachable}
    # Definition-based frontier handles irreducible graphs and loop headers.
    for x in reachable:
        for y in reachable:
            if any(
                x in dom[p] for p in function.blocks[y].predecessors if p in reachable
            ):
                if x == y or x not in dom[y]:
                    frontier[x].add(y)
    return Dominance(
        tuple(sorted(reachable)),
        tuple(sorted(set(successors) - reachable)),
        tuple(
            BlockDominance(
                b, tuple(sorted(dom[b])), immediate[b], tuple(sorted(frontier[b]))
            )
            for b in sorted(reachable)
        ),
    )
