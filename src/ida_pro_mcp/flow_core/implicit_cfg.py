"""Pure structural post-dominance and CFG control-dependence certificates."""

from dataclasses import dataclass
import heapq
from typing import Literal

from .contracts import Site
from .serialization import Model, digest
from .ssa import SSAProgram
from .states import canonical_set, check_digest, check_id, require, unique


@dataclass(frozen=True)
class ImplicitCFGPolicy(Model):
    """Deterministic structural-analysis limits, not path-feasibility limits."""

    max_blocks: int = 4096
    max_edges: int = 16384
    max_iterations: int = 1_000_000
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        require(
            self.max_blocks > 0 and self.max_edges > 0 and self.max_iterations > 0,
            "Invalid implicit CFG budget",
        )


@dataclass(frozen=True)
class PostDominatorBlock(Model):
    """A fixed-point certificate for one real block.

    ``post_dominators`` contains real blocks only. ``immediate_virtual_exit``
    records the otherwise unrepresentable synthetic-exit parent.
    """

    block: int
    post_dominators: tuple[int, ...]
    immediate: int | None
    immediate_virtual_exit: bool = False

    def __post_init__(self):
        super().__post_init__()
        require(self.block >= 0, "Negative post-dominator block")
        canonical_set(self.post_dominators)
        require(self.block in self.post_dominators, "Missing reflexive post-dominator")
        require(
            not (self.immediate is not None and self.immediate_virtual_exit),
            "Ambiguous immediate post-dominator",
        )
        if self.immediate is not None:
            require(
                self.immediate >= 0 and self.immediate in self.post_dominators,
                "Invalid immediate post-dominator",
            )
            require(self.immediate != self.block, "Reflexive immediate post-dominator")


@dataclass(frozen=True)
class ControlRegion(Model):
    """One successor-attributed edge control region.

    ``controlled_blocks`` preserves the post-dominator walk order. A partial
    region may have only ``frontier`` when the first successor is structurally
    unresolved; that is unknown coverage, never evidence of no control flow.
    """

    ordinal: int
    branch_block: int
    successor: int
    branch_node_id: str | None
    predicate_node_id: str | None
    evidence_ids: tuple[str, ...]
    sites: tuple[Site, ...]
    source_eas: tuple[int, ...]
    synthetic: bool
    controlled_blocks: tuple[int, ...]
    frontier: tuple[int, ...]
    status: Literal["complete", "partial"]
    diagnostics: tuple[str, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        require(
            self.ordinal >= 0 and self.branch_block >= 0 and self.successor >= 0,
            "Negative control-region position",
        )
        if self.branch_node_id is not None:
            check_id(self.branch_node_id, "node")
        if self.predicate_node_id is not None:
            check_id(self.predicate_node_id, "node")
            require(self.branch_node_id is not None, "Predicate without branch node")
        canonical_set(self.evidence_ids)
        for evidence_id in self.evidence_ids:
            check_id(evidence_id, "evidence")
        canonical_set(
            tuple(
                (site.block_index, site.instruction_index, site.operand_path)
                for site in self.sites
            )
        )
        canonical_set(self.source_eas)
        unique(self.controlled_blocks)
        require(
            all(block >= 0 for block in self.controlled_blocks),
            "Negative controlled block",
        )
        canonical_set(self.frontier)
        canonical_set(self.diagnostics)
        require(
            bool(self.controlled_blocks) or bool(self.frontier),
            "Empty control region is not evidence",
        )
        if self.status == "complete":
            require(
                self.branch_node_id is not None
                and self.predicate_node_id is not None
                and bool(self.controlled_blocks)
                and not self.frontier
                and not self.diagnostics,
                "Incomplete control region marked complete",
            )


@dataclass(frozen=True)
class ImplicitCFG(Model):
    """Versioned structural certificate consumed by implicit label analysis."""

    program_digest: str
    policy: ImplicitCFGPolicy
    reachable: tuple[int, ...]
    unreachable: tuple[int, ...]
    terminal_blocks: tuple[int, ...]
    return_exits: tuple[int, ...]
    unknown_exits: tuple[int, ...]
    nonreturning_blocks: tuple[int, ...]
    virtual_exit: int
    post_dominators: tuple[PostDominatorBlock, ...]
    regions: tuple[ControlRegion, ...]
    frontier: tuple[int, ...]
    status: Literal["complete", "partial"]
    diagnostics: tuple[str, ...]
    iterations: int
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        check_digest(self.program_digest)
        for values in (
            self.reachable,
            self.unreachable,
            self.terminal_blocks,
            self.return_exits,
            self.unknown_exits,
            self.nonreturning_blocks,
            self.frontier,
            self.diagnostics,
        ):
            canonical_set(values)
        require(
            not set(self.reachable) & set(self.unreachable),
            "Reachable/unreachable overlap",
        )
        require(
            set(self.return_exits) | set(self.unknown_exits)
            == set(self.terminal_blocks),
            "Terminal classification mismatch",
        )
        require(
            not set(self.return_exits) & set(self.unknown_exits),
            "Terminal classification overlap",
        )
        require(
            set(self.terminal_blocks) | set(self.nonreturning_blocks)
            <= set(self.reachable),
            "Structural classification outside reachable CFG",
        )
        require(
            self.virtual_exit >= 0
            and self.virtual_exit not in set(self.reachable) | set(self.unreachable),
            "Virtual exit aliases a real block",
        )
        require(
            tuple(block.block for block in self.post_dominators)
            == tuple(sorted(block.block for block in self.post_dominators)),
            "Post-dominator block order mismatch",
        )
        require(
            tuple(region.ordinal for region in self.regions)
            == tuple(range(len(self.regions))),
            "Control-region ordinal mismatch",
        )
        require(self.iterations >= 0, "Negative iteration count")
        if self.status == "complete":
            require(
                not self.frontier and not self.diagnostics,
                "Partial structural coverage marked complete",
            )


class _Budget:
    def __init__(self, maximum: int):
        self.maximum = maximum
        self.used = 0

    def tick(self, amount: int = 1) -> bool:
        if self.used + amount > self.maximum:
            return False
        self.used += amount
        return True


def _partial(
    program: SSAProgram,
    policy: ImplicitCFGPolicy,
    budget: _Budget,
    diagnostics: set[str],
    frontier: set[int],
    *,
    reachable: set[int] | None = None,
    unreachable: set[int] | None = None,
    terminals: set[int] | None = None,
    return_exits: set[int] | None = None,
    unknown_exits: set[int] | None = None,
    nonreturning: set[int] | None = None,
    post_dominators: tuple[PostDominatorBlock, ...] = (),
    regions: tuple[ControlRegion, ...] = (),
) -> ImplicitCFG:
    return ImplicitCFG(
        digest(program),
        policy,
        tuple(sorted(reachable or set())),
        tuple(sorted(unreachable or set())),
        tuple(sorted(terminals or set())),
        tuple(sorted(return_exits or set())),
        tuple(sorted(unknown_exits or set())),
        tuple(sorted(nonreturning or set())),
        len(program.graph.snapshot.function.blocks),
        post_dominators,
        regions,
        tuple(sorted(frontier)),
        "partial",
        tuple(sorted(diagnostics)),
        budget.used,
    )


def _reverse_reachable(
    starts: set[int],
    predecessors: dict[int, tuple[int, ...]],
    budget: _Budget,
) -> set[int] | None:
    reached: set[int] = set()
    pending = list(starts)
    heapq.heapify(pending)
    while pending:
        if not budget.tick():
            return None
        block = heapq.heappop(pending)
        if block in reached:
            continue
        reached.add(block)
        for predecessor in predecessors[block]:
            if predecessor not in reached:
                heapq.heappush(pending, predecessor)
    return reached


def analyze_implicit_cfg(
    program: SSAProgram,
    policy: ImplicitCFGPolicy = ImplicitCFGPolicy(),
) -> ImplicitCFG:
    """Compute bounded post-dominance and successor-attributed control regions."""

    function = program.graph.snapshot.function
    all_blocks = set(range(len(function.blocks)))
    edge_count = sum(len(block.successors) for block in function.blocks)
    budget = _Budget(policy.max_iterations)
    diagnostics: set[str] = set()
    if len(function.blocks) > policy.max_blocks:
        diagnostics.add("block_budget_exceeded")
    if edge_count > policy.max_edges:
        diagnostics.add("edge_budget_exceeded")
    if diagnostics:
        return _partial(program, policy, budget, diagnostics, all_blocks)

    reachable: set[int] = set()
    pending = [function.entry_block]
    while pending:
        if not budget.tick():
            diagnostics.add("iteration_budget_exceeded:reachability")
            return _partial(
                program,
                policy,
                budget,
                diagnostics,
                all_blocks - reachable,
                reachable=reachable,
            )
        block = heapq.heappop(pending)
        if block in reachable:
            continue
        reachable.add(block)
        for successor in function.blocks[block].successors:
            if successor not in reachable:
                heapq.heappush(pending, successor)
    unreachable = all_blocks - reachable

    definitions = {definition.node_id: definition for definition in program.definitions}
    nodes_by_block: dict[int, list] = {block: [] for block in all_blocks}
    for node in program.graph.nodes:
        nodes_by_block[definitions[node.node_id].block].append(node)
    for block_nodes in nodes_by_block.values():
        block_nodes.sort(
            key=lambda node: (definitions[node.node_id].order, node.node_id)
        )

    terminals = {block for block in reachable if not function.blocks[block].successors}
    return_exits: set[int] = set()
    unknown_exits: set[int] = set()
    for block in sorted(terminals):
        returns = [node for node in nodes_by_block[block] if node.kind == "Return"]
        branches = [node for node in nodes_by_block[block] if node.kind == "Branch"]
        if len(returns) == 1 and not branches:
            return_exits.add(block)
        else:
            unknown_exits.add(block)
            diagnostics.add(f"unknown_terminal:{block}")
            if branches:
                diagnostics.add(f"unresolved_branch_successor:{block}")
            if len(returns) > 1:
                diagnostics.add(f"ambiguous_return_exit:{block}")
    if len(terminals) > 1:
        diagnostics.add("multiple_terminal_exits")
    if not terminals:
        diagnostics.add("no_terminal_exit")

    predecessors = {
        block: tuple(
            predecessor
            for predecessor in function.blocks[block].predecessors
            if predecessor in reachable
        )
        for block in reachable
    }
    terminal_reaching = _reverse_reachable(terminals, predecessors, budget)
    if terminal_reaching is None:
        diagnostics.add("iteration_budget_exceeded:terminal_reachability")
        return _partial(
            program,
            policy,
            budget,
            diagnostics,
            reachable,
            reachable=reachable,
            unreachable=unreachable,
            terminals=terminals,
            return_exits=return_exits,
            unknown_exits=unknown_exits,
        )
    nonreturning = reachable - terminal_reaching
    if nonreturning:
        diagnostics.add("nonreturning_cfg_region")
    unsafe = _reverse_reachable(nonreturning, predecessors, budget)
    if unsafe is None:
        diagnostics.add("iteration_budget_exceeded:nonreturning_frontier")
        return _partial(
            program,
            policy,
            budget,
            diagnostics,
            reachable,
            reachable=reachable,
            unreachable=unreachable,
            terminals=terminals,
            return_exits=return_exits,
            unknown_exits=unknown_exits,
            nonreturning=nonreturning,
        )
    safe = reachable - unsafe

    virtual_exit = len(function.blocks)
    universe = safe | {virtual_exit}
    postdom: dict[int, set[int]] = {virtual_exit: {virtual_exit}}
    for block in safe:
        postdom[block] = set(universe)
    successors: dict[int, tuple[int, ...]] = {}
    for block in safe:
        if block in terminals:
            successors[block] = (virtual_exit,)
        else:
            successors[block] = function.blocks[block].successors
            require(
                set(successors[block]) <= safe,
                "Unsafe successor escaped nonreturning frontier",
            )

    changed = True
    while changed:
        changed = False
        for block in sorted(safe, reverse=True):
            if not budget.tick():
                diagnostics.add("iteration_budget_exceeded:post_dominance")
                return _partial(
                    program,
                    policy,
                    budget,
                    diagnostics,
                    reachable,
                    reachable=reachable,
                    unreachable=unreachable,
                    terminals=terminals,
                    return_exits=return_exits,
                    unknown_exits=unknown_exits,
                    nonreturning=nonreturning,
                )
            value = {block} | set.intersection(
                *(postdom[successor] for successor in successors[block])
            )
            if value != postdom[block]:
                postdom[block] = value
                changed = True

    immediate: dict[int, int] = {}
    post_blocks: list[PostDominatorBlock] = []
    for block in sorted(safe):
        strict = postdom[block] - {block}
        require(bool(strict), "Safe real block lacks virtual exit post-dominator")
        ordered = sorted(strict)
        parent = max(ordered, key=lambda value: (len(postdom[value]), -value))
        if sum(len(postdom[value]) == len(postdom[parent]) for value in ordered) > 1:
            diagnostics.add(f"ambiguous_immediate_post_dominator:{block}")
        immediate[block] = parent
        post_blocks.append(
            PostDominatorBlock(
                block,
                tuple(sorted(postdom[block] - {virtual_exit})),
                None if parent == virtual_exit else parent,
                parent == virtual_exit,
            )
        )

    evidence = {item.evidence_id: item for item in program.graph.evidence}
    dominance_depth = {
        item.block: len(item.dominators) for item in program.dominance.blocks
    }
    raw_regions: list[tuple[tuple[int, int, int], dict]] = []
    partial_frontier = set(unsafe)
    unknown_affected = _reverse_reachable(unknown_exits, predecessors, budget)
    if unknown_affected is None:
        diagnostics.add("iteration_budget_exceeded:unknown_exit_frontier")
        unknown_affected = set(reachable)
    partial_frontier.update(unknown_affected)
    if len(terminals) > 1:
        partial_frontier.update(reachable)
    if program.graph.axes.analysis != "complete_in_scope":
        diagnostics.add("input_graph_partial")
        partial_frontier.update(reachable)

    for branch_block in sorted(reachable):
        block_successors = function.blocks[branch_block].successors
        if len(block_successors) <= 1:
            continue
        branch_nodes = [
            node for node in nodes_by_block[branch_block] if node.kind == "Branch"
        ]
        binding_diagnostics: set[str] = set()
        branch_node = None
        predicate = None
        if len(branch_nodes) != 1:
            binding_diagnostics.add(
                f"{'missing' if not branch_nodes else 'ambiguous'}_branch_node:{branch_block}"
            )
        else:
            branch_node = branch_nodes[0]
            if len(branch_node.inputs) != 1:
                binding_diagnostics.add(f"missing_branch_predicate:{branch_block}")
            else:
                predicate = branch_node.inputs[0]

        evidence_ids = () if branch_node is None else branch_node.evidence_ids
        branch_evidence = [evidence[item] for item in evidence_ids]
        sites = tuple(
            sorted(
                {site for item in branch_evidence for site in item.sites},
                key=lambda site: (
                    site.block_index,
                    site.instruction_index,
                    site.operand_path,
                ),
            )
        )
        source_eas = tuple(
            sorted({ea for item in branch_evidence for ea in item.source_eas})
        )
        synthetic = bool(
            branch_node is not None
            and (
                branch_node.key.synthetic is not None
                or any(item.synthetic for item in branch_evidence)
            )
        )
        if binding_diagnostics:
            diagnostics.update(binding_diagnostics)
            partial_frontier.add(branch_block)

        for successor in block_successors:
            region_diagnostics = set(binding_diagnostics)
            controlled: list[int] = []
            region_frontier: set[int] = set()
            if branch_block not in safe or successor not in safe:
                region_frontier.add(successor)
                region_diagnostics.add("nonreturning_or_unresolved_successor")
            elif successor in postdom[branch_block]:
                continue
            else:
                stop = immediate[branch_block]
                runner = successor
                seen: set[int] = set()
                while runner != stop:
                    if not budget.tick():
                        region_frontier.add(runner)
                        region_diagnostics.add("iteration_budget_exceeded:region_walk")
                        break
                    if (
                        runner == virtual_exit
                        or runner not in immediate
                        or runner in seen
                    ):
                        region_frontier.add(runner)
                        region_diagnostics.add("unresolved_post_dominator_walk")
                        break
                    seen.add(runner)
                    controlled.append(runner)
                    runner = immediate[runner]

            if not controlled and not region_frontier:
                continue
            affected = {branch_block, successor, *controlled} & partial_frontier
            if affected:
                region_frontier.update(affected)
                if len(terminals) > 1:
                    region_diagnostics.add("multiple_terminal_exits")
                if unknown_exits:
                    region_diagnostics.add("unknown_exit_coverage")
                if nonreturning:
                    region_diagnostics.add("nonreturning_cfg_region")
                if program.graph.axes.analysis != "complete_in_scope":
                    region_diagnostics.add("input_graph_partial")
            raw_regions.append(
                (
                    (
                        dominance_depth.get(branch_block, len(all_blocks) + 1),
                        branch_block,
                        successor,
                    ),
                    {
                        "branch_block": branch_block,
                        "successor": successor,
                        "branch_node_id": (
                            None if branch_node is None else branch_node.node_id
                        ),
                        "predicate_node_id": predicate,
                        "evidence_ids": evidence_ids,
                        "sites": sites,
                        "source_eas": source_eas,
                        "synthetic": synthetic,
                        "controlled_blocks": tuple(controlled),
                        "frontier": tuple(sorted(region_frontier)),
                        "status": ("partial" if region_diagnostics else "complete"),
                        "diagnostics": tuple(sorted(region_diagnostics)),
                    },
                )
            )
            partial_frontier.update(region_frontier)

    raw_regions.sort(key=lambda item: item[0])
    regions = tuple(
        ControlRegion(ordinal=ordinal, **values)
        for ordinal, (_, values) in enumerate(raw_regions)
    )
    diagnostics.update(
        diagnostic for region in regions for diagnostic in region.diagnostics
    )
    status = "partial" if diagnostics or partial_frontier else "complete"
    return ImplicitCFG(
        digest(program),
        policy,
        tuple(sorted(reachable)),
        tuple(sorted(unreachable)),
        tuple(sorted(terminals)),
        tuple(sorted(return_exits)),
        tuple(sorted(unknown_exits)),
        tuple(sorted(nonreturning)),
        virtual_exit,
        tuple(post_blocks),
        regions,
        tuple(sorted(partial_frontier)),
        status,
        tuple(sorted(diagnostics)),
        budget.used,
    )


__all__ = [
    "ControlRegion",
    "ImplicitCFG",
    "ImplicitCFGPolicy",
    "PostDominatorBlock",
    "analyze_implicit_cfg",
]
