"""Opt-in angr sidecar client. SDK-free core; never imports angr.

angr pins ``z3-solver==4.13`` while this package verifies against z3 5.x, so
the engines cannot share one interpreter. The sidecar runs a repository-owned
runner script under an explicitly configured angr-capable Python and speaks
JSON files. Every transport or engine failure degrades to an explicit
``unknown`` result; only malformed client-side requests raise.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .serialization import ContractError, Model
from .states import check_digest, nonempty, require

ANGR_INTERPRETER_ENV = "IDA_MCP_ANGR_PYTHON"
ANGR_REQUEST_VERSION = 1
ANGR_RUNNER_VERSION = "flow-angr-runner/1"
ANGR_MIN_TIMEOUT_MS = 100
ANGR_MAX_TIMEOUT_MS = 120000
ANGR_DEFAULT_LOOP_BOUND = 8

X64_ARG_REGISTERS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")


@dataclass(frozen=True)
class AngrContext:
    """Everything the path tier needs besides graph and selector."""

    sidecar: AngrSidecar
    binary_path: str
    binary_sha256: str
    image_base: int

    def __post_init__(self):
        require(type(self.sidecar) is AngrSidecar, "angr sidecar misconfigured")
        nonempty(self.binary_path)
        check_digest(self.binary_sha256)
        require(
            type(self.image_base) is int and self.image_base >= 0,
            "Invalid angr image base",
        )


def build_prefix_query(
    graph,
    selector,
    context: AngrContext,
    *,
    timeout_ms: int,
    loop_bound: int = ANGR_DEFAULT_LOOP_BOUND,
) -> AngrQuery:
    """Translate an entry-rooted block prefix into a sidecar question.

    Find targets are the final block's entry addresses; every off-prefix
    successor along the way becomes an avoid address. Reject repeats,
    shortcuts, re-entry and ambiguous native translations that this global
    find/avoid encoding cannot represent. Missing addresses or a non-X64
    environment also refuse, so the caller degrades honestly instead of
    asking a different question than the selector names.
    """
    environment = graph.snapshot.identity.environment
    if not (
        environment.processor == "metapc"
        and type(environment.bitness) is int
        and environment.bitness == 64
    ):
        raise ContractError("angr_arch_unsupported")
    blocks = {block.index: block for block in graph.snapshot.function.blocks}
    entry = graph.snapshot.function.entry_block
    path = list(selector.blocks)
    require(
        len(path) > 0
        and all(type(index) is int for index in path)
        and all(index in blocks for index in path)
        and path[0] == entry,
        "angr prefix must be entry-rooted",
    )

    require(len(set(path)) == len(path), "angr_prefix_repeated_block")
    for current, following in zip(path, path[1:]):
        require(following in blocks[current].successors, "angr_prefix_nonedge")
        require(
            all(successor == following or successor not in path
                for successor in blocks[current].successors),
            "angr_prefix_order_unencodable",
        )

    def entry_addresses(index):
        # Empty blocks are common in real extraction (synthetic entries,
        # address-less glue). A block with no instructions of its own starts
        # where its linear successor chain starts; a fork in that chain is
        # ambiguous, so it refuses instead of guessing an address.
        seen = set()
        current = index
        while True:
            require(current not in seen, "angr_missing_block_addresses")
            require(current in blocks, "angr_missing_block_addresses")
            seen.add(current)
            instructions = blocks[current].instructions
            if instructions:
                require(bool(instructions[0].source_eas), "angr_missing_block_addresses")
                addresses = tuple(instructions[0].source_eas)
                require(len(addresses) == 1, "angr_ambiguous_block_addresses")
                return addresses
            successors = blocks[current].successors
            require(len(successors) == 1, "angr_missing_block_addresses")
            current = successors[0]

    # Distinct native blocks must not share instruction provenance. Empty
    # linear glue may resolve to its successor, but real overlapping blocks
    # cannot be represented faithfully by a global address find/avoid set.
    address_owners: dict[int, int] = {}
    for block in blocks.values():
        for instruction in block.instructions:
            for address in instruction.source_eas:
                require(
                    address not in address_owners
                    or address_owners[address] == block.index,
                    "angr_block_address_overlap",
                )
                address_owners[address] = block.index

    selected_addresses: set[int] = set()
    previous_index = None
    previous_address = None
    for index in path:
        address = entry_addresses(index)[0]
        if address in selected_addresses:
            # Only forward, consecutive empty glue can share a native entry.
            # An empty tail pointing back at real code is a new visit, not
            # the already-satisfied global find condition at function entry.
            require(
                previous_index is not None
                and not blocks[previous_index].instructions
                and address == previous_address,
                "angr_prefix_address_reentry",
            )
        selected_addresses.add(address)
        previous_index, previous_address = index, address
    find = entry_addresses(path[-1])
    avoid_addresses: list[int] = []
    for position in range(len(path) - 1):
        for successor in blocks[path[position]].successors:
            if successor not in path:
                avoid_addresses.extend(entry_addresses(successor))
    avoid = tuple(sorted(set(avoid_addresses)))
    require(
        not (selected_addresses & set(avoid)),
        "angr_find_avoid_overlap",
    )
    return AngrQuery(
        binary_path=context.binary_path,
        binary_sha256=context.binary_sha256,
        image_base=context.image_base,
        entry_ea=entry_addresses(path[0])[0],
        find_eas=find,
        avoid_eas=avoid,
        symbolic_registers=tuple(
            AngrSymbolicRegister(name, 64) for name in X64_ARG_REGISTERS
        ),
        loop_bound=loop_bound,
        timeout_ms=timeout_ms,
    )


def default_runner_path() -> Path:
    return Path(__file__).resolve().parents[1] / "flow_angr" / "runner.py"


@dataclass(frozen=True)
class AngrSymbolicRegister(Model):
    name: str
    width_bits: int

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.name)
        require(1 <= self.width_bits <= 64, "Symbolic register needs 1..64 bits")


@dataclass(frozen=True)
class AngrQuery(Model):
    """One prefix-feasibility question for the sidecar runner."""

    binary_path: str
    binary_sha256: str
    image_base: int
    entry_ea: int
    find_eas: tuple[int, ...]
    avoid_eas: tuple[int, ...] = ()
    symbolic_registers: tuple[AngrSymbolicRegister, ...] = ()
    loop_bound: int = 8
    timeout_ms: int = 5000
    schema_version: Literal[1] = 1

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.binary_path)
        check_digest(self.binary_sha256)
        require(
            type(self.image_base) is int and self.image_base >= 0,
            "Invalid image_base",
        )
        require(type(self.entry_ea) is int and self.entry_ea >= 0, "Invalid entry_ea")
        require(
            all(type(ea) is int and ea >= 0 for ea in self.find_eas)
            and len(self.find_eas) > 0,
            "find_eas needs at least one address",
        )
        require(
            all(type(ea) is int and ea >= 0 for ea in self.avoid_eas),
            "Invalid avoid_eas",
        )
        require(
            type(self.loop_bound) is int and 0 < self.loop_bound <= 1024,
            "Invalid angr loop bound",
        )
        require(
            type(self.timeout_ms) is int
            and ANGR_MIN_TIMEOUT_MS <= self.timeout_ms <= ANGR_MAX_TIMEOUT_MS,
            "Invalid angr timeout",
        )
        require(self.schema_version == ANGR_REQUEST_VERSION, "Invalid angr request")


@dataclass(frozen=True)
class AngrEngineInfo(Model):
    name: str
    runner_version: str
    angr_version: str
    z3_version: str
    simprocedures: tuple[str, ...] = ()
    loop_bound: int = 0
    exploration_steps: int = 0

    def __post_init__(self):
        super().__post_init__()
        require(self.name == "angr-sidecar", "Unexpected angr engine name")
        nonempty(self.runner_version)
        nonempty(self.angr_version)
        nonempty(self.z3_version)
        require(
            all(type(item) is str and bool(item) for item in self.simprocedures),
            "Invalid simprocedures",
        )
        require(
            type(self.loop_bound) is int and self.loop_bound >= 0,
            "Invalid engine loop bound",
        )
        require(
            type(self.exploration_steps) is int and self.exploration_steps >= 0,
            "Invalid exploration steps",
        )


@dataclass(frozen=True)
class AngrWitnessBinding(Model):
    name: str
    width_bits: int
    value_hex: str

    def __post_init__(self):
        super().__post_init__()
        nonempty(self.name)
        require(1 <= self.width_bits <= 64, "Witness width needs 1..64 bits")
        require(type(self.value_hex) is str, "Invalid witness value")
        try:
            value = int(self.value_hex, 16)
        except ValueError:
            raise ContractError("Invalid witness value") from None
        require(0 <= value < (1 << self.width_bits), "Witness outside width")


@dataclass(frozen=True)
class AngrResult(Model):
    status: Literal["feasible", "infeasible", "unknown"]
    witness: tuple[AngrWitnessBinding, ...] = ()
    engine: AngrEngineInfo | None = None
    unresolved: tuple[str, ...] = ()
    target_executed: bool = False

    def __post_init__(self):
        super().__post_init__()
        require(self.target_executed is False, "angr must stay static-only")
        require(
            all(type(item) is str and bool(item) for item in self.unresolved),
            "Invalid unresolved reasons",
        )
        if self.status == "unknown":
            require(len(self.witness) == 0, "Unknown answers carry no witness")
        else:
            require(self.engine is not None, "Definite answers need engine facts")


@dataclass(frozen=True)
class AngrSidecar:
    """Host configuration: which interpreter runs the vendored runner."""

    interpreter: str
    runner: str = field(default="")

    def __post_init__(self):
        # Empty interpreter is a normal unconfigured state; probe()/query()
        # degrade to explicit unknown instead of raising here.
        runner = self.runner or str(default_runner_path())
        object.__setattr__(self, "runner", runner)

    def probe(self) -> str:
        """Inspect configuration only; never import or launch the engine.

        Existing paths are configured, not proof that engine imports work.
        Only an explicitly requested query runs the sidecar.
        """
        if not os.path.isfile(self.interpreter) or not os.access(
            self.interpreter, os.X_OK
        ):
            return "angr_unavailable"
        if not os.path.isfile(self.runner):
            return "angr_runner_missing"
        return "angr_configured_unverified"


def sidecar_from_environment(explicit: str | None = None) -> AngrSidecar:
    interpreter = explicit or os.environ.get(ANGR_INTERPRETER_ENV, "")
    return AngrSidecar(interpreter=interpreter)


def _unknown(reason: str) -> AngrResult:
    return AngrResult("unknown", unresolved=(reason,))


def query(
    sidecar: AngrSidecar,
    query: AngrQuery,
    *,
    cancelled=lambda: False,
) -> AngrResult:
    """Run one sidecar question. Engine failures become explicit unknown."""
    require(type(query) is AngrQuery, "angr query must be validated first")
    blocked = sidecar.probe()
    if blocked != "angr_configured_unverified":
        return _unknown(blocked)
    if cancelled():
        return _unknown("cancelled")
    with tempfile.TemporaryDirectory(prefix="flow-angr-") as work:
        request_path = Path(work) / "request.json"
        response_path = Path(work) / "response.json"
        request_path.write_text(json.dumps(query.to_data()))
        try:
            proc = subprocess.Popen(
                [sidecar.interpreter, sidecar.runner, str(request_path),
                 str(response_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            return _unknown("angr_unavailable")
        deadline = time.monotonic() + query.timeout_ms / 1000
        while True:
            if cancelled():
                proc.kill()
                proc.wait()
                return _unknown("cancelled")
            try:
                proc.wait(timeout=0.05)
                break
            except subprocess.TimeoutExpired:
                if time.monotonic() >= deadline:
                    proc.kill()
                    proc.wait()
                    return _unknown("angr_timeout")
        if proc.returncode != 0:
            return _unknown("angr_runner_failed")
        try:
            raw = json.loads(response_path.read_text())
        except (OSError, ValueError):
            return _unknown("angr_malformed_response")
    try:
        return AngrResult.from_data(_coerce_response(raw))
    except ContractError:
        return _unknown("angr_malformed_response")


def _coerce_response(raw: Any) -> dict[str, Any]:
    require(type(raw) is dict, "angr response must be an object")
    data = dict(raw)
    witness = data.get("witness", [])
    require(type(witness) is list, "angr witness must be a list")
    data["witness"] = [
        (
            AngrWitnessBinding.from_data(item).to_data()
            if type(item) is dict
            else item
        )
        for item in witness
    ]
    engine = data.get("engine")
    if engine is not None:
        data["engine"] = (
            AngrEngineInfo.from_data(engine).to_data()
            if type(engine) is dict
            else engine
        )
    return data
