"""Real runner staging logic under a deterministic stubbed engine.

Imports ``flow_angr/runner.py`` in-process with fake ``angr``/``claripy``
modules: no angr install needed. The stub explores a scripted address CFG
so these tests prove OUR staging (ordered waypoints, state forwarding,
honest unknown) rather than the engine's symbolic semantics.
"""

import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

RUNNER_PATH = (
    Path(__file__).resolve().parents[2] / "src/ida_pro_mcp/flow_angr/runner.py"
)


def load_runner():
    spec = importlib.util.spec_from_file_location(
        "flow_angr_runner_under_test", RUNNER_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


STUB = {"cfg": {}, "sleep": 0.0, "eval": staticmethod(lambda state: 0)}


class FakeBVS:
    def __init__(self, name, bits):
        self.name = name
        self.bits = bits

    def __getitem__(self, key):
        return ("slice", self.name, key)


class FakeSolver:
    def __init__(self, state):
        self.state = state

    def eval(self, _token):
        return STUB["eval"](self.state)


class FakeState:
    def __init__(self, addr, path):
        self.addr = addr
        self.path = path
        self.regs = SimpleNamespace(rdi=None, rsi=None, rdx=None,
                                    rcx=None, r8=None, r9=None)
        self.history = SimpleNamespace(bbl_addrs=list(path))
        self.solver = FakeSolver(self)

    def fork(self, addr):
        return FakeState(addr, self.path + [addr])


class FakeSimgr:
    def __init__(self, states):
        self.stashes = {
            "active": list(states),
            "found": [],
            "deadended": [],
            "errored": [],
        }

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            return self.stashes[name]
        except KeyError:
            raise AttributeError(name) from None

    def use_technique(self, _technique):
        pass

    def explore(self, find, avoid, num_find):
        if STUB["sleep"]:
            time.sleep(STUB["sleep"])
        find, avoid = set(find), set(avoid)
        visited = set()
        queue = self.stashes["active"]
        self.stashes["active"] = []
        found_count = 0
        while queue and found_count < num_find:
            state = queue.pop(0)
            if state.addr in avoid:
                continue
            if state.addr in find:
                self.stashes["found"].append(state)
                found_count += 1
                continue
            if state.addr in visited:
                continue
            visited.add(state.addr)
            successors = STUB["cfg"].get(state.addr, [])
            if not successors:
                self.stashes["deadended"].append(state)
                continue
            queue.extend(state.fork(addr) for addr in successors)
        self.stashes["active"] = queue


class FakeFactory:
    def call_state(self, entry):
        return FakeState(entry, [entry])

    def simulation_manager(self, state):
        return FakeSimgr([state])


class FakeProject:
    def __init__(self, binary, auto_load_libs=False, main_opts=None):
        self.binary = binary
        self.loader = SimpleNamespace(symbols=[])
        self.factory = FakeFactory()
        self.analyses = SimpleNamespace(CFGFast=lambda **kwargs: object())

    def is_hooked(self, _addr):
        return False


@pytest.fixture()
def runner(monkeypatch):
    module = load_runner()
    fake_angr = ModuleType("angr")
    fake_angr.__version__ = "9.2.stub"
    fake_angr.Project = FakeProject
    fake_angr.exploration_techniques = SimpleNamespace(
        LoopSeer=lambda **kwargs: object()
    )
    fake_claripy = ModuleType("claripy")
    fake_claripy.BVS = FakeBVS
    monkeypatch.setitem(sys.modules, "angr", fake_angr)
    monkeypatch.setitem(sys.modules, "claripy", fake_claripy)
    monkeypatch.setitem(sys.modules, "z3", None)
    STUB["cfg"] = {}
    STUB["sleep"] = 0.0
    STUB["eval"] = lambda state: 0
    return module


def write_request(tmp_path, cfg, **overrides):
    binary = tmp_path / "probe.bin"
    binary.write_bytes(b"\x7fELF-fake")
    digest = "sha256-v1:" + hashlib.sha256(binary.read_bytes()).hexdigest()
    STUB["cfg"] = cfg
    request = {
        "binary_path": str(binary),
        "binary_sha256": digest,
        "image_base": 0,
        "entry_ea": 0x1000,
        "find_eas": [0x1020],
        "waypoint_eas": [],
        "avoid_eas": [],
        "symbolic_registers": [{"name": "rdi", "width_bits": 64}],
        "loop_bound": 8,
        "timeout_ms": 5000,
        "schema_version": 2,
    }
    request.update(overrides)
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(request))
    return request_path, tmp_path / "response.json"


def run(runner, request_path, response_path):
    runner.main(str(request_path), str(response_path))
    return json.loads(response_path.read_text())


def test_ordered_waypoints_reject_shortcut(runner, tmp_path):
    cfg = {0x1000: [0x1010], 0x1010: [0x1020, 0x1030], 0x1030: [0x1020]}
    request_path, response_path = write_request(
        tmp_path, cfg, waypoint_eas=[[0x1030]], find_eas=[0x1020]
    )
    payload = run(runner, request_path, response_path)
    assert payload["status"] == "feasible"
    assert payload["engine"]["runner_version"] == "flow-angr-runner/2"
    # E -> A -> B -> C: the shortcut E -> A -> C never reaches find
    # through the ordered stages, so the witness visits B.
    assert payload["engine"]["exploration_steps"] == 4


def test_unordered_single_find_accepts_shortcut(runner, tmp_path):
    cfg = {0x1000: [0x1010], 0x1010: [0x1020, 0x1030], 0x1030: [0x1020]}
    request_path, response_path = write_request(
        tmp_path, cfg, waypoint_eas=[], find_eas=[0x1020]
    )
    payload = run(runner, request_path, response_path)
    assert payload["status"] == "feasible"
    # Without waypoints the direct edge satisfies the find.
    assert payload["engine"]["exploration_steps"] == 3


def test_unreachable_waypoint_is_infeasible(runner, tmp_path):
    cfg = {0x1000: [0x1010], 0x1010: [0x1020]}
    request_path, response_path = write_request(
        tmp_path, cfg, waypoint_eas=[[0x1030]], find_eas=[0x1020]
    )
    payload = run(runner, request_path, response_path)
    assert payload["status"] == "infeasible"
    assert payload["unresolved"] == []
    assert payload["engine"]["runner_version"] == "flow-angr-runner/2"


def test_single_witness_covers_whole_ordered_path(runner, tmp_path):
    STUB["eval"] = lambda state: state.path[1]
    cfg = {
        0x1000: [0x1008, 0x1010],
        0x1008: [0x1030],
        0x1010: [0x1030],
        0x1030: [0x1020],
    }
    request_path, response_path = write_request(
        tmp_path, cfg, waypoint_eas=[[0x1030]], find_eas=[0x1020]
    )
    payload = run(runner, request_path, response_path)
    assert payload["status"] == "feasible"
    # One forwarded state's history: exactly one branch, no stitching.
    assert payload["engine"]["exploration_steps"] == 4
    (binding,) = payload["witness"]
    assert int(binding["value_hex"], 16) in (0x1008, 0x1010)


def test_empty_waypoints_behaves_like_single_find(runner, tmp_path):
    cfg = {0x1000: [0x1010], 0x1010: [0x1020, 0x1030], 0x1030: [0x1020]}
    request_path, response_path = write_request(
        tmp_path, cfg, waypoint_eas=[], find_eas=[0x1020], avoid_eas=[0x1030]
    )
    payload = run(runner, request_path, response_path)
    assert payload["status"] == "feasible"
    assert payload["engine"]["exploration_steps"] == 3


def test_sampled_stages_downgrade_later_infeasible_to_unknown(
    runner, tmp_path, monkeypatch
):
    monkeypatch.setattr(runner, "NUM_FIND_ALL", 1)
    cfg = {0x1000: [0x1008, 0x1010], 0x1008: [0x1030], 0x1010: [0x1030]}
    request_path, response_path = write_request(
        tmp_path, cfg, waypoint_eas=[[0x1030]], find_eas=[0x1020]
    )
    payload = run(runner, request_path, response_path)
    assert payload["status"] == "unknown"
    assert payload["unresolved"] == ["waypoint_exploration_capped"]


def test_waypoint_budget_exhaustion_is_honest_unknown(runner, tmp_path):
    STUB["sleep"] = 0.02
    chain = [0x1000 + index for index in range(32)]
    cfg = {addr: [nxt] for addr, nxt in zip(chain, chain[1:])}
    request_path, response_path = write_request(
        tmp_path,
        cfg,
        entry_ea=chain[0],
        waypoint_eas=[[addr] for addr in chain[1:-1]],
        find_eas=[chain[-1]],
        timeout_ms=150,
    )
    payload = run(runner, request_path, response_path)
    assert payload["status"] == "unknown"
    assert payload["unresolved"] == ["waypoint_budget_exhausted"]
    assert payload["engine"] is None
    assert payload["target_executed"] is False


def test_binary_mismatch_stays_unknown(runner, tmp_path):
    request_path, response_path = write_request(tmp_path, {})
    request = json.loads(request_path.read_text())
    request["binary_sha256"] = "sha256-v1:" + "00" * 32
    request_path.write_text(json.dumps(request))
    payload = run(runner, request_path, response_path)
    assert payload["status"] == "unknown"
    assert payload["unresolved"] == ["binary_mismatch"]
    assert payload["engine"] is None


@pytest.mark.parametrize(
    "override",
    [
        {"schema_version": 1},
        {"waypoint_eas": [[]]},
        {"waypoint_eas": [[-1]]},
        {"waypoint_eas": [["0x1000"]]},
        {"waypoint_eas": [[0x1000], "0x1010"]},
        {"timeout_ms": 0},
    ],
)
def test_request_validation_is_strict(runner, tmp_path, override):
    request_path, response_path = write_request(tmp_path, {}, **override)
    with pytest.raises(SystemExit):
        runner.main(str(request_path), str(response_path))


def test_missing_waypoint_key_is_strict(runner, tmp_path):
    request_path, response_path = write_request(tmp_path, {})
    request = json.loads(request_path.read_text())
    del request["waypoint_eas"]
    request_path.write_text(json.dumps(request))
    with pytest.raises(SystemExit):
        runner.main(str(request_path), str(response_path))
