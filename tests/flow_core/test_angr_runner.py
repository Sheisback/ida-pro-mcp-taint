"""Sidecar verdict regressions using SDK/engine-free simulation stubs."""

import json
import sys
from types import SimpleNamespace

from ida_pro_mcp.flow_angr import runner


class History:
    """Like angr's LambdaIterIter: iterable but not orderable."""

    def __init__(self, addresses):
        self.addresses = addresses

    def __iter__(self):
        return iter(self.addresses)

    def __len__(self):
        return len(self.addresses)


def run_stub(tmp_path, monkeypatch, *, found=(), unconstrained=()):
    request = {"binary_path": "unused", "binary_sha256": "unused",
               "image_base": 0x400000, "entry_ea": 0x400000,
               "find_eas": [0x400010], "symbolic_registers": [],
               "loop_bound": 8, "timeout_ms": 5000, "schema_version": 1}
    simgr = SimpleNamespace(active=[], found=list(found), errored=[],
                            unconstrained=list(unconstrained), spinning=[],
                            use_technique=lambda _: None, explore=lambda **_: None)
    factory = SimpleNamespace(call_state=lambda _: object(),
                              simulation_manager=lambda _: simgr)
    angr = SimpleNamespace(Project=lambda *a, **kw: SimpleNamespace(factory=factory),
                           exploration_techniques=SimpleNamespace(LoopSeer=lambda **_: None))
    monkeypatch.setattr(runner, "load_request", lambda _: request)
    monkeypatch.setattr(runner, "check_binary", lambda *_: True)
    monkeypatch.setattr(runner, "versions", lambda: ("test-angr", "test-z3", angr))
    monkeypatch.setitem(sys.modules, "claripy", SimpleNamespace())
    response = tmp_path / "response.json"
    runner.main("unused", str(response))
    return json.loads(response.read_text())


def test_unconstrained_states_are_unknown_not_infeasible(tmp_path, monkeypatch):
    result = run_stub(tmp_path, monkeypatch, unconstrained=(object(),))
    assert result["status"] == "unknown"
    assert result["unresolved"] == ["unconstrained_states"]
    assert result["target_executed"] is False


def test_multiple_found_histories_sort_as_comparable_tuples(tmp_path, monkeypatch):
    found = tuple(SimpleNamespace(history=SimpleNamespace(bbl_addrs=History(path)))
                  for path in ((0x400000, 0x400009), (0x400000,)))
    result = run_stub(tmp_path, monkeypatch, found=found)
    assert result["status"] == "feasible"
    assert result["engine"]["exploration_steps"] == 1


def test_exhausted_search_without_unresolved_states_is_infeasible(tmp_path, monkeypatch):
    result = run_stub(tmp_path, monkeypatch)
    assert result["status"] == "infeasible"
    assert result["unresolved"] == []
