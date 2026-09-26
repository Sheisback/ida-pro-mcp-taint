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


def run_stub(tmp_path, monkeypatch, *, found=(), unconstrained=(), spinning=(),
             setup=None):
    request = {"binary_path": "unused", "binary_sha256": "unused",
               "image_base": 0x400000, "entry_ea": 0x400000,
               "find_eas": [0x400010], "symbolic_registers": [],
               "loop_bound": 8, "timeout_ms": 5000, "schema_version": 1}
    simgr = SimpleNamespace(active=[], found=list(found), errored=[],
                            unconstrained=list(unconstrained),
                            spinning=list(spinning),
                            use_technique=lambda _: None, explore=lambda **_: None)
    factory = SimpleNamespace(call_state=lambda _: object(),
                              simulation_manager=lambda _: simgr)
    if setup is None:
        setup = {}
    cfg = object()

    def cfg_fast(**kwargs):
        setup["cfg_options"] = kwargs
        setup["cfg"] = cfg
        return cfg

    def loop_seer(**kwargs):
        setup["loop_options"] = kwargs
        return object()

    project = SimpleNamespace(factory=factory,
                              analyses=SimpleNamespace(CFGFast=cfg_fast))
    angr = SimpleNamespace(Project=lambda *a, **kw: project,
                           exploration_techniques=SimpleNamespace(
                               LoopSeer=loop_seer))
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


def test_loop_seer_uses_entry_rooted_cfg_without_unrelated_discovery(
        tmp_path, monkeypatch):
    setup = {}
    run_stub(tmp_path, monkeypatch, setup=setup)
    assert setup["cfg_options"] == {
        "normalize": True,
        "function_starts": [0x400000],
        "start_at_entry": False,
        "symbols": False,
        "function_prologues": False,
        "force_smart_scan": False,
        "force_complete_scan": False,
        "eh_frame": False,
        "data_references": False,
        "resolve_indirect_jumps": True,
    }
    assert setup["loop_options"] == {"cfg": setup["cfg"], "bound": 8}


def test_loop_bound_exhaustion_remains_unknown(tmp_path, monkeypatch):
    result = run_stub(tmp_path, monkeypatch, spinning=(object(),))
    assert result["status"] == "unknown"
    assert result["unresolved"] == ["loop_bound_exceeded"]
    assert result["witness"] == []
    assert result["target_executed"] is False
