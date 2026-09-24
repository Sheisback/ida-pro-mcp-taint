"""Unreviewed local-callee closure never turns unknown targets into summaries."""

import json
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace as NS

from ida_pro_mcp.flow_core import digest
from ida_pro_mcp.flow_core.derived_calls import FiniteIndirectTargets
from ida_pro_mcp.flow_core.contracts import Snapshot
from test_flow_capabilities import flow as flow

ROOT = Path(__file__).resolve().parents[1]


def root_snapshot():
    return Snapshot.from_data(
        json.loads(
            (ROOT / "tests/flow_fixtures/manifests/extraction_x64.json").read_text()
        )["snapshot"]
    )


def test_exact_direct_callee_is_bounded_and_never_reviewed(flow, monkeypatch):
    module, _ = flow
    service = module._service()
    base = 0x100000000
    snap = root_snapshot()
    root = NS(
        image_base=base,
        function_rva=0x100,
        snapshot=snap,
        calls=(
            NS(call=NS(callee_ea=base + 0x200), instruction_ea=base + 0x150, block_index=0, instruction_index=0),
            NS(call=NS(callee_ea=None), instruction_ea=base + 0x158, block_index=0, instruction_index=0),
            NS(call=NS(callee_ea=base + 0x100), instruction_ea=base + 0x160, block_index=0, instruction_index=0),
        ),
    )
    calls = []
    monkeypatch.setitem(
        sys.modules, "ida_funcs", NS(get_func=lambda ea: NS(start_ea=ea))
    )
    monkeypatch.setattr(
        service.extractor,
        "extract_snapshot",
        lambda ea, **kw: calls.append((ea, kw)) or NS(snapshot=snap),
    )
    checks = []
    context = NS(
        check=lambda: checks.append(True),
        deadline=None,
        cancel=NS(is_set=lambda: False),
    )
    snapshots, closure = service.extract_local_direct_callees(
        context, root, {"profile": {}, "registry": object()}
    )
    assert set(snapshots) == {0x200}
    assert closure["mode"] == "derived_static_unreviewed"
    assert {item["reason"] for item in closure["boundaries"]} == {
        "unresolved_indirect",
        "recursive_boundary",
    }
    assert len(calls) == 1 and calls[0][0] == base + 0x200
    assert calls[0][1]["function_key"] == "function-entry:" + str(base + 0x200)
    assert checks


def test_foreign_or_nonexact_callee_stays_a_boundary(flow, monkeypatch):
    module, _ = flow
    service = module._service()
    base = 0x100000000
    snap = root_snapshot()
    root = NS(
        image_base=base,
        function_rva=0x100,
        snapshot=snap,
        calls=(NS(call=NS(callee_ea=base + 0x200), instruction_ea=base + 0x150),),
    )
    context = NS(check=lambda: None, deadline=None, cancel=NS(is_set=lambda: False))
    monkeypatch.setitem(
        sys.modules, "ida_funcs", NS(get_func=lambda ea: NS(start_ea=ea + 1))
    )
    snapshots, closure = service.extract_local_direct_callees(
        context, root, {"profile": {}, "registry": object()}
    )
    assert not snapshots
    assert closure["boundaries"][0]["reason"] == "no_exact_local_function"

    monkeypatch.setitem(
        sys.modules, "ida_funcs", NS(get_func=lambda ea: NS(start_ea=ea))
    )
    identity = replace(snap.identity, binary_digest=digest("foreign-input"))
    foreign = Snapshot(identity, snap.function, identity.snapshot_id)
    monkeypatch.setattr(
        service.extractor, "extract_snapshot", lambda *a, **kw: NS(snapshot=foreign)
    )
    snapshots, closure = service.extract_local_direct_callees(
        context, root, {"profile": {}, "registry": object()}
    )
    assert not snapshots
    assert closure["boundaries"][0]["reason"] == "foreign_or_stale_callee"


def test_finite_indirect_extracts_every_exact_candidate_or_keeps_unknown(flow, monkeypatch):
    module, _ = flow
    service = module._service()
    adapter = sys.modules[service.extract_local_direct_callees.__module__]
    base = 0x100000000
    source = root_snapshot()
    root = NS(
        image_base=base,
        function_rva=0x100,
        snapshot=source,
        calls=(
            NS(
                call=NS(callee_ea=None),
                instruction_ea=base + 0x150,
                block_index=0,
                instruction_index=0,
            ),
        ),
    )
    proof = FiniteIndirectTargets(
        source.snapshot_id,
        digest("ssa-graph"),
        0,
        0,
        source.snapshot_id.replace("snapshot-v1:", "node-v1:"),
        (base + 0x200, base + 0x300),
        True,
        (),
    )
    monkeypatch.setattr(adapter, "build_ssa", lambda *_args, **_kw: object())
    monkeypatch.setattr(
        adapter, "resolve_finite_indirect_targets", lambda *_args: proof
    )
    monkeypatch.setitem(sys.modules, "ida_funcs", NS(get_func=lambda ea: NS(start_ea=ea)))
    extracted = []
    monkeypatch.setattr(
        adapter.extractor,
        "extract_snapshot",
        lambda ea, **_kw: extracted.append(ea) or NS(snapshot=source),
    )
    ctx = NS(check=lambda: None, deadline=None, cancel=NS(is_set=lambda: False))
    snapshots, closure = service.extract_local_direct_callees(
        ctx, root, {"profile": {}, "registry": object()}
    )
    assert set(snapshots) == {0x200, 0x300}
    assert extracted == list(proof.targets)
    assert closure["finite_target_sets"] == [proof.to_data()]
    assert closure["boundaries"] == []

    partial = replace(proof, targets=(base + 0x200,), complete=False, reasons=("unknown_target_value",))
    monkeypatch.setattr(
        adapter, "resolve_finite_indirect_targets", lambda *_args: partial
    )
    extracted.clear()
    snapshots, closure = service.extract_local_direct_callees(
        ctx, root, {"profile": {}, "registry": object()}
    )
    assert not snapshots and not extracted
    assert "finite_target_sets" not in closure
    assert closure["boundaries"][0]["reason"] == "finite_target_set_incomplete"
    assert closure["boundaries"][0]["target_reasons"] == ["unknown_target_value"]

    monkeypatch.setattr(
        adapter, "resolve_finite_indirect_targets", lambda *_args: proof
    )
    monkeypatch.setitem(
        sys.modules,
        "ida_funcs",
        NS(get_func=lambda ea: NS(start_ea=ea if ea == proof.targets[0] else ea + 1)),
    )
    snapshots, closure = service.extract_local_direct_callees(
        ctx, root, {"profile": {}, "registry": object()}
    )
    assert set(snapshots) == {0x200}
    assert "finite_target_sets" not in closure
    assert {item["reason"] for item in closure["boundaries"]} == {
        "no_exact_local_function",
        "finite_target_extraction_incomplete",
    }
