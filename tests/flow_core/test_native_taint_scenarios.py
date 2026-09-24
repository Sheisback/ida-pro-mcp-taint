"""SDK-free checks for native diagnostic and evidence-gated acceptance."""

from copy import deepcopy
import re

import pytest

from native_taint_scenarios import (
    CASES,
    SOURCE,
    SourceSelectionError,
    acceptance_issues,
    calibrate,
    classify,
    entry_range,
    observations,
    source_seeds,
)


@pytest.mark.parametrize(
    "expected,observed,partial,outcome",
    [
        (True, True, False, "match"),
        (False, False, False, "match"),
        (True, True, True, "match_partial"),
        (False, False, True, "match_partial"),
        (True, False, False, "missing_taint"),
        (False, True, False, "overtaint"),
        (True, False, True, "inconclusive_partial"),
        (False, True, True, "inconclusive_partial"),
        (None, True, True, "calibration"),
    ],
)
def test_unknown_never_becomes_a_complete_pass(expected, observed, partial, outcome):
    assert classify(expected, observed, partial) == outcome


def node(identifier, kind, *, inputs=(), synthetic=None, constant=None, memory=None):
    return {
        "node_id": identifier,
        "kind": kind,
        "inputs": list(inputs),
        "phi_inputs": [],
        "key": {"synthetic": synthetic},
        "constant": constant,
        "memory_operands": memory,
    }


def test_calibration_follows_spilled_content_not_stack_address():
    nodes = [
        node(
            "argument",
            "InputValue",
            synthetic="memory:entry:microregister:microregister:64:32",
        ),
        node(
            "stack_pointer",
            "InputValue",
            synthetic="memory:entry:microregister:microregister:128:64",
        ),
        node(
            "spill",
            "Store",
            inputs=("argument", "stack_pointer"),
            memory={"data": "argument", "address": "stack_pointer"},
        ),
        node(
            "reload",
            "Load",
            inputs=("stack_pointer",),
            memory={"data": None, "address": "stack_pointer"},
        ),
        node("observer_address", "Constant", constant=4096),
        node(
            "observer",
            "Store",
            inputs=("reload", "observer_address"),
            memory={"data": "reload", "address": "observer_address"},
        ),
    ]
    graph = [
        {
            "type": "edge",
            "kind": "memory_data_dependency",
            "source": "spill",
            "target": "reload",
        }
    ]
    selected = observations(nodes, 4096)
    assert [item["node_id"] for item in selected] == ["observer"]
    assert calibrate(nodes, selected, graph) == [(64, 32)]
    with pytest.raises(SourceSelectionError):
        calibrate(nodes, selected, [])


def test_storage_location_not_guessed_from_other_synthetic_nodes():
    assert (
        entry_range(node("input", "InputValue", synthetic="memory:ssa:b1:n4")) is None
    )


def test_exact_or_calibrated_bit_range_source_never_whole_register_guess():
    exact = node(
        "exact", "InputValue", synthetic="memory:entry:microregister:microregister:64:32"
    )
    wider = node(
        "wider", "InputValue", synthetic="memory:entry:microregister:microregister:64:64"
    )
    assert source_seeds([exact], [(64, 32)])[0]["node_id"] == "exact"
    low = source_seeds([wider], [(64, 32)])
    high = source_seeds([wider], [(96, 32)])
    assert low[0]["kind"] == high[0]["kind"] == "bit_range"
    assert (low[0]["bit_offset"], low[0]["width_bits"]) == (0, 32)
    assert (high[0]["bit_offset"], high[0]["width_bits"]) == (32, 32)
    assert source_seeds([wider, wider], [(64, 32)]) == []
    partial = node(
        "partial", "InputValue", synthetic="memory:entry:microregister:microregister:64:16"
    )
    assert source_seeds([partial], [(64, 32)]) == []
    assert (
        entry_range(node("input", "InputValue", synthetic="entry:stack:stack:64:32"))
        is None
    )


def test_all_c_examples_have_independent_oracles():
    functions = re.findall(r"KEEP\s+\w+\s+taint_(\w+)\(", SOURCE.read_text())
    assert set(functions) == set(CASES)
    assert len(functions) == len(set(functions)) == 28
    assert sum(expected is None for expected in CASES.values()) == 1
    assert set(CASES.values()) == {True, False, None}


def _acceptance_row(case, expected, observed, unknown, *, causes=(), proofs=()):
    return {
        "case": case,
        "expected_dependency": expected,
        "observed_dependency": observed,
        "observation_unknown": unknown,
        "observation_kind": "dedicated_volatile_store",
        "native_return_node_count": 0,
        "classification": classify(expected, observed, unknown),
        "source_absent": False,
        "source_ranges": [[64, 32]],
        "seeds": [{"node_id": "input"}],
        "observations": [{"node_id": "store"}],
        "implicit_metadata": {
            "status": "complete_in_scope" if not unknown else "partial"
        },
        "explanations": [
            {
                "metadata": {"truncated": False, "target_executed": False},
                "items": list(causes),
            }
        ],
        "snapshot_result": {"derived_call_returns": list(proofs)},
        "bounded_accesses": [{"precision": "may_alias"}],
    }


def _case_issues(row):
    receipt = {
        "target_executed": False,
        "runs": [
            {
                "arch": "x86_64",
                "optimization": "O0",
                "closed_save_false": True,
                "input_preserved": True,
                "cases": [row],
            }
        ],
    }
    return [issue for issue in acceptance_issues(receipt) if f":{row['case']}:" in issue]


def test_acceptance_requires_derived_direct_return_not_just_an_observed_label():
    row = _acceptance_row(
        "call_identity", True, True, False,
        causes=({"type": "global_diagnostic", "code": "partial_scalar_input"},),
        proofs=({"argument_indices": [0], "provenance": "derived_static"},),
    )
    assert not _case_issues(row)
    stale = deepcopy(row)
    stale["snapshot_result"]["derived_call_returns"] = []
    assert any("direct_dependency_unproven" in issue for issue in _case_issues(stale))


def test_acceptance_replays_any_claimed_fixed_global_write_evidence():
    row = _acceptance_row(
        "call_identity", True, True, False,
        proofs=({"argument_indices": [0], "provenance": "derived_static"},),
    )
    row["snapshot_result"]["derived_call_memory_writes"] = [
        {"global_address": 0x2000, "proof_digest": "sha256-v1:proof"}
    ]
    assert any(
        "global_write_evidence_unavailable" in issue for issue in _case_issues(row)
    )
    row["derived_memory_evidence_pages"] = [
        {
            "metadata": {
                "proof_digest": "sha256-v1:proof",
                "memory_effects": "single_fixed_global_write",
                "target_executed": False,
            },
            "items": [{"type": "derived_global_write_effect"}],
        }
    ]
    assert not _case_issues(row)
    row["memory_metadata"] = {"diagnostics": ["unknown_call_or_write"]}
    assert any(
        "proven_global_write_still_havoced" in issue for issue in _case_issues(row)
    )


def test_acceptance_allows_only_a_structural_caller_bypass_of_unknown_call():
    row = _acceptance_row("call_identity", True, True, False)
    row["nodes"] = [
        node("input", "InputValue"),
        node("copy", "Copy", inputs=("input",)),
        node("store", "Store", memory={"data": "copy", "address": "address"}),
        node("address", "Constant"),
    ]
    row["snapshot_result"]["callee_closure"] = {
        "boundaries": [
            {
                "reason": "derived_call_effect_unavailable",
            }
        ]
    }
    assert any(
        "direct_call_rejection_detail_missing" in issue for issue in _case_issues(row)
    )
    row["snapshot_result"]["callee_closure"]["boundaries"][0][
        "callinfo_argument_count"
    ] = 0
    assert not _case_issues(row)
    row["nodes"][1] = node("copy", "Copy", inputs=("call",))
    row["nodes"].append(node("call", "Call", inputs=("input",)))
    assert any("direct_dependency_unproven" in issue for issue in _case_issues(row))


def test_acceptance_never_promotes_unexplained_alias_or_indirect_unknown():
    alias = _acceptance_row("pointer_only", False, True, True)
    assert any("untyped_alias_reason_missing" in issue for issue in _case_issues(alias))
    alias["explanations"][0]["items"] = [
        {
            "type": "cause",
            "reason_code": "cross_object_may_alias",
            "precision": "may_alias",
            "evidence_ids": ["evidence-v1:static"],
        }
    ]
    assert any(
        "mcp_untyped_alias_boundary_missing" in issue for issue in _case_issues(alias)
    )
    assert any(
        "mcp_alias_explanation_missing" in issue for issue in _case_issues(alias)
    )
    boundary = {
        "reason_code": "untyped_input_current_frame_noalias_unproven",
        "status": "unknown",
    }
    alias["memory_items"] = [{"alias_boundary": boundary}]
    alias["explanations"][0]["items"][0]["alias_boundary"] = boundary
    assert not _case_issues(alias)
    indirect = _acceptance_row("call_indirect", True, False, True)
    assert any("indirect_unknown_boundary_missing" in issue for issue in _case_issues(indirect))
    indirect["explanations"][0]["items"] = [
        {"type": "cause", "reason_code": "call_boundary"}
    ]
    assert not _case_issues(indirect)


def test_acceptance_requires_pointer_spill_clobber_cause_when_reported():
    row = _acceptance_row("store_then_load", True, True, True)
    row["memory_metadata"] = {"diagnostics": ["partial_pointer_reload"]}
    row["explanations"][0]["items"] = [
        {
            "type": "cause",
            "reason_code": "unknown_address",
            "precision": "range_widened",
            "evidence_ids": ["evidence-v1:static"],
        }
    ]
    assert any(
        "pointer_spill_clobber_cause_missing" in issue for issue in _case_issues(row)
    )
    row["explanations"][0]["items"].append(
        {
            "type": "cause",
            "reason_code": "cross_object_may_alias",
            "precision": "may_alias",
            "evidence_ids": ["evidence-v1:static"],
            "alias_boundary": {"status": "unknown"},
        }
    )
    assert not _case_issues(row)


@pytest.mark.parametrize(
    ("case", "pointer_index"),
    [("pointer_only", 0), ("load_before_store", 1)],
)
def test_acceptance_rejects_untyped_exact_clean_without_noalias_proof(
    case, pointer_index
):
    row = _acceptance_row(case, False, False, False)
    assert any(
        "untyped_alias_promoted_without_proof" in issue for issue in _case_issues(row)
    )
    row["ssa_metadata"] = {
        "argument_bindings": [
            {
                "argument_index": pointer_index,
                "provenance": "current_idb_type_and_sdk_reg_argloc",
                "type_correctness": "analyst_assumption",
                "idb_pointer_type_assumption": True,
                "storage": {"width_bits": 64},
            }
        ]
    }
    row["memory_items"] = [{"type": "object", "kind": "typed_entry"}]
    assert not _case_issues(row)
    row["memory_items"] = [{"type": "object", "kind": "argument"}]
    assert any(
        "untyped_alias_promoted_without_proof" in issue for issue in _case_issues(row)
    )
    row["memory_items"] = [{"type": "object", "kind": "typed_entry"}]
    row["ssa_metadata"]["argument_bindings"][0][
        "idb_pointer_type_assumption"
    ] = False
    assert any(
        "untyped_alias_promoted_without_proof" in issue for issue in _case_issues(row)
    )


def test_acceptance_requires_exact_simple_case_even_if_global_is_partial():
    scalar = _acceptance_row("identity", True, True, False)
    assert not _case_issues(scalar)
    scalar["implicit_metadata"]["status"] = "partial"
    assert any("exact_source_or_precision_mismatch" in issue for issue in _case_issues(scalar))
