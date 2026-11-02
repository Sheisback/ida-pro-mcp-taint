"""Tests for api_driver (Windows driver triage tools)."""

import json
from pathlib import Path

from ..api_driver import (
    driver_audit_acl,
    driver_audit_exports,
    driver_decode_ioctls,
    driver_find_devices,
    driver_find_ioctls,
    driver_find_pooltags,
    driver_flag_functions,
    driver_survey,
    driver_trace_calls,
    driver_triage_leads,
)
from ..driver.selector_structure import (
    _same_ctree_expression,
    _top_level_statements,
    build_ioctl_selector_fact,
)
from ..driver.pipeline import run_full
from ..framework import (
    assert_has_keys,
    assert_is_list,
    assert_valid_address,
    test,
)


@test()
def test_driver_survey_shape():
    """driver_survey returns the documented shape on any binary."""
    result = driver_survey()
    assert_has_keys(
        result,
        "is_pe",
        "is_driver",
        "is_64bit",
        "driver_entry",
        "framework",
        "framework_evidence",
        "dispatchers",
        "import_count",
        "function_count",
        "limitations",
    )
    assert isinstance(result["is_driver"], bool)
    assert_is_list(result["dispatchers"])
    assert_is_list(result["limitations"])


@test(binary="crackme03.elf")
def test_driver_survey_elf_is_not_driver():
    """driver_survey reports a Linux ELF as not a driver without failing."""
    result = driver_survey()
    assert result["is_pe"] is False
    assert result["is_driver"] is False
    assert result["framework"] == "not_driver"
    assert result["dispatchers"] == []
    assert result["driver_entry"] is None


@test()
def test_driver_decode_ioctls_vectors():
    """driver_decode_ioctls decodes documented vectors on any binary."""
    result = driver_decode_ioctls(["0x222000", "0x80002003", "0xFFFFFFFF"])
    assert_has_keys(result, "results", "ntstatus_source")
    by_input = {item["input"]: item for item in result["results"]}
    buffered = by_input["0x222000"]
    assert buffered["device_name"] == "FILE_DEVICE_UNKNOWN"
    assert buffered["method"] == "METHOD_BUFFERED"
    assert buffered["access"] == "FILE_ANY_ACCESS"
    assert buffered["plausible"] is True
    neither = by_input["0x80002003"]
    assert neither["method"] == "METHOD_NEITHER"
    assert neither["plausible"] is True
    assert neither["severity_rank"] >= buffered["severity_rank"]
    sentinel = by_input["0xFFFFFFFF"]
    assert sentinel["plausible"] is False


@test()
def test_driver_decode_ioctls_rejects_bad_input():
    """driver_decode_ioctls reports per-item errors without failing the batch."""
    result = driver_decode_ioctls(["0x222000", "not-a-code"])
    by_input = {item["input"]: item for item in result["results"]}
    assert "error" not in by_input["0x222000"]
    assert "error" in by_input["not-a-code"]


@test()
def test_driver_selector_fact_rejects_heuristic_or_non_external_dispatch():
    """Only an exact external device-control ctree case gets a trigger fact."""
    fixture = json.loads((Path(__file__).resolve().parents[4]
        / "tests/fixtures/driver_ioctl_selector_projection.json").read_text())
    candidate = fixture["structuredContent"]["candidates"][0]
    producer = fixture["structuredContent"]["trigger_fact_producer"]
    assert build_ioctl_selector_fact(producer, candidate,
        device_control_code=0x0E) is not None
    assert build_ioctl_selector_fact(producer, {**candidate, "method_detail": "immediate"},
        device_control_code=0x0E) is None
    wrong_index = json.loads(json.dumps(producer))
    wrong_index["registrations"][0]["major_function_index"] = 0x0F
    assert build_ioctl_selector_fact(wrong_index, candidate,
        device_control_code=0x0E) is None


@test()
def test_driver_selector_fact_matches_the_cross_repo_projection_fixture():
    """The shared projection is emitted from the same structural IDA fact shape."""
    fixture = json.loads((Path(__file__).resolve().parents[4]
        / "tests/fixtures/driver_ioctl_selector_projection.json").read_text())
    candidate = fixture["structuredContent"]["candidates"][0]
    assert build_ioctl_selector_fact(fixture["structuredContent"]["trigger_fact_producer"],
        candidate, device_control_code=0x0E) == candidate["selector_fact"]


@test()
def test_driver_registration_write_audit_uses_the_complete_sdk_operator_families():
    """The installed SDK classifies every compound and pre/post lvar write."""
    import ida_hexrays

    assignments = (
        ida_hexrays.cot_asg, ida_hexrays.cot_asgbor, ida_hexrays.cot_asgxor,
        ida_hexrays.cot_asgband, ida_hexrays.cot_asgadd, ida_hexrays.cot_asgsub,
        ida_hexrays.cot_asgmul, ida_hexrays.cot_asgsshr, ida_hexrays.cot_asgushr,
        ida_hexrays.cot_asgshl, ida_hexrays.cot_asgsdiv, ida_hexrays.cot_asgudiv,
        ida_hexrays.cot_asgsmod, ida_hexrays.cot_asgumod,
    )
    prepost = (ida_hexrays.cot_postinc, ida_hexrays.cot_postdec,
        ida_hexrays.cot_preinc, ida_hexrays.cot_predec)
    assert all(ida_hexrays.is_assignment(op) for op in assignments)
    assert all(ida_hexrays.is_prepost(op) for op in prepost)


@test(binary="driver_fixture.sys")
def test_driver_ctree_proxy_identity_and_explicit_qvector_iteration():
    """Real SDK wrappers compare by ctree identity and cblock is indexed explicitly."""
    import ida_hexrays
    import idc

    cfunc = ida_hexrays.decompile(idc.get_name_ea_simple("DispatchDeviceControl"))
    statements = _top_level_statements(cfunc)
    assert len(statements) == len(cfunc.body.cblock)
    top_expressions = [statement.cexpr for statement in statements
        if statement.op == ida_hexrays.cit_expr]

    class Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)
            self.expressions = []

        def visit_expr(self, item):
            self.expressions.append(item)
            return 0

    visitor = Visitor()
    visitor.apply_to(cfunc.body, None)
    recreated = []
    for expression in top_expressions:
        matches = [item for item in visitor.expressions
            if item.op == expression.op and int(item.ea) == int(expression.ea)]
        if matches:
            recreated.append(matches[0] is not expression
                and _same_ctree_expression(matches[0], expression))
    assert recreated and all(recreated)


@test()
def test_mup_helper_registration_remains_unsupported_when_prefix_control_is_unproven():
    import idc
    if idc.get_name_ea_simple("DriverEntry") != 0x140023010:
        return
    survey = driver_survey()
    typed = [item for item in survey["dispatchers"]
        if item["kind"] == "device_control"]
    assert all(item["confidence"] != "typed_registration" for item in typed)
    assert survey["trigger_fact_producer"]["status"] == "unsupported"
    assert survey["trigger_fact_producer"]["reason_code"] \
        == "helper_registration_prefix_control_unsupported"
    result = driver_find_ioctls()
    producer = result["trigger_fact_producer"]
    assert producer["status"] == "unsupported"
    assert producer["reason_code"] == "helper_registration_prefix_control_unsupported"




@test(binary="crackme03.elf")
def test_driver_find_ioctls_elf_reports_not_driver():
    """driver_find_ioctls on a non-driver returns empty candidates plus a reason."""
    result = driver_find_ioctls()
    assert result["candidates"] == []
    assert "not a Windows driver" in result["reason"]


@test(binary="crackme03.elf")
def test_driver_evidence_tools_elf_report_not_driver():
    """Device/ACL/pooltag/flag/export/trace/leads tools degrade cleanly on ELF."""
    assert "not a Windows driver" in driver_find_devices()["reason"]
    assert "not a Windows driver" in driver_audit_acl()["reason"]
    assert "not a Windows driver" in driver_find_pooltags()["reason"]
    assert "not a Windows driver" in driver_flag_functions()["reason"]
    assert "not a Windows driver" in driver_audit_exports()["reason"]
    assert "not a Windows driver" in driver_trace_calls()["reason"]
    assert "not a Windows driver" in driver_triage_leads()["reason"]


@test(binary="crackme03.elf")
def test_driver_pipeline_elf_summary():
    """run_full on a non-driver returns a not_driver summary without stages."""
    artifacts = run_full()
    assert artifacts["summary"]["driver_type"] == "not_driver"
    assert artifacts["survey"]["is_driver"] is False


@test()
def test_driver_decode_ioctls_accepts_comma_string():
    """driver_decode_ioctls accepts a comma-separated string batch."""
    result = driver_decode_ioctls("0x222000, 0x222004")
    assert len(result["results"]) == 2
    for item in result["results"]:
        assert_valid_address(item["code"])


@test(binary="driver_fixture.sys")
def test_driver_fixture_survey_finds_dispatchers():
    """Owned fixture survey finds DriverEntry and both dispatchers."""
    result = driver_survey()
    assert result["is_pe"] is True
    assert result["is_driver"] is True
    assert result["driver_entry"]["name"] == "DriverEntry"
    by_kind = {d["kind"]: d for d in result["dispatchers"]}
    assert by_kind["device_control"]["name"] == "DispatchDeviceControl"
    assert by_kind["device_control"]["confidence"] == "function"
    assert by_kind["internal_device_control"]["name"] == "DispatchInternal"
    assert by_kind["file_system_control"]["name"] == "DispatchFileSystemControl"
    assert "no framework import marker; assuming WDM-shaped" not in result["limitations"]


@test(binary="driver_fixture.sys")
def test_driver_survey_excludes_constant_stores_at_dispatch_slot_offsets():
    """Unrelated data at the same displacement must not become a dispatcher."""
    result = driver_survey()
    assert all(int(item["addr"], 16) != 3 for item in result["dispatchers"])
    assert {item["name"] for item in result["dispatchers"]
            if item["kind"] == "device_control"} == {"DispatchDeviceControl"}


@test(binary="driver_stub_fixture.sys")
def test_driver_survey_unwraps_the_tail_driver_entry_call():
    """A cookie initializer before the real entry is not the driver entry."""
    result = driver_survey()
    assert result["driver_entry"]["name"] == "GsDriverEntry"
    import idc
    assert result["driver_entry"]["real_entry"] == hex(
        idc.get_name_ea_simple("DriverEntry"))
    assert result["trigger_fact_producer"]["driver_entry_ea"] \
        == result["driver_entry"]["real_entry"]


@test(binary="driver_fixture.sys")
def test_control_code_scan_follows_irp_stack_address_temporary():
    import idc
    from ..driver.dispatch import references_iocontrolcode
    ea = idc.get_name_ea_simple("StackAliasControlCode")
    assert references_iocontrolcode(ea, True)[0] is True


@test(binary="driver_fixture.sys")
def test_control_code_fallback_inspects_later_functions():
    from ..api_driver import _fresh_context
    from ..driver.ioctl_scan import scan_iocontrolcode_fallback
    result, stats = scan_iocontrolcode_fallback(_fresh_context(), set())
    assert stats["functions_scanned"] > 16
    assert any(item["code_int"] == 0x9848C
               and item["function"] == "DispatchFileSystemControl"
               for item in result)


@test(binary="driver_fixture.sys")
def test_control_code_fallback_still_runs_when_direct_dispatchers_have_codes():
    result = driver_find_ioctls()
    assert any(item["code_int"] == 0x98490
               and item["function"] == "IndirectFileSystemControlLead"
               and item["method_detail"] == "immediate"
               for item in result["candidates"])


@test(binary="driver_fixture.sys")
def test_same_control_code_in_two_functions_retains_both_handler_leads():
    result = driver_find_ioctls()
    names = {item["function"] for item in result["candidates"]
             if item["code_int"] == 0x9848C}
    assert {"DispatchFileSystemControl", "SameCodeSecondHandler"} <= names


@test(binary="driver_fixture.sys")
def test_driver_instruction_walk_does_not_silently_stop_at_20000_items():
    import idautils
    from ..driver.context import iter_func_items
    original = idautils.FuncItems
    try:
        idautils.FuncItems = lambda _ea: range(20001)
        assert sum(1 for _ in iter_func_items(0)) == 20001
    finally:
        idautils.FuncItems = original


@test(binary="driver_fixture.sys")
def test_driver_fixture_finds_control_codes():
    """Owned fixture scan includes the file-system-control selector."""
    result = driver_find_ioctls()
    codes = {c["code_int"] for c in result["candidates"]}
    assert {0x222000, 0x80002007, 0x9848C, 0x98490} <= codes
    by_code = {c["code_int"]: c for c in result["candidates"]}
    producer = result["trigger_fact_producer"]
    assert producer["status"] == "unsupported"
    assert producer["reason_code"] == "cast_registration_form_unsupported"
    assert producer["registrations"] == []
    assert by_code[0x80002007]["severity"] == "HIGH"
    assert by_code[0x80002007]["method"] == "METHOD_NEITHER"
    # BUFFERED/ANY starts LOW and only climbs via the capped sink bump.
    assert by_code[0x222000]["severity"] == "MEDIUM"
    assert any("capped" in r for r in by_code[0x222000]["risk_reasons"])
    assert all("selector_fact" not in candidate for candidate in by_code.values())


@test(binary="driver_fixture.sys")
def test_driver_fixture_devices_and_pooltag():
    """Owned fixture yields device names, symlink paths, and Tag1."""
    devices = driver_find_devices()
    texts = {d["text"] for d in devices["device_names"]}
    assert "\\Device\\DrvTriage" in texts
    assert "\\DosDevices\\DrvTriage" in texts
    assert len(devices["symbolic_links"]) == 1
    link_paths = {p["text"] for p in devices["symbolic_links"][0]["paths"]}
    assert "\\DosDevices\\DrvTriage" in link_paths

    tags = driver_find_pooltags()
    found = {(t["tag"], t["allocator"]) for t in tags["tags"]}
    assert ("Tag1", "ExAllocatePoolWithTag") in found


@test(binary="driver_fixture.sys")
def test_driver_fixture_acl_flags_world_sddl():
    """Owned fixture ACL audit reports default ACL and world SDDL."""
    result = driver_audit_acl()
    by_title = {lead["title"]: lead for lead in result["leads"]}
    assert any("without explicit security descriptor" in t for t in by_title)
    world = [lead for lead in result["leads"] if "broadly accessible" in lead["title"]]
    assert len(world) == 1
    assert world[0]["severity"] == "HIGH"
    assert "WD" in world[0]["evidence"]["sddl"]


@test(binary="driver_fixture.sys")
def test_driver_fixture_flag_and_trace_through_thunks():
    """Owned fixture resolves thunked imports for flagging and tracing."""
    flagged = driver_flag_functions()
    by_name = {m["name"]: m for m in flagged["matches"]}
    assert by_name["memcpy"]["xref_count"] >= 1
    assert by_name["MmMapIoSpace"]["xref_count"] >= 1

    traced = driver_trace_calls()
    assert len(traced["paths"]) >= 1
    chain = traced["paths"][0]["nodes"]
    assert chain[0] == "DispatchDeviceControl"
    assert chain[-1] == "MmMapIoSpace"
    assert traced["paths"][0]["sink_severity"] == "HIGH"


@test(binary="driver_fixture.sys")
def test_driver_fixture_triage_leads_cover_handlers():
    """Owned fixture leads include the planted copy and privilege gaps."""
    result = driver_triage_leads()
    kinds = {(lead["check"], lead["function"]) for lead in result["leads"]}
    assert ("unvalidated_copy", "HandleBuffered") in kinds
    assert ("missing_priv_gate", "HandleNeither") in kinds
    for lead in result["leads"]:
        assert lead["requires_manual_review"] is True
        assert_valid_address(lead["addr"])
