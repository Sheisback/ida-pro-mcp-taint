"""Tests for api_driver (Windows driver triage tools)."""

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


@test(binary="driver_fixture.sys")
def test_driver_fixture_finds_both_ioctls():
    """Owned fixture IOCTL scan recovers both planted codes, no more."""
    result = driver_find_ioctls()
    codes = {c["code_int"] for c in result["candidates"]}
    assert codes == {0x222000, 0x80002007}
    by_code = {c["code_int"]: c for c in result["candidates"]}
    assert by_code[0x80002007]["severity"] == "HIGH"
    assert by_code[0x80002007]["method"] == "METHOD_NEITHER"
    # BUFFERED/ANY starts LOW and only climbs via the capped sink bump.
    assert by_code[0x222000]["severity"] == "MEDIUM"
    assert any("capped" in r for r in by_code[0x222000]["risk_reasons"])


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
