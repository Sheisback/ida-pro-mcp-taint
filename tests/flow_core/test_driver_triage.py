"""SDK-free tests for flow_core.driver_triage (Windows driver triage core)."""

import pytest

from ida_pro_mcp.flow_core import driver_triage as dt


def test_decode_buffered_any_access():
    # 0x222000: device 0x22 (FILE_DEVICE_UNKNOWN), func 0x800, buffered/any.
    decoded = dt.decode_ioctl(0x222000)
    assert decoded["device"] == 0x22
    assert decoded["device_name"] == "FILE_DEVICE_UNKNOWN"
    assert decoded["function"] == 0x800
    assert decoded["method_name"] == "METHOD_BUFFERED"
    assert decoded["access_name"] == "FILE_ANY_ACCESS"


def test_decode_neither_read_write():
    # CTL_CODE(0x8000, 0x800, METHOD_NEITHER, FILE_READ|WRITE): 0x8000E000?
    # device=0x8000 access=3 func=0x800 method=3 -> 0x8000 << 16 | 3 << 14 | 0x800 << 2 | 3
    code = (0x8000 << 16) | (3 << 14) | (0x800 << 2) | 3
    decoded = dt.decode_ioctl(code)
    assert decoded["device"] == 0x8000
    assert decoded["method_name"] == "METHOD_NEITHER"
    assert decoded["access_name"] == "FILE_READ_ACCESS|FILE_WRITE_ACCESS"
    assert decoded["function"] == 0x800


def test_decode_unknown_device_keeps_value():
    decoded = dt.decode_ioctl(0x9C402000)
    assert decoded["device"] == 0x9C40
    assert "0x9c40" in decoded["device_name"].lower()


def test_decode_sparse_table_entries():
    assert dt.decode_ioctl(0x6D << 16)["device_name"] == "MOUNTMGRCONTROLTYPE"
    assert dt.decode_ioctl(0xF60 << 16)["device_name"] == "FILE_DEVICE_IRCLASS"


def test_parse_ioctl_code_formats():
    assert dt.parse_ioctl_code("0x222000") == 0x222000
    assert dt.parse_ioctl_code(str(0x222000)) == 0x222000
    assert dt.parse_ioctl_code(0x222000) == 0x222000
    assert dt.parse_ioctl_code("  0x22E004  ") == 0x22E004
    with pytest.raises(ValueError):
        dt.parse_ioctl_code("not-a-code")
    with pytest.raises(ValueError):
        dt.parse_ioctl_code("0x1FFFFFFFF")


def test_plausibility_rejects_status_and_sentinel():
    ok, _ = dt.is_plausible_ioctl(0xC0000005)
    assert ok is False
    ok, reason = dt.is_plausible_ioctl(0xFFFFFFFF)
    assert ok is False
    ok, reason = dt.is_plausible_ioctl(0xFFFFFFFB)  # -5 error return
    assert ok is False
    assert "negative" in reason
    ok, _ = dt.is_plausible_ioctl(0xFFFFEFFF)  # -4097 stays testable
    assert ok is True
    ok, reason = dt.is_plausible_ioctl(0x00001234)
    assert ok is False
    assert "device-type" in reason


def test_plausibility_accepts_vendor_high_bit():
    ok, _ = dt.is_plausible_ioctl(0x8000E000)
    assert ok is True
    ok, _ = dt.is_plausible_ioctl(0x222000)
    assert ok is True


def test_plausibility_honors_extra_ntstatus_values():
    ok, _ = dt.is_plausible_ioctl(0x222000, frozenset({0x222000}))
    assert ok is False


def test_base_scoring_weights():
    level, points, reasons = dt.score_ioctl_base(dt.decode_ioctl(0x222000))
    assert (level, points) == (dt.SEV_LOW, 2)
    assert any("FILE_ANY_ACCESS" in r for r in reasons)
    code = (0x8000 << 16) | (0 << 14) | (0x800 << 2) | 3  # NEITHER + ANY
    level, points, _ = dt.score_ioctl_base(dt.decode_ioctl(code))
    assert (level, points) == (dt.SEV_HIGH, 5)
    level, points, _ = dt.score_ioctl_base(dt.decode_ioctl(0x226000))  # buffered+read
    assert (level, points) == (dt.SEV_INFO, 0)


def test_sink_bump_precise_adopts_sink():
    level, notes = dt.apply_sink_bump(
        dt.SEV_LOW, 2, dt.SEV_HIGH, {"MmMapIoSpace"}, precise_attribution=True
    )
    assert level == dt.SEV_HIGH
    assert notes and "MmMapIoSpace" in notes[0]


def test_sink_bump_imprecise_is_capped():
    level, notes = dt.apply_sink_bump(
        dt.SEV_INFO, 0, dt.SEV_CRITICAL, {"x", "y"}, precise_attribution=False
    )
    assert level == dt.SEV_LOW  # one step, never forced to CRITICAL
    assert "capped" in notes[0]


def test_sink_bump_without_sinks_is_identity():
    level, notes = dt.apply_sink_bump(dt.SEV_MEDIUM, 3, dt.SEV_HIGH, set(), precise_attribution=True)
    assert (level, notes) == (dt.SEV_MEDIUM, [])


def test_major_function_slot_offsets_derived():
    assert dt.major_function_slot_offset(8, dt.IRP_MJ_DEVICE_CONTROL) == 0xE0
    assert dt.major_function_slot_offset(8, dt.IRP_MJ_INTERNAL_DEVICE_CONTROL) == 0xE8
    assert dt.major_function_slot_offset(4, dt.IRP_MJ_DEVICE_CONTROL) == 0x74
    assert dt.major_function_slot_offset(4, dt.IRP_MJ_INTERNAL_DEVICE_CONTROL) == 0x78
    with pytest.raises(ValueError):
        dt.major_function_slot_offset(2, dt.IRP_MJ_DEVICE_CONTROL)


def test_trace_paths_finds_shortest_first():
    adjacency = {
        "entry": ["a", "b"],
        "a": ["sink"],
        "b": ["a"],
        "sink": [],
    }
    paths, stats = dt.trace_paths(adjacency, ["entry"], {"sink"}, max_depth=6)
    assert paths[0].nodes == ["entry", "a", "sink"]
    assert paths[0].sink == "sink"
    assert stats["visited_nodes"] >= 3
    assert stats["truncated"] is False


def test_trace_paths_reports_unknown_seeds_and_caps():
    adjacency = {"a": ["b"], "b": []}
    paths, stats = dt.trace_paths(
        adjacency, ["a", "ghost"], {"zzz"}, max_depth=1, max_nodes=100
    )
    assert paths == []
    assert stats["unknown_seeds"] == ["ghost"]
    _, stats = dt.trace_paths(adjacency, ["a"], {"b"}, max_depth=0)
    assert stats["paths"] == 0


def test_review_lead_serializes_with_verdict_guard():
    lead = dt.ReviewLead(
        check="unvalidated_copy",
        severity=dt.SEV_HIGH,
        title="copy without nearby probe",
        detail="memcpy at 0x1c0040 with no ProbeFor* in window",
        function="DispatchDeviceControl",
        addr="0x1c0040",
        evidence={"sink": "memcpy"},
        method="windowed disasm scan",
    )
    as_dict = lead.as_dict()
    assert as_dict["severity"] == "HIGH"
    assert as_dict["severity_rank"] == 3
    assert as_dict["requires_manual_review"] is True


def test_signature_tables_are_minimal_and_consistent():
    assert dt.SEV_INFO < dt.SEV_LOW < dt.SEV_MEDIUM < dt.SEV_HIGH < dt.SEV_CRITICAL
    assert "ProbeForRead" in dt.COPY_GUARDS
    assert "ExAllocatePoolWithTag" in dt.POOL_ALLOCATORS
    assert "ExFreePoolWithTag" in dt.POOL_FREES
    assert "IoBuildDeviceIoControlRequest" in dt.OUTBOUND_IOCTL_BUILDERS
    assert dt.SENSITIVE_SINKS["MmMapIoSpace"] == dt.SEV_HIGH
    assert "memcpy" in dt.RISKY_COPY_SINKS and "memcpy" in dt.RISKY_C_FUNCS
    assert "MmMapIoSpace" in dt.RISKY_NT_APIS
    assert len(dt.RISKY_COPY_SINKS) <= 40  # curated minimal set, not a dump
    assert len(dt.SENSITIVE_SINKS) <= 20
    assert all(isinstance(v, str) and v for v in dt.RISKY_COPY_SINKS.values())
    assert dt.DRIVER_ENTRY_NAMES[0] == "GsDriverEntry"
    assert ("FltRegisterFilter", "Mini-Filter") in dt.DRIVER_FRAMEWORK_MARKERS
