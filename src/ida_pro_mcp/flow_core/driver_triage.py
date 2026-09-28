"""IDA-independent helpers for Windows kernel-driver triage.

This module holds the SDK-free part of the ``driver_*`` MCP tools: CTL_CODE
decoding, IOCTL plausibility checks, triage risk scoring, bounded call-graph
search, and the curated name tables the IDA adapter matches against.

Clean-room note: the triage *workflow* (survey dispatchers, decode IOCTLs,
collect device/pool/sink evidence, emit review leads) is inspired by the
publicly documented behavior of DriverBuddyReloaded (GPL-3.0). No code, text,
or data table was copied from that project; every table and heuristic below
was written independently from public Windows driver knowledge (WDK/MSDN
structure layouts and API names, which are facts, plus original severity
judgments). Do not paste third-party lists into this file.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

SCHEMA_VERSION = "driver-triage/1"

# ---------------------------------------------------------------------------
# Severity model (triage leads, never vulnerability verdicts)
# ---------------------------------------------------------------------------

SEV_INFO = 0
SEV_LOW = 1
SEV_MEDIUM = 2
SEV_HIGH = 3
SEV_CRITICAL = 4

SEVERITY_NAMES = {
    SEV_INFO: "INFO",
    SEV_LOW: "LOW",
    SEV_MEDIUM: "MEDIUM",
    SEV_HIGH: "HIGH",
    SEV_CRITICAL: "CRITICAL",
}


def severity_name(level: int) -> str:
    """Return the display name for a severity level, clamping out-of-range input."""
    return SEVERITY_NAMES.get(int(level), str(level))


def clamp_severity(level: int) -> int:
    """Clamp a severity level into the INFO..CRITICAL range."""
    return max(SEV_INFO, min(SEV_CRITICAL, int(level)))


# ---------------------------------------------------------------------------
# CTL_CODE decoding (public macro layout: device << 16 | access << 14 | fn << 2)
# ---------------------------------------------------------------------------

METHOD_NAMES = (
    "METHOD_BUFFERED",
    "METHOD_IN_DIRECT",
    "METHOD_OUT_DIRECT",
    "METHOD_NEITHER",
)

ACCESS_NAMES = (
    "FILE_ANY_ACCESS",
    "FILE_READ_ACCESS",
    "FILE_WRITE_ACCESS",
    "FILE_READ_ACCESS|FILE_WRITE_ACCESS",
)

# FILE_DEVICE_* values from the public WDK headers (ntddk.h/wdm.h). Values are
# facts; the table below was typed from that public knowledge, not copied.
DEVICE_TYPE_NAMES: dict[int, str] = {
    0x00000000: "FILE_DEVICE_UNKNOWN",
    0x00000001: "FILE_DEVICE_BEEP",
    0x00000002: "FILE_DEVICE_CD_ROM",
    0x00000003: "FILE_DEVICE_CD_ROM_FILE_SYSTEM",
    0x00000004: "FILE_DEVICE_CONTROLLER",
    0x00000005: "FILE_DEVICE_DATALINK",
    0x00000006: "FILE_DEVICE_DFS",
    0x00000007: "FILE_DEVICE_DISK",
    0x00000008: "FILE_DEVICE_DISK_FILE_SYSTEM",
    0x00000009: "FILE_DEVICE_FILE_SYSTEM",
    0x0000000A: "FILE_DEVICE_INPORT_PORT",
    0x0000000B: "FILE_DEVICE_KEYBOARD",
    0x0000000C: "FILE_DEVICE_MAILSLOT",
    0x0000000D: "FILE_DEVICE_MIDI_IN",
    0x0000000E: "FILE_DEVICE_MIDI_OUT",
    0x0000000F: "FILE_DEVICE_MOUSE",
    0x00000010: "FILE_DEVICE_MULTI_UNC_PROVIDER",
    0x00000011: "FILE_DEVICE_NAMED_PIPE",
    0x00000012: "FILE_DEVICE_NETWORK",
    0x00000013: "FILE_DEVICE_NETWORK_BROWSER",
    0x00000014: "FILE_DEVICE_NETWORK_FILE_SYSTEM",
    0x00000015: "FILE_DEVICE_NULL",
    0x00000016: "FILE_DEVICE_PARALLEL_PORT",
    0x00000017: "FILE_DEVICE_PHYSICAL_NETCARD",
    0x00000018: "FILE_DEVICE_PRINTER",
    0x00000019: "FILE_DEVICE_SCANNER",
    0x0000001A: "FILE_DEVICE_SERIAL_MOUSE_PORT",
    0x0000001B: "FILE_DEVICE_SERIAL_PORT",
    0x0000001C: "FILE_DEVICE_SCREEN",
    0x0000001D: "FILE_DEVICE_SOUND",
    0x0000001E: "FILE_DEVICE_STREAMS",
    0x0000001F: "FILE_DEVICE_TAPE",
    0x00000020: "FILE_DEVICE_TAPE_FILE_SYSTEM",
    0x00000021: "FILE_DEVICE_TRANSPORT",
    0x00000022: "FILE_DEVICE_UNKNOWN",
    0x00000023: "FILE_DEVICE_VIDEO",
    0x00000024: "FILE_DEVICE_VIRTUAL_DISK",
    0x00000025: "FILE_DEVICE_WAVE_IN",
    0x00000026: "FILE_DEVICE_WAVE_OUT",
    0x00000027: "FILE_DEVICE_8042_PORT",
    0x00000028: "FILE_DEVICE_NETWORK_REDIRECTOR",
    0x00000029: "FILE_DEVICE_BATTERY",
    0x0000002A: "FILE_DEVICE_BUS_EXTENDER",
    0x0000002B: "FILE_DEVICE_MODEM",
    0x0000002C: "FILE_DEVICE_VDM",
    0x0000002D: "FILE_DEVICE_MASS_STORAGE",
    0x0000002E: "FILE_DEVICE_SMB",
    0x0000002F: "FILE_DEVICE_KS",
    0x00000030: "FILE_DEVICE_CHANGER",
    0x00000031: "FILE_DEVICE_SMARTCARD",
    0x00000032: "FILE_DEVICE_ACPI",
    0x00000033: "FILE_DEVICE_DVD",
    0x00000034: "FILE_DEVICE_FULLSCREEN_VIDEO",
    0x00000035: "FILE_DEVICE_DFS_FILE_SYSTEM",
    0x00000036: "FILE_DEVICE_DFS_VOLUME",
    0x00000037: "FILE_DEVICE_SERENUM",
    0x00000038: "FILE_DEVICE_TERMSRV",
    0x00000039: "FILE_DEVICE_KSEC",
    0x0000003A: "FILE_DEVICE_FIPS",
    0x0000003B: "FILE_DEVICE_INFINIBAND",
    0x0000003C: "FILE_DEVICE_VMBUS",
    0x0000003D: "FILE_DEVICE_CRYPT_PROVIDER",
    0x0000003E: "FILE_DEVICE_WPD",
    0x0000003F: "FILE_DEVICE_BLUETOOTH",
    0x00000040: "FILE_DEVICE_MT_COMPOSITE",
    0x00000041: "FILE_DEVICE_MT_TRANSPORT",
    0x00000042: "FILE_DEVICE_BIOMETRIC",
    0x00000043: "FILE_DEVICE_PMI",
    0x00000044: "FILE_DEVICE_EHSTOR",
    0x00000045: "FILE_DEVICE_DEVAPI",
    0x00000046: "FILE_DEVICE_GPIO",
    0x00000047: "FILE_DEVICE_USBEX",
    0x00000048: "FILE_DEVICE_CONSOLE",
    0x00000049: "FILE_DEVICE_NFP",
    0x0000004A: "FILE_DEVICE_SYSENV",
    0x0000004B: "FILE_DEVICE_VIRTUAL_BLOCK",
    0x0000004C: "FILE_DEVICE_POINT_OF_SERVICE",
    0x0000004D: "FILE_DEVICE_STORAGE_REPLICATION",
    0x0000004E: "FILE_DEVICE_TRUST_ENV",
    0x0000004F: "FILE_DEVICE_UCM",
    0x00000050: "FILE_DEVICE_UCMTCPCI",
    0x00000051: "FILE_DEVICE_PERSISTENT_MEMORY",
    0x00000052: "FILE_DEVICE_NVDIMM",
    0x00000053: "FILE_DEVICE_HOLOGRAPHIC",
    0x00000054: "FILE_DEVICE_SDFXHCI",
    0x00000055: "FILE_DEVICE_UCMUCSI",
    0x00000056: "FILE_DEVICE_PRM",
    0x00000057: "FILE_DEVICE_EVENT_COLLECTOR",
    0x00000058: "FILE_DEVICE_USB4",
    0x00000059: "FILE_DEVICE_SOUNDWIRE",
    0x0000005A: "FILE_DEVICE_FABRIC_NVME",
    0x0000005B: "FILE_DEVICE_SVM",
    0x0000005C: "FILE_DEVICE_HARDWARE_ACCELERATOR",
    0x0000005D: "FILE_DEVICE_I3C",
    # Sparse vendor-defined values documented in public headers/samples.
    0x0000006D: "MOUNTMGRCONTROLTYPE",
    0x00000F60: "FILE_DEVICE_IRCLASS",
}


def decode_ioctl(code: int) -> dict:
    """Split a 32-bit IOCTL code into device/function/method/access fields.

    Returns plain-JSON-safe values: the numeric fields plus display names.
    Unknown device types keep their numeric value with an "UNKNOWN(...)" name
    instead of being dropped, so vendor codes stay visible.
    """
    code &= 0xFFFFFFFF
    device = (code >> 16) & 0xFFFF
    access = (code >> 14) & 0x3
    function = (code >> 2) & 0xFFF
    method = code & 0x3
    device_name = DEVICE_TYPE_NAMES.get(device, f"UNKNOWN_DEVICE(0x{device:04x})")
    return {
        "code": hex(code),
        "code_int": code,
        "device": device,
        "device_name": device_name,
        "function": function,
        "method": method,
        "method_name": METHOD_NAMES[method],
        "access": access,
        "access_name": ACCESS_NAMES[access],
    }


def parse_ioctl_code(text: str | int) -> int:
    """Parse user-supplied IOCTL text ("0x22e004", "5832708") into an int."""
    if isinstance(text, int):
        code = text
    else:
        raw = str(text).strip().rstrip("hH")
        if raw.lower().endswith("h") and not raw.lower().startswith("0x"):
            code = int(raw[:-1], 16)
        else:
            code = int(raw, 0)
    if not 0 <= code <= 0xFFFFFFFF:
        raise ValueError(f"IOCTL code out of 32-bit range: {text!r}")
    return code


# Well-known NTSTATUS codes (public values) used to reject immediates that are
# status returns rather than IOCTLs. This is a deliberately small fallback set;
# the IDA adapter extends it with the database's own NTSTATUS enum when present.
NTSTATUS_FALLBACK: frozenset[int] = frozenset(
    {
        0x00000000,  # STATUS_SUCCESS / STATUS_WAIT_0
        0x00000103,  # STATUS_PENDING
        0x40000000,  # STATUS_OBJECT_NAME_EXISTS
        0x80000005,  # STATUS_BUFFER_OVERFLOW
        0xC0000001,  # STATUS_UNSUCCESSFUL
        0xC0000002,  # STATUS_NOT_IMPLEMENTED
        0xC0000004,  # STATUS_INFO_LENGTH_MISMATCH
        0xC0000005,  # STATUS_ACCESS_VIOLATION
        0xC0000008,  # STATUS_INVALID_HANDLE
        0xC000000D,  # STATUS_INVALID_PARAMETER
        0xC000000E,  # STATUS_NO_SUCH_DEVICE
        0xC0000010,  # STATUS_INVALID_DEVICE_REQUEST
        0xC0000011,  # STATUS_END_OF_FILE
        0xC0000017,  # STATUS_NO_MEMORY
        0xC0000022,  # STATUS_ACCESS_DENIED
        0xC0000023,  # STATUS_BUFFER_TOO_SMALL
        0xC0000034,  # STATUS_OBJECT_NAME_NOT_FOUND
        0xC0000035,  # STATUS_OBJECT_NAME_COLLISION
        0xC000003A,  # STATUS_OBJECT_PATH_NOT_FOUND
        0xC0000043,  # STATUS_SHARING_VIOLATION
        0xC0000061,  # STATUS_PRIVILEGE_NOT_HELD
        0xC0000077,  # STATUS_INVALID_ACL
        0xC000009A,  # STATUS_INSUFFICIENT_RESOURCES
        0xC00000BB,  # STATUS_NOT_SUPPORTED
        0xC00000C0,  # STATUS_DEVICE_DOES_NOT_EXIST
        0xC0000120,  # STATUS_CANCELLED
        0xC0000225,  # STATUS_NOT_FOUND
    }
)

#: Comparison sentinels (e.g. `cmp reg, -1`) that are never IOCTLs.
IOCTL_SENTINELS: frozenset[int] = frozenset({0xFFFFFFFF})


def is_plausible_ioctl(code: int, ntstatus_values: frozenset[int] = frozenset()) -> tuple[bool, str]:
    """Judge whether an immediate could structurally be an IOCTL code.

    Returns (ok, reason). A zero device-type field, a comparison sentinel, or
    a known NTSTATUS value rejects the candidate. High-bit vendor device
    types (0x8000+) are accepted: they are real IOCTLs, not status codes.
    """
    code &= 0xFFFFFFFF
    if code in IOCTL_SENTINELS:
        return False, "comparison sentinel, not a CTL_CODE"
    if code >= 0xFFFFF000:
        # Small-magnitude negatives (-4096..-2) are status/error returns
        # (e.g. `return -5`), never constructed CTL_CODE macros.
        return False, "small-magnitude negative, likely a status return, not a CTL_CODE"
    known_status = NTSTATUS_FALLBACK | ntstatus_values
    if code in known_status:
        return False, "known NTSTATUS value, not a CTL_CODE"
    if ((code >> 16) & 0xFFFF) == 0:
        return False, "zero device-type field, not a CTL_CODE"
    return True, "structurally valid CTL_CODE"


# ---------------------------------------------------------------------------
# IOCTL risk scoring (triage priority signal, not a vulnerability verdict)
# ---------------------------------------------------------------------------

#: METHOD_NEITHER hands raw user pointers to the driver: the classic shape
#: behind read/write primitives, so it scores highest.
METHOD_POINTS = {
    "METHOD_BUFFERED": 0,
    "METHOD_IN_DIRECT": 1,
    "METHOD_OUT_DIRECT": 1,
    "METHOD_NEITHER": 3,
}

#: FILE_ANY_ACCESS skips access-rights checks on the handle.
ACCESS_POINTS = {
    "FILE_ANY_ACCESS": 2,
    "FILE_READ_ACCESS": 0,
    "FILE_WRITE_ACCESS": 1,
    "FILE_READ_ACCESS|FILE_WRITE_ACCESS": 1,
}


def points_to_level(points: int) -> int:
    """Map accumulated risk points to a severity level."""
    if points >= 5:
        return SEV_HIGH
    if points >= 3:
        return SEV_MEDIUM
    if points >= 1:
        return SEV_LOW
    return SEV_INFO


def score_ioctl_base(decoded: dict) -> tuple[int, int, list[str]]:
    """Score a decoded IOCTL from its transfer method and access mode.

    Returns (level, points, reasons). CRITICAL is never assigned here; it is
    reserved for handler-confirmed sink reachability applied by the caller.
    """
    reasons: list[str] = []
    points = 0
    method = str(decoded.get("method_name", ""))
    access = str(decoded.get("access_name", ""))
    extra = METHOD_POINTS.get(method, 0)
    if extra:
        points += extra
        reasons.append(f"{method} (+{extra})")
    extra = ACCESS_POINTS.get(access, 0)
    if extra:
        points += extra
        reasons.append(f"{access} (+{extra})")
    return points_to_level(points), points, reasons


def apply_sink_bump(
    level: int,
    points: int,
    sink_level: int,
    sink_names: set[str] | frozenset[str],
    *,
    precise_attribution: bool,
) -> tuple[int, list[str]]:
    """Bump an IOCTL score when its handler reaches a dangerous sink.

    With precise per-case attribution the sink level is adopted directly.
    With imprecise (dispatcher-closure) attribution the bump is capped at one
    step above the base level and never forced to CRITICAL, so a benign code
    sharing a dispatcher is not tarred by a dangerous sibling.
    """
    notes: list[str] = []
    if not sink_names:
        return level, notes
    if precise_attribution:
        bumped = max(level, clamp_severity(sink_level))
    else:
        bumped = min(level + 1, SEV_HIGH)
        bumped = max(level, min(bumped, clamp_severity(sink_level)))
    if bumped > level:
        notes.append(
            "handler reaches "
            + ", ".join(sorted(sink_names))
            + (" (imprecise attribution, capped)" if not precise_attribution else "")
        )
    return bumped, notes


# ---------------------------------------------------------------------------
# Curated name tables (independent minimal selection, original descriptions)
# ---------------------------------------------------------------------------
#
# These tables intentionally cover only widely known risky kernel/C routines
# and structural driver markers. They are starting points for manual review,
# not verdicts: every match must be read in context by an analyst.

#: Routines whose misuse commonly produces memory-safety bugs. Values explain
#: why the name is worth a look during review.
RISKY_COPY_SINKS: dict[str, str] = {
    "memcpy": "unbounded copy; length/src must be validated",
    "RtlCopyMemory": "alias of memcpy; same length validation concern",
    "CopyMemory": "alias of memcpy; same length validation concern",
    "memmove": "unbounded copy; length/src must be validated",
    "RtlMoveMemory": "alias of memmove; same length validation concern",
    "strcpy": "unbounded string copy; classic overflow source",
    "wcscpy": "wide-char unbounded copy; classic overflow source",
    "lstrcpy": "unbounded copy without length feedback",
    "lstrcpyA": "unbounded copy without length feedback",
    "lstrcpyW": "wide-char unbounded copy without length feedback",
    "strcat": "unbounded concatenation; needs bounds review",
    "wcscat": "wide-char unbounded concatenation; needs bounds review",
    "sprintf": "unbounded formatting; needs bounds review",
    "wsprintf": "unbounded formatting; needs bounds review",
    "swprintf": "unbounded formatting; needs bounds review",
    "vsprintf": "unbounded formatting; needs bounds review",
    "gets": "no length limit; never safe on untrusted input",
    "RtlCopyString": "length comes from the source descriptor; review it",
}

#: Routines that validate user buffers or perform checked string/arithmetic
#: operations. Their presence near a sink weakens the corresponding lead.
COPY_GUARDS: frozenset[str] = frozenset(
    {
        "ProbeForRead",
        "ProbeForWrite",
        "RtlStringCbCopyA",
        "RtlStringCbCopyW",
        "RtlStringCchCopyA",
        "RtlStringCchCopyW",
        "RtlULongAdd",
        "RtlULongLongAdd",
        "RtlULongMult",
        "RtlUIntAdd",
        "RtlUIntMult",
    }
)

#: Privilege/ACL checks whose absence on a path to a sensitive sink is notable.
PRIVILEGE_GATES: frozenset[str] = frozenset(
    {
        "SeAccessCheck",
        "SeSinglePrivilegeCheck",
        "SePrivilegedServiceAuditAlarm",
        "PsReferencePrimaryToken",
        "PsReferenceImpersonationToken",
        "ZwOpenProcessToken",
        "ZwOpenThreadToken",
    }
)

#: Kernel pool allocators; the size argument needs overflow review.
POOL_ALLOCATORS: frozenset[str] = frozenset(
    {
        "ExAllocatePool",
        "ExAllocatePoolWithTag",
        "ExAllocatePoolWithQuotaTag",
        "ExAllocatePool2",
        "ExAllocatePool3",
    }
)

#: Kernel pool release routines (use-after-free analysis).
POOL_FREES: frozenset[str] = frozenset(
    {
        "ExFreePool",
        "ExFreePoolWithTag",
    }
)

#: Large or dynamic stack allocation routines.
STACK_ALLOCATORS: frozenset[str] = frozenset({"_alloca", "alloca", "_malloca"})

#: MDL mapping routines; kernel mapping of locked pages needs mode review.
MDL_FUNCS: frozenset[str] = frozenset(
    {
        "MmMapLockedPages",
        "MmMapLockedPagesSpecifyCache",
        "MmMapLockedPagesWithReservedMapping",
        "MmProbeAndLockPages",
    }
)

#: Routines that raise IRQL; sharing a function with pageable-blockable calls
#: (Zw*, MmMap*) is worth a review note.
IRQL_RAISERS: frozenset[str] = frozenset(
    {
        "KeRaiseIrql",
        "KeRaiseIrqlToDpcLevel",
        "KeRaiseIrqlToDispatchLevel",
        "KeAcquireSpinLock",
        "KeAcquireSpinLockAtDpcLevel",
        "KeAcquireInStackQueuedSpinLock",
    }
)

#: Routines a driver calls to *send* IOCTLs downstream. Codes flowing into
#: these are outbound traffic, not the driver's own dispatch surface.
OUTBOUND_IOCTL_BUILDERS: frozenset[str] = frozenset(
    {
        "IoBuildDeviceIoControlRequest",
        "IoBuildSynchronousFsdRequest",
        "ZwDeviceIoControlFile",
        "NtDeviceIoControlFile",
        "FltDeviceIoControlFile",
    }
)

#: Sensitive sinks for call-chain tracing and sink-bump scoring. Levels are
#: this module's own triage judgments: physical/PCI access and raw MSR/port
#: style helpers rank highest because they are typical BYOVD primitives.
SENSITIVE_SINKS: dict[str, int] = {
    "MmMapIoSpace": SEV_HIGH,
    "MmMapMemoryDumpMdl": SEV_HIGH,
    "HalGetBusDataByOffset": SEV_HIGH,
    "HalSetBusDataByOffset": SEV_HIGH,
    "ZwOpenProcess": SEV_HIGH,
    "ZwMapViewOfSection": SEV_HIGH,
    "ZwOpenSection": SEV_HIGH,
    "MmMapLockedPages": SEV_MEDIUM,
    "MmProbeAndLockPages": SEV_MEDIUM,
    "IoAllocateMdl": SEV_MEDIUM,
    "PsCreateSystemThread": SEV_MEDIUM,
    "ObRegisterCallbacks": SEV_MEDIUM,
    "ObReferenceObjectByHandle": SEV_MEDIUM,
}

#: Kernel APIs frequently relevant during driver review (flagging surface).
RISKY_NT_APIS: dict[str, str] = {
    "IofCallDriver": "forwards the IRP; misuse risks double-completion",
    "IoRegisterDeviceInterface": "exposes a device interface; review ACL",
    "PsCreateSystemThread": "spawns a system thread from the driver",
    "ObReferenceObjectByHandle": "resolves arbitrary handles; review access",
    "ObRegisterCallbacks": "installs object callbacks; review carefully",
    "HalGetBusDataByOffset": "raw PCI config read primitive",
    "HalSetBusDataByOffset": "raw PCI config write primitive",
    "MmMapIoSpace": "maps physical memory; review address/length",
    "ZwLoadDriver": "loads another driver; review path handling",
    "ZwOpenProcess": "opens arbitrary processes; review desired access",
    "KeStackAttachProcess": "attaches to another process; review lifetime",
}

#: C string/memory routines worth flagging in driver code.
RISKY_C_FUNCS: dict[str, str] = dict(RISKY_COPY_SINKS)

#: Markers of the classic physical-memory BYOVD pattern.
PHYSICAL_MEMORY_MARKERS: tuple[str, ...] = ("\\Device\\PhysicalMemory",)

#: Object-manager path prefixes that indicate device exposure.
DEVICE_PATH_PREFIXES: tuple[str, ...] = (
    "\\Device\\",
    "\\DosDevices\\",
    "\\GLOBAL??\\",
    "\\\\.\\",
    "\\Driver\\",
)

#: DriverEntry symbol names, most-preferred first.
DRIVER_ENTRY_NAMES: tuple[str, ...] = (
    "GsDriverEntry",
    "DriverEntry",
    "DriverEntry_0",
)

#: Import markers used to classify the driver framework. Each entry maps an
#: import name to a framework label; absence of all markers means WDM-shaped.
DRIVER_FRAMEWORK_MARKERS: tuple[tuple[str, str], ...] = (
    ("FltRegisterFilter", "Mini-Filter"),
    ("WdfVersionBind", "WDF"),
    ("WdfVersionBindClass", "WDF"),
    ("StreamClassRegisterMinidriver", "Stream Minidriver"),
    ("KsCreateFilterFactory", "AVStream"),
    ("PcRegisterSubdevice", "PortCls"),
)

#: Mnemonics that are privileged CPU operations when reached from a handler.
PRIVILEGED_MNEMONICS: dict[str, int] = {
    "out": SEV_HIGH,
    "in": SEV_MEDIUM,
    "cli": SEV_LOW,
    "sti": SEV_LOW,
    "hlt": SEV_LOW,
    "invlpg": SEV_LOW,
}

#: SIDs that denote broad access inside SDDL strings (public SDDL vocabulary).
WORLD_SIDS: frozenset[str] = frozenset({"WD", "BU", "S-1-1-0", "S-1-5-32-545"})

#: SDDL component prefixes (public SDDL vocabulary).
SDDL_PREFIXES: tuple[str, ...] = ("D:", "O:", "G:", "S:")

#: IRP_MJ codes relevant to dispatch discovery (public DDK values).
IRP_MJ_DEVICE_CONTROL = 0x0E
IRP_MJ_INTERNAL_DEVICE_CONTROL = 0x0F


def major_function_slot_offset(ptr_size: int, mj_code: int) -> int:
    """Derive a DRIVER_OBJECT.MajorFunction slot offset from public layout.

    x64: slots start at 0x70; x86: slots start at 0x3C. Slots are pointer
    sized. Computing the offset keeps the adapter honest on both widths
    instead of hardcoding one build's bytes.
    """
    if ptr_size == 8:
        base = 0x70
    elif ptr_size == 4:
        base = 0x3C
    else:
        raise ValueError(f"unsupported pointer size: {ptr_size}")
    return base + mj_code * ptr_size


# ---------------------------------------------------------------------------
# Bounded call-graph search (pure; the IDA adapter builds the adjacency map)
# ---------------------------------------------------------------------------


@dataclass
class CallPath:
    """One seed-to-sink path through a callee adjacency map."""

    nodes: list[str]
    sink: str
    depth: int


def trace_paths(
    adjacency: dict[str, list[str]],
    seeds: list[str],
    targets: set[str] | frozenset[str],
    *,
    max_depth: int = 6,
    max_paths: int = 50,
    max_nodes: int = 5000,
) -> tuple[list[CallPath], dict]:
    """Breadth-first search from seeds to any target over an adjacency map.

    Keys and values are opaque node ids (the adapter uses hex addresses).
    Returns (paths, stats) where stats reports visited counts, truncation,
    and unresolved seeds so callers can preserve partial results honestly.
    """
    found: list[CallPath] = []
    visited: set[str] = set()
    unknown_seeds = [s for s in seeds if s not in adjacency]
    queue: deque[tuple[str, list[str]]] = deque((s, [s]) for s in seeds if s in adjacency)
    truncated = False
    for seed in seeds:
        visited.add(seed)
    while queue and len(found) < max_paths:
        if len(visited) >= max_nodes:
            truncated = True
            break
        node, path = queue.popleft()
        if len(path) - 1 >= max_depth:
            continue
        for callee in adjacency.get(node, []):
            if len(visited) >= max_nodes:
                truncated = True
                break
            if callee in path:
                continue
            next_path = path + [callee]
            if callee in targets:
                found.append(CallPath(nodes=next_path, sink=callee, depth=len(next_path) - 1))
                if len(found) >= max_paths:
                    truncated = True
                    break
            elif callee not in visited:
                visited.add(callee)
                queue.append((callee, next_path))
    stats = {
        "visited_nodes": len(visited),
        "paths": len(found),
        "truncated": truncated or len(found) >= max_paths,
        "unknown_seeds": unknown_seeds,
        "max_depth": max_depth,
    }
    return found, stats


# ---------------------------------------------------------------------------
# Review-lead record shared by the IDA adapter and tests
# ---------------------------------------------------------------------------


@dataclass
class ReviewLead:
    """One triage lead: a starting point for manual review, not a verdict."""

    check: str
    severity: int
    title: str
    detail: str
    function: str | None = None
    addr: str | None = None
    evidence: dict = field(default_factory=dict)
    method: str = ""
    requires_manual_review: bool = True

    def as_dict(self) -> dict:
        return {
            "check": self.check,
            "severity": severity_name(self.severity),
            "severity_rank": clamp_severity(self.severity),
            "title": self.title,
            "detail": self.detail,
            "function": self.function,
            "addr": self.addr,
            "evidence": dict(self.evidence),
            "method": self.method,
            "requires_manual_review": True,
        }
