/* Owned driver-shaped test fixture for the driver_* MCP tools.
 * Static-analysis oracle only: compile and inspect, never load or execute.
 * Covers dispatchers, two IOCTLs, device/symlink strings, pool tag, ACL calls,
 * an unvalidated copy, and a sensitive sink without a privilege gate.
 *
 * Rebuild (byte-identical given the same toolchain):
 *   printf 'LIBRARY ntoskrnl.exe\nEXPORTS\nIoCreateDeviceSecure\n' > extra.def
 *   x86_64-w64-mingw32-dlltool -d extra.def -l libextra.a
 *   x86_64-w64-mingw32-gcc -nostdlib -shared -Wl,--entry,DriverEntry \
 *     -Wl,--subsystem,native -Wl,--no-insert-timestamp -O1 \
 *     -o driver_fixture.sys driver_fixture.c -lntoskrnl -L. -lextra
 */
#include <stddef.h>
#include <ddk/wdm.h>

#define EXPORT __attribute__((dllexport))
#define NOINLINE __attribute__((noinline))

#define IOCTL_HELLO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RAW CTL_CODE(0x8000, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_TABLE_A CTL_CODE(FILE_DEVICE_UNKNOWN, 0x10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TABLE_B CTL_CODE(FILE_DEVICE_UNKNOWN, 0x11, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
#define FSCTL_FIXTURE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0x123, METHOD_BUFFERED, FILE_WRITE_DATA)
#define FSCTL_INDIRECT_LEAD CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0x124, METHOD_BUFFERED, FILE_WRITE_DATA)
#define FSCTL_SWITCH_A CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0x130, METHOD_BUFFERED, FILE_WRITE_DATA)
#define FSCTL_SWITCH_B CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0x131, METHOD_BUFFERED, FILE_WRITE_DATA)
#define FSCTL_SWITCH_C CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0x132, METHOD_BUFFERED, FILE_WRITE_DATA)
#define FSCTL_SWITCH_D CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0x133, METHOD_BUFFERED, FILE_WRITE_DATA)
#define FSCTL_SWITCH_E CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0x134, METHOD_BUFFERED, FILE_WRITE_DATA)

/* Missing from the MinGW wdm.h headers; declared manually for the fixture. */
NTSTATUS NTAPI IoCreateDeviceSecure(PDRIVER_OBJECT DriverObject,
                                    ULONG DeviceExtensionSize,
                                    PUNICODE_STRING DeviceName, ULONG DeviceType,
                                    ULONG DeviceCharacteristics, BOOLEAN Exclusive,
                                    PCUNICODE_STRING DefaultSDDLString,
                                    LPCGUID DeviceClassGuid,
                                    PDEVICE_OBJECT *DeviceObject);
BOOLEAN NTAPI MmIsAddressValid(PVOID VirtualAddress);

static volatile LONG sink_state;
EXPORT const ULONG AfdStyleIoctlTable[0x12] = {
  [0x10] = IOCTL_TABLE_A,
  [0x11] = IOCTL_TABLE_B,
};
EXPORT const ULONG UnboundedIoctlTable[2] = { IOCTL_TABLE_A, IOCTL_TABLE_B };
EXPORT const ULONG ConditionalIoctlTable[0x12] = {
  [0x10] = IOCTL_TABLE_A,
  [0x11] = IOCTL_TABLE_B,
};
EXPORT volatile ULONG UnrelatedIoctlMetadata[2] = { IOCTL_TABLE_A, IOCTL_TABLE_B };

EXPORT NOINLINE NTSTATUS NTAPI HandleBuffered(PDEVICE_OBJECT device, PIRP irp) {
  PIO_STACK_LOCATION stack;
  PVOID sysbuf;
  (void)device;
  stack = irp->Tail.Overlay.CurrentStackLocation;
  if (stack == 0) return STATUS_INVALID_PARAMETER;
  sysbuf = irp->AssociatedIrp.SystemBuffer;
  if (sysbuf == 0) return STATUS_INVALID_PARAMETER;
  memcpy((void *)&sink_state, sysbuf,
         stack->Parameters.DeviceIoControl.InputBufferLength);
  return STATUS_SUCCESS;
}

EXPORT NOINLINE NTSTATUS NTAPI HandleNeither(PDEVICE_OBJECT device, PIRP irp) {
  PIO_STACK_LOCATION stack;
  PHYSICAL_ADDRESS phys;
  PVOID mapped;
  (void)device;
  stack = irp->Tail.Overlay.CurrentStackLocation;
  if (stack == 0) return STATUS_INVALID_PARAMETER;
  phys.QuadPart = 0;
  mapped = MmMapIoSpace(phys, 0x1000, MmNonCached);
  if (mapped != 0) sink_state = 1;
  return STATUS_SUCCESS;
}

EXPORT NTSTATUS NTAPI DispatchDeviceControl(PDEVICE_OBJECT device, PIRP irp) {
  PIO_STACK_LOCATION stack;
  ULONG code;
  stack = irp->Tail.Overlay.CurrentStackLocation;
  if (stack == 0) return STATUS_INVALID_DEVICE_REQUEST;
  code = stack->Parameters.DeviceIoControl.IoControlCode;
  switch (code) {
  case IOCTL_HELLO:
    return HandleBuffered(device, irp);
  case IOCTL_RAW:
    return HandleNeither(device, irp);
  default:
    break;
  }
  return STATUS_INVALID_DEVICE_REQUEST;
}

EXPORT NTSTATUS NTAPI DispatchInternal(PDEVICE_OBJECT device, PIRP irp) {
  (void)device;
  (void)irp;
  return STATUS_INVALID_DEVICE_REQUEST;
}

EXPORT NTSTATUS NTAPI DispatchCreate(PDEVICE_OBJECT device, PIRP irp) {
  (void)device;
  (void)irp;
  return STATUS_SUCCESS;
}

EXPORT NTSTATUS NTAPI DispatchRead(PDEVICE_OBJECT device, PIRP irp) {
  (void)device;
  (void)irp;
  return STATUS_SUCCESS;
}

/* Place more control-code readers before the FSCTL handler than the old
 * fallback's function-count cutoff. Each has distinct code so the PE linker
 * retains its own function body. */
#define FILLER_CODE(N) \
  EXPORT NOINLINE ULONG NTAPI FillerCode##N(PIRP irp) { \
    PIO_STACK_LOCATION stack = irp->Tail.Overlay.CurrentStackLocation; \
    return stack->Parameters.DeviceIoControl.IoControlCode + (N); \
  }
FILLER_CODE(1) FILLER_CODE(2) FILLER_CODE(3) FILLER_CODE(4)
FILLER_CODE(5) FILLER_CODE(6) FILLER_CODE(7) FILLER_CODE(8)
FILLER_CODE(9) FILLER_CODE(10) FILLER_CODE(11) FILLER_CODE(12)
FILLER_CODE(13) FILLER_CODE(14) FILLER_CODE(15) FILLER_CODE(16)
FILLER_CODE(17)

EXPORT NTSTATUS NTAPI DispatchFileSystemControl(PDEVICE_OBJECT device, PIRP irp) {
  PIO_STACK_LOCATION stack = irp->Tail.Overlay.CurrentStackLocation;
  (void)device;
  if (stack == 0) return STATUS_INVALID_DEVICE_REQUEST;
  if (stack->Parameters.FileSystemControl.FsControlCode == FSCTL_FIXTURE)
    return STATUS_SUCCESS;
  return STATUS_INVALID_DEVICE_REQUEST;
}

/* The same IRP stack/code read can be compiled through an address temporary.
 * This mirrors common PDB-backed union aliases without executing the fixture. */
EXPORT NOINLINE ULONG NTAPI StackAliasControlCode(PIRP irp) {
  ULONG code;
  __asm__ volatile("leaq 0xb8(%1), %%rax\n\t"
                   "movq (%%rax), %%rdi\n\t"
                   "movl 0x18(%%rdi), %0"
                   : "=r"(code) : "r"(irp) : "rax", "rdi", "memory");
  return code;
}

/* A real dispatch routine may keep the stack location in a Windows-x64
 * nonvolatile register across an imported helper call before reading the
 * selector. The provenance scanner must preserve that ABI-guaranteed value. */
EXPORT NOINLINE ULONG NTAPI StackAliasAcrossCallControlCode(PIRP irp) {
  PIO_STACK_LOCATION stack = irp->Tail.Overlay.CurrentStackLocation;
  if (MmIsAddressValid(stack)) sink_state += 1;
  return stack->Parameters.DeviceIoControl.IoControlCode;
}

/* AFD-style dispatchers validate a function-code index against a parallel
 * table of complete IOCTL values instead of emitting a C switch. */
EXPORT NOINLINE NTSTATUS NTAPI ParallelTableDeviceControl(
    PDEVICE_OBJECT device, PIRP irp) {
  PIO_STACK_LOCATION stack = irp->Tail.Overlay.CurrentStackLocation;
  ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
  ULONG index = (code >> 2) & 0xFFF;
  (void)device;
  return index < (sizeof(AfdStyleIoctlTable) / sizeof(AfdStyleIoctlTable[0]))
      && AfdStyleIoctlTable[index] == code
    ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_REQUEST;
}

EXPORT NOINLINE ULONG NTAPI UnrelatedIoctlTableReader(PIRP irp) {
  PIO_STACK_LOCATION stack = irp->Tail.Overlay.CurrentStackLocation;
  return stack->Parameters.DeviceIoControl.IoControlCode
    ^ UnrelatedIoctlMetadata[0];
}

/* A named and scaled lookup without a dominating index check is not selector
 * evidence. This function is inspected only; the fixture is never loaded. */
EXPORT NOINLINE NTSTATUS NTAPI UnboundedTableDeviceControl(PIRP irp) {
  PIO_STACK_LOCATION stack = irp->Tail.Overlay.CurrentStackLocation;
  ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
  ULONG index = (code >> 2) & 0xFFF;
  return UnboundedIoctlTable[index] == code
    ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_REQUEST;
}

/* A bound on only one incoming path does not dominate the table lookup. */
EXPORT NOINLINE NTSTATUS NTAPI ConditionalBoundTableDeviceControl(PIRP irp) {
  PIO_STACK_LOCATION stack = irp->Tail.Overlay.CurrentStackLocation;
  ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
  ULONG_PTR index = (code >> 2) & 0xFFF;
  LONG gate = sink_state;
  ULONG matched;
  __asm__ volatile("testl %k3, %k3\n\t"
                   "jz 1f\n\t"
                   "cmpl $0x12, %k2\n\t"
                   "jnb 2f\n\t"
                   "1:\n\t"
                   "cmpl %k1, (%4,%2,4)\n\t"
                   "sete %b0\n\t"
                   "jmp 3f\n\t"
                   "2:\n\t"
                   "xorl %k0, %k0\n\t"
                   "3:"
                   : "=&q"(matched)
                   : "r"(code), "r"(index), "r"(gate), "r"(ConditionalIoctlTable)
                   : "cc", "memory");
  return matched ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_REQUEST;
}

/* Represents an unregistered internal handler: a static lead, not route proof. */
EXPORT NOINLINE NTSTATUS NTAPI IndirectFileSystemControlLead(PIRP irp) {
  PIO_STACK_LOCATION stack = irp->Tail.Overlay.CurrentStackLocation;
  return stack->Parameters.FileSystemControl.FsControlCode == FSCTL_INDIRECT_LEAD
    ? STATUS_SUCCESS : STATUS_INVALID_DEVICE_REQUEST;
}

EXPORT NOINLINE NTSTATUS NTAPI SameCodeSecondHandler(PIRP irp) {
  PIO_STACK_LOCATION stack = irp->Tail.Overlay.CurrentStackLocation;
  return stack->Parameters.FileSystemControl.FsControlCode == FSCTL_FIXTURE
    ? STATUS_INVALID_PARAMETER : STATUS_INVALID_DEVICE_REQUEST;
}

EXPORT NOINLINE NTSTATUS NTAPI IndirectSwitchFileSystemControlLead(PIRP irp) {
  PIO_STACK_LOCATION stack = irp->Tail.Overlay.CurrentStackLocation;
  switch (stack->Parameters.FileSystemControl.FsControlCode) {
  case FSCTL_SWITCH_A: return STATUS_SUCCESS;
  case FSCTL_SWITCH_B: return STATUS_INVALID_PARAMETER;
  case FSCTL_SWITCH_C: return STATUS_ACCESS_DENIED;
  case FSCTL_SWITCH_D: return STATUS_BUFFER_TOO_SMALL;
  case FSCTL_SWITCH_E: return STATUS_INVALID_DEVICE_REQUEST;
  default: return STATUS_NOT_SUPPORTED;
  }
}

/* An unrelated structure happens to use a MajorFunction-sized displacement.
 * A constant stored there is data, not a dispatcher function pointer. */
EXPORT NOINLINE void NTAPI UnrelatedSlotStore(volatile char *blob) {
  *(volatile ULONG_PTR *)(blob + 0xE0) = 3;
}

EXPORT NOINLINE void NTAPI UnrelatedFunctionStore(volatile char *blob) {
  *(volatile ULONG_PTR *)(blob + 0xE0) = (ULONG_PTR)HandleBuffered;
}

static const WCHAR dev_name[] = L"\\Device\\DrvTriage";
static const WCHAR link_name[] = L"\\DosDevices\\DrvTriage";
static const WCHAR sddl_text[] = L"D:P(A;;GA;;;WD)";

EXPORT NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry) {
  UNICODE_STRING dev;
  UNICODE_STRING link;
  UNICODE_STRING sddl;
  PDEVICE_OBJECT devobj = 0;
  PDEVICE_OBJECT secobj = 0;
  PVOID pool;
  NTSTATUS status;
  volatile char unrelated_blob[0xE8];
  (void)registry;
  if (driver == 0) return STATUS_INVALID_PARAMETER;
  UnrelatedFunctionStore(unrelated_blob);
  driver->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
  driver->MajorFunction[IRP_MJ_READ] = DispatchRead;
  driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
  driver->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = DispatchFileSystemControl;
  driver->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = DispatchInternal;
  RtlInitUnicodeString(&dev, dev_name);
  RtlInitUnicodeString(&link, link_name);
  RtlInitUnicodeString(&sddl, sddl_text);
  status = IoCreateDevice(driver, 0, &dev, FILE_DEVICE_UNKNOWN, 0, FALSE, &devobj);
  if (!NT_SUCCESS(status)) return status;
  status = IoCreateSymbolicLink(&link, &dev);
  if (!NT_SUCCESS(status)) return status;
  status = IoCreateDeviceSecure(driver, 0, &dev, FILE_DEVICE_UNKNOWN, 0, FALSE,
                                &sddl, 0, &secobj);
  if (!NT_SUCCESS(status)) return status;
  pool = ExAllocatePoolWithTag(NonPagedPool, 64, (ULONG)'1gaT'); /* Tag1 */
  if (pool != 0) sink_state = 2;
  return STATUS_SUCCESS;
}
