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
#define FSCTL_FIXTURE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0x123, METHOD_BUFFERED, FILE_WRITE_DATA)
#define FSCTL_INDIRECT_LEAD CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 0x124, METHOD_BUFFERED, FILE_WRITE_DATA)

/* Missing from the MinGW wdm.h headers; declared manually for the fixture. */
NTSTATUS NTAPI IoCreateDeviceSecure(PDRIVER_OBJECT DriverObject,
                                    ULONG DeviceExtensionSize,
                                    PUNICODE_STRING DeviceName, ULONG DeviceType,
                                    ULONG DeviceCharacteristics, BOOLEAN Exclusive,
                                    PCUNICODE_STRING DefaultSDDLString,
                                    LPCGUID DeviceClassGuid,
                                    PDEVICE_OBJECT *DeviceObject);

static volatile LONG sink_state;

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
