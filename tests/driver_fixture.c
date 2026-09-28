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
  (void)registry;
  if (driver == 0) return STATUS_INVALID_PARAMETER;
  driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
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
