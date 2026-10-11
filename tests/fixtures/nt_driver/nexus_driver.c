/*
 * Nexus OS — WDM test driver (nexus_driver.sys), built ONLY with the official WDK
 * headers (<ntddk.h>) and linked against the official x64 ntoskrnl.lib.
 *
 * No NT struct, constant or prototype is defined here: every layout and import comes
 * from the WDK, so the binary is what a real third-party driver would produce:
 *   IoCompleteRequest -> IofCompleteRequest, KeRaiseIrql -> KfRaiseIrql,
 *   IoGetCurrentIrpStackLocation -> inline read of Irp->Tail.Overlay.CurrentStackLocation,
 *   buffered I/O through Irp->AssociatedIrp.SystemBuffer.
 *
 * The copy is a volatile byte loop instead of memcpy/RtlCopyMemory: the official
 * ntoskrnl.lib carries memcpy as static code, and these committed fixtures must link
 * nothing but import thunks from it (enforced by scripts/wdk-abi.py).
 *
 * Built (and checked byte for byte) by scripts/wdk-abi.py; see docs/14.
 */
#include <ntddk.h>

#define IOCTL_NEXUS_GET_VERSION     0x80002000
#define IOCTL_NEXUS_ECHO            0x80002004
#define IOCTL_NEXUS_RAISE_IRQL_TEST 0x80002008

DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD NexusDriverUnload;
_Dispatch_type_(IRP_MJ_CREATE) _Dispatch_type_(IRP_MJ_CLOSE)
static DRIVER_DISPATCH NexusDriverCreateClose;
_Dispatch_type_(IRP_MJ_READ)
static DRIVER_DISPATCH NexusDriverRead;
_Dispatch_type_(IRP_MJ_WRITE)
static DRIVER_DISPATCH NexusDriverWrite;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
static DRIVER_DISPATCH NexusDriverDeviceControl;

static UNICODE_STRING g_DeviceName;
static UNICODE_STRING g_SymLinkName;

static NTSTATUS Complete(PIRP Irp, NTSTATUS Status, ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PDEVICE_OBJECT devObj = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrint("[nexus_driver] DriverEntry\n");

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = NexusDriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = NexusDriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_READ] = NexusDriverRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = NexusDriverWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NexusDriverDeviceControl;
    DriverObject->DriverUnload = NexusDriverUnload;

    RtlInitUnicodeString(&g_DeviceName, L"\\Device\\NexusDrv0");
    RtlInitUnicodeString(&g_SymLinkName, L"\\DosDevices\\NexusDrv0");

    status = IoCreateDevice(DriverObject, 0, &g_DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &devObj);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&g_SymLinkName, &g_DeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(devObj);
        return status;
    }

    devObj->Flags |= DO_BUFFERED_IO;
    devObj->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

static NTSTATUS NexusDriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return Complete(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS NexusDriverRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    static const char msg[] = "NEXUS_OS_WDM_READ_SUCCESS";
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PUCHAR dst = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    ULONG len = stack->Parameters.Read.Length;
    ULONG n = sizeof(msg) - 1;

    UNREFERENCED_PARAMETER(DeviceObject);
    if (dst == NULL) {
        return Complete(Irp, STATUS_INVALID_PARAMETER, 0);
    }
    if (len < n) {
        n = len;
    }
    for (ULONG i = 0; i < n; i++) {
        ((volatile UCHAR *)dst)[i] = (UCHAR)msg[i];
    }
    return Complete(Irp, STATUS_SUCCESS, n);
}

static NTSTATUS NexusDriverWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    UNREFERENCED_PARAMETER(DeviceObject);
    return Complete(Irp, STATUS_SUCCESS, stack->Parameters.Write.Length);
}

static NTSTATUS NexusDriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    PUCHAR buf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (ioctlCode) {
    case IOCTL_NEXUS_GET_VERSION:
        if (outLen < sizeof(ULONG) || buf == NULL) {
            return Complete(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        }
        *(PULONG)buf = 0x00030600;
        return Complete(Irp, STATUS_SUCCESS, sizeof(ULONG));

    case IOCTL_NEXUS_ECHO:
        if (buf == NULL || outLen < inLen) {
            return Complete(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        }
        for (ULONG i = 0; i < inLen; i++) {
            if (buf[i] >= 'a' && buf[i] <= 'z') {
                buf[i] = (UCHAR)(buf[i] - ('a' - 'A'));
            } else if (buf[i] >= 'A' && buf[i] <= 'Z') {
                buf[i] = (UCHAR)(buf[i] + ('a' - 'A'));
            }
        }
        return Complete(Irp, STATUS_SUCCESS, inLen);

    case IOCTL_NEXUS_RAISE_IRQL_TEST: {
        KIRQL oldIrql;
        KIRQL raised;
        KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
        raised = KeGetCurrentIrql();
        KeLowerIrql(oldIrql);
        if (raised != DISPATCH_LEVEL || KeGetCurrentIrql() != PASSIVE_LEVEL) {
            return Complete(Irp, STATUS_INVALID_PARAMETER, 0);
        }
        if (buf != NULL && outLen >= sizeof(ULONG)) {
            *(PULONG)buf = 0x1337C0DE;
        }
        return Complete(Irp, STATUS_SUCCESS, sizeof(ULONG));
    }

    default:
        return Complete(Irp, STATUS_NOT_IMPLEMENTED, 0);
    }
}

static VOID NexusDriverUnload(PDRIVER_OBJECT DriverObject)
{
    IoDeleteSymbolicLink(&g_SymLinkName);
    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}
