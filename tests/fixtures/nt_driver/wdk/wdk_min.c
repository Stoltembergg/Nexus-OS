/*
 * Nexus OS — minimal WDM driver built ONLY with the official WDK headers (<ntddk.h>).
 *
 * Unlike nexus_driver.c and standard_wdm.c, this file defines no NT structs or
 * prototypes of its own: every type, macro and import comes from the WDK, so its
 * layout and its import table are exactly what a real third-party driver produces
 * (e.g. IoCompleteRequest -> IofCompleteRequest, KeAcquireSpinLock ->
 * KeAcquireSpinLockRaiseToDpc, METHOD_BUFFERED via AssociatedIrp.SystemBuffer).
 *
 * PR-5 builds it in CI (scripts/wdk-abi.py) and reports whether the Nexus loader can
 * resolve its imports. It is NOT executed by Nexus yet: Nexus' NT structs still differ
 * from the WDK (audit finding C4). Executing it is the acceptance test of PR-6.
 */
#include <ntddk.h>

#define IOCTL_WDK_MIN_ECHO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _WDK_MIN_EXTENSION {
    KSPIN_LOCK Lock;
    ULONG Requests;
} WDK_MIN_EXTENSION, *PWDK_MIN_EXTENSION;

DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD WdkMinUnload;
_Dispatch_type_(IRP_MJ_CREATE) _Dispatch_type_(IRP_MJ_CLOSE)
static DRIVER_DISPATCH WdkMinCreateClose;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
static DRIVER_DISPATCH WdkMinDeviceControl;

static NTSTATUS WdkMinCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS WdkMinDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PWDK_MIN_EXTENSION ext = (PWDK_MIN_EXTENSION)DeviceObject->DeviceExtension;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;
    KIRQL old;

    if (stack->Parameters.DeviceIoControl.IoControlCode == IOCTL_WDK_MIN_ECHO) {
        ULONG in = stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG out = stack->Parameters.DeviceIoControl.OutputBufferLength;
        if (in < sizeof(ULONG) || out < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            PULONG buffer = (PULONG)Irp->AssociatedIrp.SystemBuffer;
            KeAcquireSpinLock(&ext->Lock, &old);
            ext->Requests++;
            *buffer = ~*buffer;
            KeReleaseSpinLock(&ext->Lock, old);
            information = sizeof(ULONG);
            status = STATUS_SUCCESS;
        }
    }
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static VOID WdkMinUnload(PDRIVER_OBJECT DriverObject)
{
    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING name;
    PDEVICE_OBJECT device = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);
    RtlInitUnicodeString(&name, L"\\Device\\NexusWdkMin");
    status = IoCreateDevice(DriverObject, sizeof(WDK_MIN_EXTENSION), &name,
                            FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    KeInitializeSpinLock(&((PWDK_MIN_EXTENSION)device->DeviceExtension)->Lock);
    ((PWDK_MIN_EXTENSION)device->DeviceExtension)->Requests = 0;
    device->Flags |= DO_BUFFERED_IO;
    device->Flags &= ~DO_DEVICE_INITIALIZING;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = WdkMinCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = WdkMinCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = WdkMinDeviceControl;
    DriverObject->DriverUnload = WdkMinUnload;
    return STATUS_SUCCESS;
}
