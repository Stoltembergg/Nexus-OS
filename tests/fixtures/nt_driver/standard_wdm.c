/*
 * Nexus OS — standard WDM reference driver (standard_wdm.sys), built ONLY with the
 * official WDK headers (<ntddk.h>) and linked against the official x64 ntoskrnl.lib.
 * No Nexus-specific names, hooks or hand-written NT structs.
 *
 * Exercises pool allocation with tags, spin locks (KeAcquireSpinLock ->
 * KeAcquireSpinLockRaiseToDpc on x64), synchronization events and buffered I/O
 * (Irp->AssociatedIrp.SystemBuffer, IoGetCurrentIrpStackLocation).
 *
 * Copies and fills use NxCopy/NxZero instead of RtlCopyMemory/RtlZeroMemory
 * (memcpy/memset): the official ntoskrnl.lib carries those as static code, and these
 * committed fixtures must link nothing but import thunks from it (enforced by
 * scripts/wdk-abi.py).
 *
 * Built (and checked byte for byte) by scripts/wdk-abi.py; see docs/14.
 */
#include <ntddk.h>

/* Byte loops through volatile pointers: neither clang nor MSVC may turn them into
 * memcpy/memset calls (which would pull static code from ntoskrnl.lib). */
static VOID NxCopy(PVOID Dst, const VOID *Src, SIZE_T Len)
{
    volatile UCHAR *d = (volatile UCHAR *)Dst;
    const volatile UCHAR *s = (const volatile UCHAR *)Src;
    while (Len-- != 0) {
        *d++ = *s++;
    }
}

static VOID NxZero(PVOID Dst, SIZE_T Len)
{
    volatile UCHAR *d = (volatile UCHAR *)Dst;
    while (Len-- != 0) {
        *d++ = 0;
    }
}

#define IOCTL_WDM_SAMPLE_MEM_TEST      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WDM_SAMPLE_SPINLOCK_IRQL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WDM_SAMPLE_EVENT_TEST    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define TAG_TEST 'tseT' /* 'Test' */
#define TAG_EXT  'mdWS' /* 'SWdm' */

typedef struct _SAMPLE_DEVICE_EXTENSION {
    PDEVICE_OBJECT DeviceObject;
    KSPIN_LOCK Lock;
    KEVENT SyncEvent;
    ULONG Counter;
    UNICODE_STRING SymLink;
    UCHAR Buffer[128];
} SAMPLE_DEVICE_EXTENSION, *PSAMPLE_DEVICE_EXTENSION;

DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD StandardWdmUnload;
_Dispatch_type_(IRP_MJ_CREATE) _Dispatch_type_(IRP_MJ_CLOSE)
static DRIVER_DISPATCH StandardWdmCreateClose;
_Dispatch_type_(IRP_MJ_READ)
static DRIVER_DISPATCH StandardWdmRead;
_Dispatch_type_(IRP_MJ_WRITE)
static DRIVER_DISPATCH StandardWdmWrite;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
static DRIVER_DISPATCH StandardWdmDeviceControl;

/* The extension is allocated from pool (to exercise ExAllocatePoolWithTag in
 * DriverEntry/Unload) and published through DeviceObject->DeviceExtension. */
static PSAMPLE_DEVICE_EXTENSION g_Extension = NULL;

static NTSTATUS Complete(PIRP Irp, NTSTATUS Status, ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS StandardWdmCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return Complete(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS StandardWdmRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    static const char payload[] = "STANDARD_WDM_DEVICE_PAYLOAD";
    const ULONG payloadLen = sizeof(payload) - 1;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;

    UNREFERENCED_PARAMETER(DeviceObject);
    if (buffer == NULL) {
        return Complete(Irp, STATUS_INVALID_PARAMETER, 0);
    }
    if (stack->Parameters.Read.Length < payloadLen) {
        return Complete(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }
    NxCopy(buffer, payload, payloadLen);
    return Complete(Irp, STATUS_SUCCESS, payloadLen);
}

static NTSTATUS StandardWdmWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PSAMPLE_DEVICE_EXTENSION ext = (PSAMPLE_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG len = stack->Parameters.Write.Length;

    if (buffer == NULL || ext == NULL) {
        return Complete(Irp, STATUS_INVALID_PARAMETER, 0);
    }
    if (len > sizeof(ext->Buffer)) {
        len = sizeof(ext->Buffer);
    }
    NxCopy(ext->Buffer, buffer, len);
    return Complete(Irp, STATUS_SUCCESS, len);
}

static NTSTATUS StandardWdmDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PSAMPLE_DEVICE_EXTENSION ext = (PSAMPLE_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PULONG out = (PULONG)Irp->AssociatedIrp.SystemBuffer;

    if (ext == NULL) {
        return Complete(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_WDM_SAMPLE_MEM_TEST: {
        static const char testData[] = "STANDARD_WDM_POOL_OK";
        PVOID block = ExAllocatePoolWithTag(NonPagedPool, 64, TAG_TEST);
        SIZE_T match;
        if (block == NULL) {
            return Complete(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
        }
        NxZero(block, 64);
        NxCopy(block, testData, sizeof(testData));
        match = RtlCompareMemory(block, testData, sizeof(testData));
        ExFreePoolWithTag(block, TAG_TEST);
        if (match != sizeof(testData)) {
            return Complete(Irp, STATUS_UNSUCCESSFUL, 0);
        }
        if (out == NULL || outLen < sizeof(ULONG)) {
            return Complete(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        }
        *out = 0x504F4F4C; /* 'POOL' */
        return Complete(Irp, STATUS_SUCCESS, sizeof(ULONG));
    }

    case IOCTL_WDM_SAMPLE_SPINLOCK_IRQL: {
        KIRQL oldIrql;
        KeAcquireSpinLock(&ext->Lock, &oldIrql);
        if (KeGetCurrentIrql() == DISPATCH_LEVEL) {
            ext->Counter++;
        }
        KeReleaseSpinLock(&ext->Lock, oldIrql);
        if (out == NULL || outLen < sizeof(ULONG)) {
            return Complete(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        }
        *out = ext->Counter;
        return Complete(Irp, STATUS_SUCCESS, sizeof(ULONG));
    }

    case IOCTL_WDM_SAMPLE_EVENT_TEST: {
        NTSTATUS waitStatus;
        KeSetEvent(&ext->SyncEvent, IO_NO_INCREMENT, FALSE);
        waitStatus = KeWaitForSingleObject(&ext->SyncEvent, Executive, KernelMode, FALSE, NULL);
        KeResetEvent(&ext->SyncEvent);
        if (waitStatus != STATUS_SUCCESS || out == NULL || outLen < sizeof(ULONG)) {
            return Complete(Irp, STATUS_UNSUCCESSFUL, 0);
        }
        *out = 0xCAFEFEED;
        return Complete(Irp, STATUS_SUCCESS, sizeof(ULONG));
    }

    default:
        return Complete(Irp, STATUS_NOT_IMPLEMENTED, 0);
    }
}

static VOID StandardWdmUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[StandardWdm] DriverUnload\n");
    if (g_Extension != NULL) {
        IoDeleteSymbolicLink(&g_Extension->SymLink);
        if (g_Extension->DeviceObject != NULL) {
            IoDeleteDevice(g_Extension->DeviceObject);
        }
        ExFreePoolWithTag(g_Extension, TAG_EXT);
        g_Extension = NULL;
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING devName;
    UNICODE_STRING symLink;
    PDEVICE_OBJECT devObj = NULL;
    PSAMPLE_DEVICE_EXTENSION ext;

    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrint("[StandardWdm] DriverEntry\n");

    RtlInitUnicodeString(&devName, L"\\Device\\StandardWdm0");
    RtlInitUnicodeString(&symLink, L"\\DosDevices\\StandardWdm0");

    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &devObj);
    if (!NT_SUCCESS(status) || devObj == NULL) {
        return status;
    }

    ext = (PSAMPLE_DEVICE_EXTENSION)ExAllocatePoolWithTag(NonPagedPool, sizeof(SAMPLE_DEVICE_EXTENSION), TAG_EXT);
    if (ext == NULL) {
        IoDeleteDevice(devObj);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    NxZero(ext, sizeof(SAMPLE_DEVICE_EXTENSION));
    ext->DeviceObject = devObj;
    ext->SymLink = symLink;
    ext->Counter = 100;
    KeInitializeSpinLock(&ext->Lock);
    KeInitializeEvent(&ext->SyncEvent, SynchronizationEvent, FALSE);

    devObj->DeviceExtension = ext;
    g_Extension = ext;

    status = IoCreateSymbolicLink(&symLink, &devName);
    if (!NT_SUCCESS(status)) {
        g_Extension = NULL;
        ExFreePoolWithTag(ext, TAG_EXT);
        IoDeleteDevice(devObj);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = StandardWdmCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = StandardWdmCreateClose;
    DriverObject->MajorFunction[IRP_MJ_READ] = StandardWdmRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = StandardWdmWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = StandardWdmDeviceControl;
    DriverObject->DriverUnload = StandardWdmUnload;

    devObj->Flags |= DO_BUFFERED_IO;
    devObj->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
