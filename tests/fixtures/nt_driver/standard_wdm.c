// =============================================================================
// Nexus OS — Standard WDM Kernel Driver (Independent Reference Fixture)
// Written strictly according to Microsoft Windows NT Kernel WDM Specifications.
// Contains NO Nexus-specific names, hooks, or vendor extensions.
// =============================================================================

#define STATUS_SUCCESS                   ((long)0x00000000L)
#define STATUS_UNSUCCESSFUL              ((long)0xC0000001L)
#define STATUS_NOT_IMPLEMENTED           ((long)0xC0000002L)
#define STATUS_INVALID_PARAMETER         ((long)0xC000000DL)
#define STATUS_INSUFFICIENT_RESOURCES    ((long)0xC0000017L)
#define STATUS_BUFFER_TOO_SMALL          ((long)0xC0000023L)

#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_DEVICE_CONTROL           0x0e
#define IRP_MJ_MAXIMUM_FUNCTION         0x1b

#define FILE_DEVICE_UNKNOWN             0x00000022
#define METHOD_BUFFERED                 0
#define FILE_ANY_ACCESS                 0
#define IO_NO_INCREMENT                 0

#define CTL_CODE(DeviceType, Function, Method, Access) ( \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

// Standard Generic IOCTL Definitions
#define IOCTL_WDM_SAMPLE_MEM_TEST       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WDM_SAMPLE_SPINLOCK_IRQL  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WDM_SAMPLE_EVENT_TEST     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define PASSIVE_LEVEL                   0
#define APC_LEVEL                       1
#define DISPATCH_LEVEL                  2

#define NonPagedPool                    0
#define PagedPool                       1
#define NonPagedPoolNx                  512

typedef long NTSTATUS;
typedef void *PVOID;
typedef const void *PCVOID;
typedef unsigned long ULONG;
typedef unsigned short USHORT;
typedef unsigned char UCHAR;
typedef unsigned char KIRQL;
typedef unsigned char *PUCHAR;
typedef unsigned __int64 ULONG_PTR;
typedef unsigned __int64 SIZE_T;
typedef char CCHAR;
typedef int BOOLEAN;

#define TRUE  1
#define FALSE 0
#define NULL  ((void*)0)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    ULONG _Padding;
    unsigned short *Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _IO_STATUS_BLOCK {
    NTSTATUS Status;
    ULONG _Padding;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _DEVICE_OBJECT {
    short Type;
    USHORT Size;
    int ReferenceCount;
    struct _DRIVER_OBJECT *DriverObject;
    struct _DEVICE_OBJECT *NextDevice;
    struct _DEVICE_OBJECT *AttachedDevice;
    struct _IRP *CurrentIrp;
    ULONG Flags;
    ULONG Characteristics;
    PVOID DeviceExtension;
    ULONG DeviceType;
    char StackSize;
    unsigned char _Padding[7];
} DEVICE_OBJECT, *PDEVICE_OBJECT;

typedef struct _IO_STACK_LOCATION {
    UCHAR MajorFunction;
    UCHAR MinorFunction;
    UCHAR Flags;
    UCHAR Control;
    ULONG _Padding;
    struct {
        ULONG OutputBufferLength;
        ULONG InputBufferLength;
        ULONG IoControlCode;
        PVOID Type3InputBuffer;
    } DeviceIoControl;
    PDEVICE_OBJECT DeviceObject;
    PVOID FileObject;
    PVOID CompletionRoutine;
    PVOID Context;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

typedef struct _IRP {
    short Type;
    USHORT Size;
    ULONG _Padding0;
    PVOID MdlAddress;
    ULONG Flags;
    ULONG _Padding1;
    PVOID AssociatedIrp;
    IO_STATUS_BLOCK IoStatus;
    char RequestorMode;
    UCHAR PendingReturned;
    char StackCount;
    char CurrentLocation;
    ULONG _Padding2;
    PVOID UserBuffer;
    PIO_STACK_LOCATION CurrentStackLocation;
} IRP, *PIRP;

typedef struct _DRIVER_OBJECT {
    short Type;
    short Size;
    ULONG _Padding0;
    PDEVICE_OBJECT DeviceObject;
    ULONG Flags;
    ULONG _Padding1;
    PVOID DriverStart;
    ULONG DriverSize;
    ULONG _Padding2;
    PVOID DriverSection;
    PVOID DriverExtension;
    UNICODE_STRING DriverName;
    PUNICODE_STRING HardwareDatabase;
    PVOID FastIoDispatch;
    PVOID DriverInit;
    PVOID DriverStartIo;
    void (*DriverUnload)(struct _DRIVER_OBJECT *DriverObject);
    NTSTATUS (*MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1])(PDEVICE_OBJECT DeviceObject, PIRP Irp);
} DRIVER_OBJECT, *PDRIVER_OBJECT;

typedef ULONG_PTR KSPIN_LOCK, *PKSPIN_LOCK;

typedef struct _KEVENT {
    UCHAR HeaderType;
    UCHAR HeaderSignaled;
    UCHAR HeaderSize;
    UCHAR HeaderReserved;
    int SignalState;
    PVOID WaitListBlink;
    PVOID WaitListFlink;
} KEVENT, *PKEVENT;

// Standard WDM Device Extension
typedef struct _SAMPLE_DEVICE_EXTENSION {
    PDEVICE_OBJECT DeviceObject;
    KSPIN_LOCK Lock;
    KEVENT SyncEvent;
    ULONG Counter;
    UNICODE_STRING SymLink;
    UCHAR Buffer[128];
} SAMPLE_DEVICE_EXTENSION, *PSAMPLE_DEVICE_EXTENSION;

// External NT Kernel Imports
__declspec(dllimport) void __cdecl DbgPrint(const char *format, ...);
__declspec(dllimport) NTSTATUS __stdcall IoCreateDevice(PDRIVER_OBJECT, ULONG, PUNICODE_STRING, ULONG, ULONG, BOOLEAN, PDEVICE_OBJECT*);
__declspec(dllimport) void __stdcall IoDeleteDevice(PDEVICE_OBJECT);
__declspec(dllimport) NTSTATUS __stdcall IoCreateSymbolicLink(PUNICODE_STRING, PUNICODE_STRING);
__declspec(dllimport) NTSTATUS __stdcall IoDeleteSymbolicLink(PUNICODE_STRING);
__declspec(dllimport) void __stdcall IoCompleteRequest(PIRP, CCHAR);
__declspec(dllimport) KIRQL __stdcall KeGetCurrentIrql(void);
__declspec(dllimport) void __stdcall KeRaiseIrql(KIRQL, KIRQL*);
__declspec(dllimport) void __stdcall KeLowerIrql(KIRQL);
__declspec(dllimport) void __stdcall RtlInitUnicodeString(PUNICODE_STRING, const unsigned short*);

__declspec(dllimport) PVOID __stdcall ExAllocatePoolWithTag(ULONG PoolType, SIZE_T NumberOfBytes, ULONG Tag);
__declspec(dllimport) void __stdcall ExFreePoolWithTag(PVOID P, ULONG Tag);
__declspec(dllimport) void __stdcall ExFreePool(PVOID P);
__declspec(dllimport) void __stdcall RtlCopyMemory(PVOID Destination, PCVOID Source, SIZE_T Length);
__declspec(dllimport) void __stdcall RtlZeroMemory(PVOID Destination, SIZE_T Length);
__declspec(dllimport) SIZE_T __stdcall RtlCompareMemory(PCVOID Source1, PCVOID Source2, SIZE_T Length);

__declspec(dllimport) void __stdcall KeInitializeSpinLock(PKSPIN_LOCK SpinLock);
__declspec(dllimport) void __stdcall KeAcquireSpinLock(PKSPIN_LOCK SpinLock, KIRQL *OldIrql);
__declspec(dllimport) void __stdcall KeReleaseSpinLock(PKSPIN_LOCK SpinLock, KIRQL NewIrql);

__declspec(dllimport) void __stdcall KeInitializeEvent(PKEVENT Event, ULONG Type, BOOLEAN InitialState);
__declspec(dllimport) int __stdcall KeSetEvent(PKEVENT Event, int Increment, BOOLEAN Wait);
__declspec(dllimport) int __stdcall KeResetEvent(PKEVENT Event);
__declspec(dllimport) NTSTATUS __stdcall KeWaitForSingleObject(PVOID Object, ULONG WaitReason, UCHAR WaitMode, BOOLEAN Alertable, const void *Timeout);

// Device name strings
static const unsigned short g_DeviceName[] = {
    '\\', 'D', 'e', 'v', 'i', 'c', 'e', '\\',
    'S', 't', 'a', 'n', 'd', 'a', 'r', 'd', 'W', 'd', 'm', '0', 0
};
static const unsigned short g_SymLinkName[] = {
    '\\', 'D', 'o', 's', 'D', 'e', 'v', 'i', 'c', 'e', 's', '\\',
    'S', 't', 'a', 'n', 'd', 'a', 'r', 'd', 'W', 'd', 'm', '0', 0
};

// Global reference to extension for unload
static PSAMPLE_DEVICE_EXTENSION g_Extension = NULL;

static NTSTATUS StandardWdmCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    (void)DeviceObject;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS StandardWdmClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    (void)DeviceObject;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS StandardWdmRead(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack;
    ULONG readLen;
    static const char payload[] = "STANDARD_WDM_DEVICE_PAYLOAD";
    const ULONG payloadLen = sizeof(payload) - 1;

    (void)DeviceObject;
    stack = Irp->CurrentStackLocation;
    readLen = stack ? stack->DeviceIoControl.OutputBufferLength : 0;

    if (!Irp->UserBuffer) {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_PARAMETER;
    }

    if (readLen < payloadLen) {
        Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlCopyMemory(Irp->UserBuffer, payload, payloadLen);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = payloadLen;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS StandardWdmWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack;
    ULONG writeLen;
    PSAMPLE_DEVICE_EXTENSION ext;

    ext = (PSAMPLE_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    stack = Irp->CurrentStackLocation;
    writeLen = stack ? stack->DeviceIoControl.InputBufferLength : 0;

    if (!Irp->UserBuffer || !ext) {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_PARAMETER;
    }

    if (writeLen > sizeof(ext->Buffer)) {
        writeLen = sizeof(ext->Buffer);
    }

    RtlCopyMemory(ext->Buffer, Irp->UserBuffer, writeLen);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = writeLen;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS StandardWdmDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack;
    ULONG ioctl;
    ULONG inLen;
    ULONG outLen;
    PSAMPLE_DEVICE_EXTENSION ext;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR info = 0;

    ext = (PSAMPLE_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    stack = Irp->CurrentStackLocation;

    if (!stack || !ext) {
        Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_PARAMETER;
    }

    ioctl = stack->DeviceIoControl.IoControlCode;
    inLen = stack->DeviceIoControl.InputBufferLength;
    outLen = stack->DeviceIoControl.OutputBufferLength;

    switch (ioctl) {
        case IOCTL_WDM_SAMPLE_MEM_TEST: {
            // Allocate pool memory, copy, zero, compare, and free
            PVOID poolBlock = ExAllocatePoolWithTag(NonPagedPool, 64, 'tseT'); // 'Test'
            if (!poolBlock) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            RtlZeroMemory(poolBlock, 64);
            static const char testData[] = "STANDARD_WDM_POOL_OK";
            RtlCopyMemory(poolBlock, testData, sizeof(testData));

            SIZE_T match = RtlCompareMemory(poolBlock, testData, sizeof(testData));
            ExFreePoolWithTag(poolBlock, 'tseT');

            if (match == sizeof(testData) && outLen >= sizeof(ULONG)) {
                if (Irp->UserBuffer) {
                    *(ULONG*)Irp->UserBuffer = 0x504F4F4C; // 'POOL'
                    info = sizeof(ULONG);
                    status = STATUS_SUCCESS;
                } else {
                    status = STATUS_INVALID_PARAMETER;
                }
            } else {
                status = STATUS_UNSUCCESSFUL;
            }
            break;
        }

        case IOCTL_WDM_SAMPLE_SPINLOCK_IRQL: {
            KIRQL oldIrql = PASSIVE_LEVEL;
            // Acquire spinlock: raises IRQL to DISPATCH_LEVEL (2)
            KeAcquireSpinLock(&ext->Lock, &oldIrql);

            KIRQL current = KeGetCurrentIrql();
            if (current == DISPATCH_LEVEL) {
                ext->Counter++;
            }

            // Release spinlock: lowers IRQL back to oldIrql
            KeReleaseSpinLock(&ext->Lock, oldIrql);

            if (outLen >= sizeof(ULONG) && Irp->UserBuffer) {
                *(ULONG*)Irp->UserBuffer = ext->Counter;
                info = sizeof(ULONG);
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
        }

        case IOCTL_WDM_SAMPLE_EVENT_TEST: {
            KeSetEvent(&ext->SyncEvent, 0, FALSE);
            NTSTATUS waitStatus = KeWaitForSingleObject(&ext->SyncEvent, 0, 0, FALSE, NULL);
            KeResetEvent(&ext->SyncEvent);

            if (waitStatus == STATUS_SUCCESS && outLen >= sizeof(ULONG) && Irp->UserBuffer) {
                *(ULONG*)Irp->UserBuffer = 0xCAFEFEED;
                info = sizeof(ULONG);
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_UNSUCCESSFUL;
            }
            break;
        }

        default:
            status = STATUS_NOT_IMPLEMENTED;
            info = 0;
            break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static void StandardWdmUnload(PDRIVER_OBJECT DriverObject) {
    DbgPrint("[StandardWdm] DriverUnload routine called\n");

    if (g_Extension) {
        IoDeleteSymbolicLink(&g_Extension->SymLink);
        if (g_Extension->DeviceObject) {
            IoDeleteDevice(g_Extension->DeviceObject);
        }
        ExFreePoolWithTag(g_Extension, 'mdWS'); // 'SWdm'
        g_Extension = NULL;
    }

    (void)DriverObject;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    UNICODE_STRING devName;
    UNICODE_STRING symLink;
    PDEVICE_OBJECT devObj = NULL;
    PSAMPLE_DEVICE_EXTENSION ext = NULL;

    (void)RegistryPath;
    DbgPrint("[StandardWdm] DriverEntry initializing in Ring 0\n");

    RtlInitUnicodeString(&devName, g_DeviceName);
    RtlInitUnicodeString(&symLink, g_SymLinkName);

    // 1. Create Device Object
    status = IoCreateDevice(
        DriverObject,
        0, // Extension allocated separately to test ExAllocatePoolWithTag
        &devName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &devObj
    );

    if (status != STATUS_SUCCESS || !devObj) {
        return status;
    }

    // 2. Allocate Device Extension from NonPagedPool
    ext = (PSAMPLE_DEVICE_EXTENSION)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(SAMPLE_DEVICE_EXTENSION),
        'mdWS' // 'SWdm'
    );

    if (!ext) {
        IoDeleteDevice(devObj);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ext, sizeof(SAMPLE_DEVICE_EXTENSION));
    ext->DeviceObject = devObj;
    ext->SymLink = symLink;
    ext->Counter = 100;

    // 3. Initialize SpinLock and Event
    KeInitializeSpinLock(&ext->Lock);
    KeInitializeEvent(&ext->SyncEvent, 1 /* SynchronizationEvent */, FALSE);

    devObj->DeviceExtension = ext;
    g_Extension = ext;

    // 4. Create Symbolic Link
    status = IoCreateSymbolicLink(&symLink, &devName);
    if (status != STATUS_SUCCESS) {
        ExFreePoolWithTag(ext, 'mdWS');
        IoDeleteDevice(devObj);
        return status;
    }

    // 5. Populate MajorFunction table
    DriverObject->MajorFunction[IRP_MJ_CREATE] = StandardWdmCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = StandardWdmClose;
    DriverObject->MajorFunction[IRP_MJ_READ] = StandardWdmRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = StandardWdmWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = StandardWdmDeviceControl;
    DriverObject->DriverUnload = StandardWdmUnload;

    DbgPrint("[StandardWdm] DriverEntry successfully initialized device\n");
    return STATUS_SUCCESS;
}
