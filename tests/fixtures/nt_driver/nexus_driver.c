// =============================================================================
// Nexus OS — Independent Windows NT WDM Kernel Driver Test Fixture
// Compiled with Microsoft Visual Studio MSVC 2022 (cl.exe /kernel /DRIVER)
// =============================================================================

#define STATUS_SUCCESS                   ((long)0x00000000L)
#define STATUS_INVALID_PARAMETER         ((long)0xC000000DL)
#define STATUS_NOT_IMPLEMENTED           ((long)0xC0000002L)
#define STATUS_BUFFER_TOO_SMALL          ((long)0xC0000023L)

#define IRP_MJ_CREATE                   0x00
#define IRP_MJ_CLOSE                    0x02
#define IRP_MJ_READ                     0x03
#define IRP_MJ_WRITE                    0x04
#define IRP_MJ_DEVICE_CONTROL           0x0e
#define IRP_MJ_MAXIMUM_FUNCTION         0x1b

#define FILE_DEVICE_UNKNOWN             0x00000022
#define IO_NO_INCREMENT                 0

#define PASSIVE_LEVEL                   0
#define APC_LEVEL                       1
#define DISPATCH_LEVEL                  2

// Custom IOCTLs for validation
#define IOCTL_NEXUS_GET_VERSION         0x80002000
#define IOCTL_NEXUS_ECHO                0x80002004
#define IOCTL_NEXUS_RAISE_IRQL_TEST     0x80002008

typedef long NTSTATUS;
typedef void *PVOID;
typedef unsigned long ULONG;
typedef unsigned short USHORT;
typedef unsigned char UCHAR;
typedef unsigned char KIRQL;
typedef unsigned __int64 ULONG_PTR;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    ULONG _Padding;
    unsigned short *Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

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
    void (__fastcall *DriverUnload)(struct _DRIVER_OBJECT *DriverObject);
    NTSTATUS (__fastcall *MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1])(
        PDEVICE_OBJECT DeviceObject,
        PIRP Irp
    );
} DRIVER_OBJECT, *PDRIVER_OBJECT;

// Imported NTOSKRNL symbols
__declspec(dllimport) NTSTATUS __fastcall DbgPrint(const char *Format, ...);
__declspec(dllimport) NTSTATUS __fastcall IoCreateDevice(
    PDRIVER_OBJECT DriverObject,
    ULONG DeviceExtensionSize,
    PUNICODE_STRING DeviceName,
    ULONG DeviceType,
    ULONG DeviceCharacteristics,
    UCHAR Exclusive,
    PDEVICE_OBJECT *DeviceObject
);
__declspec(dllimport) void __fastcall IoDeleteDevice(PDEVICE_OBJECT DeviceObject);
__declspec(dllimport) NTSTATUS __fastcall IoCreateSymbolicLink(
    PUNICODE_STRING SymbolicLinkName,
    PUNICODE_STRING DeviceName
);
__declspec(dllimport) NTSTATUS __fastcall IoDeleteSymbolicLink(PUNICODE_STRING SymbolicLinkName);
__declspec(dllimport) void __fastcall IoCompleteRequest(PIRP Irp, char PriorityBoost);
__declspec(dllimport) KIRQL __fastcall KeGetCurrentIrql(void);
__declspec(dllimport) void __fastcall KeRaiseIrql(KIRQL NewIrql, KIRQL *OldIrql);
__declspec(dllimport) void __fastcall KeLowerIrql(KIRQL NewIrql);
__declspec(dllimport) void __fastcall RtlInitUnicodeString(PUNICODE_STRING DestinationString, const unsigned short *SourceString);

// Driver Globals
static UNICODE_STRING g_DeviceName;
static UNICODE_STRING g_SymLinkName;
static const unsigned short g_DeviceNameStr[] = { '\\', 'D', 'e', 'v', 'i', 'c', 'e', '\\', 'N', 'e', 'x', 'u', 's', 'D', 'r', 'v', '0', 0 };
static const unsigned short g_SymLinkNameStr[] = { '\\', 'D', 'o', 's', 'D', 'e', 'v', 'i', 'c', 'e', 's', '\\', 'N', 'e', 'x', 'u', 's', 'D', 'r', 'v', '0', 0 };

// Dispatch Prototypes
static NTSTATUS __fastcall NexusDriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS __fastcall NexusDriverRead(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS __fastcall NexusDriverWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS __fastcall NexusDriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static void __fastcall NexusDriverUnload(PDRIVER_OBJECT DriverObject);

// DriverEntry
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    PDEVICE_OBJECT devObj = 0;

    (void)RegistryPath;

    if (!DriverObject) {
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint("[nexus_driver] DriverEntry initializing in Ring 0\n");

    // Verify IRQL is PASSIVE_LEVEL (0)
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        DbgPrint("[nexus_driver] Error: DriverEntry not at PASSIVE_LEVEL\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Register Dispatch Roster
    DriverObject->MajorFunction[IRP_MJ_CREATE] = NexusDriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = NexusDriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_READ] = NexusDriverRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = NexusDriverWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NexusDriverDeviceControl;
    DriverObject->DriverUnload = NexusDriverUnload;

    RtlInitUnicodeString(&g_DeviceName, g_DeviceNameStr);
    RtlInitUnicodeString(&g_SymLinkName, g_SymLinkNameStr);

    status = IoCreateDevice(
        DriverObject,
        0,
        &g_DeviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        0,
        &devObj
    );

    if (status != STATUS_SUCCESS) {
        DbgPrint("[nexus_driver] IoCreateDevice failed: %ld\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&g_SymLinkName, &g_DeviceName);
    if (status != STATUS_SUCCESS) {
        DbgPrint("[nexus_driver] IoCreateSymbolicLink failed: %ld\n", status);
        IoDeleteDevice(devObj);
        return status;
    }

    DbgPrint("[nexus_driver] Initialization complete, device & symlink active\n");
    return STATUS_SUCCESS;
}

static NTSTATUS __fastcall NexusDriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    (void)DeviceObject;
    if (Irp) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS __fastcall NexusDriverRead(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    (void)DeviceObject;
    if (!Irp) return STATUS_INVALID_PARAMETER;

    if (Irp->UserBuffer) {
        const char msg[] = "NEXUS_OS_WDM_READ_SUCCESS";
        unsigned char *dst = (unsigned char *)Irp->UserBuffer;
        ULONG i = 0;
        while (msg[i] != 0 && i < 32) {
            dst[i] = (unsigned char)msg[i];
            i++;
        }
        Irp->IoStatus.Information = i;
    } else {
        Irp->IoStatus.Information = 0;
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS __fastcall NexusDriverWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    (void)DeviceObject;
    if (!Irp) return STATUS_INVALID_PARAMETER;

    // Acknowledge written bytes
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 16;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS __fastcall NexusDriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack;
    ULONG ioctlCode;
    ULONG outLen;
    ULONG inLen;

    (void)DeviceObject;

    if (!Irp || !Irp->CurrentStackLocation) {
        return STATUS_INVALID_PARAMETER;
    }

    stack = Irp->CurrentStackLocation;
    ioctlCode = stack->DeviceIoControl.IoControlCode;
    outLen = stack->DeviceIoControl.OutputBufferLength;
    inLen = stack->DeviceIoControl.InputBufferLength;

    switch (ioctlCode) {
        case IOCTL_NEXUS_GET_VERSION: {
            if (outLen < 4 || !Irp->UserBuffer) {
                Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
            } else {
                // Return version 0x00030600 (Phase 3.6)
                ULONG *verPtr = (ULONG *)Irp->UserBuffer;
                *verPtr = 0x00030600;
                Irp->IoStatus.Status = STATUS_SUCCESS;
                Irp->IoStatus.Information = 4;
            }
            break;
        }

        case IOCTL_NEXUS_ECHO: {
            if (!Irp->UserBuffer || outLen < inLen) {
                Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
                Irp->IoStatus.Information = 0;
            } else {
                // Invert casing of characters to prove dynamic modification
                unsigned char *buf = (unsigned char *)Irp->UserBuffer;
                for (ULONG i = 0; i < inLen; i++) {
                    if (buf[i] >= 'a' && buf[i] <= 'z') {
                        buf[i] = buf[i] - ('a' - 'A');
                    } else if (buf[i] >= 'A' && buf[i] <= 'Z') {
                        buf[i] = buf[i] + ('a' - 'A');
                    }
                }
                Irp->IoStatus.Status = STATUS_SUCCESS;
                Irp->IoStatus.Information = inLen;
            }
            break;
        }

        case IOCTL_NEXUS_RAISE_IRQL_TEST: {
            // Exercise NT IRQL engine
            KIRQL oldIrql = PASSIVE_LEVEL;
            KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

            if (KeGetCurrentIrql() != DISPATCH_LEVEL) {
                KeLowerIrql(oldIrql);
                Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                Irp->IoStatus.Information = 0;
            } else {
                KeLowerIrql(oldIrql);
                if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
                    Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
                    Irp->IoStatus.Information = 0;
                } else {
                    if (Irp->UserBuffer && outLen >= 4) {
                        ULONG *resPtr = (ULONG *)Irp->UserBuffer;
                        *resPtr = 0x1337C0DE; // Test signature verified
                    }
                    Irp->IoStatus.Status = STATUS_SUCCESS;
                    Irp->IoStatus.Information = 4;
                }
            }
            break;
        }

        default:
            Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
            Irp->IoStatus.Information = 0;
            break;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}

static void __fastcall NexusDriverUnload(PDRIVER_OBJECT DriverObject) {
    DbgPrint("[nexus_driver] DriverUnload routine called in Ring 0\n");

    if (DriverObject) {
        IoDeleteSymbolicLink(&g_SymLinkName);

        if (DriverObject->DeviceObject) {
            IoDeleteDevice(DriverObject->DeviceObject);
            DriverObject->DeviceObject = 0;
        }
    }

    DbgPrint("[nexus_driver] Unload finished cleanly\n");
}
