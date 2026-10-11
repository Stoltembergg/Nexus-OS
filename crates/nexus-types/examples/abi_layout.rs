//! Prints the Nexus layout (`sizeof`/`offsetof`, in bytes) of the NT structs in
//! `nexus_types::driver` as JSON, keyed by the **WDK** struct and field names.
//!
//! `scripts/wdk-abi.py` compares this against the same table computed with the official
//! WDK headers (`wdm.h`/`ntddk.h`). The key list must match `ENTRIES` in that script; a
//! key present on only one side is reported as missing (audit finding C4, PR-5/PR-6).
//!
//! Usage: `cargo run -q -p nexus-types --example abi_layout`

use core::mem::{offset_of, size_of};
use nexus_types::driver::{
    DeviceObject, DriverObject, IoStackLocation, IoStatusBlock, Irp, KEvent,
    ParametersDeviceIoControl, UnicodeString,
};

fn main() {
    let params = offset_of!(IoStackLocation, parameters);
    let rows: &[(&str, &str, usize)] = &[
        ("UNICODE_STRING", "sizeof", size_of::<UnicodeString>()),
        (
            "UNICODE_STRING",
            "Length",
            offset_of!(UnicodeString, length),
        ),
        (
            "UNICODE_STRING",
            "MaximumLength",
            offset_of!(UnicodeString, maximum_length),
        ),
        (
            "UNICODE_STRING",
            "Buffer",
            offset_of!(UnicodeString, buffer),
        ),
        ("DRIVER_OBJECT", "sizeof", size_of::<DriverObject>()),
        (
            "DRIVER_OBJECT",
            "DeviceObject",
            offset_of!(DriverObject, device_object),
        ),
        ("DRIVER_OBJECT", "Flags", offset_of!(DriverObject, flags)),
        (
            "DRIVER_OBJECT",
            "DriverStart",
            offset_of!(DriverObject, driver_start),
        ),
        (
            "DRIVER_OBJECT",
            "DriverSize",
            offset_of!(DriverObject, driver_size),
        ),
        (
            "DRIVER_OBJECT",
            "DriverSection",
            offset_of!(DriverObject, driver_section),
        ),
        (
            "DRIVER_OBJECT",
            "DriverExtension",
            offset_of!(DriverObject, driver_extension),
        ),
        (
            "DRIVER_OBJECT",
            "DriverName",
            offset_of!(DriverObject, driver_name),
        ),
        (
            "DRIVER_OBJECT",
            "HardwareDatabase",
            offset_of!(DriverObject, hardware_database),
        ),
        (
            "DRIVER_OBJECT",
            "FastIoDispatch",
            offset_of!(DriverObject, fast_io_dispatch),
        ),
        (
            "DRIVER_OBJECT",
            "DriverInit",
            offset_of!(DriverObject, driver_init),
        ),
        (
            "DRIVER_OBJECT",
            "DriverStartIo",
            offset_of!(DriverObject, driver_start_io),
        ),
        (
            "DRIVER_OBJECT",
            "DriverUnload",
            offset_of!(DriverObject, driver_unload),
        ),
        (
            "DRIVER_OBJECT",
            "MajorFunction",
            offset_of!(DriverObject, major_function),
        ),
        ("DEVICE_OBJECT", "sizeof", size_of::<DeviceObject>()),
        ("DEVICE_OBJECT", "Size", offset_of!(DeviceObject, size)),
        (
            "DEVICE_OBJECT",
            "ReferenceCount",
            offset_of!(DeviceObject, reference_count),
        ),
        (
            "DEVICE_OBJECT",
            "DriverObject",
            offset_of!(DeviceObject, driver_object),
        ),
        (
            "DEVICE_OBJECT",
            "NextDevice",
            offset_of!(DeviceObject, next_device),
        ),
        (
            "DEVICE_OBJECT",
            "AttachedDevice",
            offset_of!(DeviceObject, attached_device),
        ),
        (
            "DEVICE_OBJECT",
            "CurrentIrp",
            offset_of!(DeviceObject, current_irp),
        ),
        ("DEVICE_OBJECT", "Flags", offset_of!(DeviceObject, flags)),
        (
            "DEVICE_OBJECT",
            "Characteristics",
            offset_of!(DeviceObject, characteristics),
        ),
        (
            "DEVICE_OBJECT",
            "DeviceExtension",
            offset_of!(DeviceObject, device_extension),
        ),
        (
            "DEVICE_OBJECT",
            "DeviceType",
            offset_of!(DeviceObject, device_type),
        ),
        (
            "DEVICE_OBJECT",
            "StackSize",
            offset_of!(DeviceObject, stack_size),
        ),
        ("IO_STATUS_BLOCK", "sizeof", size_of::<IoStatusBlock>()),
        (
            "IO_STATUS_BLOCK",
            "Status",
            offset_of!(IoStatusBlock, status),
        ),
        (
            "IO_STATUS_BLOCK",
            "Information",
            offset_of!(IoStatusBlock, information),
        ),
        ("IO_STACK_LOCATION", "sizeof", size_of::<IoStackLocation>()),
        (
            "IO_STACK_LOCATION",
            "MajorFunction",
            offset_of!(IoStackLocation, major_function),
        ),
        (
            "IO_STACK_LOCATION",
            "MinorFunction",
            offset_of!(IoStackLocation, minor_function),
        ),
        (
            "IO_STACK_LOCATION",
            "Flags",
            offset_of!(IoStackLocation, flags),
        ),
        (
            "IO_STACK_LOCATION",
            "Control",
            offset_of!(IoStackLocation, control),
        ),
        (
            "IO_STACK_LOCATION",
            "Parameters.DeviceIoControl.OutputBufferLength",
            params + offset_of!(ParametersDeviceIoControl, output_buffer_length),
        ),
        (
            "IO_STACK_LOCATION",
            "Parameters.DeviceIoControl.InputBufferLength",
            params + offset_of!(ParametersDeviceIoControl, input_buffer_length),
        ),
        (
            "IO_STACK_LOCATION",
            "Parameters.DeviceIoControl.IoControlCode",
            params + offset_of!(ParametersDeviceIoControl, io_control_code),
        ),
        (
            "IO_STACK_LOCATION",
            "Parameters.DeviceIoControl.Type3InputBuffer",
            params + offset_of!(ParametersDeviceIoControl, type3_input_buffer),
        ),
        (
            "IO_STACK_LOCATION",
            "DeviceObject",
            offset_of!(IoStackLocation, device_object),
        ),
        (
            "IO_STACK_LOCATION",
            "FileObject",
            offset_of!(IoStackLocation, file_object),
        ),
        (
            "IO_STACK_LOCATION",
            "CompletionRoutine",
            offset_of!(IoStackLocation, completion_routine),
        ),
        (
            "IO_STACK_LOCATION",
            "Context",
            offset_of!(IoStackLocation, context),
        ),
        ("IRP", "Size", offset_of!(Irp, size)),
        ("IRP", "MdlAddress", offset_of!(Irp, mdl_address)),
        ("IRP", "Flags", offset_of!(Irp, flags)),
        (
            "IRP",
            "AssociatedIrp.SystemBuffer",
            offset_of!(Irp, associated_irp),
        ),
        ("IRP", "IoStatus", offset_of!(Irp, io_status)),
        ("IRP", "RequestorMode", offset_of!(Irp, requestor_mode)),
        ("IRP", "PendingReturned", offset_of!(Irp, pending_returned)),
        ("IRP", "StackCount", offset_of!(Irp, stack_count)),
        ("IRP", "CurrentLocation", offset_of!(Irp, current_location)),
        ("IRP", "UserBuffer", offset_of!(Irp, user_buffer)),
        (
            "IRP",
            "Tail.Overlay.CurrentStackLocation",
            offset_of!(Irp, current_stack_location),
        ),
        ("KEVENT", "sizeof", size_of::<KEvent>()),
        ("KEVENT", "Header.Type", offset_of!(KEvent, header_type)),
        (
            "KEVENT",
            "Header.SignalState",
            offset_of!(KEvent, signal_state),
        ),
        (
            "KEVENT",
            "Header.WaitListHead.Flink",
            offset_of!(KEvent, wait_list_flink),
        ),
        (
            "KEVENT",
            "Header.WaitListHead.Blink",
            offset_of!(KEvent, wait_list_blink),
        ),
    ];
    println!("{{");
    println!("  \"source\": \"nexus-types\",");
    println!("  \"layout\": [");
    for (i, (ty, field, value)) in rows.iter().enumerate() {
        let comma = if i + 1 == rows.len() { "" } else { "," };
        println!("    {{\"type\": \"{ty}\", \"field\": \"{field}\", \"value\": {value}}}{comma}");
    }
    println!("  ]");
    println!("}}");
}
