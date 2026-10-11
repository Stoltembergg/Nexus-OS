//! Loads each `.sys` given on the command line with the Nexus NT driver host and prints
//! one JSON object per file. Used by `scripts/wdk-abi.py`.
//!
//! - default: **load** only (map, relocate, resolve imports); nothing is executed.
//! - `--run`: additionally apply W^X, call `DriverEntry`, send `IRP_MJ_CREATE` and
//!   `IRP_MJ_CLOSE` (with a real `IO_STACK_LOCATION`) to every device the driver created,
//!   then `DriverUnload`, and require: `STATUS_SUCCESS` everywhere, no bugcheck, every
//!   device deleted and the pool balanced (the checks of `LoadedDriver::unload`). This is
//!   only meaningful because PR-6 aligned the Nexus NT structs with the WDK x64 layout.
//! - `--exports`: print the `NTOSKRNL.EXE` exports Nexus provides (one JSON object), so
//!   the script can check each one is a real export of the official `ntoskrnl.lib`.
//!
//! Usage: `cargo run -q -p nexus-loader --example probe_load -- [--run] a.sys b.sys`
//!        `cargo run -q -p nexus-loader --example probe_load -- --exports`

use nexus_loader::driver::{bugcheck_count, last_bugcheck, BUGCHECK_HANDLER};
use nexus_loader::{NtDriverHost, PeImage};
use nexus_types::driver::{
    IoStackLocation, Irp, UnicodeString, IRP_MJ_CLOSE, IRP_MJ_CREATE, STATUS_SUCCESS,
};

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Records the bugcheck (the stub then aborts the offending call) instead of panicking,
/// so a misbehaving driver is reported rather than killing the probe.
fn record_bugcheck(_code: u32, _params: [usize; 4]) {}

/// Runs the driver lifecycle. `Err` describes the first failure.
fn run_lifecycle(driver: &mut nexus_loader::LoadedDriver) -> Result<usize, String> {
    driver
        .apply_platform_protection()
        .map_err(|e| format!("W^X protection failed: {e:?}"))?;
    let checks = bugcheck_count();
    let (reg, _backing) = UnicodeString::from_str_vec("\\Registry\\Machine\\System\\WdkProbe");
    let status = unsafe { driver.init(&reg) };
    if status != STATUS_SUCCESS {
        return Err(format!("DriverEntry returned {:#010x}", status as u32));
    }
    let mut devices = 0usize;
    let mut dev = driver.driver_object.device_object;
    while !dev.is_null() {
        devices += 1;
        for major in [IRP_MJ_CREATE, IRP_MJ_CLOSE] {
            if driver.driver_object.major_function[major].is_none() {
                continue;
            }
            let mut stack = IoStackLocation {
                major_function: major as u8,
                device_object: dev,
                ..Default::default()
            };
            let mut irp = Irp {
                current_stack_location: &mut stack,
                ..Default::default()
            };
            let status = unsafe { driver.dispatch(major, dev, &mut irp) };
            if status != STATUS_SUCCESS || irp.io_status.status != STATUS_SUCCESS {
                return Err(format!(
                    "IRP major {major:#x} returned {:#010x} (IoStatus {:#010x})",
                    status as u32, irp.io_status.status as u32
                ));
            }
        }
        dev = unsafe { (*dev).next_device };
    }
    unsafe { driver.unload() }.map_err(|e| format!("DriverUnload: {e:?}"))?;
    if bugcheck_count() != checks {
        return Err(format!(
            "bugcheck {:#x} during the lifecycle",
            last_bugcheck()
        ));
    }
    Ok(devices)
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let host = NtDriverHost::new();
    if args.first().map(String::as_str) == Some("--exports") {
        let names: Vec<String> = host
            .kernel_table()
            .export_names()
            .filter(|(dll, _)| *dll == "NTOSKRNL.EXE")
            .map(|(_, f)| json_str(f))
            .collect();
        println!("{{\"exports\": [{}]}}", names.join(", "));
        return;
    }
    let run = args.first().map(String::as_str) == Some("--run");
    if run {
        args.remove(0);
        BUGCHECK_HANDLER.store(
            record_bugcheck as *mut (),
            core::sync::atomic::Ordering::SeqCst,
        );
    }
    if args.is_empty() {
        eprintln!("usage: probe_load [--run] <driver.sys>... | probe_load --exports");
        std::process::exit(2);
    }
    for file in args {
        let bytes = match std::fs::read(&file) {
            Ok(b) => b,
            Err(e) => {
                println!(
                    "{{\"file\": {}, \"load\": \"error\", \"error\": {}}}",
                    json_str(&file),
                    json_str(&format!("read failed: {e}"))
                );
                continue;
            }
        };
        let imports = PeImage::parse(&bytes)
            .ok()
            .and_then(|pe| pe.parse_imports(&bytes).ok())
            .map(|list| {
                list.iter()
                    .flat_map(|dll| {
                        dll.functions
                            .iter()
                            .map(move |f| json_str(&format!("{}!{}", dll.dll_name, f.name)))
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        match host.load_driver(&bytes, "\\Driver\\WdkProbe", "\\Registry\\WdkProbe") {
            Ok(mut driver) => {
                let run_json = if run {
                    match run_lifecycle(&mut driver) {
                        Ok(devices) => format!(", \"run\": \"ok\", \"devices\": {devices}"),
                        Err(e) => format!(", \"run\": \"error\", \"run_error\": {}", json_str(&e)),
                    }
                } else {
                    String::new()
                };
                println!(
                    "{{\"file\": {}, \"load\": \"ok\", \"executed\": {run}{run_json}, \"imports\": [{}]}}",
                    json_str(&file),
                    imports
                );
            }
            Err(e) => println!(
                "{{\"file\": {}, \"load\": \"error\", \"error\": {}, \"imports\": [{}]}}",
                json_str(&file),
                json_str(&format!("{e:?}")),
                imports
            ),
        }
    }
}
