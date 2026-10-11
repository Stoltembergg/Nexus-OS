//! Tries to **load** (map, relocate and resolve imports, without executing anything) each
//! `.sys` given on the command line with the Nexus NT driver host, and prints one JSON
//! object per file. Used by `scripts/wdk-abi.py` to report whether drivers rebuilt with
//! the official WDK can be loaded. `DriverEntry` is deliberately NOT called: drivers
//! built with the real WDK headers use struct layouts that Nexus does not match yet
//! (audit finding C4), so executing them is unsafe until PR-6.
//!
//! Usage: `cargo run -q -p nexus-loader --example probe_load -- a.sys b.sys`

use nexus_loader::{NtDriverHost, PeImage};

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

fn main() {
    let files: Vec<String> = std::env::args().skip(1).collect();
    if files.is_empty() {
        eprintln!("usage: probe_load <driver.sys>...");
        std::process::exit(2);
    }
    let host = NtDriverHost::new();
    for file in files {
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
        let result = host.load_driver(&bytes, "\\Driver\\WdkProbe", "\\Registry\\WdkProbe");
        match result {
            Ok(_) => println!(
                "{{\"file\": {}, \"load\": \"ok\", \"executed\": false, \"imports\": [{}]}}",
                json_str(&file),
                imports
            ),
            Err(e) => println!(
                "{{\"file\": {}, \"load\": \"error\", \"error\": {}, \"imports\": [{}]}}",
                json_str(&file),
                json_str(&format!("{e:?}")),
                imports
            ),
        }
    }
}
