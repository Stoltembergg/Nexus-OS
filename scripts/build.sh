#!/usr/bin/env bash
set -euo pipefail

echo "[*] Building Nexus OS Workspace..."
cargo build --workspace --all-targets "$@"

echo "[*] Running Workspace Tests..."
cargo test --workspace

echo "[*] Running Phase 0 PoC..."
cargo run -p nexus-poc

echo "[+] Nexus OS build and tests completed successfully!"
