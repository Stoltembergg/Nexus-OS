# Nexus OS - Test & Verification Helper Script (PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "[1/3] Checking workspace compilation..." -ForegroundColor Cyan
cargo check --workspace --all-targets

Write-Host "[2/3] Running automated unit and integration tests..." -ForegroundColor Cyan
cargo test --workspace --verbose

Write-Host "[3/3] Running Phase 0 PoC binary..." -ForegroundColor Cyan
cargo run -p nexus-poc

Write-Host "`n[+] All tests and verifications PASSED!" -ForegroundColor Green
