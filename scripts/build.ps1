# Nexus OS - Build Helper Script (PowerShell)
param (
    [switch]$Release,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

if ($Clean) {
    Write-Host "[*] Cleaning build artifacts..." -ForegroundColor Yellow
    cargo clean
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$buildFlags = @("--workspace", "--all-targets")
if ($Release) {
    $buildFlags += "--release"
}

Write-Host "[*] Compiling Nexus OS workspace..." -ForegroundColor Cyan
cargo build @buildFlags
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "[+] Build completed successfully!" -ForegroundColor Green
