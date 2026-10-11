# Phase 3.5: external binaries and real guest assertions + QEMU exit.
param(
    [string]$QemuPath = "C:\Program Files\qemu\qemu-system-x86_64.exe",
    [string]$OvmfPath = "C:\Program Files\qemu\share\edk2-x86_64-code.fd",
    [int]$TimeoutSeconds = 60,
    [int]$MemoryMB = 128,
    [string]$Cpu = "qemu64",
    [string]$ZigPath = "",
    [switch]$Release
)
$ErrorActionPreference = "Stop"
$WorkspaceRoot = (Get-Item $PSScriptRoot).Parent.FullName
Push-Location $WorkspaceRoot
try {
    if (!$ZigPath -and (Test-Path "build/tools/zig-windows-x86_64-0.13.0/zig.exe")) {
        $ZigPath = "build/tools/zig-windows-x86_64-0.13.0/zig.exe"
    }
    $fixtureArgs = @("scripts/build-fixtures.py")
    if ($ZigPath) { $fixtureArgs += @("--zig", $ZigPath) }
    python @fixtureArgs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $testArgs = @("scripts/test-hardening.py", "--qemu", $QemuPath, "--ovmf", $OvmfPath,
        "--timeout", $TimeoutSeconds, "--ram", $MemoryMB, "--cpu", $Cpu)
    if ($Release) { $testArgs += "--release" }
    python @testArgs
    exit $LASTEXITCODE
} finally { Pop-Location }
