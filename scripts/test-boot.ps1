# Nexus OS - Phase 1 Automated Bare-Metal UEFI Boot Test (PowerShell)
# Runs QEMU with OVMF firmware and verifies bare-metal boot sequence.

param(
    [string]$QemuPath = "C:\Program Files\qemu\qemu-system-x86_64.exe",
    [string]$OvmfPath = "C:\Program Files\qemu\share\edk2-x86_64-code.fd",
    [int]$TimeoutSeconds = 10
)

$ErrorActionPreference = "Stop"
$WorkspaceRoot = (Get-Item $PSScriptRoot).Parent.FullName

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "       Nexus OS - Phase 1 Bare-Metal Boot Verification      " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Build UEFI Bootloader and Kernel
Write-Host "[1/4] Compiling nexus-boot for x86_64-unknown-uefi..." -ForegroundColor Yellow
Push-Location $WorkspaceRoot
try {
    cargo build -p nexus-boot --target x86_64-unknown-uefi
} finally {
    Pop-Location
}

$EfiSource = Join-Path $WorkspaceRoot "target\x86_64-unknown-uefi\debug\bootx64.efi"
if (!(Test-Path $EfiSource)) {
    Write-Error "bootx64.efi not found at $EfiSource"
    exit 1
}

# 2. Stage EFI System Partition (ESP) and Firmware
Write-Host "[2/4] Staging ESP directory structure and OVMF firmware..." -ForegroundColor Yellow
$BuildDir = Join-Path $WorkspaceRoot "build"
$EspDir = Join-Path $BuildDir "esp"
$BootDir = Join-Path $EspDir "EFI\BOOT"
New-Item -ItemType Directory -Path $BootDir -Force | Out-Null
Copy-Item $EfiSource (Join-Path $BootDir "BOOTX64.EFI") -Force

if (!(Test-Path $QemuPath)) {
    Write-Error "QEMU binary not found at $QemuPath"
    exit 1
}
if (!(Test-Path $OvmfPath)) {
    Write-Error "OVMF firmware not found at $OvmfPath"
    exit 1
}

$StagedOvmf = Join-Path $BuildDir "ovmf.fd"
Copy-Item $OvmfPath $StagedOvmf -Force

$LogFile = Join-Path $BuildDir "boot_serial.log"
if (Test-Path $LogFile) {
    Remove-Item $LogFile -Force
}

# 3. Launch QEMU with Serial Port Redirection
Write-Host "[3/4] Launching QEMU with OVMF UEFI firmware..." -ForegroundColor Yellow

$qemuArgs = @(
    "-drive", "if=pflash,format=raw,readonly=on,file=$StagedOvmf",
    "-drive", "file=fat:rw:$EspDir,format=raw",
    "-vga", "std",
    "-display", "none",
    "-serial", "stdio",
    "-no-reboot"
)

$proc = Start-Process -FilePath $QemuPath -ArgumentList $qemuArgs -RedirectStandardOutput $LogFile -PassThru

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$successFound = $false

while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
    Start-Sleep -Milliseconds 500
    if (Test-Path $LogFile) {
        $content = Get-Content $LogFile -Raw -ErrorAction SilentlyContinue
        if ($content -and $content -match "NEXUS_BOOT_SUCCESS") {
            $successFound = $true
            break
        }
    }
}

Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue

# 4. Verify Boot Output
Write-Host "[4/4] Validating Serial Boot Logs..." -ForegroundColor Yellow

if (!(Test-Path $LogFile)) {
    Write-Error "Test Failed: No serial output log was generated."
    exit 1
}

$logContent = Get-Content $LogFile -Raw
Write-Host "`n--- Serial Log Output ---" -ForegroundColor DarkGray
Write-Host $logContent -ForegroundColor Gray
Write-Host "-------------------------`n" -ForegroundColor DarkGray

if ($logContent -match "NEXUS_BOOT_SUCCESS" -and
    $logContent -match "GDT and TSS Configured" -and
    $logContent -match "IDT Initialized" -and
    $logContent -match "GOP Framebuffer Detected" -and
    $logContent -match "PMM Initialized") {
    Write-Host "[+] BARE-METAL BOOT TEST PASSED: All Phase 1 kernel components verified." -ForegroundColor Green
    exit 0
} else {
    Write-Error "Test Failed: Expected boot milestones missing from log."
    exit 1
}
