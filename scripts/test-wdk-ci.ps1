# Orchestrate the existing ABI and QEMU validators; all output is CI evidence.
param(
    [Parameter(Mandatory)][string]$WdkRoot,
    [Parameter(Mandatory)][string]$SdkRoot
)
$ErrorActionPreference = 'Stop'
$evidence = Join-Path (Get-Location) 'build/wdk-ci'
New-Item -ItemType Directory -Force $evidence | Out-Null
$common = @('scripts/wdk-abi.py', '--wdk-root', (Resolve-Path $WdkRoot).Path,
    '--sdk-root', (Resolve-Path $SdkRoot).Path, '--enforce', '--check-reproducible')

function Invoke-Abi([string]$Name, [string]$Compiler, [string[]]$Extra, [string]$ExpectedProblem = '') {
    $out = Join-Path $evidence $Name
    & python @common --cc $Compiler --out $out @Extra 2>&1 | Tee-Object (Join-Path $evidence "$Name.log") | Out-Host
    $code = $LASTEXITCODE
    $report = Get-Content (Join-Path $out 'wdk-abi.json') -Raw | ConvertFrom-Json
    if ($ExpectedProblem) {
        if ($code -ne 1 -or @($report.problems).Count -ne 1 -or $report.problems[0] -notlike $ExpectedProblem) {
            throw "$Name did not fail exclusively for the expected control: $ExpectedProblem"
        }
    } elseif ($code -ne 0 -or @($report.problems).Count -ne 0) {
        throw "$Name ABI enforcement failed (exit $code)"
    }
    if (@($report.abi).Count -ne 62 -or @($report.drivers).Count -ne 3 -or
        @($report.drivers | Where-Object { -not $_.compiled -or -not $_.linked -or -not $_.reproducible }).Count -ne 0) {
        throw "$Name missing full ABI/compilation/reproducibility evidence"
    }
    return $report
}

$msvc = Invoke-Abi 'msvc' 'cl' @()
Invoke-Abi 'negative-layout' 'cl' @('--inject-layout-error', 'KEVENT.Header.WaitListHead.Flink') `
    'ABI KEVENT.Header.WaitListHead.Flink: WDK 0x8 != Nexus 0x10' | Out-Null
$negative = Invoke-Abi 'negative-import' 'cl' @('--inject-import-error') `
    '*: Nexus load failed (*UnresolvedImport*NexusMissingExport*)'
$corrupt = @($negative.drivers | Where-Object { $_.injected_import -eq 'NexusMissingExport' })
if ($corrupt.Count -ne 1 -or $corrupt[0].nexus_load -ne 'error' -or $corrupt[0].nexus_run -eq 'ok') {
    throw 'Missing-import negative control was not rejected before DriverEntry'
}
Invoke-Abi 'clang-fixtures' 'clang-cl' @('--check-fixtures') | Out-Null

# Guest embeds these files at compile time. Back up and restore even on failure;
# the MSVC hashes must match the positively executed host report.
$backup = Join-Path $evidence 'committed-fixtures'
New-Item -ItemType Directory -Force $backup | Out-Null
$embedded = @()
try {
    foreach ($driver in $msvc.drivers) {
        Copy-Item -LiteralPath $driver.fixture -Destination (Join-Path $backup "$($driver.driver).sys")
        Copy-Item -LiteralPath $driver.path -Destination $driver.fixture
        $hash = (Get-FileHash -LiteralPath $driver.fixture -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($hash -ne $driver.sha256) { throw 'Guest driver hash differs from MSVC report' }
        $embedded += @{ driver = $driver.driver; fixture = $driver.fixture; sha256 = $hash }
    }
    $embedded | ConvertTo-Json | Set-Content (Join-Path $evidence 'guest-msvc-drivers.json')
    & python scripts/build-fixtures.py 2>&1 | Tee-Object (Join-Path $evidence 'external-fixtures.log')
    if ($LASTEXITCODE -ne 0) { throw 'External PE/ELF compilation failed' }
    & python scripts/test-hardening.py --ram 256 --cpu max --timeout 120 2>&1 |
        Tee-Object (Join-Path $evidence 'guest-msvc.log')
    if ($LASTEXITCODE -ne 0) { throw 'MSVC drivers failed real QEMU/OVMF execution' }
} finally {
    foreach ($driver in $msvc.drivers) {
        $saved = Join-Path $backup "$($driver.driver).sys"
        if (Test-Path -LiteralPath $saved) { Copy-Item -LiteralPath $saved -Destination $driver.fixture }
    }
}
