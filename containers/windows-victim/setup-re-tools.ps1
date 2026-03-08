# Orchestrator: Install all reverse engineering and development tools
# Run as Administrator
# Installs tools in dependency order; each sub-script is independently runnable.
param(
    [switch]$SkipBuildTools,
    [switch]$SkipWdk,
    [switch]$SkipGhidra,
    [switch]$SkipX64dbg,
    [switch]$SkipSysinternals,
    [switch]$SkipPython
)

Write-Host "============================================"
Write-Host "  APTL Windows RE Tools - Full Installation"
Write-Host "============================================"
Write-Host ""
Write-Host "This will install the following tools:"
Write-Host "  1. Visual Studio 2022 Build Tools (C++ workload)"
Write-Host "  2. Windows Driver Kit (WDK)"
Write-Host "  3. Ghidra (with AdoptOpenJDK 17)"
Write-Host "  4. x64dbg debugger"
Write-Host "  5. Sysinternals Suite"
Write-Host "  6. Python 3 with RE libraries"
Write-Host ""
Write-Host "Estimated disk space: ~20-25 GB"
Write-Host "Estimated time: 30-60 minutes"
Write-Host ""

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$results = @{}

function Run-Step {
    param([string]$Name, [string]$Script, [bool]$Skip)
    if ($Skip) {
        Write-Host "--- Skipping $Name ---"
        $results[$Name] = "SKIPPED"
        return
    }
    Write-Host ""
    Write-Host ">>> Starting: $Name"
    Write-Host ""
    try {
        & "$scriptDir\$Script"
        if ($LASTEXITCODE -eq 0 -or $null -eq $LASTEXITCODE) {
            $results[$Name] = "OK"
        } else {
            $results[$Name] = "FAILED (exit code $LASTEXITCODE)"
        }
    } catch {
        $results[$Name] = "FAILED ($_)"
    }
}

# Run in dependency order
Run-Step "VS Build Tools"   "setup-vs-buildtools.ps1" $SkipBuildTools
Run-Step "WDK"              "setup-wdk.ps1"            $SkipWdk
Run-Step "Ghidra"           "setup-ghidra.ps1"         $SkipGhidra
Run-Step "x64dbg"           "setup-x64dbg.ps1"         $SkipX64dbg
Run-Step "Sysinternals"     "setup-sysinternals.ps1"   $SkipSysinternals
Run-Step "Python RE"        "setup-python-re.ps1"      $SkipPython

# Print summary
Write-Host ""
Write-Host "============================================"
Write-Host "  Installation Summary"
Write-Host "============================================"
Write-Host ""
Write-Host ("{0,-20} {1}" -f "Component", "Status")
Write-Host ("{0,-20} {1}" -f "---------", "------")
foreach ($key in @("VS Build Tools", "WDK", "Ghidra", "x64dbg", "Sysinternals", "Python RE")) {
    $status = $results[$key]
    Write-Host ("{0,-20} {1}" -f $key, $status)
}
Write-Host ""

$failed = $results.Values | Where-Object { $_ -like "FAILED*" }
if ($failed.Count -gt 0) {
    Write-Host "WARNING: $($failed.Count) component(s) failed. Check output above for details."
} else {
    Write-Host "All components installed successfully."
}

Write-Host ""
Write-Host "NOTE: A reboot may be required for VS Build Tools and WDK to function correctly."
Write-Host "============================================"
