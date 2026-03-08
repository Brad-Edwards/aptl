# Install Sysinternals Suite for dynamic analysis
# Run as Administrator
param(
    [string]$DownloadUrl = "https://download.sysinternals.com/files/SysinternalsSuite.zip",
    [string]$InstallDir = "C:\Tools\Sysinternals"
)

Write-Host "=== Installing Sysinternals Suite ==="

$zipPath = "$env:TEMP\SysinternalsSuite.zip"

# Download Sysinternals Suite
Write-Host "Downloading Sysinternals Suite..."
Invoke-WebRequest -Uri $DownloadUrl -OutFile $zipPath

# Extract to install directory
Write-Host "Extracting Sysinternals to $InstallDir..."
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
Expand-Archive -Path $zipPath -DestinationPath $InstallDir -Force

# Add to system PATH
$currentPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
if ($currentPath -notlike "*$InstallDir*") {
    [System.Environment]::SetEnvironmentVariable("Path", "$currentPath;$InstallDir", "Machine")
    $env:Path = "$env:Path;$InstallDir"
}

# Accept EULA for all Sysinternals tools via registry
Write-Host "Accepting Sysinternals EULA via registry..."
$sysinternalsKey = "HKCU:\Software\Sysinternals"
if (-not (Test-Path $sysinternalsKey)) {
    New-Item -Path $sysinternalsKey -Force | Out-Null
}
$tools = Get-ChildItem -Path $InstallDir -Filter "*.exe" | ForEach-Object { $_.BaseName }
foreach ($tool in $tools) {
    $toolKey = "$sysinternalsKey\$tool"
    if (-not (Test-Path $toolKey)) {
        New-Item -Path $toolKey -Force | Out-Null
    }
    Set-ItemProperty -Path $toolKey -Name "EulaAccepted" -Value 1 -Type DWord
}
Write-Host "EULA accepted for $($tools.Count) tools"

# Verify key tools exist
$requiredTools = @("procmon.exe", "procexp.exe", "autoruns.exe")
$missing = @()
foreach ($tool in $requiredTools) {
    if (-not (Test-Path "$InstallDir\$tool")) {
        $missing += $tool
    }
}

if ($missing.Count -eq 0) {
    Write-Host "All key tools verified: $($requiredTools -join ', ')"
} else {
    Write-Host "WARNING: Missing tools: $($missing -join ', ')"
}

# Clean up
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

Write-Host "=== Sysinternals Suite installation complete ==="
