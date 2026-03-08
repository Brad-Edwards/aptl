# Install Visual Studio 2022 Build Tools with C++ workload
# Run as Administrator
param(
    [string]$InstallerUrl = "https://aka.ms/vs/17/release/vs_BuildTools.exe",
    [string]$InstallPath = "C:\BuildTools",
    [int]$TimeoutSeconds = 1800
)

Write-Host "=== Installing Visual Studio 2022 Build Tools ==="
Write-Host "Install path: $InstallPath"
Write-Host "Timeout: $TimeoutSeconds seconds"

$installerPath = "$env:TEMP\vs_BuildTools.exe"

# Download installer
Write-Host "Downloading VS Build Tools installer..."
Invoke-WebRequest -Uri $InstallerUrl -OutFile $installerPath

# Install with C++ workload, Windows 11 SDK, and Spectre-mitigated libraries
Write-Host "Installing VS Build Tools (this may take 20-30 minutes)..."
$installArgs = @(
    "--installPath", $InstallPath,
    "--add", "Microsoft.VisualStudio.Workload.VCTools",
    "--add", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
    "--add", "Microsoft.VisualStudio.Component.Windows11SDK.22621",
    "--add", "Microsoft.VisualStudio.Component.VC.ASAN",
    "--add", "Microsoft.VisualStudio.Component.VC.Runtimes.x86.x64.Spectre",
    "--includeRecommended",
    "--quiet", "--wait", "--norestart", "--nocache"
)
$process = Start-Process -FilePath $installerPath -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) {
    Write-Host "ERROR: VS Build Tools installation failed with exit code $($process.ExitCode)"
    exit 1
}

# Verify installation
$msvcPath = "$InstallPath\VC\Tools\MSVC\"
if (Test-Path $msvcPath) {
    Write-Host "MSVC tools found at $msvcPath"
} else {
    Write-Host "WARNING: MSVC tools directory not found at $msvcPath"
}

$spectrePaths = Get-ChildItem -Path "$InstallPath\VC\Tools\MSVC\*\lib\spectre\" -ErrorAction SilentlyContinue
if ($spectrePaths) {
    Write-Host "Spectre-mitigated libraries found"
} else {
    Write-Host "WARNING: Spectre-mitigated libraries not found"
}

# Clean up
Remove-Item $installerPath -Force -ErrorAction SilentlyContinue

Write-Host "=== VS Build Tools installation complete ==="
if ($process.ExitCode -eq 3010) {
    Write-Host "NOTE: A reboot may be required to complete installation"
}
