# Install Windows Driver Kit for kernel driver analysis
# Run as Administrator
# Requires: VS Build Tools must be installed first (run setup-vs-buildtools.ps1)
param(
    [string]$WdkUrl = "https://go.microsoft.com/fwlink/?linkid=2272234",
    [string]$VsExtUrl = "https://go.microsoft.com/fwlink/?linkid=2272317",
    [string]$BuildToolsPath = "C:\BuildTools",
    [int]$TimeoutSeconds = 600
)

Write-Host "=== Installing Windows Driver Kit ==="

# Pre-flight check: VS Build Tools must be installed
if (-not (Test-Path "$BuildToolsPath\VC\Tools\MSVC\")) {
    Write-Host "ERROR: VS Build Tools not found at $BuildToolsPath"
    Write-Host "Run setup-vs-buildtools.ps1 first"
    exit 1
}
Write-Host "VS Build Tools found at $BuildToolsPath"

$wdkInstallerPath = "$env:TEMP\wdksetup.exe"
$vsExtPath = "$env:TEMP\wdk-vsext.vsix"

# Download WDK installer
Write-Host "Downloading WDK installer..."
Invoke-WebRequest -Uri $WdkUrl -OutFile $wdkInstallerPath

# Install WDK
Write-Host "Installing WDK..."
$process = Start-Process -FilePath $wdkInstallerPath -ArgumentList "/q", "/norestart" -Wait -PassThru -NoNewWindow
if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) {
    Write-Host "ERROR: WDK installation failed with exit code $($process.ExitCode)"
    exit 1
}

# Download and install WDK VS extension
Write-Host "Downloading WDK Visual Studio extension..."
Invoke-WebRequest -Uri $VsExtUrl -OutFile $vsExtPath

Write-Host "Installing WDK VS extension..."
$vsixInstaller = "$BuildToolsPath\Common7\IDE\VSIXInstaller.exe"
if (Test-Path $vsixInstaller) {
    $extProcess = Start-Process -FilePath $vsixInstaller -ArgumentList "/q", $vsExtPath -Wait -PassThru -NoNewWindow
    if ($extProcess.ExitCode -ne 0) {
        Write-Host "WARNING: WDK VS extension install returned exit code $($extProcess.ExitCode)"
    }
} else {
    Write-Host "WARNING: VSIXInstaller.exe not found at $vsixInstaller, skipping extension install"
}

# Verify installation
$wdkInclude = "C:\Program Files (x86)\Windows Kits\10\Include\"
$wdkLib = "C:\Program Files (x86)\Windows Kits\10\Lib\"
if ((Test-Path $wdkInclude) -and (Test-Path $wdkLib)) {
    Write-Host "WDK Include and Lib directories found"
} else {
    Write-Host "WARNING: WDK directories not found at expected paths"
    if (-not (Test-Path $wdkInclude)) { Write-Host "  Missing: $wdkInclude" }
    if (-not (Test-Path $wdkLib)) { Write-Host "  Missing: $wdkLib" }
}

# Clean up
Remove-Item $wdkInstallerPath, $vsExtPath -Force -ErrorAction SilentlyContinue

Write-Host "=== WDK installation complete ==="
if ($process.ExitCode -eq 3010) {
    Write-Host "NOTE: A reboot may be required to complete installation"
}
