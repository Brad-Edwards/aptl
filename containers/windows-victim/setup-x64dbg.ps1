# Install x64dbg debugger (portable)
# Run as Administrator
param(
    [string]$DownloadUrl,
    [string]$InstallDir = "C:\Tools\x64dbg"
)

Write-Host "=== Installing x64dbg ==="

$zipPath = "$env:TEMP\x64dbg.zip"

# Resolve download URL from GitHub API if not provided
if (-not $DownloadUrl) {
    Write-Host "Querying GitHub for latest x64dbg release..."
    $releaseInfo = Invoke-RestMethod -Uri "https://api.github.com/repos/x64dbg/x64dbg/releases/latest" -UseBasicParsing
    $asset = $releaseInfo.assets | Where-Object { $_.name -like "snapshot_*.zip" } | Select-Object -First 1
    if (-not $asset) {
        Write-Host "ERROR: Could not find snapshot zip in latest release"
        exit 1
    }
    $DownloadUrl = $asset.browser_download_url
    Write-Host "Found: $($asset.name)"
}

# Download x64dbg
Write-Host "Downloading x64dbg from $DownloadUrl..."
Invoke-WebRequest -Uri $DownloadUrl -OutFile $zipPath -UseBasicParsing

# Extract to install directory
Write-Host "Extracting x64dbg to $InstallDir..."
if (-not (Test-Path (Split-Path $InstallDir -Parent))) {
    New-Item -ItemType Directory -Path (Split-Path $InstallDir -Parent) -Force | Out-Null
}
Expand-Archive -Path $zipPath -DestinationPath $InstallDir -Force

# Add both x32 and x64 directories to system PATH
$x64Dir = "$InstallDir\release\x64"
$x32Dir = "$InstallDir\release\x32"
$currentPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
$pathsToAdd = @()
if ($currentPath -notlike "*$x64Dir*") { $pathsToAdd += $x64Dir }
if ($currentPath -notlike "*$x32Dir*") { $pathsToAdd += $x32Dir }
if ($pathsToAdd.Count -gt 0) {
    $newPath = $currentPath + ";" + ($pathsToAdd -join ";")
    [System.Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
    $env:Path = "$env:Path;" + ($pathsToAdd -join ";")
}

# Create desktop shortcuts
$desktopPath = [System.Environment]::GetFolderPath("CommonDesktopDirectory")
$shell = New-Object -ComObject WScript.Shell

$shortcut64 = $shell.CreateShortcut("$desktopPath\x64dbg.lnk")
$shortcut64.TargetPath = "$x64Dir\x64dbg.exe"
$shortcut64.WorkingDirectory = $x64Dir
$shortcut64.Description = "x64dbg - 64-bit debugger"
$shortcut64.Save()

$shortcut32 = $shell.CreateShortcut("$desktopPath\x32dbg.lnk")
$shortcut32.TargetPath = "$x32Dir\x32dbg.exe"
$shortcut32.WorkingDirectory = $x32Dir
$shortcut32.Description = "x32dbg - 32-bit debugger"
$shortcut32.Save()

# Verify installation
if (Test-Path "$x64Dir\x64dbg.exe") {
    Write-Host "x64dbg.exe found at $x64Dir"
} else {
    Write-Host "WARNING: x64dbg.exe not found at $x64Dir"
}

if (Test-Path "$x32Dir\x32dbg.exe") {
    Write-Host "x32dbg.exe found at $x32Dir"
} else {
    Write-Host "WARNING: x32dbg.exe not found at $x32Dir"
}

# Clean up
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

Write-Host "=== x64dbg installation complete ==="
