# Install Python 3 and reverse engineering libraries
# Run as Administrator
param(
    [string]$PythonVersion = "3.12.8",
    [string]$PythonUrl = "https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe"
)

Write-Host "=== Installing Python $PythonVersion with RE Libraries ==="

$installerPath = "$env:TEMP\python-installer.exe"

# Download Python installer
Write-Host "Downloading Python $PythonVersion..."
Invoke-WebRequest -Uri $PythonUrl -OutFile $installerPath

# Install Python silently
Write-Host "Installing Python $PythonVersion..."
$process = Start-Process -FilePath $installerPath -ArgumentList "/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_pip=1" -Wait -PassThru
if ($process.ExitCode -ne 0) {
    Write-Host "ERROR: Python installation failed with exit code $($process.ExitCode)"
    exit 1
}

# Refresh PATH for this session
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

# Verify Python
$pythonVer = & python --version 2>&1
Write-Host "Python installed: $pythonVer"

# Install RE packages via pip
$packages = @(
    "pefile",           # PE file parsing
    "yara-python",      # YARA rule matching
    "capstone",         # Disassembly framework
    "unicorn",          # CPU emulator
    "keystone-engine",  # Assembler
    "floss",            # Obfuscated string solver
    "capa"              # Malware capability analysis
)

Write-Host "Installing RE packages..."
foreach ($package in $packages) {
    Write-Host "  Installing $package..."
    & python -m pip install --quiet $package
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  WARNING: Failed to install $package"
    }
}

# Verify installed packages
Write-Host ""
Write-Host "Installed packages:"
& python -m pip list --format=columns 2>&1 | Select-String -Pattern ($packages -join "|")

# Clean up
Remove-Item $installerPath -Force -ErrorAction SilentlyContinue

Write-Host "=== Python RE environment installation complete ==="
