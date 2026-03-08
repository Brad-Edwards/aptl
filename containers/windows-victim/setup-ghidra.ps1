# Install Ghidra decompiler/disassembler with AdoptOpenJDK
# Run as Administrator
param(
    [string]$GhidraVersion = "11.3.1",
    [string]$InstallDir = "C:\Tools\Ghidra",
    [string]$JdkUrl = "https://api.adoptium.net/v3/installer/latest/17/ga/windows/x64/jdk/hotspot/normal/eclipse"
)

Write-Host "=== Installing Ghidra $GhidraVersion ==="

# Install AdoptOpenJDK 17 (LTS)
# The Adoptium API redirects to the actual MSI; use -UseBasicParsing and ensure .msi extension
Write-Host "Downloading AdoptOpenJDK 17..."
$jdkMsi = "$env:TEMP\adoptium-jdk17.msi"
# Resolve redirect to get direct download URL
$response = Invoke-WebRequest -Uri $JdkUrl -UseBasicParsing -MaximumRedirection 0 -ErrorAction SilentlyContinue
if ($response.StatusCode -eq 307 -or $response.StatusCode -eq 302) {
    $directUrl = $response.Headers.Location
    Write-Host "Resolved JDK URL: $directUrl"
    Invoke-WebRequest -Uri $directUrl -OutFile $jdkMsi -UseBasicParsing
} else {
    Invoke-WebRequest -Uri $JdkUrl -OutFile $jdkMsi -UseBasicParsing
}

Write-Host "Installing AdoptOpenJDK 17..."
# Adoptium MSI features: FeatureMain, FeatureEnvironment (PATH), FeatureJavaHome (JAVA_HOME)
$msiArgs = '/i "' + $jdkMsi + '" /qn /norestart ADDLOCAL=FeatureMain,FeatureEnvironment,FeatureJavaHome'
$jdkProcess = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
if ($jdkProcess.ExitCode -ne 0) {
    Write-Host "ERROR: JDK installation failed with exit code $($jdkProcess.ExitCode)"
    exit 1
}

# Refresh PATH for this session
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

# Verify Java
$javaVersion = & java --version 2>&1 | Select-Object -First 1
if ($javaVersion) {
    Write-Host "Java installed: $javaVersion"
} else {
    Write-Host "WARNING: java --version did not return expected output"
}

# Download Ghidra
$ghidraZipName = "ghidra_${GhidraVersion}_PUBLIC_20250219.zip"
$ghidraUrl = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GhidraVersion}_build/$ghidraZipName"
$ghidraZip = "$env:TEMP\ghidra.zip"

Write-Host "Downloading Ghidra $GhidraVersion..."
Invoke-WebRequest -Uri $ghidraUrl -OutFile $ghidraZip

# Extract Ghidra
Write-Host "Extracting Ghidra to $InstallDir..."
$extractDir = "$env:TEMP\ghidra_extract"
Expand-Archive -Path $ghidraZip -DestinationPath $extractDir -Force

# Move the extracted folder to the install directory
$extractedFolder = Get-ChildItem -Path $extractDir -Directory | Select-Object -First 1
if (-not (Test-Path (Split-Path $InstallDir -Parent))) {
    New-Item -ItemType Directory -Path (Split-Path $InstallDir -Parent) -Force | Out-Null
}
if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
Move-Item -Path $extractedFolder.FullName -Destination $InstallDir

# Add Ghidra to system PATH
$currentPath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
if ($currentPath -notlike "*$InstallDir*") {
    [System.Environment]::SetEnvironmentVariable("Path", "$currentPath;$InstallDir", "Machine")
    $env:Path = "$env:Path;$InstallDir"
}

# Create desktop shortcut
$desktopPath = [System.Environment]::GetFolderPath("CommonDesktopDirectory")
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut("$desktopPath\Ghidra.lnk")
$shortcut.TargetPath = "$InstallDir\ghidraRun.bat"
$shortcut.WorkingDirectory = $InstallDir
$shortcut.Description = "Ghidra $GhidraVersion"
$shortcut.Save()

# Verify installation
if (Test-Path "$InstallDir\ghidraRun.bat") {
    Write-Host "Ghidra installed at $InstallDir"
} else {
    Write-Host "WARNING: ghidraRun.bat not found in $InstallDir"
}

# Clean up
Remove-Item $jdkMsi, $ghidraZip -Force -ErrorAction SilentlyContinue
Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "=== Ghidra installation complete ==="
