# Install Sysmon for enhanced Windows telemetry
# Run as Administrator

Write-Host "=== Installing Sysmon ==="

$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonZip = "$env:TEMP\Sysmon.zip"
$sysmonDir = "$env:TEMP\Sysmon"

# SwiftOnSecurity Sysmon config (community standard)
$configUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$configPath = "$env:TEMP\sysmonconfig.xml"

# Download Sysmon
Write-Host "Downloading Sysmon..."
Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip
Expand-Archive -Path $sysmonZip -DestinationPath $sysmonDir -Force

# Download config
Write-Host "Downloading Sysmon config..."
Invoke-WebRequest -Uri $configUrl -OutFile $configPath

# Install Sysmon
Write-Host "Installing Sysmon with SwiftOnSecurity config..."
& "$sysmonDir\Sysmon64.exe" -accepteula -i $configPath

# Verify installation
$sysmonService = Get-Service Sysmon64 -ErrorAction SilentlyContinue
if ($sysmonService -and $sysmonService.Status -eq "Running") {
    Write-Host "=== Sysmon installed and running ==="
} else {
    Write-Host "WARNING: Sysmon may not be running correctly"
}

# Clean up
Remove-Item $sysmonZip, $sysmonDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Sysmon events will be captured by Wazuh agent"
Write-Host "Check Event Viewer > Applications and Services Logs > Microsoft > Windows > Sysmon"
