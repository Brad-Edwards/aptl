# Install Wazuh Agent on Windows 11
# Run as Administrator
param(
    [string]$WazuhManagerIP = "172.20.0.10"
)

Write-Host "=== Installing Wazuh Agent ==="
Write-Host "Manager IP: $WazuhManagerIP"

$installerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi"
$installerPath = "$env:TEMP\wazuh-agent.msi"

# Download installer
Write-Host "Downloading Wazuh agent..."
Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath

# Install with manager IP
Write-Host "Installing Wazuh agent..."
Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /q WAZUH_MANAGER=`"$WazuhManagerIP`" WAZUH_AGENT_NAME=`"win11-endpoint`"" -Wait

# Start the service
Start-Service WazuhSvc
Set-Service -Name WazuhSvc -StartupType Automatic

# Clean up
Remove-Item $installerPath -Force

Write-Host "=== Wazuh Agent installed and started ==="
Write-Host "Agent will register with manager at $WazuhManagerIP"
