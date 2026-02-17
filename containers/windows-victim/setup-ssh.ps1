# Enable and configure OpenSSH Server on Windows 11
# Run as Administrator

Write-Host "=== Configuring OpenSSH Server ==="

# Install OpenSSH Server feature
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start and enable the service
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic

# Configure SSH
$sshdConfig = "C:\ProgramData\ssh\sshd_config"
$content = Get-Content $sshdConfig
$content = $content -replace '#PubkeyAuthentication yes', 'PubkeyAuthentication yes'
$content = $content -replace '#PasswordAuthentication yes', 'PasswordAuthentication yes'
Set-Content $sshdConfig $content

# Allow SSH through firewall
New-NetFirewallRule -Name "OpenSSH-Server" -DisplayName "OpenSSH Server" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

Restart-Service sshd

Write-Host "=== OpenSSH Server configured ==="
Write-Host "SSH is available on port 22"
