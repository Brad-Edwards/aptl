# Windows VM Setup Script for RDP and SSH
# This script configures a Windows VM for remote access via RDP and SSH

# Enable PowerShell execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force

# Enable RDP
Write-Host "Enabling Remote Desktop..."
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1

# Configure Windows Firewall for RDP
Write-Host "Configuring Windows Firewall for RDP..."
New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow

# Install OpenSSH Server
Write-Host "Installing OpenSSH Server..."
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start and configure SSH service
Write-Host "Configuring SSH service..."
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# Configure SSH to allow password authentication
$sshd_config = "C:\ProgramData\ssh\sshd_config"
if (Test-Path $sshd_config) {
    Write-Host "Configuring SSH authentication..."
    (Get-Content $sshd_config) -replace '#PasswordAuthentication yes', 'PasswordAuthentication yes' | Set-Content $sshd_config
    (Get-Content $sshd_config) -replace '#PubkeyAuthentication yes', 'PubkeyAuthentication yes' | Set-Content $sshd_config
    
    # Restart SSH service to apply changes
    Restart-Service sshd
}

# Configure Windows Firewall for SSH
Write-Host "Configuring Windows Firewall for SSH..."
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

# Create user if specified
if ($env:VM_USER -and $env:VM_PASSWORD) {
    Write-Host "Creating user account: $env:VM_USER"
    $securePassword = ConvertTo-SecureString $env:VM_PASSWORD -AsPlainText -Force
    New-LocalUser -Name $env:VM_USER -Password $securePassword -FullName $env:VM_USER -Description "VM User Account"
    Add-LocalGroupMember -Group "Administrators" -Member $env:VM_USER
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $env:VM_USER
}

# Disable IE Enhanced Security Configuration
Write-Host "Disabling IE Enhanced Security Configuration..."
$AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force

# Disable Windows Defender Real-time protection (for lab environment)
Write-Host "Configuring Windows Defender for lab use..."
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableIntrusionPreventionSystem $true

# Enable Windows Remote Management (WinRM) for PowerShell remoting
Write-Host "Configuring WinRM..."
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
Restart-Service WinRM

# Configure network profile to Private (helps with firewall rules)
Write-Host "Setting network profile to Private..."
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private

# Install Chocolatey for easier software management
Write-Host "Installing Chocolatey..."
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install useful tools via Chocolatey
Write-Host "Installing useful tools..."
choco install -y googlechrome
choco install -y 7zip
choco install -y notepadplusplus
choco install -y putty
choco install -y winscp

Write-Host "Windows VM setup completed successfully!"
Write-Host "RDP is enabled on port 3389"
Write-Host "SSH is enabled on port 22"
Write-Host "Please reboot the VM to ensure all changes take effect."