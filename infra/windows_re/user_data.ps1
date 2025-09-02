<powershell>
# Set administrator password
net user Administrator "${admin_password}"
net user Administrator /active:yes

# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Install common tools for exploit dev
choco install -y git
choco install -y vscode
choco install -y python3
choco install -y visualstudio2022community
choco install -y x64dbg
choco install -y ghidra
choco install -y wireshark
choco install -y 7zip
choco install -y firefox

# Install Windows SDK
choco install -y windows-sdk-10-version-2004-all

# Create desktop shortcuts
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\x64dbg.lnk")
$Shortcut.TargetPath = "C:\tools\x64dbg\x64dbg.exe"
$Shortcut.Save()

# Disable Windows Defender real-time protection for exploit dev
Set-MpPreference -DisableRealtimeMonitoring $true

# Configure Windows for exploit development
# Disable ASLR for easier debugging
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "MoveImages" -Value 0

# Disable DEP for test binaries (can be re-enabled per application)
bcdedit /set {current} nx OptOut

# Enable WinRM for remote PowerShell access
Enable-PSRemoting -Force
Set-WSManQuickConfig -Force

# Configure WinRM for remote access
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/client '@{AllowUnencrypted="true"}'
winrm set winrm/config/client/auth '@{Basic="true"}'

# Enable Windows Remote Management service
Set-Service -Name WinRM -StartupType Automatic
Start-Service WinRM

# Install OpenSSH Server (may already be installed on Server 2025)
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 -ErrorAction SilentlyContinue

# Start and enable SSH service
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# Configure SSH firewall rule
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH SSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

# Configure SSH for key-only authentication
$sshdConfigPath = "$env:ProgramData\ssh\sshd_config"
if (Test-Path $sshdConfigPath) {
    # Disable password authentication, enable key auth only
    (Get-Content $sshdConfigPath) -replace '#PasswordAuthentication yes', 'PasswordAuthentication no' | Set-Content $sshdConfigPath
    (Get-Content $sshdConfigPath) -replace '#PubkeyAuthentication yes', 'PubkeyAuthentication yes' | Set-Content $sshdConfigPath
    Add-Content $sshdConfigPath "`nMatch User Administrator`n    AuthorizedKeysFile C:/Users/Administrator/.ssh/authorized_keys"
}

# Create SSH directory and set up authorized_keys
New-Item -ItemType Directory -Force -Path "C:\Users\Administrator\.ssh"
$authorizedKeysPath = "C:\Users\Administrator\.ssh\authorized_keys"

# Get the public key from EC2 metadata and install it
try {
    # Get public key from EC2 instance metadata
    $publicKey = Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key" -TimeoutSec 10
    Set-Content -Path $authorizedKeysPath -Value $publicKey
    
    # Also copy to administrators_authorized_keys (required for Administrator user)
    $adminKeysPath = "$env:ProgramData\ssh\administrators_authorized_keys"
    Copy-Item $authorizedKeysPath $adminKeysPath
    
    # Set proper permissions on user authorized_keys (crucial for Windows SSH)
    icacls $authorizedKeysPath /reset
    icacls $authorizedKeysPath /grant:r "Administrator:F"
    icacls $authorizedKeysPath /inheritance:r
    
    # Set proper permissions on administrators_authorized_keys
    icacls $adminKeysPath /reset
    icacls $adminKeysPath /grant:r "Administrator:F"
    icacls $adminKeysPath /grant:r "BUILTIN\Administrators:F"
    icacls $adminKeysPath /inheritance:r
} catch {
    Write-Host "Warning: Could not set up SSH key - reverting to password auth"
    (Get-Content $sshdConfigPath) -replace 'PasswordAuthentication no', 'PasswordAuthentication yes' | Set-Content $sshdConfigPath
}

# Restart SSH service to apply configuration
Restart-Service sshd

# Install SysInternals Suite for dynamic analysis
New-Item -ItemType Directory -Force -Path C:\Tools
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile "C:\Tools\SysinternalsSuite.zip"
Expand-Archive -Path "C:\Tools\SysinternalsSuite.zip" -DestinationPath "C:\Tools\SysInternals"

# Add SysInternals to PATH
$env:PATH += ";C:\Tools\SysInternals"
[Environment]::SetEnvironmentVariable("PATH", $env:PATH, [EnvironmentVariableTarget]::Machine)

# Enable audit policies for dynamic analysis
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Process Termination" /success:enable

# Create analysis directories
New-Item -ItemType Directory -Force -Path C:\Analysis\Logs
New-Item -ItemType Directory -Force -Path C:\Analysis\Samples
New-Item -ItemType Directory -Force -Path C:\Analysis\Tools

# Create dynamic analysis helper script
@'
# Dynamic Analysis Helper Script
param(
    [string]$DriverPath,
    [string]$LogDir = "C:\Analysis\Logs"
)

Write-Host "Starting dynamic analysis of: $DriverPath"

# Start process monitoring
Start-Process -FilePath "C:\Tools\SysInternals\procmon.exe" -ArgumentList "/minimized", "/backingfile", "$LogDir\procmon.pml"

# Monitor registry for driver installation
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} | Out-File "$LogDir\service_installs.log" -Append

# Monitor for driver loading events
Get-WinEvent -FilterHashtable @{LogName='System'; ID=6} | Out-File "$LogDir\driver_loads.log" -Append

Write-Host "Dynamic analysis monitoring started - logs in $LogDir"
'@ | Out-File -FilePath "C:\Analysis\Tools\start_analysis.ps1" -Encoding UTF8

Write-Host "Windows RE box setup complete with dynamic analysis capabilities!"
</powershell>
