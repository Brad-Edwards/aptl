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

Write-Host "Windows RE box setup complete!"
</powershell>
