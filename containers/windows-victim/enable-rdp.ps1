# Enable Remote Desktop on Windows 11
# Run as Administrator

Write-Host "=== Enabling Remote Desktop ==="

# Enable RDP
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0

# Allow RDP through firewall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Allow NLA (Network Level Authentication)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1

Write-Host "=== Remote Desktop enabled ==="
Write-Host "Connect via: xfreerdp /v:<ip> /u:<user> /d:TECHVAULT"
