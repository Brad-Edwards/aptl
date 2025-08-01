<powershell>
# SPDX-License-Identifier: BUSL-1.1
# Capcom.sys CTF Victim Configuration

# Log output to file
Start-Transcript -Path "C:\user-data.log" -Append

Write-Host "====================================="
Write-Host "Starting Capcom CTF victim initialization..."
Write-Host "CTF: Capcom.sys Driver Exploitation"
Write-Host "Current time: $(Get-Date)"
Write-Host "====================================="

# Set Administrator password
$AdminPassword = ConvertTo-SecureString "${admin_password}" -AsPlainText -Force
Set-LocalUser -Name "Administrator" -Password $AdminPassword
Write-Host "Administrator password set"

# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Write-Host "RDP enabled"

# Create CTF user with limited privileges
$CTFUserPassword = ConvertTo-SecureString "${ctf_player_password}" -AsPlainText -Force
New-LocalUser -Name "ctfplayer" -Password $CTFUserPassword -Description "CTF Player Account" -PasswordNeverExpires
Add-LocalGroupMember -Group "Users" -Member "ctfplayer"
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "ctfplayer"
Write-Host "Created CTF player account: ctfplayer"

# Create CTF directories
New-Item -Path "C:\CTF" -ItemType Directory -Force
New-Item -Path "C:\CTF\Tools" -ItemType Directory -Force
New-Item -Path "C:\CTF\Hints" -ItemType Directory -Force

# Create CTF welcome message
$WelcomeMessage = @"
============================================
APTL Capcom.sys CTF Challenge
============================================

Welcome to the Capcom Driver Exploitation CTF!

Your mission:
1. You have access as 'ctfplayer' (limited user)
2. Exploit the vulnerable Capcom.sys driver
3. Escalate privileges to SYSTEM
4. Read the flag at C:\Windows\System32\flag.txt

Hints are available in C:\CTF\Hints\

Good luck!
============================================
"@

Set-Content -Path "C:\CTF\README.txt" -Value $WelcomeMessage

# Create hint file
$HintContent = @"
Hint 1: Check what drivers are loaded on the system
Hint 2: Research CVE-2016-7255
Hint 3: The driver allows arbitrary code execution in kernel mode
Hint 4: Tools for exploitation might be in C:\CTF\Tools\
"@

Set-Content -Path "C:\CTF\Hints\hints.txt" -Value $HintContent

# Note: Actual Capcom.sys installation and flag creation would be done
# in the next phase when you're ready to set up the full CTF

# Create a completion marker
New-Item -Path "C:\user-data-complete.txt" -ItemType File -Force
Set-Content -Path "C:\user-data-complete.txt" -Value "Capcom CTF victim initialization completed at $(Get-Date)"

Write-Host "====================================="
Write-Host "Capcom CTF victim initialization complete!"
Write-Host "CTF Player: ctfplayer / ${ctf_player_password}"
Write-Host "Administrator: Administrator / ${admin_password}"
Write-Host "====================================="

Stop-Transcript
</powershell>