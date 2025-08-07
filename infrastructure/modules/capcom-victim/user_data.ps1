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

# SIEM Integration Setup
%{ if siem_private_ip != "" ~}
Write-Host "Configuring SIEM integration..."
$SIEM_IP = "${siem_private_ip}"
$SIEM_TYPE = "${siem_type}"

%{ if siem_type == "splunk" ~}
$SIEM_PORT = 5514
%{ else ~}
$SIEM_PORT = 514  
%{ endif ~}

# Create PowerShell syslog forwarding function
$SyslogScript = @"
function Send-SyslogMessage {
    param(
        [string]`$Server,
        [int]`$Port,
        [string]`$Message,
        [string]`$Protocol = "TCP"
    )
    
    try {
        if (`$Protocol -eq "TCP") {
            `$tcpClient = New-Object System.Net.Sockets.TcpClient
            `$tcpClient.Connect(`$Server, `$Port)
            `$stream = `$tcpClient.GetStream()
            `$data = [System.Text.Encoding]::UTF8.GetBytes(`$Message + "`n")
            `$stream.Write(`$data, 0, `$data.Length)
            `$stream.Close()
            `$tcpClient.Close()
        } else {
            `$udpClient = New-Object System.Net.Sockets.UdpClient
            `$data = [System.Text.Encoding]::UTF8.GetBytes(`$Message)
            `$udpClient.Send(`$data, `$data.Length, `$Server, `$Port) | Out-Null
            `$udpClient.Close()
        }
        return `$true
    } catch {
        Write-Error "Failed to send syslog message: `$(`$_.Exception.Message)"
        return `$false
    }
}

function Send-WindowsEventToSIEM {
    param(
        [string]`$EventMessage,
        [string]`$EventLevel = "INFO"
    )
    
    `$timestamp = Get-Date -Format "MMM dd HH:mm:ss"
    `$hostname = `$env:COMPUTERNAME
    
    # Syslog format: <Priority>Timestamp Hostname Tag: Message
    `$priority = 134  # Local0.Info (16*8 + 6)
    `$syslogMsg = "<`$priority>`$timestamp `$hostname CAPCOM_CTF: `$EventMessage"
    
    return Send-SyslogMessage -Server "$SIEM_IP" -Port $SIEM_PORT -Message `$syslogMsg
}
"@

Set-Content -Path "C:\CTF\Scripts\Send-SyslogMessage.ps1" -Value $SyslogScript

Write-Host "SIEM forwarding configured for ${siem_type} at ${siem_private_ip}:$SIEM_PORT"

# Create CTF event generation script
$CTFEventScript = @"
# Load syslog functions
. C:\CTF\Scripts\Send-SyslogMessage.ps1

Write-Host "=== Capcom CTF Event Generator ==="
Write-Host "Generating CTF-specific security events for ${siem_type}..."
Write-Host "SIEM: ${siem_private_ip}:$SIEM_PORT"
Write-Host ""

# CTF Login Events
Write-Host "1. Generating Authentication Events..."
Send-WindowsEventToSIEM "CTF_AUTH: User ctfplayer successful logon from `$((`$env:COMPUTERNAME).ToLower())"
Send-WindowsEventToSIEM "CTF_AUTH: Failed logon attempt for Administrator from unknown source"
Send-WindowsEventToSIEM "CTF_AUTH: Multiple failed logon attempts detected for user admin"

# Driver-related Events
Write-Host "2. Generating Driver Events..."
Send-WindowsEventToSIEM "CTF_DRIVER: Capcom.sys driver loaded successfully"
Send-WindowsEventToSIEM "CTF_DRIVER: Unsigned driver detected - Capcom.sys"
Send-WindowsEventToSIEM "CTF_DRIVER: Test signing mode enabled for driver loading"

# Privilege Escalation Simulation
Write-Host "3. Generating Privilege Escalation Events..."
Send-WindowsEventToSIEM "CTF_PRIVESC: Process creation detected - suspicious execution pattern"
Send-WindowsEventToSIEM "CTF_PRIVESC: Token privileges modified - SeDebugPrivilege enabled"
Send-WindowsEventToSIEM "CTF_PRIVESC: SYSTEM level access achieved via driver exploitation"

# System Integrity Events
Write-Host "4. Generating System Events..."
Send-WindowsEventToSIEM "CTF_SYSTEM: Unusual process spawned from SYSTEM context"
Send-WindowsEventToSIEM "CTF_SYSTEM: Suspicious file access to C:\Windows\System32\flag.txt"
Send-WindowsEventToSIEM "CTF_SYSTEM: CTF flag accessed successfully"

Write-Host ""
Write-Host "✅ CTF events generated successfully!"
%{ if siem_type == "qradar" ~}
Write-Host "📊 Check qRadar Log Activity for CAPCOM_CTF events"
Write-Host "🚨 Expected offenses: Authentication, privilege escalation, driver abuse"
%{ else ~}
Write-Host "📊 Check Splunk Search for CAPCOM_CTF events"  
Write-Host "🚨 Expected alerts: Authentication, privilege escalation, driver abuse"
%{ endif ~}
"@

Set-Content -Path "C:\CTF\Scripts\Generate-CTFEvents.ps1" -Value $CTFEventScript

# Create SIEM connection test script
$TestScript = @"
# Load syslog functions
. C:\CTF\Scripts\Send-SyslogMessage.ps1

Write-Host "=== SIEM Connection Test ==="
Write-Host "Testing connection to ${siem_type} SIEM..."
Write-Host "Target: ${siem_private_ip}:$SIEM_PORT"
Write-Host ""

# Test network connectivity
Write-Host "Testing network connectivity..."
try {
    `$connection = Test-NetConnection -ComputerName "${siem_private_ip}" -Port $SIEM_PORT -InformationLevel Quiet
    if (`$connection) {
        Write-Host "✅ Network: ${siem_type} reachable on port $SIEM_PORT" -ForegroundColor Green
    } else {
        Write-Host "❌ Network: Cannot reach ${siem_type} on port $SIEM_PORT" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Network: Connection test failed - `$(`$_.Exception.Message)" -ForegroundColor Red
}

# Test syslog message sending
Write-Host ""
Write-Host "Testing syslog message delivery..."
`$testResult = Send-WindowsEventToSIEM "SIEM_TEST: Connection test from `$env:COMPUTERNAME at `$(Get-Date)"

if (`$testResult) {
    Write-Host "✅ Syslog: Test message sent successfully" -ForegroundColor Green
%{ if siem_type == "qradar" ~}
    Write-Host "📊 Check qRadar Log Activity for CAPCOM_CTF test message (10-30 seconds)"
%{ else ~}
    Write-Host "📊 Check Splunk Search for CAPCOM_CTF test message (10-30 seconds)"
%{ endif ~}
} else {
    Write-Host "❌ Syslog: Failed to send test message" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== CTF Scripts Available ==="
Write-Host "C:\CTF\Scripts\Generate-CTFEvents.ps1 - Generate CTF security events"
Write-Host "C:\CTF\Scripts\Test-SIEMConnection.ps1 - Test SIEM connectivity"
"@

Set-Content -Path "C:\CTF\Scripts\Test-SIEMConnection.ps1" -Value $TestScript

Write-Host "SIEM forwarding configured for ${siem_type} at ${siem_private_ip}:$SIEM_PORT"
%{ else ~}
Write-Host "SIEM not enabled - skipping event forwarding configuration"

# Create basic event generation script for local testing
$LocalEventScript = @"
Write-Host "=== Local CTF Event Generator ==="
Write-Host "SIEM disabled - generating events locally..."
Write-Host ""

# Use Windows Event Log for local events
Write-EventLog -LogName Application -Source "Capcom_CTF" -EventID 1001 -Message "CTF_AUTH: User ctfplayer logon simulation" -EntryType Information -ErrorAction SilentlyContinue
Write-EventLog -LogName Application -Source "Capcom_CTF" -EventID 1002 -Message "CTF_DRIVER: Capcom.sys driver simulation" -EntryType Warning -ErrorAction SilentlyContinue  
Write-EventLog -LogName Application -Source "Capcom_CTF" -EventID 1003 -Message "CTF_PRIVESC: Privilege escalation simulation" -EntryType Warning -ErrorAction SilentlyContinue

Write-Host "✅ Local events generated in Windows Application Log"
Write-Host "📊 Check Event Viewer > Windows Logs > Application for Capcom_CTF events"
"@

# Create event source for local logging
try { New-EventLog -LogName Application -Source "Capcom_CTF" -ErrorAction SilentlyContinue } catch { }
Set-Content -Path "C:\CTF\Scripts\Generate-CTFEvents.ps1" -Value $LocalEventScript
%{ endif ~}

# Note: Actual Capcom.sys installation and flag creation would be done
# in the next phase when you're ready to set up the full CTF

# Create a completion marker
New-Item -Path "C:\user-data-complete.txt" -ItemType File -Force
Set-Content -Path "C:\user-data-complete.txt" -Value "Capcom CTF victim initialization completed at $(Get-Date)"

Write-Host "====================================="
Write-Host "Capcom CTF victim initialization complete!"
Write-Host "CTF Player: ctfplayer / ${ctf_player_password}"
Write-Host "Administrator: Administrator / ${admin_password}"
%{ if siem_private_ip != "" ~}
Write-Host "SIEM Integration: ${siem_type} at ${siem_private_ip}"
Write-Host "Event Scripts: C:\CTF\Scripts\"
%{ else ~}
Write-Host "SIEM Integration: Disabled (local events only)"
%{ endif ~}
Write-Host "====================================="

Stop-Transcript
</powershell>