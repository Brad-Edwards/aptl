#!/bin/bash
# Log everything for troubleshooting
exec > >(tee /var/log/user-data.log)
exec 2>&1

# Update system
sudo dnf update -y

# Install useful packages for purple team exercises
sudo dnf install -y telnet nc nmap-ncat bind-utils wget curl policycoreutils-python-utils

# Configure SELinux for rsyslog client operations
echo "Configuring SELinux for log forwarding..."

# Allow rsyslog to make outbound network connections
sudo setsebool -P rsyslog_client 1 || true

# Add SIEM ports to allowed syslog ports
sudo semanage port -a -t syslogd_port_t -p udp 5514 2>/dev/null || true
sudo semanage port -a -t syslogd_port_t -p tcp 5514 2>/dev/null || true
sudo semanage port -a -t syslogd_port_t -p udp 514 2>/dev/null || true
sudo semanage port -a -t syslogd_port_t -p tcp 514 2>/dev/null || true

%{ if siem_private_ip != "" ~}
# Configure rsyslog forwarding to SIEM
echo "Configuring rsyslog forwarding to ${siem_type} SIEM..."

# Get SIEM private IP
SIEM_IP="${siem_private_ip}"

%{ if siem_type == "splunk" ~}
# Add rsyslog forwarding rule (TCP for reliable delivery) - Splunk uses port 5514
echo "# Purple Team Lab - Forward all logs to ${siem_type} SIEM" | sudo tee -a /etc/rsyslog.conf
echo "*.* @@$SIEM_IP:5514" | sudo tee -a /etc/rsyslog.conf
%{ else ~}
# Add rsyslog forwarding rule (TCP for reliable delivery) - qRadar uses port 514
echo "# Purple Team Lab - Forward all logs to ${siem_type} SIEM" | sudo tee -a /etc/rsyslog.conf
echo "*.* @@$SIEM_IP:514" | sudo tee -a /etc/rsyslog.conf
%{ endif ~}

# Restart rsyslog to apply changes
sudo systemctl restart rsyslog
%{ else ~}
echo "SIEM not enabled - skipping rsyslog configuration"
%{ endif ~}

# Create comprehensive purple team test scripts
cat > /home/ec2-user/generate_test_events.sh << 'EOFSCRIPT'
#!/bin/bash
echo "=== Purple Team Lab - Security Event Generator ==="
echo "Generating realistic security events for ${siem_type} testing..."
%{ if siem_private_ip != "" ~}
echo "SIEM IP: ${siem_private_ip}"
%{ else ~}
echo "SIEM IP: Not configured (SIEM disabled)"
%{ endif ~}
echo ""

# Authentication Events
echo "1. Generating Authentication Events..."
logger -p auth.info "PURPLE_TEST: Successful SSH login for user $(whoami) from $(hostname -I | awk '{print $1}')"
logger -p auth.warning "PURPLE_TEST: Failed login attempt for user 'admin' from 192.168.1.100"
logger -p auth.error "PURPLE_TEST: Multiple failed passwords for user 'root' from 10.0.1.200"
logger -p auth.alert "PURPLE_TEST: User account lockout triggered for 'testuser'"

# Privilege Escalation
echo "2. Generating Privilege Escalation Events..."
logger -p security.warning "PURPLE_TEST: sudo command executed: /bin/bash by $(whoami)"
logger -p security.alert "PURPLE_TEST: Attempted privilege escalation detected"
logger -p auth.error "PURPLE_TEST: su command failed for user 'attacker'"

# Network Security Events  
echo "3. Generating Network Security Events..."
logger -p daemon.warning "PURPLE_TEST: Suspicious outbound connection to 203.0.113.1:443"
logger -p security.notice "PURPLE_TEST: Port scan detected from $(hostname -I | awk '{print $1}') to 10.0.1.1"
logger -p daemon.alert "PURPLE_TEST: Unusual DNS query to suspicious-domain.evil"

# Malware/Threat Simulation
echo "4. Generating Malware Detection Events..."
logger -p security.critical "PURPLE_TEST: Malware signature detected in /tmp/suspicious_file.exe"
logger -p security.alert "PURPLE_TEST: Behavioral analysis: Process injection detected"
logger -p security.warning "PURPLE_TEST: Command and control communication detected"

# System Security Events
echo "5. Generating System Security Events..."
logger -p daemon.warning "PURPLE_TEST: Unexpected system file modification detected"
logger -p security.notice "PURPLE_TEST: New service installation: backdoor.service"
logger -p daemon.error "PURPLE_TEST: System integrity check failed"

echo ""
echo "✅ Security events generated successfully!"
echo "📊 Check ${siem_type} Log Activity for events from IP: $(hostname -I | awk '{print $1}')"
%{ if siem_type == "qradar" ~}
echo "🚨 Expected offenses: Authentication failures, privilege escalation, suspicious network activity"
%{ else ~}
echo "🚨 Expected alerts: Authentication failures, privilege escalation, suspicious network activity"
%{ endif ~}
EOFSCRIPT
chmod +x /home/ec2-user/generate_test_events.sh

# Create brute force attack simulation
cat > /home/ec2-user/simulate_brute_force.sh << 'EOFSCRIPT'
#!/bin/bash
echo "=== Brute Force Attack Simulation ==="
echo "Generating 20 failed SSH attempts to trigger ${siem_type} alerts..."

for i in {1..20}; do
  echo "Attempt $i/20..."
  logger -p auth.warning "PURPLE_BRUTE_FORCE: Failed password for user 'admin' from 192.168.1.100 port 22 ssh2"
  logger -p auth.error "PURPLE_BRUTE_FORCE: authentication failure; logname= uid=0 euid=0 user=hacker rhost=192.168.1.100"
  sleep 1
done

echo ""
echo "🚨 Brute force simulation complete!"
%{ if siem_type == "qradar" ~}
echo "📈 This should trigger 'Multiple Login Failures' offense in qRadar"
echo "🕐 Check qRadar Offenses tab in 2-3 minutes"
%{ else ~}
echo "📈 This should trigger authentication alerts in Splunk"
echo "🕐 Check Splunk Search & Reporting for auth events in 2-3 minutes"
%{ endif ~}
EOFSCRIPT
chmod +x /home/ec2-user/simulate_brute_force.sh

# Create lateral movement simulation
cat > /home/ec2-user/simulate_lateral_movement.sh << 'EOFSCRIPT'
#!/bin/bash
echo "=== Lateral Movement Simulation ==="
echo "Simulating APT-style lateral movement activities..."

# Discovery phase
logger -p security.notice "LATERAL_MOVEMENT: Network discovery initiated from $(hostname)"
logger -p daemon.info "LATERAL_MOVEMENT: SMB enumeration detected to 10.0.1.0/24"
logger -p security.warning "LATERAL_MOVEMENT: Admin share access attempt to \\\\10.0.1.10\\C$"

# Credential harvesting
logger -p security.alert "LATERAL_MOVEMENT: LSASS memory dump detected"
logger -p security.critical "LATERAL_MOVEMENT: Mimikatz-like activity detected"
logger -p auth.warning "LATERAL_MOVEMENT: Pass-the-hash attempt detected"

# Persistence
logger -p security.warning "LATERAL_MOVEMENT: WMI persistence mechanism created"
logger -p daemon.alert "LATERAL_MOVEMENT: Scheduled task created for persistence"

# Data exfiltration preparation  
logger -p security.alert "LATERAL_MOVEMENT: Large file access pattern detected"
logger -p daemon.warning "LATERAL_MOVEMENT: Unusual data compression activity"

echo ""
echo "🎯 Lateral movement simulation complete!"
echo "🔍 This simulates advanced persistent threat (APT) behavior"
echo "📊 Check ${siem_type} for correlated events and potential alerts"
EOFSCRIPT
chmod +x /home/ec2-user/simulate_lateral_movement.sh

# Create custom MITRE ATT&CK technique simulator
cat > /home/ec2-user/simulate_mitre_attack.sh << 'EOFSCRIPT'
#!/bin/bash

if [ -z "$1" ]; then
  echo "=== MITRE ATT&CK Technique Simulator ==="
  echo "Usage: $0 <technique>"
  echo ""
  echo "Available techniques:"
  echo "  T1078 - Valid Accounts"
  echo "  T1110 - Brute Force"  
  echo "  T1021 - Remote Services"
  echo "  T1055 - Process Injection"
  echo "  T1003 - OS Credential Dumping"
  echo "  T1562 - Impair Defenses"
  echo ""
  echo "Example: $0 T1110"
  exit 1
fi

case $1 in
  T1078)
    echo "🎯 Simulating T1078 - Valid Accounts"
    logger -p auth.info "MITRE_T1078: Legitimate user account access outside normal hours"
    logger -p auth.warning "MITRE_T1078: Service account used for interactive login"
    logger -p security.notice "MITRE_T1078: Privileged account accessed from unusual location"
    ;;
  T1110)
    echo "🎯 Simulating T1110 - Brute Force"
    for i in {1..15}; do
      logger -p auth.error "MITRE_T1110: Password brute force attempt $i for user admin"
      sleep 0.5
    done
    ;;
  T1021)
    echo "🎯 Simulating T1021 - Remote Services"
    logger -p daemon.warning "MITRE_T1021: RDP connection established from unusual source"
    logger -p security.notice "MITRE_T1021: SSH tunnel creation detected"
    logger -p daemon.alert "MITRE_T1021: PSExec-like remote execution detected"
    ;;
  T1055)
    echo "🎯 Simulating T1055 - Process Injection"
    logger -p security.critical "MITRE_T1055: Process hollowing detected PID:1234"
    logger -p security.alert "MITRE_T1055: DLL injection into legitimate process"
    logger -p daemon.warning "MITRE_T1055: Reflective DLL loading detected"
    ;;
  T1003)
    echo "🎯 Simulating T1003 - OS Credential Dumping"
    logger -p security.critical "MITRE_T1003: SAM database access detected"
    logger -p security.alert "MITRE_T1003: NTDS.dit file access attempt"
    logger -p security.warning "MITRE_T1003: /etc/shadow file access detected"
    ;;
  T1562)
    echo "🎯 Simulating T1562 - Impair Defenses"
    logger -p security.alert "MITRE_T1562: Security service disabled: auditd"
    logger -p daemon.warning "MITRE_T1562: Firewall rules modified"
    logger -p security.critical "MITRE_T1562: Antivirus real-time protection disabled"
    ;;
  *)
    echo "❌ Unknown technique: $1"
    echo "Run without arguments to see available techniques"
    exit 1
    ;;
esac

echo "✅ MITRE ATT&CK technique $1 simulation complete!"
echo "📊 Check ${siem_type} for technique-specific events and potential correlations"
EOFSCRIPT
chmod +x /home/ec2-user/simulate_mitre_attack.sh

# Create a status check script
cat > /home/ec2-user/check_siem_connection.sh << 'EOFSCRIPT'
#!/bin/bash
echo "=== SIEM Connection Status ==="
%{ if siem_private_ip != "" ~}
echo "SIEM Type: ${siem_type}"
echo "SIEM IP: ${siem_private_ip}"
echo ""

# Test network connectivity
echo "Testing network connectivity..."
%{ if siem_type == "splunk" ~}
if timeout 5 telnet ${siem_private_ip} 5514 2>/dev/null | grep -q Connected; then
  echo "✅ Network: ${siem_type} reachable on port 5514"
else
  echo "❌ Network: Cannot reach ${siem_type} on port 5514"
fi
%{ else ~}
if timeout 5 telnet ${siem_private_ip} 514 2>/dev/null | grep -q Connected; then
  echo "✅ Network: ${siem_type} reachable on port 514"
else
  echo "❌ Network: Cannot reach ${siem_type} on port 514"
fi
%{ endif ~}

# Check rsyslog status
echo ""
echo "Checking rsyslog status..."
if systemctl is-active --quiet rsyslog; then
  echo "✅ Rsyslog: Service is running"
else
  echo "❌ Rsyslog: Service is not running"
fi

# Check rsyslog configuration
echo ""
echo "Checking rsyslog configuration..."
%{ if siem_type == "splunk" ~}
if grep -q "@@${siem_private_ip}:5514" /etc/rsyslog.conf; then
  echo "✅ Config: Log forwarding configured correctly"
else
  echo "❌ Config: Log forwarding not configured"
fi
%{ else ~}
if grep -q "@@${siem_private_ip}:514" /etc/rsyslog.conf; then
  echo "✅ Config: Log forwarding configured correctly"
else
  echo "❌ Config: Log forwarding not configured"
fi
%{ endif ~}

# Test log generation
echo ""
echo "Testing log generation..."
logger "SIEM_TEST: Connection check from $(hostname) at $(date)"
%{ if siem_type == "qradar" ~}
echo "✅ Test log sent (check qRadar Log Activity in 10-30 seconds)"
%{ else ~}
echo "✅ Test log sent (check Splunk Search in 10-30 seconds)"
%{ endif ~}
%{ else ~}
echo "SIEM IP: Not configured (SIEM disabled)"
echo ""
echo "ℹ️  SIEM is disabled - no log forwarding configured"
echo "📝 Event generation scripts will still work for local testing"
%{ endif ~}

echo ""
echo "=== Ready to run purple team exercises! ==="
echo "Commands available:"
echo "  ./generate_test_events.sh     - Generate diverse security events"
echo "  ./simulate_brute_force.sh     - Trigger authentication alerts"
echo "  ./simulate_lateral_movement.sh - APT-style attack simulation"
echo "  ./simulate_mitre_attack.sh T1110 - Specific MITRE ATT&CK techniques"
EOFSCRIPT
chmod +x /home/ec2-user/check_siem_connection.sh

echo "Purple team victim machine setup complete"
%{ if siem_private_ip != "" ~}
echo "Log forwarding configured to: ${siem_private_ip}:514"
echo "Ready for testing after ${siem_type} installation!"
%{ else ~}
echo "SIEM disabled - local event generation ready for testing"
%{ endif ~} 