#!/bin/bash
# Log everything for troubleshooting
exec > >(tee /var/log/user-data.log)
exec 2>&1

# Update system
echo "Updating Kali Linux system..."
sudo apt-get update -y
sudo apt-get upgrade -y

# Install additional useful tools for red team operations
echo "Installing additional tools..."
sudo apt-get install -y \
  git \
  python3-pip \
  golang \
  docker.io \
  docker-compose \
  kali-tools-top10

# Enable Docker service
sudo systemctl enable docker
sudo systemctl start docker

# Add default user to docker group
sudo usermod -aG docker kali 2>/dev/null || true

%{ if siem_private_ip != "" ~}
# Configure rsyslog for red team log forwarding
echo "Configuring red team log forwarding to ${siem_type} SIEM..."

# Get SIEM private IP
SIEM_IP="${siem_private_ip}"

%{ if siem_type == "splunk" ~}
# Configure rsyslog for Splunk (port 5514) with red team log routing
echo "# APTL Red Team Log Forwarding - Splunk" | sudo tee -a /etc/rsyslog.conf
echo "# Route red team logs to keplerops-aptl-redteam index" | sudo tee -a /etc/rsyslog.conf
echo ":msg, contains, \"REDTEAM_LOG\" @@$SIEM_IP:5514" | sudo tee -a /etc/rsyslog.conf
%{ else ~}
# Configure rsyslog for qRadar (port 514) with red team identification  
echo "# APTL Red Team Log Forwarding - qRadar" | sudo tee -a /etc/rsyslog.conf
echo "# Red team logs identified by source IP in qRadar" | sudo tee -a /etc/rsyslog.conf
echo ":msg, contains, \"REDTEAM_LOG\" @@$SIEM_IP:514" | sudo tee -a /etc/rsyslog.conf
%{ endif ~}

# Restart rsyslog to apply changes
sudo systemctl restart rsyslog

echo "Red team log forwarding configured for ${siem_type}"
%{ else ~}
echo "SIEM not enabled - skipping red team log configuration"
%{ endif ~}

# Create working directory for red team operations
mkdir -p /home/kali/operations

# Create red team logging functions
cat > /home/kali/redteam_logging.sh << 'EOFLOGGING'
#!/bin/bash
# APTL Red Team Logging Functions
# Provides structured logging for red team activities

# Red team logging function - commands
log_redteam_command() {
    local command="$1"
    local target="$${2:-}"
    local result="$${3:-executed}"
    
%{ if siem_type == "splunk" ~}
    # Splunk format with REDTEAM_LOG for index routing
    logger -t "redteam-commands" "REDTEAM_LOG RedTeamActivity=commands RedTeamCommand=\"$command\" RedTeamTarget=\"$target\" RedTeamResult=\"$result\" RedTeamUser=$(whoami) RedTeamHost=$(hostname)"
%{ else ~}
    # qRadar format with structured data
    logger -t "redteam-commands" "REDTEAM_LOG RedTeamActivity=commands RedTeamCommand=\"$command\" RedTeamTarget=\"$target\" RedTeamResult=\"$result\" RedTeamUser=$(whoami) RedTeamHost=$(hostname)"
%{ endif ~}
}

# Red team logging function - network activities
log_redteam_network() {
    local activity="$1"
    local target="$${2:-}"
    local ports="$${3:-}"
    local result="$${4:-completed}"
    
%{ if siem_type == "splunk" ~}
    logger -t "redteam-network" "REDTEAM_LOG RedTeamActivity=network RedTeamNetworkActivity=\"$activity\" RedTeamTarget=\"$target\" RedTeamPorts=\"$ports\" RedTeamResult=\"$result\" RedTeamUser=$(whoami) RedTeamHost=$(hostname)"
%{ else ~}
    logger -t "redteam-network" "REDTEAM_LOG RedTeamActivity=network RedTeamNetworkActivity=\"$activity\" RedTeamTarget=\"$target\" RedTeamPorts=\"$ports\" RedTeamResult=\"$result\" RedTeamUser=$(whoami) RedTeamHost=$(hostname)"
%{ endif ~}
}

# Red team logging function - authentication activities  
log_redteam_auth() {
    local activity="$1"
    local target="$${2:-}"
    local username="$${3:-}"
    local result="$${4:-attempted}"
    
%{ if siem_type == "splunk" ~}
    logger -t "redteam-auth" "REDTEAM_LOG RedTeamActivity=auth RedTeamAuthActivity=\"$activity\" RedTeamTarget=\"$target\" RedTeamUsername=\"$username\" RedTeamResult=\"$result\" RedTeamUser=$(whoami) RedTeamHost=$(hostname)"
%{ else ~}
    logger -t "redteam-auth" "REDTEAM_LOG RedTeamActivity=auth RedTeamAuthActivity=\"$activity\" RedTeamTarget=\"$target\" RedTeamUsername=\"$username\" RedTeamResult=\"$result\" RedTeamUser=$(whoami) RedTeamHost=$(hostname)"
%{ endif ~}
}

# Export functions for use in shell
export -f log_redteam_command
export -f log_redteam_network  
export -f log_redteam_auth
EOFLOGGING

chmod +x /home/kali/redteam_logging.sh

# Create comprehensive red team activity simulator
cat > /home/kali/simulate_redteam_operations.sh << 'EOFSIMULATOR'
#!/bin/bash
# Source logging functions
source /home/kali/redteam_logging.sh

echo "=== APTL Red Team Activity Simulator ==="
echo "Generating structured red team logs for ${siem_type} analysis..."
%{ if siem_private_ip != "" ~}
echo "SIEM IP: ${siem_private_ip}"
%{ else ~}
echo "SIEM IP: Not configured (SIEM disabled)"
%{ endif ~}
echo ""

# 1. Reconnaissance Activities
echo "1. Simulating Reconnaissance Phase..."
log_redteam_network "port_scan" "${victim_private_ip}" "22,80,443,3389" "completed"
log_redteam_network "service_enumeration" "${victim_private_ip}" "ssh,http,rdp" "discovered"
log_redteam_command "nmap -sS ${victim_private_ip}" "${victim_private_ip}" "scan_completed"
log_redteam_command "nmap -sV -p 22,80,443 ${victim_private_ip}" "${victim_private_ip}" "services_identified"

# 2. Initial Access Attempts
echo "2. Simulating Initial Access Attempts..."
log_redteam_auth "ssh_login_attempt" "${victim_private_ip}" "admin" "failed"
log_redteam_auth "ssh_login_attempt" "${victim_private_ip}" "root" "failed"
log_redteam_auth "brute_force_ssh" "${victim_private_ip}" "admin" "multiple_failures"
log_redteam_command "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://${victim_private_ip}" "${victim_private_ip}" "brute_force_executed"

# 3. Exploitation Attempts
echo "3. Simulating Exploitation Phase..."
log_redteam_command "searchsploit apache 2.4" "${victim_private_ip}" "vulnerabilities_researched"
log_redteam_command "msfconsole -x 'use exploit/linux/http/apache_mod_cgi_bash_env_exec'" "${victim_private_ip}" "exploit_loaded"
log_redteam_network "exploit_attempt" "${victim_private_ip}" "80" "payload_sent"

# 4. Post-Exploitation Activities
echo "4. Simulating Post-Exploitation Phase..."
log_redteam_command "whoami" "${victim_private_ip}" "user_enumerated"
log_redteam_command "id" "${victim_private_ip}" "privileges_checked"
log_redteam_command "sudo -l" "${victim_private_ip}" "sudo_rights_checked"
log_redteam_auth "privilege_escalation" "${victim_private_ip}" "www-data" "attempted"

# 5. Persistence and Lateral Movement
echo "5. Simulating Persistence and Lateral Movement..."
log_redteam_command "crontab -e" "${victim_private_ip}" "persistence_attempted"
log_redteam_command "ssh-keygen -t rsa" "${victim_private_ip}" "ssh_keys_generated"
log_redteam_auth "ssh_key_deployment" "${victim_private_ip}" "attacker" "backdoor_installed"
log_redteam_network "lateral_movement_scan" "10.0.1.0/24" "22,3389,445" "network_enumerated"

# 6. Data Collection and Exfiltration
echo "6. Simulating Data Collection..."
log_redteam_command "find / -name '*.txt' -o -name '*.doc' -o -name '*.pdf' 2>/dev/null" "${victim_private_ip}" "files_enumerated"
log_redteam_command "grep -r 'password' /etc/" "${victim_private_ip}" "credentials_searched"
log_redteam_command "tar -czf /tmp/collected_data.tar.gz /home/user/documents/" "${victim_private_ip}" "data_archived"
log_redteam_network "data_exfiltration" "external.evil.com" "443" "data_transferred"

echo ""
echo "✅ Red team activity simulation complete!"
%{ if siem_type == "qradar" ~}
echo "📊 Check qRadar Log Activity > Filter by Log Source: APTL-Kali-RedTeam"
echo "🔍 Look for RedTeamActivity custom properties in event details"
%{ else ~}
echo "📊 Check Splunk Search: index=keplerops-aptl-redteam"
echo "🔍 Filter by source_type=redteam:commands, redteam:network, redteam:auth"
%{ endif ~}
echo ""
echo "🎯 Correlation opportunities:"
echo "   - Compare red team timestamps with victim log events"
echo "   - Identify successful attacks vs SIEM detection"
echo "   - Analyze attack timeline and techniques used"
EOFSIMULATOR

chmod +x /home/kali/simulate_redteam_operations.sh

# Create individual attack technique simulators
cat > /home/kali/simulate_port_scan.sh << 'EOFPORTSCAN'
#!/bin/bash
source /home/kali/redteam_logging.sh

echo "=== Port Scan Simulation ==="
if [ -z "$1" ]; then
    echo "Usage: $0 <target_ip>"
    echo "Example: $0 ${victim_private_ip}"
    exit 1
fi

TARGET="$1"
echo "Simulating port scan against $TARGET..."

# Log the reconnaissance activity
log_redteam_network "nmap_port_scan" "$TARGET" "1-1000" "initiated"
log_redteam_command "nmap -sS -p 1-1000 $TARGET" "$TARGET" "scan_started"

# Simulate scan results
echo "Scanning ports 1-1000..."
sleep 2

# Log discovered services
log_redteam_network "open_ports_discovered" "$TARGET" "22,80,443" "ssh,http,https_detected"
log_redteam_command "nmap -sV -p 22,80,443 $TARGET" "$TARGET" "version_scan_completed"

echo "✅ Port scan simulation complete!"
%{ if siem_type == "qradar" ~}
echo "📊 Check qRadar for RedTeamActivity=network events"
%{ else ~}
echo "📊 Check Splunk: index=keplerops-aptl-redteam source_type=redteam:network"
%{ endif ~}
EOFPORTSCAN

chmod +x /home/kali/simulate_port_scan.sh

# Create a welcome script with lab information
cat > /home/kali/lab_info.sh << 'EOFSCRIPT'
#!/bin/bash
echo "=== APTL Red Team Kali Instance ==="
echo ""
echo "Lab Network Information:"
%{ if siem_private_ip != "" ~}
echo "  SIEM Private IP: ${siem_private_ip}"
%{ else ~}
echo "  SIEM Private IP: Not available (SIEM disabled)"
%{ endif ~}
%{ if victim_private_ip != "" ~}
echo "  Victim Private IP: ${victim_private_ip}"
%{ else ~}
echo "  Victim Private IP: Not available (Victim disabled)"
%{ endif ~}
echo "  Kali Private IP: $(hostname -I | awk '{print $1}')"
echo ""
echo "Available Tools:"
echo "  - Metasploit Framework"
echo "  - Nmap"
echo "  - Burp Suite"
echo "  - SQLMap"
echo "  - John the Ripper"
echo "  - Hashcat"
echo "  - Hydra"
echo "  - And many more..."
echo ""
echo "Working Directory: ~/operations"
echo ""
%{ if siem_private_ip != "" ~}
echo "Red Team Logging:"
echo "  SIEM: ${siem_type} (${siem_private_ip})"
echo "  Logging Functions: source ~/redteam_logging.sh"
echo "  Activity Simulator: ./simulate_redteam_operations.sh"
echo "  Port Scan Test: ./simulate_port_scan.sh <target_ip>"
echo ""
%{ else ~}
echo "Red Team Logging: SIEM disabled"
echo ""
%{ endif ~}
echo "Happy hunting!"
EOFSCRIPT
chmod +x /home/kali/lab_info.sh

# Set proper ownership
chown -R kali:kali /home/kali/operations 2>/dev/null || true
chown kali:kali /home/kali/lab_info.sh 2>/dev/null || true

# Set up SSH keys for the kali user
sudo -u kali ssh-keygen -t rsa -b 2048 -f /home/kali/.ssh/id_rsa -N "" 2>/dev/null || true
sudo chown -R kali:kali /home/kali/.ssh/

# Ensure all created files are owned by kali user
chown kali:kali /home/kali/lab_info.sh
chown kali:kali /home/kali/redteam_logging.sh
chown kali:kali /home/kali/simulate_redteam_operations.sh  
chown kali:kali /home/kali/simulate_port_scan.sh
chown -R kali:kali /home/kali/operations/

%{ if siem_private_ip != "" ~}
# Source red team logging functions in .bashrc for easy access
echo "" >> /home/kali/.bashrc
echo "# APTL Red Team Logging Functions" >> /home/kali/.bashrc
echo "source ~/redteam_logging.sh" >> /home/kali/.bashrc
echo "" >> /home/kali/.bashrc
chown kali:kali /home/kali/.bashrc
%{ endif ~}

# Mark setup as complete
touch /home/kali/kali_setup_complete
chown kali:kali /home/kali/kali_setup_complete

echo "Kali Linux red team instance setup complete" 