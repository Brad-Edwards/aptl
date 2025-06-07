# Basic Reconnaissance and Discovery

**Exercise ID**: BEG-001  
**MITRE ATT&CK Tactics**: Discovery (TA0007), Reconnaissance (TA0043)  
**Difficulty**: 🟢 Beginner  
**Duration**: 2-3 hours  

## Overview & Learning Objectives

This exercise introduces new purple teams to fundamental discovery techniques attackers use to map target environments. By the end of this exercise, blue teams will:

- Understand basic network and system discovery techniques
- Learn to detect common reconnaissance activities in SIEM logs
- Create basic detection rules for discovery commands
- Practice incident triage for low-priority discovery events

**Target MITRE ATT&CK Techniques:**

- T1082: System Information Discovery
- T1083: File and Directory Discovery  
- T1057: Process Discovery
- T1033: System Owner/User Discovery
- T1018: Remote System Discovery

## Infrastructure Requirements

- **Minimum Setup**: 1 victim machine (Linux preferred)
- **Recommended Setup**: 2 machines (1 Linux, 1 Windows victim)
- **Kali Linux**: Available via MCP for AI red team
- **SIEM**: Splunk or qRadar with standard log forwarding configured
- **Network**: All machines in same subnet with basic connectivity

## Setup Instructions (for Blue Team)

### Pre-Exercise Checklist

1. **Verify SIEM Connectivity**

   ```bash
   # On victim machine(s), verify log forwarding
   ./check_siem_connection.sh
   ```

2. **Baseline Activity**
   - Take screenshots of current SIEM dashboard
   - Document normal process/network activity levels
   - Set up real-time monitoring dashboard for the exercise

3. **Detection Preparation**
   - Create saved searches for process execution monitoring
   - Set up alerts for unusual command execution (if not already configured)
   - Prepare incident response template for documentation

### SIEM Query Examples

**Splunk - Monitor for Discovery Commands:**

```splunk
index=main (whoami OR id OR uname OR hostname OR ps OR netstat OR ifconfig OR ip)
| eval discovery_command=case(
    match(_raw,"whoami"), "User Discovery",
    match(_raw,"uname"), "System Info Discovery", 
    match(_raw,"ps"), "Process Discovery",
    match(_raw,"netstat"), "Network Discovery",
    1=1, "Other Discovery"
)
| stats count by host, discovery_command, user
| sort -count
```

**qRadar - System Discovery Events:**

```sql
SELECT 
    sourceip, 
    "Log Source", 
    "Event Name",
    payload
FROM events 
WHERE 
    (payload ilike '%whoami%' OR 
     payload ilike '%uname%' OR 
     payload ilike '%ps aux%' OR
     payload ilike '%netstat%')
    AND starttime > NOW() - INTERVAL '2 HOURS'
ORDER BY starttime DESC
```

## Red Team AI Instructions

**Context**: You are an AI red team operator working within the APTL environment. You have access to Kali Linux via MCP and need to perform basic reconnaissance on the target victim machine(s). Execute the following procedures in order, documenting each step clearly.

### Phase 1: Initial System Discovery (T1082)

**Objective**: Gather basic system information to understand the target environment.

1. **Connect to the victim machine** using SSH (credentials should be available in lab_connections.txt)

2. **Execute system discovery commands in this exact order:**

   ```bash
   # Basic system info - execute each separately with 30-second intervals
   whoami
   id
   uname -a
   hostname
   pwd
   cat /etc/os-release
   uptime
   date
   ```

3. **Document findings**: After each command, provide timestamp and output summary.

### Phase 2: Process and Service Discovery (T1057)

**Objective**: Enumerate running processes and services.

1. **Process enumeration:**

   ```bash
   # Execute with 1-minute intervals between commands
   ps aux
   ps -ef
   top -n 1
   pstree
   ```

2. **Service discovery:**

   ```bash
   # Check for running services
   systemctl --type=service --state=running
   netstat -tulpn
   ss -tulpn
   ```

3. **Document any interesting processes or services** that might be valuable for further exploitation.

### Phase 3: Network Discovery (T1018)

**Objective**: Map network environment and identify potential lateral movement targets.

1. **Network interface discovery:**

   ```bash
   # Network configuration discovery
   ifconfig -a
   ip addr show
   ip route show
   cat /etc/resolv.conf
   ```

2. **Local network scanning:**

   ```bash
   # Discover other systems on the network
   arp -a
   ping -c 1 $(ip route | grep default | awk '{print $3}')
   nmap -sn $(ip route | grep -E 'src' | head -1 | awk '{print $1}')
   ```

### Phase 4: File System Discovery (T1083)

**Objective**: Explore file system for interesting files and directories.

1. **Basic directory exploration:**

   ```bash
   # Explore key directories
   ls -la /home/
   ls -la /opt/
   ls -la /tmp/
   find /home -name "*.txt" -o -name "*.log" 2>/dev/null | head -10
   ```

2. **Configuration file discovery:**

   ```bash
   # Look for configuration files
   find /etc -name "*.conf" 2>/dev/null | head -10
   cat /etc/passwd | head -10
   cat /etc/group | head -10
   ```

### Expected AI Behavior

- **Wait 30-60 seconds between command executions** to generate realistic timing
- **Provide clear output documentation** for each command
- **Note any errors or unexpected responses**
- **Summarize findings** after each phase

## Detection Scenarios

### Scenario 1: System Discovery Alert

**Expected Timeline**: 5-15 minutes after exercise start
**What Blue Team Should See**: Multiple system discovery commands executed in sequence

**Detection Points:**

- Multiple `whoami`, `id`, `uname` commands from same user/session
- Unusual command frequency for discovery activities
- Commands executed outside normal business hours (if applicable)

### Scenario 2: Process Discovery Pattern

**Expected Timeline**: 15-25 minutes after exercise start  
**What Blue Team Should See**: Process enumeration commands indicating reconnaissance

**Detection Points:**

- `ps aux`, `ps -ef`, `top` commands in close succession
- Service enumeration via `systemctl` and `netstat`
- Potential privilege escalation indicators

### Scenario 3: Network Reconnaissance

**Expected Timeline**: 25-35 minutes after exercise start
**What Blue Team Should See**: Network mapping activities

**Detection Points:**

- Network interface queries
- ARP table enumeration  
- Nmap scanning activities (if configured to detect)
- Unusual network discovery patterns

## Expected Outcomes

### Blue Team Success Metrics

- **Detection Rate**: Should detect at least 70% of discovery activities
- **Response Time**: Should identify pattern within 20 minutes
- **Alert Quality**: Minimal false positives on legitimate system administration

### Common Detection Gaps

- **Legitimate Admin Activity**: Distinguish between admin tasks and reconnaissance
- **Command Timing**: May miss slow, spread-out discovery attempts
- **Aggregation**: Individual commands may not trigger alerts but patterns should

### Improvement Opportunities

1. **Behavioral Analytics**: Implement user behavior monitoring
2. **Command Correlation**: Create rules that trigger on command sequences
3. **Baseline Establishment**: Better understanding of normal discovery patterns

## Cleanup & Lessons Learned

### Post-Exercise Activities

1. **Reset Environment**: Clear any temporary files created during reconnaissance
2. **Document Findings**: Record all detection successes and failures
3. **Update Detection Rules**: Improve based on exercise results
4. **Schedule Follow-up**: Plan next exercise based on identified gaps

### Discussion Points

- Which discovery techniques were easiest/hardest to detect?
- How can detection be improved without creating excessive false positives?
- What additional log sources would improve detection coverage?
- How would an attacker modify these techniques to evade detection?

### Next Steps

- Progress to **BEG-002: Basic Persistence Mechanisms**
- Consider lateral movement exercise with multiple victim machines
- Explore advanced discovery techniques in intermediate exercises

---

**Exercise Notes:**

- This exercise generates low-risk, easily detectable activities
- Perfect for teams new to purple teaming concepts
- Establishes baseline detection capabilities before advancing to complex scenarios
- Can be repeated with different victim OS types for comparison
