# Purple Team Exercises

## Basic Security Event Testing

### Authentication Events

```bash
# SSH to victim machine and run:

# 1. Authentication events
ssh nonexistentuser@localhost
sudo ls /etc/shadow

# 2. Automated event simulation
./generate_test_events.sh

# 3. Network activity
telnet google.com 80
nc -zv localhost 22

# 4. Custom attack scenarios
logger -p security.alert "MALWARE: Suspicious file access detected"
logger -p security.warning "LATERAL_MOVEMENT: SMB connection to domain controller"
```

## Available Scripts

The lab includes several pre-built simulation scripts:

```bash
./check_siem_connection.sh        # Verify connectivity
./generate_test_events.sh         # Generate diverse security events
./simulate_brute_force.sh         # Trigger authentication offense
./simulate_lateral_movement.sh    # APT-style attack simulation
./simulate_mitre_attack.sh T1110  # Specific MITRE ATT&CK techniques
```

## MITRE ATT&CK Techniques

The lab supports simulation of the following MITRE ATT&CK techniques:

### T1078 - Valid Accounts
Simulate adversaries using legitimate accounts to maintain access.

### T1110 - Brute Force  
Password guessing attacks against user accounts.

### T1021 - Remote Services
Lateral movement through remote services like SSH, RDP, SMB.

### T1055 - Process Injection
Injecting code into legitimate processes.

### T1003 - OS Credential Dumping
Extracting credentials from operating system data structures.

### T1562 - Impair Defenses
Disabling or modifying security tools and logging.

## Running MITRE Simulations

Execute specific techniques:

```bash
./simulate_mitre_attack.sh T1110  # Brute force attack
./simulate_mitre_attack.sh T1078  # Valid accounts abuse
./simulate_mitre_attack.sh T1021  # Remote services exploitation
```

## Monitoring Results

After running exercises:

1. **Check SIEM**: Log into qRadar web interface
2. **Review Offenses**: Look for triggered security rules
3. **Analyze Logs**: Search for specific events and patterns
4. **Correlate Activities**: Match red team actions to SIEM detections

## Custom Exercise Development

Create your own exercises by:

1. **Planning Attack Scenarios**: Define realistic attack chains
2. **Developing Scripts**: Write automation for repeatable exercises
3. **Setting Baselines**: Establish normal behavior patterns
4. **Testing Detection**: Verify SIEM rules trigger correctly
5. **Documenting Results**: Track detection rates and false positives

## Advanced Scenarios

### Multi-Stage Attack Simulation

```bash
# 1. Initial Access
./simulate_mitre_attack.sh T1566  # Phishing

# 2. Discovery
./simulate_mitre_attack.sh T1082  # System Information Discovery

# 3. Credential Access
./simulate_mitre_attack.sh T1003  # OS Credential Dumping

# 4. Lateral Movement
./simulate_mitre_attack.sh T1021  # Remote Services

# 5. Persistence
./simulate_mitre_attack.sh T1053  # Scheduled Task/Job
```

### Purple Team Collaboration

1. **Red Team Actions**: Execute attacks using provided scripts
2. **Blue Team Response**: Monitor SIEM and investigate alerts
3. **Analysis Phase**: Review effectiveness of detections
4. **Improvement Cycle**: Tune rules and update procedures

These exercises provide systematic security testing and detection capability development.