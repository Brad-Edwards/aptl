<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Advanced Purple Team Lab (APTL)

> **🚧 UNDER CONSTRUCTION 🚧**  
> **⚠️ This project is actively being developed and tested**  
> **🔧 Documentation and features may change rapidly**  
> **💡 Use at your own risk - this is a proof of concept**  
> **🚨 Don't be stupid or you'll get yourself in trouble.**

---

Want unlimited personalized AI-driven purple team exercises?

A shoestring budget purple team lab infrastructure using AWS and Terraform, featuring IBM qRadar Community Edition 7.5.

This lab assumes you have basic understanding of AWS CLI, Terraform, and Linux admin tasks.

This is a lab environment, not for production use. qRadar trial license expires in 30 days. See IBM's [qRadar Community Edition](https://www.ibm.com/community/101/qradar/ce/) for more information.

And this is only the beginning... SecOps agents are coming.

## DISCLAIMER

- The author takes no responsibility for your use of this lab.
- You are solely responsible for whether you are in compliance with the laws of your jurisdiction
- You are solely responsible for following the terms and conditions of any services or applications you use.

## Overview

This project creates a purple team lab environment in AWS with:

- qRadar Community Edition 7.5 on t3a.2xlarge instance (8 vCPU, 32GB RAM)
- Victim machine on t3.micro instance  
- Single VPC with both instances in same subnet
- Security groups restricting access to your IP address only

## Architecture

```mermaid
flowchart TD
    A[Internet] --> B[Internet Gateway]
    B --> C[Public Subnet<br/>10.0.1.0/24]
    C --> D[qRadar<br/>SIEM]
    C --> E[Victim<br/>Machine]
    E -.->|Logs| D
    
    classDef default fill:#ffffff,stroke:#000000,stroke-width:2px,color:#000000
    classDef subnet fill:#f0f0f0,stroke:#000000,stroke-width:2px,color:#000000
    classDef instances fill:#e0e0e0,stroke:#000000,stroke-width:2px,color:#000000
    
    class A,B default
    class C subnet
    class D,E instances
```

## Prerequisites

1. AWS Account with programmatic access configured
2. Terraform installed (version 1.0 or later)
3. AWS CLI configured with your credentials
4. qRadar CE ISO file (see IBM requirements below)

## Quick Start

### 1. Clone and Configure

```bash
git clone <repository-url>
cd purple-team-lab
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:

```hcl
aws_region    = "us-east-1"
allowed_ip    = "YOUR_IP/32"  # Get your IP: curl ipinfo.io/ip
aws_profile   = "your-aws-profile"  # Optional
```

### 2. Get qRadar Files

You must obtain the qRadar CE ISO file and license key before proceeding.

1. Sign up for IBM ID at: <https://www.ibm.com/community/101/qradar/ce/>
2. Download ISO file: `750-QRADAR-QRFULL-2021.06.12.20250509154206.iso` (~5GB)
3. Download license key file: `qradar_trial.license`
4. Create files directory: `mkdir files`
5. Place both files in the `files/` directory

### 3. Subscribe to Kali Linux in AWS Marketplace

1. Go to [AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-fznsw3f7mq7to?sr=0-1&ref_=beagle&applicationId=AWSMPContessa)
2. Click "Subscribe"
3. Wait until setup is done
4. Click "Continue to Configuration"
5. Copy the AMI ID, AMI Alias, and Product Code
6. Add the values to `terraform.tfvars`

### 4. Deploy Infrastructure

```bash
terraform init
terraform plan
terraform apply
```

### 5. Install qRadar

After infrastructure deployment:

```bash
# Connection info is saved to lab_connections.txt
cat lab_connections.txt

# Transfer qRadar ISO (~8 minutes for 5GB file)
scp -i ~/.ssh/purple-team-key files/750-QRADAR-QRFULL-2021.06.12.20250509154206.iso ec2-user@SIEM_IP:/tmp/

# SSH to SIEM instance
ssh -i ~/.ssh/purple-team-key ec2-user@SIEM_IP

# Step 1: Prepare system (handles reboots if needed)
./prepare_for_qradar.sh

# If system reboots, wait ~2 minutes then SSH back and run prepare script again
# Continue until you see "System ready for qRadar installation!"

# Step 2: Install qRadar (only after system is ready)
./install_qradar.sh
```

Installation takes 1-2 hours. Choose:

- Software installation
- "All-In-One" console  
- Default settings
- Your timezone and city
- Set passwords (don't forget them)

Installation appears stuck on "Installing DSM rpms:" but it's working. Takes 30+ minutes.

## Accessing the Lab

### qRadar SIEM

- SSH: `ssh -i ~/.ssh/purple-team-key ec2-user@SIEM_IP`
- Web UI: `https://SIEM_IP` (after installation)
- Login: admin/(password you set)

### Victim Machine

- SSH: `ssh -i ~/.ssh/purple-team-key ec2-user@VICTIM_IP`
- RDP: Use any RDP client to connect to `VICTIM_IP`

## Log Forwarding

The victim machine is automatically configured to forward logs to qRadar. No manual configuration required.

### Verify Log Forwarding

1. Check qRadar Log Activity tab
2. Filter by Source IP = your victim machine IP
3. Generate test events:

```bash
# SSH to victim machine
ssh -i ~/.ssh/purple-team-key ec2-user@VICTIM_IP

# Run test event generator
./generate_test_events.sh
```

## Purple Team Exercises

### Basic Security Event Testing

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

### Available Scripts

```bash
./check_siem_connection.sh        # Verify connectivity
./generate_test_events.sh         # Generate diverse security events
./simulate_brute_force.sh         # Trigger authentication offense
./simulate_lateral_movement.sh    # APT-style attack simulation
./simulate_mitre_attack.sh T1110  # Specific MITRE ATT&CK techniques
```

### MITRE ATT&CK Techniques

Available techniques:

- T1078 - Valid Accounts
- T1110 - Brute Force  
- T1021 - Remote Services
- T1055 - Process Injection
- T1003 - OS Credential Dumping
- T1562 - Impair Defenses

Example: `./simulate_mitre_attack.sh T1110`

Have fun!

![Offences in qRadar](assets/images/qradar_offences.png)

## AI Red Teaming

### Automated Red Team Agent

No red team around? You can use AI coding assistants like **Cline** or **Cursor** as an AI red team agent:

1. **SSH Access**: Give your AI agent the SSH connection details from `lab_connections.txt`
2. **Explain the Lab**: Give the AI a quick overview of the lab, it's purpose, and that you have permission to attack the victim machine. Because you do. Right?
3. **Red Team Mission**: Ask the AI to:
   - SSH into the victim machine
   - Enumerate the system and find vulnerabilities
   - Install common pentesting tools
   - Execute attack scenarios autonomously
   - Explain how the attack works and what you should see in the SIEM

4. **Example AI Prompts**:

   ```text
   "SSH into the victim machine and perform a basic privilege escalation assessment"
   "Set up a persistent backdoor and test if it's detected by the SIEM"
   "Simulate a data exfiltration scenario using common attack tools"
   "Perform automated vulnerability scanning and exploitation"
   ```

5. **Benefits**:
   - Easy set up
   - Endless personalization
   - On the spot tutoring
   - Masters' level system knowledge
   - AI adapts tactics based on what it discovers
   - Won't judge your SIEM query fails!

This creates a true **autonomous red team vs. blue team** scenario where AI attacks while you monitor and tune your defenses in qRadar.

## Roadmap

### 🔜 Coming Soon (v1.1)

- **Splunk Integration**: Alternative SIEM option alongside qRadar
- **Kali MCP**: Kali LinuxModel Context Protocol integration for better AI red teaming
- **Victim Machine Presets**: Windows, Linux, web apps, etc
- **Suggested Exercises**: AI-driven exercises based on what you've done
- **Challenges with Pre-Seeded SIEM Data**: Set piece challenges to practice your SIEM skills

### 🎯 Future Releases

- Additional SIEM platforms (Elastic Security, Wazuh)
- Windows victim machines
- Container-based deployments
- Automated report generation

## Cost Estimation

- t3a.2xlarge (SIEM): ~$220/month
- t3.micro (Victim): ~$7/month
- Storage: ~$50/month (250GB root + 200GB /store + 30GB victim)
- Elastic IPs: $3.65/month
- Total: ~$280/month

Stop instances when not in use to save ~85% on compute costs.

## Security Considerations

- Access restricted to your IP address only
- All instances in public subnet for lab simplicity
- Change default passwords immediately
- Use strong SSH keys and rotate regularly

## Cleanup

```bash
terraform destroy
```

This will permanently delete all resources and data.

## Troubleshooting

See [troubleshooting.md](troubleshooting.md) for detailed troubleshooting steps.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

## Contributing

This is an early stage demo project. Feel free to fork and adapt for your personal needs.

For consulting, enterprise licensing, or other inquiries, contact me at [brad@keplerops.com](mailto:brad@keplerops.com).

## License

BUSL-1.1

---

*10-23 AI hacker shenanigans 🚓*
