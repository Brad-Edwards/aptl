# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.2.0"
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile != "" ? var.aws_profile : null
}

# VPC Configuration
resource "aws_vpc" "purple_team_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "purple-team-vpc"
    Project = "purple-team-lab"
    Environment = "poc"
  }
}

# Public Subnet
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.purple_team_vpc.id
  cidr_block              = var.subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true

  tags = {
    Name = "purple-team-public-subnet"
    Project = "purple-team-lab"
    Environment = "poc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.purple_team_vpc.id

  tags = {
    Name = "purple-team-igw"
    Project = "purple-team-lab"
    Environment = "poc"
  }
}

# Route Table
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.purple_team_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "purple-team-public-rt"
    Project = "purple-team-lab"
    Environment = "poc"
  }
}

# Route Table Association
resource "aws_route_table_association" "public_rta" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# Security Group for SIEM
resource "aws_security_group" "siem_sg" {
  name        = "siem-security-group"
  description = "Security group for qRadar SIEM"
  vpc_id      = aws_vpc.purple_team_vpc.id

  # SSH access from allowed IPs
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }

  # Web access from allowed IPs
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }

  # Allow syslog from victim machine
  ingress {
    from_port       = 514
    to_port         = 514
    protocol        = "udp"
    security_groups = [aws_security_group.victim_sg.id]
  }

  # Allow syslog TCP from victim machine (for reliable forwarding)
  ingress {
    from_port       = 514
    to_port         = 514
    protocol        = "tcp"
    security_groups = [aws_security_group.victim_sg.id]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "siem-security-group"
    Project = "purple-team-lab"
    Environment = "poc"
  }
}

# Security Group for Victim
resource "aws_security_group" "victim_sg" {
  name        = "victim-security-group"
  description = "Security group for victim machine"
  vpc_id      = aws_vpc.purple_team_vpc.id

  # SSH access from allowed IPs
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }

  # RDP access from allowed IPs
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }

  # Web access from allowed IPs
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "victim-security-group"
    Project = "purple-team-lab"
    Environment = "poc"
  }
}

# Security Group for Kali
resource "aws_security_group" "kali_sg" {
  count       = var.enable_kali ? 1 : 0
  name        = "kali-security-group"
  description = "Security group for Kali Linux red team machine"
  vpc_id      = aws_vpc.purple_team_vpc.id

  # SSH access from allowed IPs
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "kali-security-group"
    Project = "purple-team-lab"
    Environment = "poc"
  }
}

# SIEM Instance
resource "aws_instance" "siem" {
  count         = var.enable_siem ? 1 : 0
  ami           = var.siem_ami
  instance_type = var.siem_instance_type
  subnet_id     = aws_subnet.public_subnet.id
  key_name      = var.key_name

  vpc_security_group_ids = [aws_security_group.siem_sg.id]

  root_block_device {
    volume_size = 250  # Minimum requirement per docs
    volume_type = "gp3"
  }

  user_data = <<-EOF
              #!/bin/bash
              # Log everything for troubleshooting
              exec > >(tee /var/log/user-data.log)
              exec 2>&1
              
              # Update system
              sudo dnf update -y
              
              # Install required packages
              sudo dnf install -y wget
              
              # Baseline OS configuration for qRadar
              sudo hostnamectl set-hostname qradar.local
              
              # Add hostname to /etc/hosts using private IP
              PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
              echo "$PRIVATE_IP qradar.local" | sudo tee -a /etc/hosts
              
              # Disable SELinux immediately and permanently
              sudo setenforce 0 || true  # Don't fail if already disabled
              sudo sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
              
              # Setup swap (8GB)
              sudo swapoff -a
              sudo dd if=/dev/zero of=/swap bs=1M count=8192
              sudo mkswap /swap
              sudo swapon /swap
              echo '/swap swap swap defaults 0 0' | sudo tee -a /etc/fstab
              
              # Wait for additional EBS volume to attach
              echo "Waiting for /store volume to attach..."
              while [ ! -b /dev/nvme1n1 ] && [ ! -b /dev/xvdf ]; do
                sleep 5
              done
              
              # Determine the correct device name (newer instances use nvme, older use xvd)
              if [ -b /dev/nvme1n1 ]; then
                STORE_DEVICE="/dev/nvme1n1"
              else
                STORE_DEVICE="/dev/xvdf"
              fi
              
              # Format and mount /store volume
              echo "Setting up /store on $STORE_DEVICE"
              sudo mkfs.ext4 -F $STORE_DEVICE
              sudo mkdir -p /store
              sudo mount $STORE_DEVICE /store
              
              # Add to fstab for persistent mounting
              echo "$STORE_DEVICE /store ext4 defaults 0 0" | sudo tee -a /etc/fstab
              
              # Set proper ownership and permissions
              sudo chown root:root /store
              sudo chmod 755 /store
              
              # Create reboot flag to track if reboot is needed
              touch /home/ec2-user/system_ready_for_qradar
              
              # Create qRadar installation script
              cat > /home/ec2-user/install_qradar.sh << 'EOFSCRIPT'
              #!/bin/bash
              
              # Check if system was rebooted after initial setup
              if [ ! -f /home/ec2-user/post_reboot_setup_done ]; then
                echo "Performing post-reboot setup..."
                
                # Verify SELinux is disabled
                if [ "$(getenforce)" != "Disabled" ]; then
                  echo "ERROR: SELinux is still enabled. Rebooting system..."
                  sudo reboot
                  exit 1
                fi
                
                # Verify /store is mounted
                if ! mountpoint -q /store; then
                  echo "ERROR: /store is not mounted. Checking..."
                  sudo mount -a
                  if ! mountpoint -q /store; then
                    echo "ERROR: Failed to mount /store"
                    exit 1
                  fi
                fi
                
                # Remove conflicting Red Hat Cloud packages that cause qRadar installation issues
                echo "Removing conflicting cloud packages..."
                sudo dnf remove -y redhat-cloud-client-configuration rhc insights-client || true
                
                # Clean package cache
                sudo dnf clean all
                
                # Mark post-reboot setup as done
                touch /home/ec2-user/post_reboot_setup_done
              fi
              
              echo "System ready for qRadar installation."
              echo "Mounting ISO..."
              sudo mkdir -p /iso
              sudo mount -o loop /tmp/750-QRADAR-QRFULL-2021.06.12.20250509154206.iso /iso
              
              echo "Starting qRadar setup..."
              cd /iso
              sudo ./setup
              EOFSCRIPT
              chmod +x /home/ec2-user/install_qradar.sh
              
              # Create system preparation completion script
              cat > /home/ec2-user/prepare_for_qradar.sh << 'EOFSCRIPT'
              #!/bin/bash
              echo "Checking system preparation status..."
              
              # Check SELinux status
              echo "SELinux status: $(getenforce)"
              
              # Check /store mount
              echo "/store mount status: $(mountpoint /store && echo 'OK' || echo 'NOT MOUNTED')"
              
              # Check available space
              echo "Disk space:"
              df -h / /store
              
              # If SELinux is not disabled, reboot
              if [ "$(getenforce)" != "Disabled" ]; then
                echo "SELinux not fully disabled. Rebooting system in 10 seconds..."
                echo "After reboot, re-run this script to verify, then run install_qradar.sh"
                sleep 10
                sudo reboot
              else
                echo "System ready for qRadar installation!"
                echo "Run: ./install_qradar.sh"
              fi
              EOFSCRIPT
              chmod +x /home/ec2-user/prepare_for_qradar.sh
              
              # Final system preparation
              echo "Initial setup complete. System may need reboot for SELinux changes."
              EOF

  tags = {
    Name = "qradar-siem"
    Project = "purple-team-lab"
    Environment = "poc"
  }
}

# EBS Volume for qRadar /store
resource "aws_ebs_volume" "siem_store" {
  count             = var.enable_siem ? 1 : 0
  availability_zone = var.availability_zone
  size              = 200  # GB for /store - adjust as needed
  type              = "gp3"
  
  tags = {
    Name = "qradar-store-volume"
    Project = "purple-team-lab"
    Environment = "poc"
  }
}

resource "aws_volume_attachment" "siem_store_attachment" {
  count       = var.enable_siem ? 1 : 0
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.siem_store[0].id
  instance_id = aws_instance.siem[0].id
}

# Victim Instance
resource "aws_instance" "victim" {
  count         = var.enable_victim ? 1 : 0
  ami           = var.victim_ami
  instance_type = var.victim_instance_type
  subnet_id     = aws_subnet.public_subnet.id
  key_name      = var.key_name

  vpc_security_group_ids = [aws_security_group.victim_sg.id]

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  user_data = <<-EOF
              #!/bin/bash
              # Log everything for troubleshooting
              exec > >(tee /var/log/user-data.log)
              exec 2>&1
              
              # Update system
              sudo dnf update -y
              
              # Install useful packages for purple team exercises
              sudo dnf install -y telnet nc nmap-ncat bind-utils wget curl
              
              # Configure rsyslog forwarding to SIEM
              echo "Configuring rsyslog forwarding to qRadar SIEM..."
              
              # Get SIEM private IP
              SIEM_IP="${aws_instance.siem.private_ip}"
              
              # Add rsyslog forwarding rule (TCP for reliable delivery)
              echo "# Purple Team Lab - Forward all logs to qRadar SIEM" | sudo tee -a /etc/rsyslog.conf
              echo "*.* @@$SIEM_IP:514" | sudo tee -a /etc/rsyslog.conf
              
              # Restart rsyslog to apply changes
              sudo systemctl restart rsyslog
              
              # Create comprehensive purple team test scripts
              cat > /home/ec2-user/generate_test_events.sh << 'EOFSCRIPT'
              #!/bin/bash
              echo "=== Purple Team Lab - Security Event Generator ==="
              echo "Generating realistic security events for qRadar testing..."
              echo "SIEM IP: ${aws_instance.siem.private_ip}"
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
              echo "📊 Check qRadar Log Activity for events from IP: $(hostname -I | awk '{print $1}')"
              echo "🚨 Expected offenses: Authentication failures, privilege escalation, suspicious network activity"
              EOFSCRIPT
              chmod +x /home/ec2-user/generate_test_events.sh
              
              # Create brute force attack simulation
              cat > /home/ec2-user/simulate_brute_force.sh << 'EOFSCRIPT'
              #!/bin/bash
              echo "=== Brute Force Attack Simulation ==="
              echo "Generating 20 failed SSH attempts to trigger qRadar offense..."
              
              for i in {1..20}; do
                echo "Attempt $i/20..."
                logger -p auth.warning "PURPLE_BRUTE_FORCE: Failed password for user 'admin' from 192.168.1.100 port 22 ssh2"
                logger -p auth.error "PURPLE_BRUTE_FORCE: authentication failure; logname= uid=0 euid=0 user=hacker rhost=192.168.1.100"
                sleep 1
              done
              
              echo ""
              echo "🚨 Brute force simulation complete!"
              echo "📈 This should trigger 'Multiple Login Failures' offense in qRadar"
              echo "🕐 Check qRadar Offenses tab in 2-3 minutes"
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
              echo "📊 Check qRadar for correlated events and potential offenses"
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
              echo "📊 Check qRadar for technique-specific events and potential correlations"
              EOFSCRIPT
              chmod +x /home/ec2-user/simulate_mitre_attack.sh
              
              # Create a status check script
              cat > /home/ec2-user/check_siem_connection.sh << 'EOFSCRIPT'
              #!/bin/bash
              echo "=== SIEM Connection Status ==="
              echo "SIEM IP: ${aws_instance.siem.private_ip}"
              echo ""
              
              # Test network connectivity
              echo "Testing network connectivity..."
              if timeout 5 telnet ${aws_instance.siem.private_ip} 514 2>/dev/null | grep -q Connected; then
                echo "✅ Network: qRadar reachable on port 514"
              else
                echo "❌ Network: Cannot reach qRadar on port 514"
              fi
              
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
              if grep -q "@@${aws_instance.siem.private_ip}:514" /etc/rsyslog.conf; then
                echo "✅ Config: Log forwarding configured correctly"
              else
                echo "❌ Config: Log forwarding not configured"
              fi
              
              # Test log generation
              echo ""
              echo "Testing log generation..."
              logger "SIEM_TEST: Connection check from $(hostname) at $(date)"
              echo "✅ Test log sent (check qRadar Log Activity in 10-30 seconds)"
              
              echo ""
              echo "=== Ready to run purple team exercises! ==="
              echo "Commands available:"
              echo "  ./generate_test_events.sh     - Generate diverse security events"
              echo "  ./simulate_brute_force.sh     - Trigger authentication offense"
              echo "  ./simulate_lateral_movement.sh - APT-style attack simulation"
              echo "  ./simulate_mitre_attack.sh T1110 - Specific MITRE ATT&CK techniques"
              EOFSCRIPT
              chmod +x /home/ec2-user/check_siem_connection.sh
              
              echo "Purple team victim machine setup complete"
              echo "Log forwarding configured to: ${aws_instance.siem.private_ip}:514"
              echo "Ready for testing after qRadar installation!"
              EOF

  tags = {
    Name = "victim-machine"
    Project = "purple-team-lab"
    Environment = "poc"
  }
}

resource "aws_eip" "siem_eip" {
  count    = var.enable_siem ? 1 : 0
  instance = aws_instance.siem[0].id
  domain   = "vpc"

  tags = {
    Name = "siem-eip"
    Project = "purple-team-lab"
    Environment = "poc"
  }
}

resource "aws_eip" "victim_eip" {
  count    = var.enable_victim ? 1 : 0
  instance = aws_instance.victim[0].id
  domain   = "vpc"

  tags = {
    Name = "victim-eip"
    Project = "purple-team-lab"
    Environment = "poc"
  }
}

# Kali Instance
resource "aws_instance" "kali" {
  count         = var.enable_kali ? 1 : 0
  ami           = var.kali_ami
  instance_type = var.kali_instance_type
  subnet_id     = aws_subnet.public_subnet.id
  key_name      = var.key_name

  vpc_security_group_ids = [aws_security_group.kali_sg[0].id]

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  user_data = <<-EOF
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
                docker-compose
              
              # Enable Docker service
              sudo systemctl enable docker
              sudo systemctl start docker
              
              # Add default user to docker group
              sudo usermod -aG docker kali 2>/dev/null || true
              
              # Create working directory for red team operations
              mkdir -p /home/kali/operations
              
              # Create a welcome script with lab information
              cat > /home/kali/lab_info.sh << 'EOFSCRIPT'
              #!/bin/bash
              echo "=== APTL Red Team Kali Instance ==="
              echo ""
              echo "Lab Network Information:"
              echo "  SIEM Private IP: ${aws_instance.siem.private_ip}"
              echo "  Victim Private IP: ${aws_instance.victim.private_ip}"
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
              echo "Happy hunting!"
              EOFSCRIPT
              chmod +x /home/kali/lab_info.sh
              
              # Set proper ownership
              chown -R kali:kali /home/kali/operations 2>/dev/null || true
              chown kali:kali /home/kali/lab_info.sh 2>/dev/null || true
              
              echo "Kali Linux red team instance setup complete"
              EOF

  tags = {
    Name = "kali-redteam"
    Project = "purple-team-lab"
    Environment = "poc"
  }
}

resource "aws_eip" "kali_eip" {
  count    = var.enable_kali ? 1 : 0
  instance = aws_instance.kali[0].id
  domain   = "vpc"

  tags = {
    Name = "kali-eip"
    Project = "purple-team-lab"
    Environment = "poc"
  }
}

# Existing lab_connections.txt file (keep for backward compatibility)
resource "local_file" "connection_info" {
  filename = "${path.module}/lab_connections.txt"
  content = <<-EOF
APTL Purple Team Lab Connection Info
====================================

SIEM Instance (qRadar):
  Public IP:  ${aws_eip.siem_eip.public_ip}
  Private IP: ${aws_instance.siem.private_ip}
  SSH: ssh -i ~/.ssh/${var.key_name} ec2-user@${aws_eip.siem_eip.public_ip}
  HTTPS: https://${aws_eip.siem_eip.public_ip}

Victim Instance:
  Public IP:  ${aws_eip.victim_eip.public_ip}
  Private IP: ${aws_instance.victim.private_ip}
  SSH: ssh -i ~/.ssh/${var.key_name} ec2-user@${aws_eip.victim_eip.public_ip}
  RDP: mstsc /v:${aws_eip.victim_eip.public_ip}

${var.enable_kali ? "Kali Red Team Instance:\n  Public IP:  ${aws_eip.kali_eip[0].public_ip}\n  Private IP: ${aws_instance.kali[0].private_ip}\n  SSH: ssh -i ~/.ssh/${var.key_name} kali@${aws_eip.kali_eip[0].public_ip}\n\n" : ""}qRadar ISO Transfer:
  scp -i ~/.ssh/${var.key_name} files/750-QRADAR-QRFULL-2021.06.12.20250509154206.iso ec2-user@${aws_eip.siem_eip.public_ip}:/tmp/

Log Forwarding Verification:
  1. SSH to victim machine and run: ./generate_test_events.sh
  2. Login to qRadar web interface: https://${aws_eip.siem_eip.public_ip}
  3. Go to Log Activity tab and filter by Source IP: ${aws_instance.victim.private_ip}
  4. You should see logs from victim machine automatically

Purple Team Testing:
  SSH to victim: ssh -i ~/.ssh/${var.key_name} ec2-user@${aws_eip.victim_eip.public_ip}
  Generate events: ./generate_test_events.sh
  Monitor in qRadar: Log Activity → Source IP filter → ${aws_instance.victim.private_ip}

${var.enable_kali ? "Red Team Operations:\n  SSH to Kali: ssh -i ~/.ssh/${var.key_name} kali@${aws_eip.kali_eip[0].public_ip}\n  Run lab info: ./lab_info.sh\n  Target SIEM: ${aws_instance.siem.private_ip}\n  Target Victim: ${aws_instance.victim.private_ip}\n\n" : ""}Network Summary:
  VPC CIDR: ${var.vpc_cidr}
  Subnet CIDR: ${var.subnet_cidr}
  Your Allowed IP: ${var.allowed_ip}

Generated: ${timestamp()}
EOF
}

# New JSON configuration file for MCP server
resource "local_file" "lab_config_json" {
  filename = "${path.module}/lab_config.json"
  content = jsonencode({
    version   = "1.0"
    generated = timestamp()
    lab = {
      name        = "APTL Purple Team Lab"
      vpc_cidr    = aws_vpc.purple_team_vpc.cidr_block
      project     = var.project_name
      environment = var.environment
    }
    instances = {
      siem = {
        public_ip     = aws_eip.siem_eip.public_ip
        private_ip    = aws_instance.siem.private_ip
        ssh_key       = "~/.ssh/${var.key_name}"
        ssh_user      = "ec2-user"
        instance_type = var.siem_instance_type
        ports = {
          ssh        = 22
          https      = 443
          syslog_udp = 514
          syslog_tcp = 514
        }
      }
      victim = {
        public_ip     = aws_eip.victim_eip.public_ip
        private_ip    = aws_instance.victim.private_ip
        ssh_key       = "~/.ssh/${var.key_name}"
        ssh_user      = "ec2-user"
        instance_type = var.victim_instance_type
        ports = {
          ssh  = 22
          rdp  = 3389
          http = 80
        }
      }
      kali = var.enable_kali ? {
        public_ip     = aws_eip.kali_eip[0].public_ip
        private_ip    = aws_instance.kali[0].private_ip
        ssh_key       = "~/.ssh/${var.key_name}"
        ssh_user      = "kali"
        instance_type = var.kali_instance_type
        enabled       = true
        ports = {
          ssh = 22
        }
      } : {
        enabled = false
      }
    }
    network = {
      vpc_cidr    = aws_vpc.purple_team_vpc.cidr_block
      subnet_cidr = aws_subnet.public_subnet.cidr_block
      allowed_ip  = var.allowed_ip
    }
    mcp = {
      server_name      = "kali-red-team"
      allowed_targets  = [aws_subnet.public_subnet.cidr_block]
      max_session_time = 3600
      audit_enabled    = true
      log_level       = "info"
    }
  })
  
  # Make file readable only by owner for security
  file_permission = "0600"
}
