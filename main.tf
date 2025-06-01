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

# SIEM Instance
resource "aws_instance" "siem" {
  ami           = var.siem_ami
  instance_type = "t3a.2xlarge"  # 8 vCPU, 32GB RAM - meets minimum requirements
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

  # Ensure the EBS volume is attached before instance creation completes
  depends_on = [aws_volume_attachment.siem_store_attachment]
}

# EBS Volume for qRadar /store
resource "aws_ebs_volume" "siem_store" {
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
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.siem_store.id
  instance_id = aws_instance.siem.id
}

# Victim Instance
resource "aws_instance" "victim" {
  ami           = var.victim_ami
  instance_type = var.victim_instance_type
  subnet_id     = aws_subnet.public_subnet.id
  key_name      = var.key_name

  vpc_security_group_ids = [aws_security_group.victim_sg.id]

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  tags = {
    Name = "victim-machine"
    Project = "purple-team-lab"
    Environment = "poc"
  }
}

resource "aws_eip" "siem_eip" {
  instance = aws_instance.siem.id
  domain   = "vpc"

  tags = {
    Name = "siem-eip"
    Project = "purple-team-lab"
    Environment = "poc"
  }
}

resource "aws_eip" "victim_eip" {
  instance = aws_instance.victim.id
  domain   = "vpc"

  tags = {
    Name = "victim-eip"
    Project = "purple-team-lab"
    Environment = "poc"
  }
}

resource "local_file" "connection_info" {
  filename = "${path.module}/lab_connections.txt"
  content = <<-EOF
Purple Team Lab Connection Info
===============================

SIEM Instance:
  IP: ${aws_eip.siem_eip.public_ip}
  SSH: ssh -i ~/.ssh/purple-team-key ec2-user@${aws_eip.siem_eip.public_ip}
  HTTPS: https://${aws_eip.siem_eip.public_ip}

Victim Instance:
  IP: ${aws_eip.victim_eip.public_ip}
  SSH: ssh -i ~/.ssh/purple-team-key ec2-user@${aws_eip.victim_eip.public_ip}
  RDP: mstsc /v:${aws_eip.victim_eip.public_ip}

qRadar ISO Transfer:
  scp -i ~/.ssh/purple-team-key files/750-QRADAR-QRFULL-2021.06.12.20250509154206.iso ec2-user@${aws_eip.siem_eip.public_ip}:/tmp/

Generated: ${timestamp()}
EOF
} 