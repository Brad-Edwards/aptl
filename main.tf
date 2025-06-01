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

  # Note: The ISO file (750-QRADAR-QRFULL-2021.06.12.20250509154206.iso) needs to be manually transferred
  # to the instance after it's created. You can use:
  # scp -i <key>.pem 750-QRADAR-QRFULL-2021.06.12.20250509154206.iso ec2-user@<instance-ip>:/tmp/

  user_data = <<-EOF
              #!/bin/bash
              # Update system
              sudo dnf update -y
              
              # Install required packages
              sudo dnf install -y wget
              
              # Baseline OS configuration for qRadar
              sudo hostnamectl set-hostname qradar.local
              
              # Add hostname to /etc/hosts using private IP
              PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
              echo "$PRIVATE_IP qradar.local" | sudo tee -a /etc/hosts
              
              # Disable SELinux
              sudo setenforce 0
              sudo sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
              
              # Setup swap (8GB)
              sudo swapoff -a
              sudo dd if=/dev/zero of=/swap bs=1M count=8192
              sudo mkswap /swap
              sudo swapon /swap
              echo '/swap swap swap defaults 0 0' | sudo tee -a /etc/fstab
              
              # Create qRadar installation script for after ISO transfer
              cat > /home/ec2-user/install_qradar.sh << 'EOFSCRIPT'
              #!/bin/bash
              sudo mkdir -p /iso
              sudo mount -o loop /tmp/750-QRADAR-QRFULL-2021.06.12.20250509154206.iso /iso
              cd /iso
              sudo ./setup
              EOFSCRIPT
              chmod +x /home/ec2-user/install_qradar.sh
              EOF

  tags = {
    Name = "qradar-siem"
    Project = "purple-team-lab"
    Environment = "poc"
  }
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