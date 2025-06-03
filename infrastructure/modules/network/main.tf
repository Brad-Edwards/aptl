# SPDX-License-Identifier: BUSL-1.1

# VPC Configuration
resource "aws_vpc" "purple_team_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.project_name}-vpc"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Public Subnet
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.purple_team_vpc.id
  cidr_block              = var.subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.project_name}-public-subnet"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.purple_team_vpc.id

  tags = {
    Name        = "${var.project_name}-igw"
    Project     = var.project_name
    Environment = var.environment
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
    Name        = "${var.project_name}-public-rt"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Route Table Association
resource "aws_route_table_association" "public_rta" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# Security Group for SIEM
resource "aws_security_group" "siem_sg" {
  name        = "${var.project_name}-siem-sg"
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

  # Allow syslog from Kali machine
  ingress {
    from_port       = 514
    to_port         = 514
    protocol        = "udp"
    security_groups = [aws_security_group.kali_sg.id]
  }

  # Allow syslog TCP from Kali machine
  ingress {
    from_port       = 514
    to_port         = 514
    protocol        = "tcp"
    security_groups = [aws_security_group.kali_sg.id]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-siem-sg"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Security Group for Victim
resource "aws_security_group" "victim_sg" {
  name        = "${var.project_name}-victim-sg"
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

  # Allow all attacks from Kali
  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_security_group.kali_sg.id]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-victim-sg"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Security Group for Kali
resource "aws_security_group" "kali_sg" {
  name        = "${var.project_name}-kali-sg"
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
    Name        = "${var.project_name}-kali-sg"
    Project     = var.project_name
    Environment = var.environment
  }
} 