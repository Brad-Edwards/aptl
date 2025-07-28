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

  # Splunk web access (port 8000) - only when using Splunk
  dynamic "ingress" {
    for_each = var.siem_type == "splunk" ? [1] : []
    content {
      from_port   = 8000
      to_port     = 8000
      protocol    = "tcp"
      cidr_blocks = [var.allowed_ip]
    }
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

  # Splunk syslog (port 5514) from victim machine - only when using Splunk
  dynamic "ingress" {
    for_each = var.siem_type == "splunk" ? [1] : []
    content {
      from_port       = 5514
      to_port         = 5514
      protocol        = "udp"
      security_groups = [aws_security_group.victim_sg.id]
    }
  }

  # Splunk syslog TCP (port 5514) from victim machine - only when using Splunk
  dynamic "ingress" {
    for_each = var.siem_type == "splunk" ? [1] : []
    content {
      from_port       = 5514
      to_port         = 5514
      protocol        = "tcp"
      security_groups = [aws_security_group.victim_sg.id]
    }
  }

  # Splunk syslog (port 5514) from Kali machine - only when using Splunk
  dynamic "ingress" {
    for_each = var.siem_type == "splunk" ? [1] : []
    content {
      from_port       = 5514
      to_port         = 5514
      protocol        = "udp"
      security_groups = [aws_security_group.kali_sg.id]
    }
  }

  # Splunk syslog TCP (port 5514) from Kali machine - only when using Splunk
  dynamic "ingress" {
    for_each = var.siem_type == "splunk" ? [1] : []
    content {
      from_port       = 5514
      to_port         = 5514
      protocol        = "tcp"
      security_groups = [aws_security_group.kali_sg.id]
    }
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

  # Note: Cross-references to Kali SG handled by separate rules below

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

  # Note: Outbound rules to victim and SIEM handled by separate rules below

  tags = {
    Name        = "${var.project_name}-kali-sg"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Separate security group rules to avoid circular dependencies

# Kali -> Victim attacks
resource "aws_security_group_rule" "victim_allow_kali_attacks" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "-1"
  source_security_group_id = aws_security_group.kali_sg.id
  security_group_id        = aws_security_group.victim_sg.id
}

# Victim -> Kali responses
resource "aws_security_group_rule" "victim_respond_to_kali" {
  type                     = "egress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "-1"
  source_security_group_id = aws_security_group.kali_sg.id
  security_group_id        = aws_security_group.victim_sg.id
}

# Victim -> SIEM syslog UDP
resource "aws_security_group_rule" "victim_syslog_udp_to_siem" {
  type                     = "egress"
  from_port                = 514
  to_port                  = 514
  protocol                 = "udp"
  source_security_group_id = aws_security_group.siem_sg.id
  security_group_id        = aws_security_group.victim_sg.id
}

# Victim -> SIEM syslog TCP
resource "aws_security_group_rule" "victim_syslog_tcp_to_siem" {
  type                     = "egress"
  from_port                = 514
  to_port                  = 514
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.siem_sg.id
  security_group_id        = aws_security_group.victim_sg.id
}

# Kali -> Victim attacks
resource "aws_security_group_rule" "kali_attack_victim" {
  type                     = "egress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "-1"
  source_security_group_id = aws_security_group.victim_sg.id
  security_group_id        = aws_security_group.kali_sg.id
}

# Kali -> SIEM syslog UDP
resource "aws_security_group_rule" "kali_syslog_udp_to_siem" {
  type                     = "egress"
  from_port                = 514
  to_port                  = 514
  protocol                 = "udp"
  source_security_group_id = aws_security_group.siem_sg.id
  security_group_id        = aws_security_group.kali_sg.id
}

# Kali -> SIEM syslog TCP
resource "aws_security_group_rule" "kali_syslog_tcp_to_siem" {
  type                     = "egress"
  from_port                = 514
  to_port                  = 514
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.siem_sg.id
  security_group_id        = aws_security_group.kali_sg.id
}

# Lab Container Host Security Group
resource "aws_security_group" "lab_container_host_sg" {
  name        = "${var.project_name}-lab-container-host-sg"
  description = "Security group for lab container host"
  vpc_id      = aws_vpc.purple_team_vpc.id

  # SSH access from allowed IPs (host access)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }

  # Kali SSH access from allowed IPs (container access)
  ingress {
    from_port   = 2222
    to_port     = 2222
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }

  # Allow all outbound traffic for ECR pulls and container communication
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.project_name}-lab-container-host-sg"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Container -> Victim attacks (same as Kali -> Victim)
resource "aws_security_group_rule" "victim_allow_container_attacks" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "-1"
  source_security_group_id = aws_security_group.lab_container_host_sg.id
  security_group_id        = aws_security_group.victim_sg.id
}

# Container syslog to SIEM (UDP)
resource "aws_security_group_rule" "container_syslog_udp_to_siem" {
  type                     = "egress"
  from_port                = 514
  to_port                  = 5514
  protocol                 = "udp"
  source_security_group_id = aws_security_group.siem_sg.id
  security_group_id        = aws_security_group.lab_container_host_sg.id
}

# Container syslog to SIEM (TCP)
resource "aws_security_group_rule" "container_syslog_tcp_to_siem" {
  type                     = "egress"
  from_port                = 514
  to_port                  = 5514
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.siem_sg.id
  security_group_id        = aws_security_group.lab_container_host_sg.id
}