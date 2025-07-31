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

  # Allow syslog from lab container host
  ingress {
    from_port       = 514
    to_port         = 514
    protocol        = "udp"
    security_groups = [aws_security_group.lab_container_host_sg.id]
  }

  # Allow syslog TCP from lab container host
  ingress {
    from_port       = 514
    to_port         = 514
    protocol        = "tcp"
    security_groups = [aws_security_group.lab_container_host_sg.id]
  }

  # Splunk syslog (port 5514) from lab container host - only when using Splunk
  dynamic "ingress" {
    for_each = var.siem_type == "splunk" ? [1] : []
    content {
      from_port       = 5514
      to_port         = 5514
      protocol        = "udp"
      security_groups = [aws_security_group.lab_container_host_sg.id]
    }
  }

  # Splunk syslog TCP (port 5514) from lab container host - only when using Splunk
  dynamic "ingress" {
    for_each = var.siem_type == "splunk" ? [1] : []
    content {
      from_port       = 5514
      to_port         = 5514
      protocol        = "tcp"
      security_groups = [aws_security_group.lab_container_host_sg.id]
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

  # Admin access from allowed IPs - all TCP ports for any scenario
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }

  # Admin access from allowed IPs - all UDP ports for any scenario
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    cidr_blocks = [var.allowed_ip]
  }

  # Admin access - ICMP (ping, traceroute, network diagnostics)
  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [var.allowed_ip]
  }

  # Admin access - ESP (IPSec VPN)
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "50"
    cidr_blocks = [var.allowed_ip]
  }

  # Admin access - AH (IPSec Authentication Header)
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "51"
    cidr_blocks = [var.allowed_ip]
  }

  # Admin access - GRE (Generic Routing Encapsulation)
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "47"
    cidr_blocks = [var.allowed_ip]
  }

  # Admin access from allowed IPs - ICMP for ping/traceroute
  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = [var.allowed_ip]
  }

  # Network isolation: No direct internet access for victim
  # Specific egress rules for SIEM and internal communication handled separately below

  # Allow egress for admin SSH responses only
  egress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ip]
  }

  # Note: Web and RDP traffic handled by bidirectional Kali <-> Victim rules

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

  # Network isolation: No direct internet access for Kali
  # Specific egress rules for victim attacks and SIEM communication handled separately below

  # Allow egress for admin SSH responses
  egress {
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

# Kali -> Victim attacks (TCP)
resource "aws_security_group_rule" "victim_allow_kali_attacks_tcp" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.kali_sg.id
  security_group_id        = aws_security_group.victim_sg.id
}

# Kali -> Victim attacks (UDP)
resource "aws_security_group_rule" "victim_allow_kali_attacks_udp" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "udp"
  source_security_group_id = aws_security_group.kali_sg.id
  security_group_id        = aws_security_group.victim_sg.id
}

# Kali -> Victim attacks (ICMP)
resource "aws_security_group_rule" "victim_allow_kali_attacks_icmp" {
  type                     = "ingress"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = aws_security_group.kali_sg.id
  security_group_id        = aws_security_group.victim_sg.id
}

# Kali -> Victim attacks (ESP - IPSec)
resource "aws_security_group_rule" "victim_allow_kali_attacks_esp" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "50"
  source_security_group_id = aws_security_group.kali_sg.id
  security_group_id        = aws_security_group.victim_sg.id
}

# Kali -> Victim attacks (AH - IPSec)
resource "aws_security_group_rule" "victim_allow_kali_attacks_ah" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "51"
  source_security_group_id = aws_security_group.kali_sg.id
  security_group_id        = aws_security_group.victim_sg.id
}

# Kali -> Victim attacks (GRE)
resource "aws_security_group_rule" "victim_allow_kali_attacks_gre" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "47"
  source_security_group_id = aws_security_group.kali_sg.id
  security_group_id        = aws_security_group.victim_sg.id
}

# Victim -> Kali responses (TCP)
resource "aws_security_group_rule" "victim_respond_to_kali_tcp" {
  type                     = "egress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.kali_sg.id
  security_group_id        = aws_security_group.victim_sg.id
}

# Victim -> Kali responses (UDP)
resource "aws_security_group_rule" "victim_respond_to_kali_udp" {
  type                     = "egress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "udp"
  source_security_group_id = aws_security_group.kali_sg.id
  security_group_id        = aws_security_group.victim_sg.id
}

# Victim -> Kali responses (ICMP)
resource "aws_security_group_rule" "victim_respond_to_kali_icmp" {
  type                     = "egress"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = aws_security_group.kali_sg.id
  security_group_id        = aws_security_group.victim_sg.id
}

# Victim -> Kali responses (ESP)
resource "aws_security_group_rule" "victim_respond_to_kali_esp" {
  type                     = "egress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "50"
  source_security_group_id = aws_security_group.kali_sg.id
  security_group_id        = aws_security_group.victim_sg.id
}

# Victim -> Kali responses (AH)
resource "aws_security_group_rule" "victim_respond_to_kali_ah" {
  type                     = "egress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "51"
  source_security_group_id = aws_security_group.kali_sg.id
  security_group_id        = aws_security_group.victim_sg.id
}

# Victim -> Kali responses (GRE)
resource "aws_security_group_rule" "victim_respond_to_kali_gre" {
  type                     = "egress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "47"
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

# Victim -> SIEM Splunk syslog UDP (port 5514) - only when using Splunk
resource "aws_security_group_rule" "victim_splunk_syslog_udp_to_siem" {
  count                    = var.siem_type == "splunk" ? 1 : 0
  type                     = "egress"
  from_port                = 5514
  to_port                  = 5514
  protocol                 = "udp"
  source_security_group_id = aws_security_group.siem_sg.id
  security_group_id        = aws_security_group.victim_sg.id
}

# Victim -> SIEM Splunk syslog TCP (port 5514) - only when using Splunk
resource "aws_security_group_rule" "victim_splunk_syslog_tcp_to_siem" {
  count                    = var.siem_type == "splunk" ? 1 : 0
  type                     = "egress"
  from_port                = 5514
  to_port                  = 5514
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.siem_sg.id
  security_group_id        = aws_security_group.victim_sg.id
}

# Kali -> Victim attacks (TCP)
resource "aws_security_group_rule" "kali_attack_victim_tcp" {
  type                     = "egress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.victim_sg.id
  security_group_id        = aws_security_group.kali_sg.id
}

# Kali -> Victim attacks (UDP)
resource "aws_security_group_rule" "kali_attack_victim_udp" {
  type                     = "egress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "udp"
  source_security_group_id = aws_security_group.victim_sg.id
  security_group_id        = aws_security_group.kali_sg.id
}

# Kali -> Victim attacks (ICMP)
resource "aws_security_group_rule" "kali_attack_victim_icmp" {
  type                     = "egress"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = aws_security_group.victim_sg.id
  security_group_id        = aws_security_group.kali_sg.id
}

# Kali -> Victim attacks (ESP)
resource "aws_security_group_rule" "kali_attack_victim_esp" {
  type                     = "egress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "50"
  source_security_group_id = aws_security_group.victim_sg.id
  security_group_id        = aws_security_group.kali_sg.id
}

# Kali -> Victim attacks (AH)
resource "aws_security_group_rule" "kali_attack_victim_ah" {
  type                     = "egress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "51"
  source_security_group_id = aws_security_group.victim_sg.id
  security_group_id        = aws_security_group.kali_sg.id
}

# Kali -> Victim attacks (GRE)
resource "aws_security_group_rule" "kali_attack_victim_gre" {
  type                     = "egress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "47"
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

# Kali -> SIEM Splunk syslog UDP (port 5514) - only when using Splunk
resource "aws_security_group_rule" "kali_splunk_syslog_udp_to_siem" {
  count                    = var.siem_type == "splunk" ? 1 : 0
  type                     = "egress"
  from_port                = 5514
  to_port                  = 5514
  protocol                 = "udp"
  source_security_group_id = aws_security_group.siem_sg.id
  security_group_id        = aws_security_group.kali_sg.id
}

# Kali -> SIEM Splunk syslog TCP (port 5514) - only when using Splunk
resource "aws_security_group_rule" "kali_splunk_syslog_tcp_to_siem" {
  count                    = var.siem_type == "splunk" ? 1 : 0
  type                     = "egress"
  from_port                = 5514
  to_port                  = 5514
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

# Victim -> Kali reverse shells (TCP)
resource "aws_security_group_rule" "kali_allow_victim_reverse_shells_tcp" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.victim_sg.id
  security_group_id        = aws_security_group.kali_sg.id
}

# Victim -> Kali reverse shells (UDP)
resource "aws_security_group_rule" "kali_allow_victim_reverse_shells_udp" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 65535
  protocol                 = "udp"
  source_security_group_id = aws_security_group.victim_sg.id
  security_group_id        = aws_security_group.kali_sg.id
}

# Victim -> Kali reverse shells (ICMP)
resource "aws_security_group_rule" "kali_allow_victim_reverse_shells_icmp" {
  type                     = "ingress"
  from_port                = -1
  to_port                  = -1
  protocol                 = "icmp"
  source_security_group_id = aws_security_group.victim_sg.id
  security_group_id        = aws_security_group.kali_sg.id
}

# Victim -> Kali reverse shells (ESP)
resource "aws_security_group_rule" "kali_allow_victim_reverse_shells_esp" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "50"
  source_security_group_id = aws_security_group.victim_sg.id
  security_group_id        = aws_security_group.kali_sg.id
}

# Victim -> Kali reverse shells (AH)
resource "aws_security_group_rule" "kali_allow_victim_reverse_shells_ah" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "51"
  source_security_group_id = aws_security_group.victim_sg.id
  security_group_id        = aws_security_group.kali_sg.id
}

# Victim -> Kali reverse shells (GRE)
resource "aws_security_group_rule" "kali_allow_victim_reverse_shells_gre" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "47"
  source_security_group_id = aws_security_group.victim_sg.id
  security_group_id        = aws_security_group.kali_sg.id
}

# Victim -> Lab Container Host reverse shells
resource "aws_security_group_rule" "container_host_allow_victim_reverse_shells" {
  type                     = "ingress"
  from_port                = 0
  to_port                  = 0
  protocol                 = "-1"
  source_security_group_id = aws_security_group.victim_sg.id
  security_group_id        = aws_security_group.lab_container_host_sg.id
}