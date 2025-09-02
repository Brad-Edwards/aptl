terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = "CatalystGlobalAdministrator-764508635290"
}

# Data source for Windows AMI (Server 2022 - closest to modern Windows for exploit dev)
data "aws_ami" "windows" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# VPC
resource "aws_vpc" "windows_re_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "windows-re-vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "windows_re_igw" {
  vpc_id = aws_vpc.windows_re_vpc.id

  tags = {
    Name = "windows-re-igw"
  }
}

# Public Subnet
resource "aws_subnet" "windows_re_public" {
  vpc_id                  = aws_vpc.windows_re_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "windows-re-public-subnet"
  }
}

# Route Table
resource "aws_route_table" "windows_re_public" {
  vpc_id = aws_vpc.windows_re_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.windows_re_igw.id
  }

  tags = {
    Name = "windows-re-public-rt"
  }
}

# Route Table Association
resource "aws_route_table_association" "windows_re_public" {
  subnet_id      = aws_subnet.windows_re_public.id
  route_table_id = aws_route_table.windows_re_public.id
}

# Security Group
resource "aws_security_group" "windows_re_sg" {
  name        = "windows-re-sg"
  description = "Security group for Windows RE box"
  vpc_id      = aws_vpc.windows_re_vpc.id

  # RDP access from your IP
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.your_ip_cidr]
  }

  # HTTP for downloads if needed
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.your_ip_cidr]
  }

  # HTTPS for downloads if needed
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.your_ip_cidr]
  }

  # WinRM HTTP for remote PowerShell
  ingress {
    from_port   = 5985
    to_port     = 5985
    protocol    = "tcp"
    cidr_blocks = [var.your_ip_cidr]
  }

  # WinRM HTTPS for secure remote PowerShell
  ingress {
    from_port   = 5986
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = [var.your_ip_cidr]
  }

  # SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.your_ip_cidr]
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "windows-re-sg"
  }
}

# Key Pair
resource "aws_key_pair" "windows_re_key" {
  key_name   = "windows-re-key"
  public_key = file(var.public_key_path)
}

# EC2 Instance
resource "aws_instance" "windows_re" {
  ami                    = data.aws_ami.windows.id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.windows_re_key.key_name
  vpc_security_group_ids = [aws_security_group.windows_re_sg.id]
  subnet_id              = aws_subnet.windows_re_public.id

  root_block_device {
    volume_type = "gp3"
    volume_size = var.disk_size_gb
    encrypted   = true
  }

  user_data = base64encode(templatefile("${path.module}/user_data.ps1", {
    admin_password = var.admin_password
  }))

  tags = {
    Name = "windows-re-box"
  }
}

# Elastic IP
resource "aws_eip" "windows_re_eip" {
  instance = aws_instance.windows_re.id
  domain   = "vpc"

  tags = {
    Name = "windows-re-eip"
  }
}
