# SPDX-License-Identifier: BUSL-1.1

# IAM role for ECR access
resource "aws_iam_role" "lab_container_host_role" {
  name = "${var.project_name}-lab-container-host-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-lab-container-host-role"
    Project     = var.project_name
    Environment = var.environment
  }
}

# IAM policy for ECR access
resource "aws_iam_role_policy" "lab_container_host_ecr_policy" {
  name = "${var.project_name}-lab-container-host-ecr-policy"
  role = aws_iam_role.lab_container_host_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = "*"
      }
    ]
  })
}

# Instance profile for the role
resource "aws_iam_instance_profile" "lab_container_host_profile" {
  name = "${var.project_name}-lab-container-host-profile"
  role = aws_iam_role.lab_container_host_role.name

  tags = {
    Name        = "${var.project_name}-lab-container-host-profile"
    Project     = var.project_name
    Environment = var.environment
  }
}

# Lab Container Host Instance
resource "aws_instance" "lab_container_host" {
  ami           = var.lab_container_host_ami
  instance_type = var.lab_container_host_instance_type
  subnet_id     = var.subnet_id
  key_name      = var.key_name

  vpc_security_group_ids = [var.security_group_id]
  iam_instance_profile   = aws_iam_instance_profile.lab_container_host_profile.name

  root_block_device {
    volume_size = 50
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/user_data.sh", {
    ecr_repository_url = var.ecr_repository_url
    siem_private_ip    = var.siem_private_ip
    victim_private_ip  = var.victim_private_ip
    siem_type          = var.siem_type
  })

  tags = {
    Name        = "${var.project_name}-lab-container-host"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_eip" "lab_container_host_eip" {
  instance = aws_instance.lab_container_host.id
  domain   = "vpc"

  tags = {
    Name        = "${var.project_name}-lab-container-host-eip"
    Project     = var.project_name
    Environment = var.environment
  }
}