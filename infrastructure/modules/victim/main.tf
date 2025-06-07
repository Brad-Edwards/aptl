# SPDX-License-Identifier: BUSL-1.1

# Victim Instance
resource "aws_instance" "victim" {
  ami           = var.victim_ami
  instance_type = var.victim_instance_type
  subnet_id     = var.subnet_id
  key_name      = var.key_name
  vpc_security_group_ids = [var.security_group_id]
  
  associate_public_ip_address = true

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/user_data.sh", {
    siem_private_ip = var.siem_private_ip
    siem_type       = var.siem_type
  })

  tags = {
    Name        = "${var.project_name}-victim"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_eip" "victim_eip" {
  instance = aws_instance.victim.id
  domain   = "vpc"

  tags = {
    Name        = "${var.project_name}-victim-eip"
    Project     = var.project_name
    Environment = var.environment
  }
} 