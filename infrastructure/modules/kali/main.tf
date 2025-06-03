# SPDX-License-Identifier: BUSL-1.1

# Kali Instance
resource "aws_instance" "kali" {
  ami           = var.kali_ami
  instance_type = var.kali_instance_type
  subnet_id     = var.subnet_id
  key_name      = var.key_name

  vpc_security_group_ids = [var.security_group_id]

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/user_data.sh", {
    siem_private_ip   = var.siem_private_ip
    victim_private_ip = var.victim_private_ip
  })

  tags = {
    Name        = "${var.project_name}-kali"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_eip" "kali_eip" {
  instance = aws_instance.kali.id
  domain   = "vpc"

  tags = {
    Name        = "${var.project_name}-kali-eip"
    Project     = var.project_name
    Environment = var.environment
  }
} 