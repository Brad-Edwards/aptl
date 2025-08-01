# SPDX-License-Identifier: BUSL-1.1

# Capcom CTF Victim Instance
resource "aws_instance" "capcom_victim" {
  ami           = var.capcom_victim_ami
  instance_type = var.capcom_victim_instance_type
  subnet_id     = var.subnet_id
  key_name      = var.key_name
  vpc_security_group_ids = [var.security_group_id]
  
  associate_public_ip_address = true

  root_block_device {
    volume_size = 50
    volume_type = "gp3"
  }

  user_data = templatefile("${path.module}/user_data.ps1", {
    siem_private_ip = var.siem_private_ip
    siem_type       = var.siem_type
  })

  tags = {
    Name        = "${var.project_name}-capcom-ctf-victim"
    Project     = var.project_name
    Environment = var.environment
    CTF         = "capcom-driver-exploit"
  }
}

resource "aws_eip" "capcom_victim_eip" {
  instance = aws_instance.capcom_victim.id
  domain   = "vpc"

  tags = {
    Name        = "${var.project_name}-capcom-victim-eip"
    Project     = var.project_name
    Environment = var.environment
  }
}