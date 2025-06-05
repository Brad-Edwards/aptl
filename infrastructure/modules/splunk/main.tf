# SPDX-License-Identifier: BUSL-1.1

# Splunk Instance
resource "aws_instance" "splunk" {
  ami           = var.splunk_ami
  instance_type = var.splunk_instance_type
  subnet_id     = var.subnet_id
  key_name      = var.key_name

  vpc_security_group_ids = [var.security_group_id]

  associate_public_ip_address = true

  root_block_device {
    volume_size = 100  # Sufficient for Splunk Enterprise
    volume_type = "gp3"
  }

  user_data = file("${path.module}/user_data.sh")

  tags = {
    Name        = "${var.project_name}-splunk"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_eip" "splunk_eip" {
  instance = aws_instance.splunk.id
  domain   = "vpc"

  tags = {
    Name        = "${var.project_name}-splunk-eip"
    Project     = var.project_name
    Environment = var.environment
  }
} 