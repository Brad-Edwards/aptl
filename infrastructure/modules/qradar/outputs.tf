# SPDX-License-Identifier: BUSL-1.1

output "instance_id" {
  description = "ID of the qRadar instance"
  value       = aws_instance.qradar.id
}

output "private_ip" {
  description = "Private IP address of the qRadar instance"
  value       = aws_instance.qradar.private_ip
}

output "public_ip" {
  description = "Public IP address of the qRadar instance"
  value       = aws_eip.qradar_eip.public_ip
}

output "instance_type" {
  description = "Instance type of the qRadar instance"
  value       = aws_instance.qradar.instance_type
}

output "ssh_user" {
  description = "SSH username for the qRadar instance"
  value       = "ec2-user"
}

output "ports" {
  description = "Open ports for the qRadar instance"
  value = {
    ssh        = 22
    https      = 443
    syslog_udp = 514
    syslog_tcp = 514
  }
} 