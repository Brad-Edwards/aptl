# SPDX-License-Identifier: BUSL-1.1

output "instance_id" {
  description = "ID of the Kali instance"
  value       = aws_instance.kali.id
}

output "private_ip" {
  description = "Private IP address of the Kali instance"
  value       = aws_instance.kali.private_ip
}

output "public_ip" {
  description = "Public IP address of the Kali instance"
  value       = aws_eip.kali_eip.public_ip
}

output "instance_type" {
  description = "Instance type of the Kali instance"
  value       = aws_instance.kali.instance_type
}

output "ssh_user" {
  description = "SSH username for the Kali instance"
  value       = "kali"
}

output "ports" {
  description = "Open ports for the Kali instance"
  value = {
    ssh = 22
  }
} 