# SPDX-License-Identifier: BUSL-1.1

output "instance_id" {
  description = "ID of the victim instance"
  value       = aws_instance.victim.id
}

output "private_ip" {
  description = "Private IP address of the victim instance"
  value       = aws_instance.victim.private_ip
}

output "public_ip" {
  description = "Public IP address of the victim instance"
  value       = aws_eip.victim_eip.public_ip
}

output "instance_type" {
  description = "Instance type of the victim instance"
  value       = aws_instance.victim.instance_type
}

output "ssh_user" {
  description = "SSH username for the victim instance"
  value       = "ec2-user"
}

output "ports" {
  description = "Open ports for the victim instance"
  value = {
    ssh  = 22
    rdp  = 3389
    http = 80
  }
} 