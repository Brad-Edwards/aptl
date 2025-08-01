# SPDX-License-Identifier: BUSL-1.1

output "capcom_victim_instance_id" {
  description = "ID of the Capcom CTF victim EC2 instance"
  value       = aws_instance.capcom_victim.id
}

output "capcom_victim_public_ip" {
  description = "Public IP address of the Capcom CTF victim instance"
  value       = aws_eip.capcom_victim_eip.public_ip
}

output "capcom_victim_private_ip" {
  description = "Private IP address of the Capcom CTF victim instance"
  value       = aws_instance.capcom_victim.private_ip
}