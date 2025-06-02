# SPDX-License-Identifier: BUSL-1.1

output "siem_public_ip" {
  description = "Public IP address of the SIEM instance"
  value       = aws_eip.siem_eip.public_ip
}

output "victim_public_ip" {
  description = "Public IP address of the victim instance"
  value       = aws_eip.victim_eip.public_ip
}

output "siem_ssh_command" {
  description = "SSH command to connect to the SIEM instance"
  value       = "ssh -i ${var.key_name}.pem ec2-user@${aws_eip.siem_eip.public_ip}"
}

output "victim_ssh_command" {
  description = "SSH command to connect to the victim instance"
  value       = "ssh -i ${var.key_name}.pem ec2-user@${aws_eip.victim_eip.public_ip}"
}

output "victim_rdp_command" {
  description = "RDP command to connect to the victim instance (Windows)"
  value       = "mstsc /v:${aws_eip.victim_eip.public_ip}"
} 