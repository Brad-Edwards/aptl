# SPDX-License-Identifier: BUSL-1.1

# SIEM Outputs
output "siem_public_ip" {
  description = "Public IP address of the SIEM instance"
  value       = aws_eip.siem_eip.public_ip
}

output "siem_private_ip" {
  description = "Private IP address of the SIEM instance"
  value       = aws_instance.siem.private_ip
}

output "siem_ssh_command" {
  description = "SSH command to connect to the SIEM instance"
  value       = "ssh -i ~/.ssh/${var.key_name} ec2-user@${aws_eip.siem_eip.public_ip}"
}

# Victim Outputs
output "victim_public_ip" {
  description = "Public IP address of the victim instance"
  value       = aws_eip.victim_eip.public_ip
}

output "victim_private_ip" {
  description = "Private IP address of the victim instance"
  value       = aws_instance.victim.private_ip
}

output "victim_ssh_command" {
  description = "SSH command to connect to the victim instance"
  value       = "ssh -i ~/.ssh/${var.key_name} ec2-user@${aws_eip.victim_eip.public_ip}"
}

output "victim_rdp_command" {
  description = "RDP command to connect to the victim instance (Windows)"
  value       = "mstsc /v:${aws_eip.victim_eip.public_ip}"
}

# Kali Outputs (conditional)
output "kali_public_ip" {
  description = "Public IP address of the Kali instance"
  value       = var.enable_kali ? aws_eip.kali_eip[0].public_ip : "N/A - Kali not enabled"
}

output "kali_private_ip" {
  description = "Private IP address of the Kali instance"
  value       = var.enable_kali ? aws_instance.kali[0].private_ip : "N/A - Kali not enabled"
}

output "kali_ssh_command" {
  description = "SSH command to connect to the Kali instance"
  value       = var.enable_kali ? "ssh -i ~/.ssh/${var.key_name} kali@${aws_eip.kali_eip[0].public_ip}" : "N/A - Kali not enabled"
}

# Lab Information
output "lab_connections_file" {
  description = "Path to the lab connections file"
  value       = "${path.module}/lab_connections.txt"
}
