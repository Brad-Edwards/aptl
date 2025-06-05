# SPDX-License-Identifier: BUSL-1.1

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.purple_team_vpc.id
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.purple_team_vpc.cidr_block
}

output "subnet_id" {
  description = "ID of the public subnet"
  value       = aws_subnet.public_subnet.id
}

output "subnet_cidr" {
  description = "CIDR block of the public subnet"
  value       = aws_subnet.public_subnet.cidr_block
}

output "siem_security_group_id" {
  description = "ID of the SIEM security group"
  value       = aws_security_group.siem_sg.id
}

output "victim_security_group_id" {
  description = "ID of the victim security group"
  value       = aws_security_group.victim_sg.id
}

output "kali_security_group_id" {
  description = "ID of the Kali security group"
  value       = aws_security_group.kali_sg.id
} 