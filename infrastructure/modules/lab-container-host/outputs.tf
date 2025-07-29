# SPDX-License-Identifier: BUSL-1.1

output "public_ip" {
  description = "Public IP address of the lab container host"
  value       = aws_eip.lab_container_host_eip.public_ip
}

output "private_ip" {
  description = "Private IP address of the lab container host"
  value       = aws_instance.lab_container_host.private_ip
}

output "instance_id" {
  description = "Instance ID of the lab container host"
  value       = aws_instance.lab_container_host.id
}

output "ssh_user" {
  description = "SSH user for the lab container host"
  value       = "ec2-user"
}

output "instance_type" {
  description = "Instance type of the lab container host"
  value       = aws_instance.lab_container_host.instance_type
}

output "ports" {
  description = "Open ports on the lab container host"
  value = {
    ssh           = 22
    kali_ssh      = 2222
    docker_daemon = 2376
  }
}