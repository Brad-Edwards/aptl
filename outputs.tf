# SPDX-License-Identifier: BUSL-1.1

# SIEM Outputs
output "siem_public_ip" {
  description = "Public IP address of the SIEM instance"
  value       = var.enable_siem ? aws_eip.siem_eip[0].public_ip : null
}

output "siem_private_ip" {
  description = "Private IP address of the SIEM instance"
  value       = var.enable_siem ? aws_instance.siem[0].private_ip : null
}

output "siem_ssh_command" {
  description = "SSH command to connect to the SIEM instance"
  value       = var.enable_siem ? "ssh -i ~/.ssh/${var.key_name} ec2-user@${aws_eip.siem_eip[0].public_ip}" : "N/A - SIEM not enabled"
}

# Victim Outputs
output "victim_public_ip" {
  description = "Public IP address of the victim instance"
  value       = var.enable_victim ? aws_eip.victim_eip[0].public_ip : null
}

output "victim_private_ip" {
  description = "Private IP address of the victim instance"
  value       = var.enable_victim ? aws_instance.victim[0].private_ip : null
}

output "victim_ssh_command" {
  description = "SSH command to connect to the victim instance"
  value       = var.enable_victim ? "ssh -i ~/.ssh/${var.key_name} ec2-user@${aws_eip.victim_eip[0].public_ip}" : "N/A - Victim not enabled"
}

output "victim_rdp_command" {
  description = "RDP command to connect to the victim instance (Windows)"
  value       = var.enable_victim ? "mstsc /v:${aws_eip.victim_eip[0].public_ip}" : "N/A - Victim not enabled"
}

# Kali Outputs (conditional)
output "kali_public_ip" {
  description = "Public IP address of the Kali instance (if enabled)"
  value       = var.enable_kali ? aws_eip.kali_eip[0].public_ip : null
}

output "kali_private_ip" {
  description = "Private IP address of the Kali instance (if enabled)"
  value       = var.enable_kali ? aws_instance.kali[0].private_ip : null
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

output "ssh_key_name" {
  description = "Name of the SSH key used for the instances"
  value       = var.key_name
}

output "vpc_cidr" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.purple_team_vpc.cidr_block
}

output "allowed_ip" {
  description = "Allowed IP address for accessing the instances"
  value       = var.allowed_ip
  sensitive   = true
}

# New JSON configuration output for MCP server
output "lab_config_json" {
  description = "Lab configuration in JSON format for MCP server"
  value = jsonencode({
    version   = "1.0"
    generated = timestamp()
    lab = {
      name     = "APTL Purple Team Lab"
      vpc_cidr = aws_vpc.purple_team_vpc.cidr_block
      project  = var.project_name
      environment = var.environment
    }
    instances = {
      siem = var.enable_siem ? {
        public_ip  = aws_eip.siem_eip[0].public_ip
        private_ip = aws_instance.siem[0].private_ip
        ssh_key    = "~/.ssh/${var.key_name}"
        ssh_user   = "ec2-user"
        instance_type = var.siem_instance_type
        enabled    = true
        ports = {
          ssh   = 22
          https = 443
          syslog_udp = 514
          syslog_tcp = 514
        }
      } : {
        enabled = false
      }
      victim = var.enable_victim ? {
        public_ip  = aws_eip.victim_eip[0].public_ip
        private_ip = aws_instance.victim[0].private_ip
        ssh_key    = "~/.ssh/${var.key_name}"
        ssh_user   = "ec2-user"
        instance_type = var.victim_instance_type
        enabled    = true
        ports = {
          ssh = 22
          rdp = 3389
          http = 80
        }
      } : {
        enabled = false
      }
      kali = var.enable_kali ? {
        public_ip  = aws_eip.kali_eip[0].public_ip
        private_ip = aws_instance.kali[0].private_ip
        ssh_key    = "~/.ssh/${var.key_name}"
        ssh_user   = "kali"
        instance_type = var.kali_instance_type
        enabled    = true
        ports = {
          ssh = 22
        }
      } : {
        enabled = false
      }
    }
    network = {
      vpc_cidr    = aws_vpc.purple_team_vpc.cidr_block
      subnet_cidr = aws_subnet.public_subnet.cidr_block
      allowed_ip  = var.allowed_ip
    }
    mcp = {
      server_name       = "kali-red-team"
      allowed_targets   = [aws_subnet.public_subnet.cidr_block]
      max_session_time  = 3600
      audit_enabled     = true
      log_level        = "info"
    }
  })
  sensitive = true
}

# Legacy connection info output
output "connection_info" {
  description = "Connection information for all instances"
  value = <<-EOF
Purple Team Lab Connection Info
===============================

SIEM Instance:
  IP: ${aws_eip.siem_eip.public_ip}
  Private IP: ${aws_instance.siem.private_ip}
  SSH: ssh -i ~/.ssh/${var.key_name} ec2-user@${aws_eip.siem_eip.public_ip}
  HTTPS: https://${aws_eip.siem_eip.public_ip}

Victim Instance:
  IP: ${aws_eip.victim_eip.public_ip}
  Private IP: ${aws_instance.victim.private_ip}
  SSH: ssh -i ~/.ssh/${var.key_name} ec2-user@${aws_eip.victim_eip.public_ip}
  RDP: mstsc /v:${aws_eip.victim_eip.public_ip}

${var.enable_kali ? "Kali Instance:\n  IP: ${aws_eip.kali_eip[0].public_ip}\n  Private IP: ${aws_instance.kali[0].private_ip}\n  SSH: ssh -i ~/.ssh/${var.key_name} kali@${aws_eip.kali_eip[0].public_ip}\n" : "Kali Instance: Not enabled"}

Generated: ${timestamp()}
EOF
}
