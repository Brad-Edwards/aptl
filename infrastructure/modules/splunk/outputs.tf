# SPDX-License-Identifier: BUSL-1.1

output "instance_id" {
  description = "ID of the Splunk instance"
  value       = aws_instance.splunk.id
}

output "private_ip" {
  description = "Private IP address of the Splunk instance"
  value       = aws_instance.splunk.private_ip
}

output "public_ip" {
  description = "Public IP address of the Splunk instance"
  value       = aws_eip.splunk_eip.public_ip
}

output "instance_type" {
  description = "Instance type of the Splunk instance"
  value       = aws_instance.splunk.instance_type
}

output "ssh_user" {
  description = "SSH username for the Splunk instance"
  value       = "ec2-user"
}

output "ports" {
  description = "Open ports for the Splunk instance"
  value = {
    ssh          = 22
    https        = 443
    splunk_web   = 8000
    splunk_mgmt  = 8089
    forwarder    = 9997
    syslog_udp   = 514
    syslog_tcp   = 514
  }
} 