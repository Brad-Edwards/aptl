output "instance_public_ip" {
  description = "Public IP address of the Windows RE instance"
  value       = aws_eip.windows_re_eip.public_ip
}

output "rdp_connection_command" {
  description = "Command to connect via RDP"
  value       = "mstsc /v:${aws_eip.windows_re_eip.public_ip}"
}

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.windows_re.id
}
