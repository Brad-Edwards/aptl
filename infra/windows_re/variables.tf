variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "your_ip_cidr" {
  description = "Your IP address in CIDR format for RDP access"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.large"
}

variable "disk_size_gb" {
  description = "Root disk size in GB"
  type        = number
  default     = 100
}

variable "admin_password" {
  description = "Administrator password for Windows instance"
  type        = string
  sensitive   = true
}

variable "public_key_path" {
  description = "Path to SSH public key file"
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}
