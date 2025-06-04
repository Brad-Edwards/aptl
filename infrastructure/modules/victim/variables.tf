# SPDX-License-Identifier: BUSL-1.1

variable "subnet_id" {
  description = "ID of the subnet to deploy the victim instance"
  type        = string
}

variable "security_group_id" {
  description = "ID of the security group for the victim instance"
  type        = string
}

variable "victim_ami" {
  description = "AMI ID for the victim instance"
  type        = string
}

variable "victim_instance_type" {
  description = "Instance type for the victim machine"
  type        = string
  default     = "t3.micro"
}

variable "key_name" {
  description = "Name of the SSH key pair to use for the instance"
  type        = string
}

variable "siem_private_ip" {
  description = "Private IP of the SIEM instance for log forwarding (empty if SIEM disabled)"
  type        = string
  default     = ""
}

variable "project_name" {
  description = "Name of the project for resource tagging"
  type        = string
  default     = "aptl"
}

variable "environment" {
  description = "Environment name for resource tagging"
  type        = string
  default     = "lab"
} 