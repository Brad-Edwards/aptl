# SPDX-License-Identifier: BUSL-1.1

variable "capcom_victim_ami" {
  description = "AMI ID for the Capcom CTF victim instance"
  type        = string
}

variable "capcom_victim_instance_type" {
  description = "Instance type for the Capcom CTF victim instance"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID where the Capcom victim will be deployed"
  type        = string
}

variable "security_group_id" {
  description = "Security group ID for the Capcom victim"
  type        = string
}

variable "key_name" {
  description = "Name of the SSH key pair to use for the instance"
  type        = string
}

variable "siem_private_ip" {
  description = "Private IP address of the SIEM server"
  type        = string
}

variable "siem_type" {
  description = "Type of SIEM being used (splunk or qradar)"
  type        = string
}

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "aptl"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "lab"
}

variable "capcom_admin_password" {
  description = "Administrator password for the Capcom CTF victim"
  type        = string
  sensitive   = true
}

variable "capcom_ctf_password" {
  description = "CTF player password for the Capcom CTF victim"
  type        = string
  sensitive   = true
}