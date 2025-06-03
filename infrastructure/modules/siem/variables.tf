# SPDX-License-Identifier: BUSL-1.1

variable "subnet_id" {
  description = "ID of the subnet to deploy the SIEM instance"
  type        = string
}

variable "security_group_id" {
  description = "ID of the security group for the SIEM instance"
  type        = string
}

variable "siem_ami" {
  description = "AMI ID for the qRadar SIEM instance"
  type        = string
}

variable "siem_instance_type" {
  description = "Instance type for the SIEM instance"
  type        = string
  default     = "t3a.2xlarge"
}

variable "key_name" {
  description = "Name of the SSH key pair to use for the instance"
  type        = string
}

variable "availability_zone" {
  description = "Availability zone for the EBS volume"
  type        = string
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