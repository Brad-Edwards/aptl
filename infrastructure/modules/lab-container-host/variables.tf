# SPDX-License-Identifier: BUSL-1.1

variable "subnet_id" {
  description = "ID of the subnet to deploy the lab container host"
  type        = string
}

variable "security_group_id" {
  description = "ID of the security group for the lab container host"
  type        = string
}

variable "lab_container_host_ami" {
  description = "AMI ID for the lab container host (Amazon Linux 2023)"
  type        = string
  default     = "ami-08a6efd148b1f7504" # Amazon Linux 2023 x86_64
}

variable "lab_container_host_instance_type" {
  description = "Instance type for the lab container host"
  type        = string
  default     = "t3.large"
}

variable "key_name" {
  description = "Name of the SSH key pair to use for the instance"
  type        = string
}

variable "ecr_repository_url" {
  description = "ECR repository URL for Kali container"
  type        = string
}

variable "siem_private_ip" {
  description = "Private IP of the SIEM instance (empty if SIEM disabled)"
  type        = string
  default     = ""
}

variable "victim_private_ip" {
  description = "Private IP of the victim instance (empty if victim disabled)"
  type        = string
  default     = ""
}

variable "siem_type" {
  description = "Type of SIEM being used (splunk or qradar)"
  type        = string
  default     = "splunk"
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

variable "aws_region" {
  description = "AWS region for ECR authentication"
  type        = string
}