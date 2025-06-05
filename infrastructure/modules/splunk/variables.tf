# SPDX-License-Identifier: BUSL-1.1

variable "subnet_id" {
  description = "ID of the subnet to deploy the Splunk instance"
  type        = string
}

variable "security_group_id" {
  description = "ID of the security group for the Splunk instance"
  type        = string
}

variable "splunk_ami" {
  description = "AMI ID for the Splunk instance"
  type        = string
}

variable "splunk_instance_type" {
  description = "Instance type for the Splunk instance"
  type        = string
  default     = "c5.4xlarge"
}

variable "key_name" {
  description = "Name of the SSH key pair to use for the instance"
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