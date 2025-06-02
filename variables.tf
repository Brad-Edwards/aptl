# SPDX-License-Identifier: BUSL-1.1

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
}

variable "subnet_cidr" {
  description = "CIDR block for the subnet"
  type        = string
}

variable "availability_zone" {
  description = "Availability zone for the subnet"
  type        = string
}

variable "allowed_ip" {
  description = "IP address allowed to access the instances (CIDR notation)"
  type        = string
  sensitive   = true
}

variable "key_name" {
  description = "Name of the SSH key pair to use for the instances"
  type        = string
}

variable "qradar_ami" {
  description = "AMI ID for the qRadar SIEM instance"
  type        = string
}

variable "splunk_ami" {
  description = "AMI ID for the Splunk SIEM instance"
  type        = string
  default     = ""
}

variable "siem_type" {
  description = "Which SIEM platform to deploy (qradar or splunk)"
  type        = string
  default     = "qradar"
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

variable "aws_profile" {
  description = "AWS CLI profile to use (optional, leave empty for default credentials)"
  type        = string
  default     = ""
}

# OpenAI API Configuration
variable "openai_api_key" {
  description = "OpenAI API key for AI-powered features"
  type        = string
  default     = ""
  sensitive   = true
}

variable "openai_model" {
  description = "OpenAI model to use (e.g., gpt-4, gpt-3.5-turbo)"
  type        = string
  default     = "gpt-4"
}

# Claude/Anthropic API Configuration
variable "anthropic_api_key" {
  description = "Anthropic API key for Claude AI features"
  type        = string
  default     = ""
  sensitive   = true
}

variable "claude_model" {
  description = "Claude model to use (e.g., claude-3-sonnet-20240229, claude-3-haiku-20240307)"
  type        = string
  default     = "claude-3-sonnet-20240229"
} 