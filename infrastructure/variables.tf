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
}

variable "key_name" {
  description = "Name of the SSH key pair to use for the instances"
  type        = string
}

# SIEM Selection Configuration
variable "siem_type" {
  description = "SIEM platform to deploy (splunk or qradar)"
  type        = string
  default     = "qradar"
  validation {
    condition     = contains(["splunk", "qradar"], var.siem_type)
    error_message = "siem_type must be either 'splunk' or 'qradar'."
  }
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

variable "qradar_ami" {
  description = "AMI ID for the qRadar instance"
  type        = string
}

variable "qradar_instance_type" {
  description = "Instance type for the qRadar instance"
  type        = string
  default     = "t3a.2xlarge"
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

variable "kali_ami" {
  description = "AMI ID for the Kali Linux instance"
  type        = string
}

variable "kali_ami_alias" {
  description = "Alias for the Kali Linux AMI"
  type        = string
}

variable "kali_product_code" {
  description = "Product code for the Kali Linux AMI"
  type        = string
}

variable "kali_instance_type" {
  description = "Instance type for the Kali Linux instance"
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

variable "enable_kali" {
  description = "Whether to create the Kali Linux instance for red team operations"
  type        = bool
  default     = true
}

variable "enable_siem" {
  description = "Whether to create a SIEM instance (type controlled by siem_type variable)"
  type        = bool
  default     = true
}

variable "enable_victim" {
  description = "Whether to create the victim instance for testing"
  type        = bool
  default     = true
}

# Lab Container Host Configuration
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

variable "enable_lab_container_host" {
  description = "Whether to create the lab container host for containerized deployments"
  type        = bool
  default     = true
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