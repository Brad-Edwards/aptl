# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.4"
    }
  }
  required_version = ">= 1.2.0"
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile != "" ? var.aws_profile : null
}

# Generate UUID for unique bucket naming to prevent enumeration
resource "random_uuid" "bucket_suffix" {}

# S3 bucket for main infrastructure Terraform state
resource "aws_s3_bucket" "aptl_main" {
  bucket = "aptl-main-${random_uuid.bucket_suffix.result}"
  
  tags = {
    Name        = "APTL Main Infrastructure State"
    Environment = var.environment
    Purpose     = "terraform-state"
  }
}

resource "aws_s3_bucket_versioning" "aptl_main_versioning" {
  bucket = aws_s3_bucket.aptl_main.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "aptl_main_encryption" {
  bucket = aws_s3_bucket.aptl_main.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "aptl_main_pab" {
  bucket = aws_s3_bucket.aptl_main.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# DynamoDB table for state locking
resource "aws_dynamodb_table" "aptl_main_locks" {
  name           = "aptl-main-locks-${random_uuid.bucket_suffix.result}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    Name        = "APTL Main Infrastructure Terraform Locks"
    Environment = var.environment
  }
}

# Data source for bootstrap remote state
data "terraform_remote_state" "bootstrap" {
  backend = "s3"
  config = {
    bucket = "aptl-bootstrap-7a62a0d4-83fe-d271-b97c-c2d81acdf082"
    key    = "terraform.tfstate"
    region = var.aws_region
  }
}


# Local values for dynamic SIEM selection
locals {
  # Get ECR repository URL from bootstrap remote state
  ecr_repository_url = try(data.terraform_remote_state.bootstrap.outputs.ecr_repository_url, "")

  # Determine which SIEM is active and get its outputs
  active_siem = var.enable_siem ? (
    var.siem_type == "splunk" && length(module.splunk) > 0 ? {
      private_ip    = module.splunk[0].private_ip
      public_ip     = module.splunk[0].public_ip
      instance_id   = module.splunk[0].instance_id
      ssh_user      = module.splunk[0].ssh_user
      instance_type = module.splunk[0].instance_type
      ports         = module.splunk[0].ports
    } : var.siem_type == "qradar" && length(module.qradar) > 0 ? {
      private_ip    = module.qradar[0].private_ip
      public_ip     = module.qradar[0].public_ip
      instance_id   = module.qradar[0].instance_id
      ssh_user      = module.qradar[0].ssh_user
      instance_type = module.qradar[0].instance_type
      ports         = module.qradar[0].ports
    } : null
  ) : null

  siem_private_ip = local.active_siem != null ? local.active_siem.private_ip : ""
}

# Network module - always deployed
module "network" {
  source = "./modules/network"

  vpc_cidr          = var.vpc_cidr
  subnet_cidr       = var.subnet_cidr
  availability_zone = var.availability_zone
  allowed_ip        = var.allowed_ip
  project_name      = var.project_name
  environment       = var.environment
  siem_type         = var.siem_type
}

# Splunk module - conditional
module "splunk" {
  count  = var.enable_siem && var.siem_type == "splunk" ? 1 : 0
  source = "./modules/splunk"

  subnet_id           = module.network.subnet_id
  security_group_id   = module.network.siem_security_group_id
  splunk_ami          = var.splunk_ami
  splunk_instance_type = var.splunk_instance_type
  key_name            = var.key_name
  project_name        = var.project_name
  environment         = var.environment
}

# qRadar module - conditional
module "qradar" {
  count  = var.enable_siem && var.siem_type == "qradar" ? 1 : 0
  source = "./modules/qradar"

  subnet_id             = module.network.subnet_id
  security_group_id     = module.network.siem_security_group_id
  qradar_ami            = var.qradar_ami
  qradar_instance_type  = var.qradar_instance_type
  key_name              = var.key_name
  availability_zone     = var.availability_zone
  project_name          = var.project_name
  environment           = var.environment
}

# Victim module - conditional
module "victim" {
  count  = var.enable_victim ? 1 : 0
  source = "./modules/victim"

  subnet_id             = module.network.subnet_id
  security_group_id     = module.network.victim_security_group_id
  victim_ami            = var.victim_ami
  victim_instance_type  = var.victim_instance_type
  key_name              = var.key_name
  siem_private_ip       = local.siem_private_ip
  siem_type             = var.siem_type
  project_name          = var.project_name
  environment           = var.environment
}

# Kali module - conditional
module "kali" {
  count  = var.enable_kali ? 1 : 0
  source = "./modules/kali"

  subnet_id           = module.network.subnet_id
  security_group_id   = module.network.kali_security_group_id
  kali_ami            = var.kali_ami
  kali_instance_type  = var.kali_instance_type
  key_name            = var.key_name
  siem_private_ip     = local.siem_private_ip
  victim_private_ip   = var.enable_victim ? module.victim[0].private_ip : ""
  siem_type           = var.siem_type
  project_name        = var.project_name
  environment         = var.environment
}

# Lab Container Host module - conditional
module "lab_container_host" {
  count  = var.enable_lab_container_host ? 1 : 0
  source = "./modules/lab-container-host"

  subnet_id                        = module.network.subnet_id
  security_group_id                = module.network.lab_container_host_security_group_id
  lab_container_host_ami           = var.lab_container_host_ami
  lab_container_host_instance_type = var.lab_container_host_instance_type
  key_name                         = var.key_name
  ecr_repository_url               = local.ecr_repository_url
  aws_region                       = var.aws_region
  siem_private_ip                  = local.siem_private_ip
  victim_private_ip                = var.enable_victim ? module.victim[0].private_ip : ""
  siem_type                        = var.siem_type
  project_name                     = var.project_name
  environment                      = var.environment
}

# Connection info file (backward compatibility)
resource "local_file" "connection_info" {
  filename = "${path.module}/lab_connections.txt"
  content = <<-EOF
APTL Purple Team Lab Connection Info
====================================

${local.active_siem != null ? "${upper(var.siem_type)} Instance:\n  Public IP:  ${local.active_siem.public_ip}\n  Private IP: ${local.active_siem.private_ip}\n  SSH: ssh -i ~/.ssh/${var.key_name} ${local.active_siem.ssh_user}@${local.active_siem.public_ip}\n  Web: ${var.siem_type == "qradar" ? "https" : "http"}://${local.active_siem.public_ip}${var.siem_type == "splunk" ? ":8000" : ""}\n\n" : "SIEM Instance: Disabled\n\n"}${var.enable_victim ? "Victim Instance:\n  Public IP:  ${module.victim[0].public_ip}\n  Private IP: ${module.victim[0].private_ip}\n  SSH: ssh -i ~/.ssh/${var.key_name} ec2-user@${module.victim[0].public_ip}\n  RDP: mstsc /v:${module.victim[0].public_ip}\n\n" : "Victim Instance: Disabled\n\n"}${var.enable_kali ? "Kali Red Team Instance:\n  Public IP:  ${module.kali[0].public_ip}\n  Private IP: ${module.kali[0].private_ip}\n  SSH: ssh -i ~/.ssh/${var.key_name} kali@${module.kali[0].public_ip}\n\n" : "Kali Instance: Disabled\n\n"}${var.enable_lab_container_host ? "Lab Container Host:\n  Public IP:  ${module.lab_container_host[0].public_ip}\n  Private IP: ${module.lab_container_host[0].private_ip}\n  Host SSH: ssh -i ~/.ssh/${var.key_name} ec2-user@${module.lab_container_host[0].public_ip}\n  Kali Container SSH: ssh -i ~/.ssh/${var.key_name} -p 2222 kali@${module.lab_container_host[0].public_ip}\n  Container Password: kali\n\n" : "Lab Container Host: Disabled\n\n"}${var.siem_type == "qradar" && local.active_siem != null ? "qRadar ISO Transfer:\n  scp -i ~/.ssh/${var.key_name} files/750-QRADAR-QRFULL-2021.06.12.20250509154206.iso ec2-user@${local.active_siem.public_ip}:/tmp/\n\n" : ""}${var.enable_victim && local.active_siem != null ? "Log Forwarding Verification:\n  1. SSH to victim machine and run: ./generate_test_events.sh\n  2. Login to ${var.siem_type} web interface: ${var.siem_type == "qradar" ? "https" : "http"}://${local.active_siem.public_ip}${var.siem_type == "splunk" ? ":8000" : ""}\n  3. Check for logs from victim machine IP: ${module.victim[0].private_ip}\n\n" : ""}${var.enable_victim ? "Purple Team Testing:\n  SSH to victim: ssh -i ~/.ssh/${var.key_name} ec2-user@${module.victim[0].public_ip}\n  Generate events: ./generate_test_events.sh\n  ${local.active_siem != null ? "Monitor in ${var.siem_type}: Check logs for ${module.victim[0].private_ip}" : "Events will be generated locally (SIEM disabled)"}\n\n" : ""}${var.enable_kali ? "Red Team Operations:\n  SSH to Kali: ssh -i ~/.ssh/${var.key_name} kali@${module.kali[0].public_ip}\n  Run lab info: ./lab_info.sh\n  ${local.active_siem != null ? "Target SIEM: ${local.active_siem.private_ip}" : "SIEM: Disabled"}\n  ${var.enable_victim ? "Target Victim: ${module.victim[0].private_ip}" : "Victim: Disabled"}\n\n" : ""}Network Summary:
  VPC CIDR: ${module.network.vpc_cidr}
  Subnet CIDR: ${module.network.subnet_cidr}
  Your Allowed IP: ${var.allowed_ip}
  SIEM Type: ${var.siem_type} ${var.enable_siem ? "(enabled)" : "(disabled)"}

Generated: ${timestamp()}
EOF
} 