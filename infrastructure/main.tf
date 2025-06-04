# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.2.0"
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile != "" ? var.aws_profile : null
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
}

# qRadar module - conditional
module "qradar" {
  count  = var.enable_qradar ? 1 : 0
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
  siem_private_ip       = var.enable_qradar ? module.qradar[0].private_ip : ""
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
  siem_private_ip     = var.enable_qradar ? module.qradar[0].private_ip : ""
  victim_private_ip   = var.enable_victim ? module.victim[0].private_ip : ""
  project_name        = var.project_name
  environment         = var.environment
}

# Connection info file (backward compatibility)
resource "local_file" "connection_info" {
  filename = "${path.module}/lab_connections.txt"
  content = <<-EOF
APTL Purple Team Lab Connection Info
====================================

${var.enable_qradar ? "qRadar Instance:\n  Public IP:  ${module.qradar[0].public_ip}\n  Private IP: ${module.qradar[0].private_ip}\n  SSH: ssh -i ~/.ssh/${var.key_name} ec2-user@${module.qradar[0].public_ip}\n  HTTPS: https://${module.qradar[0].public_ip}\n\n" : "qRadar Instance: Disabled\n\n"}${var.enable_victim ? "Victim Instance:\n  Public IP:  ${module.victim[0].public_ip}\n  Private IP: ${module.victim[0].private_ip}\n  SSH: ssh -i ~/.ssh/${var.key_name} ec2-user@${module.victim[0].public_ip}\n  RDP: mstsc /v:${module.victim[0].public_ip}\n\n" : "Victim Instance: Disabled\n\n"}${var.enable_kali ? "Kali Red Team Instance:\n  Public IP:  ${module.kali[0].public_ip}\n  Private IP: ${module.kali[0].private_ip}\n  SSH: ssh -i ~/.ssh/${var.key_name} kali@${module.kali[0].public_ip}\n\n" : "Kali Instance: Disabled\n\n"}${var.enable_qradar ? "qRadar ISO Transfer:\n  scp -i ~/.ssh/${var.key_name} files/750-QRADAR-QRFULL-2021.06.12.20250509154206.iso ec2-user@${module.qradar[0].public_ip}:/tmp/\n\n" : ""}${var.enable_victim && var.enable_qradar ? "Log Forwarding Verification:\n  1. SSH to victim machine and run: ./generate_test_events.sh\n  2. Login to qRadar web interface: https://${module.qradar[0].public_ip}\n  3. Go to Log Activity tab and filter by Source IP: ${module.victim[0].private_ip}\n  4. You should see logs from victim machine automatically\n\n" : ""}${var.enable_victim ? "Purple Team Testing:\n  SSH to victim: ssh -i ~/.ssh/${var.key_name} ec2-user@${module.victim[0].public_ip}\n  Generate events: ./generate_test_events.sh\n  ${var.enable_qradar ? "Monitor in qRadar: Log Activity → Source IP filter → ${module.victim[0].private_ip}" : "Events will be generated locally (qRadar disabled)"}\n\n" : ""}${var.enable_kali ? "Red Team Operations:\n  SSH to Kali: ssh -i ~/.ssh/${var.key_name} kali@${module.kali[0].public_ip}\n  Run lab info: ./lab_info.sh\n  ${var.enable_qradar ? "Target qRadar: ${module.qradar[0].private_ip}" : "qRadar: Disabled"}\n  ${var.enable_victim ? "Target Victim: ${module.victim[0].private_ip}" : "Victim: Disabled"}\n\n" : ""}Network Summary:
  VPC CIDR: ${module.network.vpc_cidr}
  Subnet CIDR: ${module.network.subnet_cidr}
  Your Allowed IP: ${var.allowed_ip}

Generated: ${timestamp()}
EOF
} 