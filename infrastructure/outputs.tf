# SPDX-License-Identifier: BUSL-1.1

output "lab_config_json" {
  description = "Complete lab configuration in JSON format for MCP server"
  value = jsonencode({
    version   = "1.0"
    generated = timestamp()
    lab = {
      name        = "APTL Purple Team Lab"
      vpc_cidr    = module.network.vpc_cidr
      project     = var.project_name
      environment = var.environment
    }
    instances = {
      siem = local.active_siem != null ? {
        public_ip     = local.active_siem.public_ip
        private_ip    = local.active_siem.private_ip
        ssh_key       = "~/.ssh/${var.key_name}"
        ssh_user      = local.active_siem.ssh_user
        instance_type = local.active_siem.instance_type
        enabled       = true
        ports         = local.active_siem.ports
        type          = var.siem_type
      } : {
        public_ip     = null
        private_ip    = null
        ssh_key       = null
        ssh_user      = null
        instance_type = null
        enabled       = false
        ports         = null
        type          = var.siem_type
      }
      victim = var.enable_victim ? {
        public_ip     = module.victim[0].public_ip
        private_ip    = module.victim[0].private_ip
        ssh_key       = "~/.ssh/${var.key_name}"
        ssh_user      = module.victim[0].ssh_user
        instance_type = module.victim[0].instance_type
        enabled       = true
        ports         = module.victim[0].ports
      } : {
        public_ip     = null
        private_ip    = null
        ssh_key       = null
        ssh_user      = null
        instance_type = null
        enabled       = false
        ports         = null
      }
      kali = var.enable_kali ? {
        public_ip     = module.kali[0].public_ip
        private_ip    = module.kali[0].private_ip
        ssh_key       = "~/.ssh/${var.key_name}"
        ssh_user      = module.kali[0].ssh_user
        instance_type = module.kali[0].instance_type
        enabled       = true
        ports         = module.kali[0].ports
      } : {
        public_ip     = null
        private_ip    = null
        ssh_key       = null
        ssh_user      = null
        instance_type = null
        enabled       = false
        ports         = null
      }
    }
    network = {
      vpc_cidr    = module.network.vpc_cidr
      subnet_cidr = module.network.subnet_cidr
      allowed_ip  = var.allowed_ip
    }
    mcp = {
      server_name      = "kali-red-team"
      allowed_targets  = [module.network.subnet_cidr]
      max_session_time = 3600
      audit_enabled    = true
      log_level       = "info"
    }
  })
}

# Individual outputs for convenience
output "siem_info" {
  description = "Active SIEM instance information"
  value = local.active_siem != null ? {
    type        = var.siem_type
    public_ip   = local.active_siem.public_ip
    private_ip  = local.active_siem.private_ip
    ssh_command = "ssh -i ~/.ssh/${var.key_name} ${local.active_siem.ssh_user}@${local.active_siem.public_ip}"
  } : null
}

output "victim_info" {
  description = "Victim instance information"
  value = var.enable_victim ? {
    public_ip  = module.victim[0].public_ip
    private_ip = module.victim[0].private_ip
    ssh_command = "ssh -i ~/.ssh/${var.key_name} ${module.victim[0].ssh_user}@${module.victim[0].public_ip}"
  } : null
}

output "kali_info" {
  description = "Kali instance information"
  value = var.enable_kali ? {
    public_ip  = module.kali[0].public_ip
    private_ip = module.kali[0].private_ip
    ssh_command = "ssh -i ~/.ssh/${var.key_name} ${module.kali[0].ssh_user}@${module.kali[0].public_ip}"
  } : null
}

output "network_info" {
  description = "Network configuration"
  value = {
    vpc_cidr    = module.network.vpc_cidr
    subnet_cidr = module.network.subnet_cidr
    allowed_ip  = var.allowed_ip
  }
} 