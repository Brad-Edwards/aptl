locals {
  common_tags = merge(var.tags, {
    Environment = var.environment
  })
}

# Storage Infrastructure
module "storage" {
  source = "./modules/storage"
  
  storage_pools = var.storage_pools
}

# Network Infrastructure  
module "network" {
  source = "./modules/network"
  
  networks = var.networks
}