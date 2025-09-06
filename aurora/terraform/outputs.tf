output "storage_pools" {
  description = "Information about created storage pools"
  value       = module.storage.storage_pools
}

output "networks" {
  description = "Information about created networks"
  value       = module.network.networks
}

output "infrastructure_summary" {
  description = "Summary of Aurora infrastructure"
  value = {
    environment    = var.environment
    storage_pools  = keys(var.storage_pools)
    networks       = keys(var.networks)
  }
}