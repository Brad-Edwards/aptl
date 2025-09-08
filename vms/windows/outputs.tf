output "vm_id" {
  description = "VM ID assigned by Proxmox"
  value       = proxmox_virtual_environment_vm.windows_vm.vm_id
}

output "vm_name" {
  description = "VM name"
  value       = proxmox_virtual_environment_vm.windows_vm.name
}

output "vm_ipv4_addresses" {
  description = "VM IPv4 addresses"
  value       = proxmox_virtual_environment_vm.windows_vm.ipv4_addresses
}