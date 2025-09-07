output "vm_name" {
  description = "Name of the Windows VM"
  value       = proxmox_virtual_environment_vm.windows_vm.name
}

output "vm_id" {
  description = "VM ID in Proxmox"
  value       = proxmox_virtual_environment_vm.windows_vm.vm_id
}

output "vm_ip_address" {
  description = "IP address of the Windows VM (DHCP assigned)"
  value       = proxmox_virtual_environment_vm.windows_vm.ipv4_addresses
}