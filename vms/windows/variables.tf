variable "proxmox_api_url" {
  description = "Proxmox API URL"
  type        = string
}

variable "proxmox_user" {
  description = "Proxmox username"
  type        = string
}

variable "proxmox_password" {
  description = "Proxmox password"
  type        = string
  sensitive   = true
}

variable "proxmox_tls_insecure" {
  description = "Skip TLS verification for Proxmox API"
  type        = bool
}

variable "proxmox_node" {
  description = "Proxmox node name"
  type        = string
}

variable "vm_name" {
  description = "Name of the Windows VM"
  type        = string
}

variable "vm_id" {
  description = "VM ID in Proxmox"
  type        = number
}

variable "vm_cores" {
  description = "Number of CPU cores"
  type        = number
}

variable "vm_memory" {
  description = "RAM in MB"
  type        = number
}

variable "disk_size" {
  description = "Disk size (e.g., '50G')"
  type        = string
}

variable "storage_pool" {
  description = "Proxmox storage pool"
  type        = string
}

variable "network_bridge" {
  description = "Network bridge name"
  type        = string
}

variable "vm_user" {
  description = "VM username"
  type        = string
}

variable "vm_password" {
  description = "VM user password"
  type        = string
  sensitive   = true
}

variable "ssh_public_key" {
  description = "SSH public key"
  type        = string
}