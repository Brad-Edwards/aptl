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
}

variable "proxmox_tls_insecure" {
  description = "Skip TLS verification"
  type        = bool
}

variable "proxmox_node" {
  description = "Proxmox node name"
  type        = string
}

variable "vm_name" {
  description = "VM name"
  type        = string
}

variable "vm_cores" {
  description = "Number of CPU cores"
  type        = number
}

variable "vm_memory" {
  description = "Memory in MB"
  type        = number
}


variable "network_bridge" {
  description = "Network bridge name"
  type        = string
}