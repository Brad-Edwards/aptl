terraform {
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = "0.66.3"
    }
  }
}

provider "proxmox" {
  endpoint = var.proxmox_api_url
  username = "${var.proxmox_user}@pam"
  password = var.proxmox_password
  insecure = var.proxmox_tls_insecure
}

resource "proxmox_virtual_environment_vm" "windows_vm" {
  name      = var.vm_name
  node_name = var.proxmox_node
  
  clone {
    vm_id = 100  # windows-server-2025 template
    full  = true
  }
  
  agent {
    enabled = true
    trim    = true
    type    = "virtio"
    timeout = "30s"  # Short timeout to avoid long waits
  }
  
  cpu {
    cores = var.vm_cores
    type  = "host"
  }
  
  memory {
    dedicated = var.vm_memory
  }
  
  
  network_device {
    bridge = var.network_bridge
    model  = "e1000"
  }
  
  vga {
    type = "std"
  }
  
  on_boot = true
}