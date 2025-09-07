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
  username = var.proxmox_user
  password = var.proxmox_password
  insecure = var.proxmox_tls_insecure
}

resource "proxmox_virtual_environment_file" "cloud_config" {
  content_type = "snippets"
  datastore_id = "local"
  node_name    = var.proxmox_node

  source_raw {
    data = <<-EOF
    #ps1_sysnative
    # Enable RDP
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    
    # Set timezone
    Set-TimeZone -Id "UTC"
    
    # Install Windows Updates (optional)
    # Install-WindowsUpdate -AcceptAll -AutoReboot
    EOF
    file_name = "${var.vm_name}-cloud-init.ps1"
  }
}

resource "proxmox_virtual_environment_vm" "windows_vm" {
  name      = var.vm_name
  node_name = var.proxmox_node
  vm_id     = var.vm_id
  
  clone {
    vm_id = 101
    full  = true
  }
  
  agent {
    enabled = true
    trim    = true
    type    = "virtio"
    timeout = "2m"
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
  
  initialization {
    user_account {
      username = var.vm_user
      password = var.vm_password
    }
    
    user_data_file_id = proxmox_virtual_environment_file.cloud_config.id
  }

  on_boot = true
}

resource "null_resource" "configure_windows" {
  depends_on = [proxmox_virtual_environment_vm.windows_vm]
  
  connection {
    type     = "winrm"
    host     = proxmox_virtual_environment_vm.windows_vm.ipv4_addresses[0][0]
    user     = var.vm_user
    password = var.vm_password
    https    = false
    insecure = true
    timeout  = "3m"
  }
  
  provisioner "remote-exec" {
    inline = [
      "powershell -Command \"Rename-Computer -NewName '${var.vm_name}-${random_id.vm_suffix.hex}' -Force -Restart\""
    ]
  }
}

resource "random_id" "vm_suffix" {
  byte_length = 4
}