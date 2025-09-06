terraform {
  required_providers {
    libvirt = {
      source = "dmacvicar/libvirt"
    }
  }
}

resource "libvirt_pool" "storage_pool" {
  for_each = var.storage_pools

  name = each.key
  type = each.value.type
  
  target {
    path = each.value.path
  }
}