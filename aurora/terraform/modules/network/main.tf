terraform {
  required_providers {
    libvirt = {
      source = "dmacvicar/libvirt"
    }
  }
}

resource "libvirt_network" "network" {
  for_each = var.networks

  name      = each.key
  mode      = each.value.mode
  domain    = each.value.domain
  addresses = each.value.addresses
  bridge    = each.value.bridge

  dynamic "dhcp" {
    for_each = each.value.dhcp != null && each.value.dhcp.enabled ? [1] : []
    content {
      enabled = each.value.dhcp.enabled
    }
  }

  dynamic "dns" {
    for_each = each.value.domain != null ? [1] : []
    content {
      enabled = true
    }
  }

  autostart = true
}