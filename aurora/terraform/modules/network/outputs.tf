output "networks" {
  description = "Created networks"
  value = {
    for k, v in libvirt_network.network : k => {
      name      = v.name
      mode      = v.mode
      addresses = v.addresses
      bridge    = v.bridge
    }
  }
}