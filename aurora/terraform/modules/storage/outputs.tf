output "storage_pools" {
  description = "Created storage pools"
  value = {
    for k, v in libvirt_pool.storage_pool : k => {
      name = v.name
      path = v.target[0].path
      type = v.type
    }
  }
}