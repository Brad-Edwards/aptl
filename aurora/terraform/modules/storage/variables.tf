variable "storage_pools" {
  description = "Map of storage pools to create"
  type = map(object({
    type = string
    path = string
  }))
}