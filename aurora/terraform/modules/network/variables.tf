variable "networks" {
  description = "Map of networks to create"
  type = map(object({
    mode       = string
    domain     = optional(string)
    addresses  = optional(list(string))
    bridge     = optional(string)
    dhcp = optional(object({
      enabled = bool
      start   = optional(string)
      end     = optional(string)
    }))
  }))
}