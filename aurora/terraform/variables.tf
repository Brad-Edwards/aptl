# Storage Configuration
variable "storage_pools" {
  description = "Map of storage pools to create"
  type = map(object({
    type = string
    path = string
  }))
  default = {
    vm1-pool = {
      type = "dir"
      path = "/vm1/vms"
    }
    vm2-pool = {
      type = "dir" 
      path = "/vm2/vms"
    }
    vm3-pool = {
      type = "dir"
      path = "/vm3/vms"
    }
  }
}

# Network Configuration
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
  default = {
    aurora-bridge = {
      mode   = "bridge"
      bridge = "br0"
    }
    aurora-nat = {
      mode      = "nat"
      domain    = "aurora.lab"
      addresses = ["192.168.110.0/24"]
      dhcp = {
        enabled = true
        start   = "192.168.110.10"
        end     = "192.168.110.100"
      }
    }
    aurora-isolated = {
      mode      = "none"
      domain    = "isolated.lab"
      addresses = ["10.0.100.0/24"]
      dhcp = {
        enabled = true
        start   = "10.0.100.10" 
        end     = "10.0.100.100"
      }
    }
  }
}

# Environment
variable "environment" {
  description = "Environment name"
  type        = string
  default     = "aurora"
}

variable "tags" {
  description = "Common tags for resources"
  type        = map(string)
  default = {
    Project     = "APTL"
    Environment = "aurora"
    ManagedBy   = "terraform"
  }
}