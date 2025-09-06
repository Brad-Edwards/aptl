variable "name" {
  description = "Name of the Windows VM"
  type        = string
}

variable "memory" {
  description = "Memory allocation in MiB"
  type        = number
  default     = 4096
}

variable "vcpu" {
  description = "Number of virtual CPUs"
  type        = number
  default     = 2
}

variable "disk_size" {
  description = "Disk size in bytes"
  type        = number
  default     = 64424509440 # 60GB
}

variable "storage_pool" {
  description = "Storage pool to use"
  type        = string
  default     = "vm1-pool"
}

variable "network" {
  description = "Network to connect to"
  type        = string
  default     = "aurora-nat"
}

variable "iso_path" {
  description = "Path to Windows Server 2022 ISO"
  type        = string
  default     = "/var/lib/libvirt/images/2022_SERVER_EVAL_x64FRE_en-us.iso"
}

variable "admin_password" {
  description = "Administrator password"
  type        = string
  default     = "AdminPass123!"
  sensitive   = true
}

variable "lab_user" {
  description = "Lab user configuration"
  type = object({
    username = string
    password = string
  })
  default = {
    username = "labuser"
    password = "LabPass123!"
  }
  sensitive = true
}

variable "computer_name" {
  description = "Computer name for the Windows VM"
  type        = string
  default     = null
}