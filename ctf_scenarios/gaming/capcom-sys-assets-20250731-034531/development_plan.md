# Windows Victim Box Development Plan - Capcom.sys CTF

## Overview
Add a Windows victim box with Capcom.sys installed. The attacker starts with access and must exploit the driver to get SYSTEM and read the flag.

## Implementation

### 1. Create Windows Victim Module
```
infrastructure/modules/victim-windows/
├── main.tf
├── variables.tf  
├── outputs.tf
└── user_data.ps1
```

### 2. Variables
Add to `infrastructure/variables.tf`:
```hcl
variable "enable_victim_windows" {
  description = "Whether to create the Windows victim instance"
  type        = bool
  default     = false
}

variable "victim_windows_ami" {
  description = "AMI ID for Windows victim"
  type        = string
}

variable "victim_windows_instance_type" {
  description = "Instance type for Windows victim"
  type        = string
  default     = "t3.medium"
}
```

### 3. Windows Setup (user_data.ps1)
```powershell
# Enable test signing
bcdedit /set testsigning on

# Install Capcom.sys
Copy-Item "Capcom.sys" -Destination "C:\Windows\System32\drivers\"
sc create Capcom type= kernel binPath= "C:\Windows\System32\drivers\Capcom.sys"
sc start Capcom

# Create flag - only SYSTEM can read
$flag = "APTL{Got_System_Via_Capcom}"
Set-Content -Path "C:\Windows\System32\flag.txt" -Value $flag
icacls "C:\Windows\System32\flag.txt" /setowner "NT AUTHORITY\SYSTEM"
icacls "C:\Windows\System32\flag.txt" /inheritance:r
icacls "C:\Windows\System32\flag.txt" /grant "SYSTEM:(F)"
icacls "C:\Windows\System32\flag.txt" /remove "Users" /remove "Administrators"

# SIEM logging setup
# [Configure Windows event forwarding]
```

### 4. Main Infrastructure
Add to `infrastructure/main.tf`:
```hcl
module "victim_windows" {
  count  = var.enable_victim_windows ? 1 : 0
  source = "./modules/victim-windows"
  
  subnet_id         = module.network.subnet_id
  security_group_id = module.network.victim_security_group_id
  ami              = var.victim_windows_ami
  instance_type    = var.victim_windows_instance_type
  key_name         = var.key_name
  siem_private_ip  = local.active_siem != null ? local.active_siem.private_ip : ""
}
```

## CTF Challenge
- **Given**: Access to Windows box with user privileges
- **Goal**: Get SYSTEM and read flag at C:\Windows\System32\flag.txt
- **Hint**: "There's a game driver on this system"