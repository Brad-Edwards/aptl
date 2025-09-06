# Aurora Terraform Infrastructure

Modular Terraform configuration for managing libvirt infrastructure on Aurora host.

## Structure

```
terraform/
├── main.tf                    # Root module
├── variables.tf              # Root variables
├── outputs.tf                # Root outputs
├── providers.tf              # Provider configuration
├── terraform.tfvars.example  # Example configuration
├── modules/
│   ├── storage/              # Storage pool module
│   └── network/              # Network module
└── README.md                 # This file
```

## Usage

### Initial Setup

1. **Copy example configuration**:
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   ```

2. **Customize configuration**:
   Edit `terraform.tfvars` for your environment

3. **Initialize Terraform**:
   ```bash
   terraform init
   ```

### Deploy Infrastructure

```bash
# Plan deployment
terraform plan

# Apply changes
terraform apply

# View outputs
terraform output
```

### Manage Infrastructure

```bash
# Show current state
terraform show

# Refresh state
terraform refresh

# Destroy infrastructure
terraform destroy
```

## Configuration

### Storage Pools

Configure storage pools in `terraform.tfvars`:

```hcl
storage_pools = {
  vm1-pool = {
    type = "dir"
    path = "/vm1/vms"
  }
  vm2-pool = {
    type = "dir"
    path = "/vm2/vms"
  }
}
```

### Networks

Configure networks in `terraform.tfvars`:

```hcl
networks = {
  # Bridge network (requires host br0 setup)
  aurora-bridge = {
    mode   = "bridge"
    bridge = "br0"
  }
  
  # NAT network
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
}
```

## Network Types

- **bridge**: Direct connection to host network
- **nat**: NAT with internet access
- **none**: Isolated network

## Best Practices

1. **Version Control**: Track `terraform.tfvars` changes
2. **State Management**: Consider remote state for team use
3. **Planning**: Always run `terraform plan` before apply
4. **Modules**: Extend with additional modules for VMs