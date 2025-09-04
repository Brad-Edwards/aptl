# Windows RE Infrastructure

Terraform configuration for deploying a Windows 11 EC2 instance for exploit development and reverse engineering.

## Prerequisites

- AWS CLI configured with appropriate credentials
- Terraform installed
- SSH key pair generated (`ssh-keygen -t rsa -b 4096`)

## Setup

1. **Initialize Terraform**

   ```bash
   cd infra/windows_re
   terraform init
   ```

2. **Configure Variables**

   ```bash
   cp terraform.tfvars.example terraform.tfvars
   ```

   Edit `terraform.tfvars` with your values:
   - `your_ip_cidr`: Your public IP in CIDR format (get with `curl ifconfig.me`)
   - `admin_password`: Strong password for RDP access
   - Adjust other settings as needed

3. **Deploy Infrastructure**

   ```bash
   terraform plan
   terraform apply
   ```

4. **Get Connection Info**

   ```bash
   terraform output
   ```

## Connecting

### Windows RDP

Use the output IP address to connect via RDP:

- **Username**: `Administrator`
- **Password**: The password you set in terraform.tfvars
- **Connection**: Use your preferred RDP client or the command from terraform output

### Pre-installed Tools

The instance comes pre-configured with:

- **Debuggers**: x64dbg, Visual Studio 2022 Community
- **Reverse Engineering**: Ghidra
- **Development**: Python 3, Git, VS Code
- **Analysis**: Wireshark
- **Utilities**: 7-Zip, Firefox
- **SDK**: Windows SDK 10

## Security Notes

- RDP access is restricted to your IP address only
- Windows Defender real-time protection is disabled for exploit development
- ASLR and DEP are configured for easier debugging
- Instance uses encrypted EBS storage

## Cleanup

When finished:

```bash
terraform destroy
```

## Cost Optimization

- Default instance type is `t3.large` - modify in terraform.tfvars if needed
- Instance will incur charges while running
- Consider stopping (not terminating) the instance when not in use
