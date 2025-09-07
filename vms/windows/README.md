# Windows VM Deployment on Proxmox

This Terraform configuration deploys a Windows virtual machine on Proxmox with RDP and SSH access configured.

## Prerequisites

1. **Proxmox VE** running at 192.168.1.72 (or adjust the IP in variables)
2. **Windows ISO** uploaded to Proxmox storage (e.g., Windows Server 2022)
3. **VirtIO drivers ISO** uploaded to Proxmox storage (optional but recommended)
4. **Terraform** installed on your local machine

## Setup Instructions

### 1. Download Required ISOs

Download and upload these ISOs to your Proxmox storage:

- **Windows Server 2022**: Download from Microsoft
- **VirtIO drivers**: Download from [Fedora Project](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso)

Upload them to Proxmox via the web interface: Datacenter → Storage → local → ISO Images

### 2. Configure Variables

Copy the example variables file and customize it:

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your specific values:

- `proxmox_password`: Your Proxmox root password
- `proxmox_node`: Your Proxmox node name (check in Proxmox web interface)
- `storage_pool`: Your storage pool name (e.g., "local-lvm", "local-zfs")
- `vm_ip`: Desired IP address for the VM (must be in your network range)
- `windows_iso_path`: Path to your Windows ISO in Proxmox storage
- `virtio_iso_path`: Path to VirtIO drivers ISO in Proxmox storage

### 3. Deploy the VM

Initialize and apply the Terraform configuration:

```bash
# Initialize Terraform
terraform init

# Plan the deployment
terraform plan

# Deploy the VM
terraform apply
```

### 4. Complete Windows Setup

1. **Access VM Console**: Use Proxmox web interface → VM → Console
2. **Install Windows**: Boot from the Windows ISO and complete installation
3. **Install VirtIO drivers**: During Windows setup or after installation
4. **Run setup script**: After Windows is installed, run the PowerShell setup script

### 5. Post-Installation Configuration

After Windows is installed and running:

1. **Copy setup script** to the VM (via console or file share)
2. **Run PowerShell as Administrator**
3. **Execute the setup script**:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force
   .\setup-windows.ps1
   ```

### 6. Connect to the VM

After setup is complete:

**RDP Connection:**
```bash
# Windows/Linux with RDP client
mstsc /v:192.168.1.100:3389

# Linux with Remmina or similar
remmina -c rdp://192.168.1.100:3389
```

**SSH Connection:**
```bash
ssh labadmin@192.168.1.100
```

## Network Configuration

The VM is configured to use your existing 192.168.1.x network:

- **VM IP**: 192.168.1.100 (configurable)
- **Gateway**: 192.168.1.1
- **DNS**: 192.168.1.1, 8.8.8.8
- **Network**: Bridged to vmbr0

## Default Credentials

- **Username**: labadmin
- **Password**: LabPassword123!

*Change these in terraform.tfvars before deployment*

## Firewall Configuration

The VM will be configured with Windows Firewall rules allowing:

- **RDP**: Port 3389
- **SSH**: Port 22
- **WinRM**: Ports 5985, 5986 (for PowerShell remoting)

## Troubleshooting

### Common Issues

1. **VM won't start**: Check if VM ID is unique and storage pool exists
2. **Network not working**: Verify bridge name (vmbr0) and IP configuration
3. **Can't connect**: Ensure Windows Firewall is configured and services are running
4. **ISO not found**: Check ISO paths in Proxmox storage

### Useful Commands

```bash
# Check Terraform state
terraform state list

# Show current configuration
terraform show

# Destroy the VM
terraform destroy

# Check Proxmox from command line
qm list
qm status 100
```

### Proxmox Commands

```bash
# On Proxmox host, check VM status
qm list
qm status 100

# Start/stop VM manually
qm start 100
qm stop 100

# Access VM console
qm monitor 100
```

## Security Notes

- This configuration is intended for lab/development use
- Windows Defender is configured for lab environment (reduced protection)
- Default passwords should be changed for production use
- SSH and RDP are enabled - ensure network security is appropriate

## Customization

You can customize the deployment by modifying:

- `variables.tf`: Add new configuration options
- `main.tf`: Modify VM hardware or configuration
- `setup-windows.ps1`: Add additional software or configuration
- `terraform.tfvars`: Change deployment-specific values