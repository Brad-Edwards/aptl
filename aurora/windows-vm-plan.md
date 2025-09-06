# Windows VM Deployment Plan

## Prerequisites

- Windows Server ISOs available at `/home/vmadmin/iso/`
- Storage pools: vm1-pool, vm2-pool, vm3-pool (ready)

## Setup Aurora Networking (Run Once)

```bash
sudo ./aurora/setup-aurora-defaults.sh
```

Creates:
- `aurora-default-bridge`: Bridged to host network for direct access
- `aurora-default-nat`: Isolated NAT network (192.168.110.0/24)

## Deploy Automated Windows VM

```bash
sudo ./aurora/deploy-windows-vm.sh [vm-name] [pool] [size] [ram-mb] [vcpus] [network]
```

Example:
```bash
sudo ./aurora/deploy-windows-vm.sh windows-victim vm1-pool 60G 4096 2 aurora-default-bridge
```

## Automated Features

- **Unattended Installation**: Windows Server 2022 with unattend.xml
- **Pre-configured Users**: Administrator and labuser (Password123!)
- **Services Enabled**: RDP, WinRM, OpenSSH Server
- **Security Disabled**: Windows Defender (lab use)
- **Tools Installed**: Chocolatey, Notepad++, Firefox, PuTTY
- **Network**: Direct access on host network (192.168.1.x)

## Access

- **RDP**: VM IP:3389
- **SSH**: VM IP:22  
- **Credentials**: labuser / Password123!

Installation completes automatically in ~30 minutes.
