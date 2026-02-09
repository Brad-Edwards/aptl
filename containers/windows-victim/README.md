# Windows 11 Victim VM

Windows endpoint for APTL enterprise lab. Runs as a VM (not a container) and integrates with the Docker-based lab infrastructure.

## Prerequisites

- KVM/QEMU with libvirt (or VMware Workstation)
- Windows 11 ISO or Microsoft Development VM
- 4-6GB RAM available for the VM
- 40GB+ disk space

## Setup

### 1. Create the VM

Using virt-install (KVM):
```bash
virt-install \
  --name aptl-windows \
  --ram 4096 \
  --vcpus 2 \
  --disk size=40 \
  --os-variant win11 \
  --network bridge=virbr0 \
  --cdrom /path/to/windows11.iso \
  --graphics spice
```

Or download the Microsoft Development VM:
```
https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/
```

### 2. Configure Networking

The VM needs to reach the Docker lab network. Options:

**Option A: Bridge to Docker network (recommended)**
```bash
# Create a macvlan on the Docker aptl-internal network
docker network create -d macvlan \
  --subnet=172.20.2.0/24 \
  --gateway=172.20.2.1 \
  -o parent=br0 \
  aptl-internal-vm
```

**Option B: Route through host**
```bash
# Add route on the Windows VM to reach Docker networks
route add 172.20.0.0 mask 255.255.0.0 <host-ip>
```

Assign the VM a static IP: `172.20.3.10` (endpoints network).

### 3. Run Setup Scripts

From the VM (run PowerShell as Administrator):

```powershell
# Enable SSH
.\setup-ssh.ps1

# Install Wazuh agent
.\setup-wazuh-agent.ps1

# Join AD domain
.\join-domain.ps1

# Enable RDP (optional)
.\enable-rdp.ps1

# Install Sysmon
.\setup-sysmon.ps1
```

### 4. Verify Integration

From Kali container:
```bash
# Test SSH
ssh labadmin@172.20.3.10

# Test RDP
xfreerdp /v:172.20.3.10 /u:jessica.williams /p:password123 /d:TECHVAULT
```

From Wazuh Dashboard:
- Check agent list for the Windows endpoint
- Verify Windows Event Logs are flowing
- Confirm Sysmon events appear

## Attack Scenarios

With a domain-joined Windows endpoint, these attack techniques become possible:

- **T1558.003** Kerberoasting (request TGS tickets for service accounts)
- **T1550.002** Pass the Hash (use NTLM hashes for lateral movement)
- **T1003.001** LSASS Memory Dump (extract credentials)
- **T1021.001** Remote Desktop Protocol (lateral movement via RDP)
- **T1059.001** PowerShell execution (fileless attacks)
- **T1547.001** Registry Run Keys (persistence)
- **T1053.005** Scheduled Tasks (persistence)
- **T1070.001** Clear Windows Event Logs (defense evasion)

## MCP Integration

Add to `.mcp.json` or `.cursor/mcp.json`:
```json
{
  "aptl-windows-victim": {
    "command": "node",
    "args": ["./mcp/mcp-windows-re/build/index.js"],
    "cwd": "/path/to/aptl"
  }
}
```

Update `mcp/mcp-windows-re/docker-lab-config.json` with the VM's IP address.
