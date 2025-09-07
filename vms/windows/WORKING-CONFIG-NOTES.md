# Working Proxmox Windows VM Configuration

## Key Success Factors

**CRITICAL**: Use SeaBIOS instead of OVMF/UEFI to avoid the "press any key to boot from CD" timeout issue.

## Working Terraform Configuration

```hcl
# BIOS Configuration - CRITICAL for auto-boot
bios    = "seabios"  # NOT "ovmf" - this causes timeout issues
machine = "pc"       # NOT "q35" 
os_type = "win11"    # Works for Server 2025

# Disk Configuration  
disk {
  slot    = "ide0"
  type    = "disk" 
  storage = var.storage_pool
  size    = var.disk_size
}

disk {
  slot  = "ide2"    # IDE controller works best
  type  = "cdrom"
  iso   = "local:iso/SERVER_2025_EVAL_x64FRE_en-us.iso"
}

# Boot Order - IDE first, then network
boot = "order=ide0;ide2;net0"
```

## Tested Working With:
- Windows Server 2025 Evaluation ISO
- Proxmox 9.0.3
- Terraform Provider: telmate/proxmox v3.0.2-rc04

## Why SeaBIOS Works:
- No UEFI timeout prompts
- Direct boot from CD/DVD without user intervention  
- Compatible with Windows Server 2025
- Simpler configuration than OVMF

## Storage Setup:
- Multiple drives added: /mnt/storage1, /mnt/storage2, /mnt/storage3
- ISOs stored in Proxmox local storage
- Templates can be created from working VMs

## Next Steps:
- Create unattended installation (autounattend.xml)
- Set up RDP/SSH automation
- Template working VMs for fast deployment

## Other Windows ISOs:
This configuration should work with other Windows versions by just changing the ISO path.