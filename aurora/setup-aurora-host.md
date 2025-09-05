# Aurora Host Setup

Setup KVM hypervisor on Ubuntu for VM deployment.

## Prerequisites

- Ubuntu 22.04+ with hardware virtualization
- Separate storage drives for VM storage
- Network connectivity to APTL host

## Install Hypervisor Stack

```bash
# Install virtualization packages
sudo apt update
sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager

# Install Terraform
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install terraform
```

## Create VM User

```bash
# Create dedicated VM management user
sudo adduser --disabled-password --gecos 'VM Administrator' vmadmin
sudo usermod -a -G libvirt,kvm vmadmin
```

## Configure Storage

Create VM storage directories:

```bash
# Single drive: Use /var/lib/libvirt/images or custom path
sudo mkdir -p /var/lib/libvirt/aurora-vms
sudo chown vmadmin:vmadmin /var/lib/libvirt/aurora-vms

# Multiple drives: Mount to /vm1, /vm2, etc.
# sudo mkdir -p /vm{1,2,3}/vms
# sudo chown vmadmin:vmadmin /vm{1,2,3}/vms

# Create libvirt storage pool (single drive)
sudo -u vmadmin virsh pool-define-as aurora-pool dir - - - - /var/lib/libvirt/aurora-vms
sudo -u vmadmin virsh pool-start aurora-pool
sudo -u vmadmin virsh pool-autostart aurora-pool
```

## Configure Network

```bash
# Create VM bridge network
sudo -u vmadmin virsh net-define /dev/stdin <<EOF
<network>
  <name>vm-bridge</name>
  <forward mode='nat'/>
  <bridge name='virbr1' stp='on' delay='0'/>
  <ip address='192.168.100.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.100.10' end='192.168.100.254'/>
    </dhcp>
  </ip>
</network>
EOF

sudo -u vmadmin virsh net-start vm-bridge
sudo -u vmadmin virsh net-autostart vm-bridge
```

## SSH Access

Setup SSH key authentication for vmadmin from APTL host:

```bash
# Copy public key to vmadmin
sudo mkdir -p /home/vmadmin/.ssh
sudo cp /path/to/aptl_aurora_key.pub /home/vmadmin/.ssh/authorized_keys
sudo chown -R vmadmin:vmadmin /home/vmadmin/.ssh
sudo chmod 700 /home/vmadmin/.ssh
sudo chmod 600 /home/vmadmin/.ssh/authorized_keys
```

## Verification

```bash
# Check virtualization
ls -la /dev/kvm
lscpu | grep Virtualization

# Check libvirt
sudo -u vmadmin virsh pool-list
sudo -u vmadmin virsh net-list

# Test SSH from APTL host
ssh -i ~/.ssh/aptl_aurora_key vmadmin@AURORA_IP "virsh version"
```

## Storage Layout

- Single drive: All VMs in `/var/lib/libvirt/aurora-vms`
- Multiple drives: Separate by VM type or function

Update `aptl.json` with actual Aurora host IP.