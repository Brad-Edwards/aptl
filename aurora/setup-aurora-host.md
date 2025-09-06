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
# Multiple drives: Mount to /vm1, /vm2, etc.
sudo mkdir -p /vm{1,2,3}/vms
sudo chown vmadmin:vmadmin /vm{1,2,3}/vms
```

## Install Terraform Libvirt Provider

```bash
# Initialize Terraform in aurora-configs
cd /home/vmadmin/aurora-configs/terraform
terraform init
```

**Note**: Storage pools and networks will be managed by Terraform configurations.

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

# Test SSH from APTL host
ssh -i ~/.ssh/aptl_aurora_key vmadmin@AURORA_IP "virsh version"

# Check Terraform
ssh -i ~/.ssh/aptl_aurora_key vmadmin@AURORA_IP "cd ~/aurora-configs/terraform && terraform version"
```

## Storage Layout

- Multiple drives: /vm1, /vm2, /vm3 for VM storage
- Terraform manages libvirt storage pools and networks

Update `aptl.json` with actual Aurora host IP.