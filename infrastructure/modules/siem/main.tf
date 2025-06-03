# SPDX-License-Identifier: BUSL-1.1

# SIEM Instance
resource "aws_instance" "siem" {
  ami           = var.siem_ami
  instance_type = var.siem_instance_type
  subnet_id     = var.subnet_id
  key_name      = var.key_name

  vpc_security_group_ids = [var.security_group_id]

  root_block_device {
    volume_size = 250  # Minimum requirement per docs
    volume_type = "gp3"
  }

  user_data = <<-EOF
              #!/bin/bash
              # Log everything for troubleshooting
              exec > >(tee /var/log/user-data.log)
              exec 2>&1
              
              # Update system
              sudo dnf update -y
              
              # Install required packages
              sudo dnf install -y wget
              
              # Baseline OS configuration for qRadar
              sudo hostnamectl set-hostname qradar.local
              
              # Add hostname to /etc/hosts using private IP
              PRIVATE_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
              echo "$PRIVATE_IP qradar.local" | sudo tee -a /etc/hosts
              
              # Disable SELinux immediately and permanently
              sudo setenforce 0 || true  # Don't fail if already disabled
              sudo sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
              
              # Setup swap (8GB)
              sudo swapoff -a
              sudo dd if=/dev/zero of=/swap bs=1M count=8192
              sudo mkswap /swap
              sudo swapon /swap
              echo '/swap swap swap defaults 0 0' | sudo tee -a /etc/fstab
              
              # Wait for additional EBS volume to attach
              echo "Waiting for /store volume to attach..."
              while [ ! -b /dev/nvme1n1 ] && [ ! -b /dev/xvdf ]; do
                sleep 5
              done
              
              # Determine the correct device name (newer instances use nvme, older use xvd)
              if [ -b /dev/nvme1n1 ]; then
                STORE_DEVICE="/dev/nvme1n1"
              else
                STORE_DEVICE="/dev/xvdf"
              fi
              
              # Format and mount /store volume
              echo "Setting up /store on $STORE_DEVICE"
              sudo mkfs.ext4 -F $STORE_DEVICE
              sudo mkdir -p /store
              sudo mount $STORE_DEVICE /store
              
              # Add to fstab for persistent mounting
              echo "$STORE_DEVICE /store ext4 defaults 0 0" | sudo tee -a /etc/fstab
              
              # Set proper ownership and permissions
              sudo chown root:root /store
              sudo chmod 755 /store
              
              # Create reboot flag to track if reboot is needed
              touch /home/ec2-user/system_ready_for_qradar
              
              # Create qRadar installation script
              cat > /home/ec2-user/install_qradar.sh << 'EOFSCRIPT'
              #!/bin/bash
              
              # Check if system was rebooted after initial setup
              if [ ! -f /home/ec2-user/post_reboot_setup_done ]; then
                echo "Performing post-reboot setup..."
                
                # Verify SELinux is disabled
                if [ "$(getenforce)" != "Disabled" ]; then
                  echo "ERROR: SELinux is still enabled. Rebooting system..."
                  sudo reboot
                  exit 1
                fi
                
                # Verify /store is mounted
                if ! mountpoint -q /store; then
                  echo "ERROR: /store is not mounted. Checking..."
                  sudo mount -a
                  if ! mountpoint -q /store; then
                    echo "ERROR: Failed to mount /store"
                    exit 1
                  fi
                fi
                
                # Remove conflicting Red Hat Cloud packages that cause qRadar installation issues
                echo "Removing conflicting cloud packages..."
                sudo dnf remove -y redhat-cloud-client-configuration rhc insights-client || true
                
                # Clean package cache
                sudo dnf clean all
                
                # Mark post-reboot setup as done
                touch /home/ec2-user/post_reboot_setup_done
              fi
              
              echo "System ready for qRadar installation."
              echo "Mounting ISO..."
              sudo mkdir -p /iso
              sudo mount -o loop /tmp/750-QRADAR-QRFULL-2021.06.12.20250509154206.iso /iso
              
              echo "Starting qRadar setup..."
              cd /iso
              sudo ./setup
              EOFSCRIPT
              chmod +x /home/ec2-user/install_qradar.sh
              
              # Create system preparation completion script
              cat > /home/ec2-user/prepare_for_qradar.sh << 'EOFSCRIPT'
              #!/bin/bash
              echo "Checking system preparation status..."
              
              # Check SELinux status
              echo "SELinux status: $(getenforce)"
              
              # Check /store mount
              echo "/store mount status: $(mountpoint /store && echo 'OK' || echo 'NOT MOUNTED')"
              
              # Check available space
              echo "Disk space:"
              df -h / /store
              
              # If SELinux is not disabled, reboot
              if [ "$(getenforce)" != "Disabled" ]; then
                echo "SELinux not fully disabled. Rebooting system in 10 seconds..."
                echo "After reboot, re-run this script to verify, then run install_qradar.sh"
                sleep 10
                sudo reboot
              else
                echo "System ready for qRadar installation!"
                echo "Run: ./install_qradar.sh"
              fi
              EOFSCRIPT
              chmod +x /home/ec2-user/prepare_for_qradar.sh
              
              # Final system preparation
              echo "Initial setup complete. System may need reboot for SELinux changes."
              EOF

  tags = {
    Name        = "${var.project_name}-siem"
    Project     = var.project_name
    Environment = var.environment
  }
}

# EBS Volume for qRadar /store
resource "aws_ebs_volume" "siem_store" {
  availability_zone = var.availability_zone
  size              = 200  # GB for /store - adjust as needed
  type              = "gp3"
  
  tags = {
    Name        = "${var.project_name}-siem-store"
    Project     = var.project_name
    Environment = var.environment
  }
}

resource "aws_volume_attachment" "siem_store_attachment" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.siem_store.id
  instance_id = aws_instance.siem.id
}

resource "aws_eip" "siem_eip" {
  instance = aws_instance.siem.id
  domain   = "vpc"

  tags = {
    Name        = "${var.project_name}-siem-eip"
    Project     = var.project_name
    Environment = var.environment
  }
} 