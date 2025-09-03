#!/bin/bash
set -e

echo "=== Installing Falco with Modern eBPF (RHEL-based) ==="

# Check if Falco is already installed
if [ -f /var/ossec/.falco_installed ]; then
    echo "Falco already installed, starting services..."
    systemctl start falco-modern-bpf.service
    exit 0
fi

echo "Setting up Falco repository..."
rpm --import https://falco.org/repo/falcosecurity-packages.asc
cat > /etc/yum.repos.d/falco.repo << 'EOF'
[falco]
name=Falco repository  
baseurl=https://download.falco.org/packages/rpm
gpgcheck=1
gpgkey=https://falco.org/repo/falcosecurity-packages.asc
enabled=1
EOF

echo "Installing Falco..."
dnf install -y falco

echo "Enabling and starting Falco service..."
systemctl enable falco-modern-bpf.service
systemctl start falco-modern-bpf.service

systemctl is-active falco-modern-bpf && echo "Falco service is active" || echo "Falco service failed to start"

echo "=== Falco Installation Complete ==="

touch /var/ossec/.falco_installed