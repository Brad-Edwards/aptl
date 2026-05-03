#!/bin/bash
set -e

echo "=== Installing Falco with Modern eBPF ==="

# Check if Falco is already installed
if [ -f /var/ossec/.falco_installed ]; then
    echo "Falco already installed, starting services..."
    systemctl start falco-modern-bpf.service
    exit 0
fi

# Install Falco (skip if pre-installed at build time per SAF-002)
if rpm -q falco &>/dev/null; then
    echo "Falco already installed (pre-baked in image, SAF-002)"
else
    echo "Falco not pre-installed, downloading from internet..."
    rpm --import https://falco.org/repo/falcosecurity-packages.asc
    cat > /etc/yum.repos.d/falco.repo << 'EOF'
[falco]
name=Falco repository
baseurl=https://download.falco.org/packages/rpm
gpgcheck=1
gpgkey=https://falco.org/repo/falcosecurity-packages.asc
enabled=1
EOF
    dnf install -y falco
fi

echo "Enabling and starting Falco service..."
systemctl enable falco-modern-bpf.service
systemctl start falco-modern-bpf.service

systemctl is-active falco-modern-bpf && echo "Falco service is active" || echo "Falco service failed to start"

echo "=== Falco Installation Complete ==="

touch /var/ossec/.falco_installed
