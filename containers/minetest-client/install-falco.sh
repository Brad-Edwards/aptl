#!/bin/bash
set -e

echo "=== Installing Falco with Modern eBPF (Ubuntu) ==="

# Check if Falco is already installed
if [ -f /opt/lab/.falco_installed ]; then
    echo "Falco already installed, starting services..."
    systemctl start falco-modern-bpf.service
    exit 0
fi

echo "Setting up Falco repository..."

# Install dependencies
apt-get update
apt-get install -y curl gnupg

# Add Falco repository
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
    gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg

cat > /etc/apt/sources.list.d/falco.list << EOF
deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main
EOF

echo "Installing Falco..."
apt-get update
apt-get install -y falco

echo "Enabling and starting Falco service..."
systemctl enable falco-modern-bpf.service
systemctl start falco-modern-bpf.service

systemctl is-active falco-modern-bpf && echo "Falco service is active" || echo "Falco service failed to start"

echo "=== Falco Installation Complete ==="

mkdir -p /opt/lab
touch /opt/lab/.falco_installed