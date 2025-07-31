#!/bin/bash
# Log everything for troubleshooting
exec > >(tee /var/log/user-data.log)
exec 2>&1

echo "Starting lab container host setup..."

# Update system
yum update -y

# Install Docker
yum install -y docker
systemctl start docker
systemctl enable docker

# Add ec2-user to docker group
usermod -aG docker ec2-user

# Install Docker Compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Install AWS CLI v2 (if not already present)
if ! command -v aws &> /dev/null; then
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip
    ./aws/install
    rm -rf aws awscliv2.zip
fi

# Configure ECR login
ECR_REGISTRY=$(echo "${ecr_repository_url}" | cut -d'/' -f1)
aws ecr get-login-password --region ${aws_region} | docker login --username AWS --password-stdin $ECR_REGISTRY

# Pull Kali container image
echo "Pulling Kali container from ECR..."
docker pull ${ecr_repository_url}:latest

# Create docker-compose.yml for lab containers
cat > /home/ec2-user/docker-compose.yml << 'EOF'
version: '3.8'

services:
  kali:
    image: ${ecr_repository_url}:latest
    container_name: aptl-kali
    ports:
      - "2222:22"
    environment:
      - SIEM_PRIVATE_IP=${siem_private_ip}
      - VICTIM_PRIVATE_IP=${victim_private_ip}
      - SIEM_TYPE=${siem_type}
    volumes:
      - kali-operations:/home/kali/operations
      - /home/ec2-user/.ssh:/host-ssh-keys:ro
    restart: unless-stopped
    networks:
      - lab-network
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - SYS_PTRACE
      - NET_BIND_SERVICE
      - SETUID
      - SETGID
      - DAC_OVERRIDE
    privileged: false
    security_opt:
      - seccomp:unconfined
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
      nproc:
        soft: 32768
        hard: 32768
    shm_size: 2gb

networks:
  lab-network:
    driver: bridge

volumes:
  kali-operations:
EOF

# Set ownership of docker-compose file
chown ec2-user:ec2-user /home/ec2-user/docker-compose.yml

# Start the lab containers
cd /home/ec2-user
docker-compose up -d

# Create connection info script
cat > /home/ec2-user/lab_info.sh << 'EOFINFO'
#!/bin/bash
echo "=== APTL Lab Container Host ==="
echo ""
echo "Container Status:"
docker-compose ps
echo ""
echo "Container Access:"
PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
echo "  Kali SSH: ssh -p 2222 kali@$PUBLIC_IP"
echo "  Password: kali"
echo ""
echo "Host Access:"
echo "  Host SSH: ssh ec2-user@$PUBLIC_IP"
echo ""
echo "Container Management:"
echo "  View logs: docker-compose logs kali"
echo "  Restart: docker-compose restart kali"
echo "  Shell: docker-compose exec kali bash"
EOFINFO

chmod +x /home/ec2-user/lab_info.sh
chown ec2-user:ec2-user /home/ec2-user/lab_info.sh

echo "Lab container host setup complete!"
echo "Kali container should be accessible on port 2222"