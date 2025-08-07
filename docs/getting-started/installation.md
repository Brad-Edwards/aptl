# Installation

## Quick Setup

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
./start-lab.sh
```

## Manual Setup

```bash
# Clone
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl

# SSH keys
./scripts/generate-ssh-keys.sh

# System config (Linux/WSL2)
sudo sysctl -w vm.max_map_count=262144

# SSL certificates
docker compose -f generate-indexer-certs.yml run --rm generator

# MCP server
cd mcp && npm install && npm run build && cd ..

# Start lab
docker compose up --build -d
```

## Verify

```bash
# Check containers
docker compose ps

# Test access
curl -k https://localhost:443
ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022 "echo ok"
ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023 "echo ok"
```

## Troubleshooting

**Port conflicts:**
```bash
sudo netstat -tlnp | grep -E "(443|2022|2023|9200|55000)"
sudo systemctl stop apache2  # if using port 443
```

**Build failures:**
```bash
docker compose down
docker system prune -f
docker compose up --build -d
```

**Permission issues:**
```bash
sudo usermod -aG docker $USER
# Logout/login
```