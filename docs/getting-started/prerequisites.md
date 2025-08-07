# Prerequisites

## Requirements

- 8GB RAM, 20GB disk
- Docker Engine 20.10+
- Docker Compose 2.0+
- Git

## Install Docker

**Linux:**
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

**macOS/Windows:** Install Docker Desktop

## System Config

**Linux/WSL2:**
```bash
# Required for OpenSearch
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
```

**Check ports available:**
```bash
netstat -tlnp | grep -E "(443|2022|2023|9200|55000)"
```

## Verify

```bash
docker --version
docker compose version
docker ps
```