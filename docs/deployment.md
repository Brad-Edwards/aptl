# Deployment

## Quick Setup

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
./start-lab.sh
```

**Use the script.** Manual deployment is error-prone and takes longer.

## Manual Deployment

**These steps are automated by `start-lab.sh`. Use the script unless troubleshooting.**

#### 1. Prerequisites

```bash
# Check requirements
docker --version && docker compose version
sysctl vm.max_map_count  # Should be >= 262144
netstat -tlnp | grep -E "(443|2022|2023|9200|55000)"  # Ports must be free

# Fix vm.max_map_count if needed (Linux/WSL2)
sudo sysctl -w vm.max_map_count=262144
```

#### 2. Setup

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl

# Generate SSH keys
./scripts/generate-ssh-keys.sh

# Generate SSL certificates
docker compose -f generate-indexer-certs.yml run --rm generator

# Build MCP servers (optional - for AI integration)
cd mcp-red && npm install && npm run build && cd ..
cd mcp-blue && npm install && npm run build && cd ..
```

#### 3. Deploy

```bash
docker compose up --build -d
```

Wait 5-10 minutes for Wazuh indexer initialization.

## Startup Times

| Component | First Run | Restart |
|-----------|-----------|---------|
| SSL cert generation | 30s | 0s |
| Wazuh Indexer | 2-5 min | 1-2 min |
| Wazuh Manager | 1-2 min | 30s |
| Dashboard | 30s | 15s |
| Victim/Kali | 1-2 min | 30s |
| **Total** | **5-10 min** | **3-5 min** |

## Access

| Service | URL | Credentials |
|---------|-----|-------------|
| Wazuh Dashboard | <https://localhost:443> | admin / SecretPassword |
| Wazuh Indexer | <https://localhost:9200> | admin / SecretPassword |
| Wazuh API | <https://localhost:55000> | wazuh-wui / WazuhPass123! |
| Victim SSH | localhost:2022 | labadmin / aptl_lab_key |
| Kali SSH | localhost:2023 | kali / aptl_lab_key |

## Verification

```bash
# Check status
docker compose ps

# Test endpoints  
curl -k https://localhost:443          # Dashboard
curl -k https://localhost:9200        # Indexer
ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022 "echo OK"  # Victim
ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023 "echo OK"      # Kali
```

## Management

```bash
# Start lab
./start-lab.sh

# Stop lab
docker compose stop

# Restart
docker compose restart

# Clean removal
docker compose down -v
```

## Troubleshooting

### Port Conflicts

```bash
netstat -tlnp | grep -E "(443|2022|2023|9200|55000)"
sudo lsof -t -i:443 | xargs kill
```

### Certificate Issues

```bash
rm -rf config/wazuh_indexer_ssl_certs
docker compose -f generate-indexer-certs.yml run --rm generator
```

### Container Build Failures

```bash
docker builder prune -f
docker compose build --no-cache
```

### Recovery

```bash
docker compose down
docker system prune -f
./start-lab.sh
```
