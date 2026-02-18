# Deployment

## Quick Setup

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
pip install -e .
aptl lab start
```

Alternative: `./start-lab.sh`

Both handle SSH keys, SSL certificates, system checks, MCP builds, and container startup.

## Configuration

Edit `aptl.json` to enable/disable container profiles:

```json
{
  "containers": {
    "wazuh": true,
    "victim": true,
    "kali": true,
    "reverse": false,
    "enterprise": true,
    "soc": true,
    "mail": false,
    "fileshare": false,
    "dns": false
  }
}
```

Only enabled profiles are started. The `wazuh`, `victim`, and `kali` profiles are enabled by default.

## Manual Deployment

**These steps are automated by `aptl lab start` and `start-lab.sh`. Use them unless troubleshooting.**

#### 1. Prerequisites

```bash
docker --version && docker compose version
sysctl vm.max_map_count  # Should be >= 262144

# Fix vm.max_map_count if needed (Linux/WSL2)
sudo sysctl -w vm.max_map_count=262144
```

#### 2. Setup

```bash
# Generate SSH keys
./scripts/generate-ssh-keys.sh

# Generate SSL certificates
docker compose -f generate-indexer-certs.yml run --rm generator

# Build MCP servers (optional)
./mcp/build-all-mcps.sh
```

#### 3. Deploy

Profile flags are **required** for manual docker compose commands:

```bash
# Core lab (wazuh + victim + kali)
docker compose --profile wazuh --profile victim --profile kali up --build -d

# With additional profiles
docker compose --profile wazuh --profile victim --profile kali --profile reverse up --build -d
```

Wait 5-10 minutes for Wazuh indexer initialization on first run.

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
| Wazuh Dashboard | https://localhost:443 | admin / SecretPassword |
| Wazuh Indexer | https://localhost:9200 | admin / SecretPassword |
| Wazuh API | https://localhost:55000 | wazuh-wui / WazuhPass123! |
| Victim SSH | localhost:2022 | labadmin / aptl_lab_key |
| Kali SSH | localhost:2023 | kali / aptl_lab_key |
| Reverse SSH | localhost:2027 | labadmin / aptl_lab_key |

## Verification

```bash
aptl lab status
# or
docker compose --profile wazuh --profile victim --profile kali ps
```

## Management

```bash
aptl lab start            # Start lab
aptl lab status           # Check status
aptl lab stop             # Stop lab
aptl lab stop -v          # Stop and remove volumes
```

Manual docker compose commands require profile flags:

```bash
docker compose --profile wazuh --profile victim --profile kali stop
docker compose --profile wazuh --profile victim --profile kali restart
docker compose --profile wazuh --profile victim --profile kali down -v
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
docker compose --profile wazuh --profile victim --profile kali build --no-cache
```

### Recovery

```bash
docker compose --profile wazuh --profile victim --profile kali down -v
docker system prune -f
aptl lab start
```
