# Deployment

## Quick Setup

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
pip install -e .
aptl lab start
```

**Use the CLI.** Manual deployment is error-prone and takes longer.

## Configuration

Edit `aptl.json` to enable/disable containers:

```json
{
  "containers": {
    "wazuh": true,
    "victim": true,
    "kali": true,
    "reverse": false
  }
}
```

## Manual Deployment

**These steps are automated by `aptl lab start`. Use the CLI unless troubleshooting.**

#### 1. Prerequisites

```bash
# Check requirements
docker --version && docker compose version
sysctl vm.max_map_count  # Should be >= 262144
netstat -tlnp | grep -E "(443|2027|8443|9000|9001|9200|55000)"  # Ports must be free

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
./mcp/build-all-mcps.sh
```

#### 3. Deploy

```bash
aptl lab start
```

**Use `aptl lab start` for the deploy itself.** Beyond the steps above it also
renders the credentialized Wazuh config from the checked-in templates into the
gitignored `.aptl/config/` tree (ADR-028)—there is no standalone manual
command for that render, so a hand-run `docker compose --profile wazuh ... up`
on a fresh checkout fails at the `.aptl/config/...` bind mounts. Once a lab has
been started, a raw `docker compose --profile wazuh --profile victim --profile
kali up -d` (profile flags are required for manual compose commands) reuses the
already-rendered config.

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
| Wazuh Dashboard | <https://localhost:443> | `INDEXER_USERNAME` / `INDEXER_PASSWORD` from `.env` |
| Wazuh Indexer | <https://localhost:9200> | `INDEXER_USERNAME` / `INDEXER_PASSWORD` from `.env` |
| Wazuh API | <https://localhost:55000> | `API_USERNAME` / `API_PASSWORD` from `.env` |
| Victim shell | `aptl container shell aptl-victim` | container shell (no host SSH port) |
| Kali shell | `aptl container shell aptl-kali` | container shell (no host SSH port) |

## Verification

```bash
# Check status (works against local or SSH-remote labs)
aptl container list

# Test endpoints
curl -k https://localhost:443          # Dashboard
curl -k https://localhost:9200        # Indexer
ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022 "echo OK"  # Victim
ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023 "echo OK"      # Kali
```

## Management

```bash
# Start lab (recommended)
aptl lab start

# Check status
aptl lab status

# Stop lab
aptl lab stop

# Stop and remove all volumes
aptl lab stop -v

# Manual stop (requires profile flags)
docker compose --profile wazuh --profile victim --profile kali stop

# Manual clean removal
docker compose --profile wazuh --profile victim --profile kali down -v
```

## Troubleshooting

### Port Conflicts

```bash
netstat -tlnp | grep -E "(443|2027|8443|9000|9001|9200|55000)"
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
aptl lab start
```
