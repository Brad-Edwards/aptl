# Deployment

## Quick Setup

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
aptl lab start
```

The virtualenv keeps the editable install off the system Python, so it works
on modern Debian/Ubuntu/WSL2 hosts that block system-wide `pip` under
[PEP 668](https://peps.python.org/pep-0668/). Those hosts need the
`python3-venv` package (`sudo apt install python3-venv`).

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
docker --version && docker compose version && docker buildx version
sysctl vm.max_map_count  # Native Linux Docker Engine only; should be >= 262144
netstat -tlnp | grep -E "(443|2027|8443|9000|9001|9200|55000)"  # Ports must be free

# Fix vm.max_map_count if needed (native Linux Docker Engine)
sudo sysctl -w vm.max_map_count=262144
```

#### 2. Setup

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl

# Generate SSH keys
./scripts/generate-ssh-keys.sh

# Build MCP servers (optional - for AI integration)
./mcp/build-all-mcps.sh
```

#### 3. Deploy

```bash
aptl lab start
```

**Use `aptl lab start` for the deploy itself.** Beyond the steps above it also
generates the Wazuh Indexer SSL certificates automatically (producer-owned,
platform-aware—see [Troubleshooting](troubleshooting/index.md)) and renders
the credentialized Wazuh config from the checked-in templates into the
gitignored `.aptl/config/` tree (ADR-028); there is no standalone manual
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

## Lifecycle Policy

The lab can auto-teardown on a TTL or idle timeout and provision on a schedule
(DEP-003). Add a `lifecycle_policy` block to `aptl.json`:

```json
{
  "lab": { "name": "aptl" },
  "lifecycle_policy": {
    "ttl_minutes": 240,
    "idle_timeout_minutes": 60,
    "teardown_remove_volumes": true,
    "schedule": [
      { "at": "08:00", "days": ["mon", "tue", "wed", "thu", "fri"], "scenario": null }
    ]
  }
}
```

- `ttl_minutes` tears the range down once it has run that long.
- `idle_timeout_minutes` tears the range down after no run capture activity for
  that long.
- `teardown_remove_volumes` controls whether an auto-teardown removes Compose
  volumes (a full clean teardown).
- `schedule` provisions a clean range at each `HH:MM` UTC time. `days` is an
  optional weekday filter (empty means every day); `scenario` is an optional
  curated scenario id.

Enforcement is a single idempotent tick that you schedule yourself:

```bash
# One evaluate-and-act tick (wire to a systemd timer or cron)
aptl lab enforce

# Or run a single-owner loop on a host without a timer
aptl lab monitor --interval 60

# Inspect the resolved policy and current lifecycle state
aptl lab policy show
```

The tick holds a per-project lock, so a manual `enforce` and a running
`monitor` never act at once. See
[ADR-045](adrs/adr-045-ephemeral-lifecycle-policy-enforcement.md) for the
design.

## Troubleshooting

### Port Conflicts

```bash
netstat -tlnp | grep -E "(443|2027|8443|9000|9001|9200|55000)"
sudo lsof -t -i:443 | xargs kill
```

### Certificate Issues

```bash
rm -rf config/wazuh_indexer_ssl_certs
aptl lab start
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
