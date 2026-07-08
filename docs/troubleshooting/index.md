# Troubleshooting

## Quick Checks

```bash
# Container status (works against local or SSH-remote labs)
aptl container list

# Service logs
aptl container logs aptl-wazuh-manager
aptl container logs aptl-victim
aptl container logs aptl-kali

# Network connectivity (raw docker exec is fine for one-off ping/etc.)
docker exec aptl-kali ping 172.20.2.20
docker exec aptl-victim ping 172.20.2.30
```

## Common Issues

### Containers won't start

**Check logs:**
```bash
aptl container logs <container-name>
# e.g. aptl container logs aptl-wazuh-manager
```

**Port conflicts:**
```bash
netstat -tlnp | grep -E "(443|2022|2023|9200|55000)"
sudo systemctl stop apache2  # if port 443 conflict
```

**Memory issues:**
```bash
free -h
# Increase Docker memory in Docker Desktop settings
```

**vm.max_map_count (native Linux Docker Engine):**
```bash
sudo sysctl -w vm.max_map_count=262144
```

Docker Desktop on macOS, Windows, and WSL2 manages this setting inside the
Linux VM. On those platforms, `aptl lab start` skips the host sysctl check.

### SSH access fails

**Key permissions on Linux/macOS:**
```bash
chmod 600 ~/.ssh/aptl_lab_key
```

On Windows, `aptl lab start` hardens the key with NTFS ACLs. If OpenSSH still
rejects it, regenerate the key by moving `%USERPROFILE%\.ssh\aptl_lab_key` and
running `aptl lab start` again.

**Test SSH service:**
```bash
docker exec aptl-victim systemctl status sshd
docker exec aptl-kali systemctl status ssh
```

**Direct container access:**
```bash
aptl container shell aptl-victim
aptl container shell aptl-kali
# Or, against an alpine-based image: aptl container shell <name> --shell /bin/sh
```

### Wazuh Dashboard not accessible

**Check container:**
```bash
aptl container logs aptl-wazuh-dashboard
```

**Test port:**
```bash
curl -k https://localhost:443
```

**Regenerate certificates:**
```bash
rm -rf config/wazuh_indexer_ssl_certs
docker compose -f generate-indexer-certs.yml run --rm generator
```

### No logs in Wazuh

**Test log generation:**
```bash
docker exec aptl-victim logger "Test entry $(date)"
```

**Check log forwarding:**
```bash
docker exec aptl-victim cat /etc/rsyslog.d/90-forward.conf
docker exec aptl-victim systemctl status rsyslog
```

**Test syslog connectivity:**
```bash
docker exec aptl-victim telnet 172.20.2.30 514
```

### MCP issues

**Build MCP servers:**
```bash
cd mcp/mcp-red && npm install && npm run build && cd ../..
cd mcp/mcp-wazuh && npm install && npm run build && cd ../..
```

**Check the kali container is reachable:**
```bash
docker exec aptl-kali echo test
```

## Recovery

### Complete reset
```bash
docker compose down -v
docker system prune -f
aptl lab start
```

### Service reset
```bash
docker compose restart [service_name]
# or
docker compose stop [service_name]
docker compose rm -f [service_name]
docker compose up -d [service_name]
```

### Clean rebuild
```bash
docker compose down
docker system prune -f
aptl lab start
```

`aptl lab start` re-renders the credentialized Wazuh config under `.aptl/config/`
and brings up the profiles from `aptl.json`—a bare `docker compose up` would
skip the credential render and the profile selection.

## Platform Issues

### Linux
```bash
# Docker permissions
sudo usermod -aG docker $USER
# Logout/login required
```

### macOS
```bash
# Check AirPlay on port 443
sudo lsof -i :443
# Disable in System Preferences → Sharing
```

### `aptl lab start` fails with "Existing network aptl_aptl-... does not match realized network"

Symptom on a machine that has run an older aptl-labs release before the
`org.aptl.realization.network=true` label was introduced:

```
Lab start failed: ACES runtime handoff failed: ...
  Existing network aptl_aptl-dmz does not match realized network dmz-net:
  label org.aptl.realization.network expected 'true', found ''.
```

The stale networks were created without the label the current version
expects. `aptl lab stop` (graceful) does not always remove them. Remove
by name and retry:

```bash
aptl lab stop
docker network ls --filter name=aptl \
  --format '{{.Name}}\t{{.Labels}}' \
  | awk '/org\.aptl\.realization\.network=true/{next} $1 ~ /^aptl_aptl-/ {print $1}' \
  | xargs -r docker network rm
aptl lab start
```

Tracked in [#722](https://github.com/Brad-Edwards/aptl/issues/722).

### macOS: Docker Desktop uninstall leftovers

If you uninstalled Docker Desktop and switched to Colima (or brew-installed
Docker), two leftover pieces silently break `aptl lab start`:

**Dead CLI plugin symlinks** in `~/.docker/cli-plugins/*` still point at
`/Applications/Docker.app/Contents/Resources/cli-plugins/...`. `docker
buildx` and `docker compose` then fail with `unknown command` even after
`brew install docker-buildx docker-compose`. Repoint them at the brew
binaries and drop the other dead symlinks:

```bash
ln -sf "$(brew --prefix docker-buildx)/bin/docker-buildx" ~/.docker/cli-plugins/docker-buildx
ln -sf "$(brew --prefix docker-compose)/bin/docker-compose" ~/.docker/cli-plugins/docker-compose
for f in ~/.docker/cli-plugins/*; do [ -L "$f" ] && [ ! -e "$f" ] && rm "$f"; done
```

**Stale `credsStore` in `~/.docker/config.json`.** Docker Desktop's
installer sets `"credsStore": "desktop"`, and `docker pull` on any image
requiring a credential lookup then fails with:

```
error getting credentials - err: exec: "docker-credential-desktop": executable file not found in $PATH
```

Remove that key from `~/.docker/config.json`. A minimal working config after
switching to Colima looks like:

```json
{
  "auths": {},
  "currentContext": "colima"
}
```

### WSL2
```bash
# Restart WSL2
wsl --shutdown
# Edit ~/.wslconfig:
[wsl2]
memory=8GB
processors=4
```
