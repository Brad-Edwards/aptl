# Troubleshooting

## Quick Checks

```bash
# Container status
docker compose ps

# Service logs  
docker compose logs wazuh.manager
docker compose logs victim
docker compose logs kali

# Network connectivity
docker exec aptl-kali ping 172.20.0.20
docker exec aptl-victim ping 172.20.0.10
```

## Common Issues

### Containers won't start

**Check logs:**
```bash
docker compose logs [service_name]
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

**vm.max_map_count (Linux/WSL2):**
```bash
sudo sysctl -w vm.max_map_count=262144
```

### SSH access fails

**Key permissions:**
```bash
chmod 600 ~/.ssh/aptl_lab_key
```

**Test SSH service:**
```bash
docker exec aptl-victim systemctl status sshd
docker exec aptl-kali systemctl status ssh
```

**Direct container access:**
```bash
docker exec -it aptl-victim /bin/bash
docker exec -it aptl-kali /bin/bash
```

### Wazuh Dashboard not accessible

**Check container:**
```bash
docker compose logs wazuh.dashboard
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
docker exec aptl-victim telnet 172.20.0.10 514
```

### MCP issues

**Build MCP server:**
```bash
cd mcp && npm install && npm run build
```

**Test MCP server:**
```bash
cd mcp && node dist/index.js
```

**Check SSH from MCP:**
```bash
ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023 "echo test"
```

## Recovery

### Complete reset
```bash
docker compose down -v
docker system prune -f
./start-lab.sh
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
docker compose up --build -d
```

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

### WSL2
```bash
# Restart WSL2
wsl --shutdown
# Edit ~/.wslconfig:
[wsl2]
memory=8GB
processors=4
```