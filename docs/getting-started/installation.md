# Installation

## Automated Setup

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
./start-lab.sh
```

The script handles SSH keys, SSL certificates, system requirements, and container startup.

## Manual Steps

If you need to run steps individually:

1. Generate SSH keys: `./scripts/generate-ssh-keys.sh`
2. Set vm.max_map_count (Linux/WSL2): `sudo sysctl -w vm.max_map_count=262144`
3. Generate SSL certificates: `docker compose -f generate-indexer-certs.yml run --rm generator`
4. Start lab: `docker compose up --build -d`

## MCP Integration

Build MCP servers for AI agent control:
```bash
cd mcp-red && npm install && npm run build && cd ..
cd mcp-blue && npm install && npm run build && cd ..
```

See [MCP Integration](../components/mcp-integration.md) for configuration details.

## Verification

Access lab components:
- Wazuh Dashboard: https://localhost:443 (admin/SecretPassword)
- Victim SSH: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022`
- Kali SSH: `ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023`