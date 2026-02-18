# Installation

## Python CLI (Recommended)

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
pip install -e .
aptl lab start
```

The CLI handles SSH keys, SSL certificates, system requirements, image pulling, MCP builds, container startup, and service readiness checks.

## Bash Script (Alternative)

```bash
./start-lab.sh
```

Performs the same steps as the CLI.

## Manual Steps

If you need to run steps individually:

1. Generate SSH keys: `./scripts/generate-ssh-keys.sh`
2. Set vm.max_map_count (Linux/WSL2): `sudo sysctl -w vm.max_map_count=262144`
3. Generate SSL certificates: `docker compose -f generate-indexer-certs.yml run --rm generator`
4. Start lab: `docker compose --profile wazuh --profile victim --profile kali up --build -d`

Profile flags are **required** for manual docker compose commands. Add more profiles as needed (e.g., `--profile reverse`).

## MCP Integration

MCP servers are built automatically by `aptl lab start`. To build manually:

```bash
./mcp/build-all-mcps.sh
```

See [MCP Integration](../components/mcp-integration.md) for AI client configuration.

## Verification

```bash
aptl lab status
```

Access:

- Wazuh Dashboard: https://localhost:443 (admin/SecretPassword)
- Victim SSH: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022`
- Kali SSH: `ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023`
- Reverse SSH: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2027`