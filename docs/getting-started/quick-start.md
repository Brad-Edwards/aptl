# Quick Start

## Start Lab

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl

# Option A: Python CLI (recommended)
pip install -e .
aptl lab start

# Option B: Bash script
./start-lab.sh
```

## Manage Lab

```bash
aptl lab status   # Show running containers and health
aptl lab stop     # Stop the lab
aptl lab stop -v  # Stop and remove all volumes
```

## Access

**Wazuh Dashboard:** https://localhost:443 (admin/SecretPassword)

**SSH Access:**
- Victim: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022`
- Kali: `ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023`

## Test

Generate test activity and view in Wazuh Dashboard:

```bash
# Generate log from victim
ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022 "logger 'Test log entry'"

# Run scan from Kali  
ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023 "nmap 172.20.0.20"
```

View events in Wazuh Dashboard → Security Events

## AI Integration

For AI agent control, build and configure MCP servers. See [MCP Integration](../components/mcp-integration.md) for setup details.