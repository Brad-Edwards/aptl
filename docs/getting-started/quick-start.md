# Quick Start

## Start Lab

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl

pip install -e .
cp .env.example .env   # then replace every CHANGE_ME value
aptl lab start
```

`aptl lab start` refuses to run while `.env` still contains the
`.env.example` placeholder values.

## Manage Lab

```bash
aptl lab status   # Show running containers and health
aptl lab stop     # Stop the lab
aptl lab stop -v  # Stop and remove all volumes
aptl kill         # Emergency: kill all MCP server processes immediately
aptl kill -c      # Emergency: kill MCP processes AND all lab containers
```

## Access

**Wazuh Dashboard:** <https://localhost:443> (`admin` / your `INDEXER_PASSWORD` from `.env`)

**Container shells** (victim and kali publish no host SSH ports):

```bash
aptl container shell aptl-victim
aptl container shell aptl-kali
```

The reverse engineering container is the only one with host SSH:
`ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2027`.

## Test

Generate test activity and view in Wazuh Dashboard:

```bash
# Generate log from victim
docker exec aptl-victim logger 'Test log entry'

# Run scan from Kali
docker exec aptl-kali nmap 172.20.2.20
```

View events in Wazuh Dashboard → Security Events

## AI Integration

For AI agent control, build and configure MCP servers. See [MCP Integration](../components/mcp-integration.md) for setup details.
