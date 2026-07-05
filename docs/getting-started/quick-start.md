# Quick Start

## Start Lab

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
pipx install aptl
aptl lab start
```

Clone the repo even with the published package: `aptl lab start` reads the
Compose topology, scenarios, and config templates from the checkout.
[pipx](https://pipx.pypa.io/) isolates the CLI in its own virtualenv, so the
[PEP 668](https://peps.python.org/pep-0668/) system-`pip` block on modern
Debian/Ubuntu/WSL2 hosts never applies (`sudo apt install pipx` to get it). To
run from source instead, use a virtualenv editable install
(`python3 -m venv .venv && source .venv/bin/activate && pip install -e .`; needs
`python3-venv`). See [Prerequisites](prerequisites.md).

`aptl lab start` creates `.env` automatically when it is missing and replaces
template placeholder values with lab credentials that match the running
containers. The startup output points to `.env` for passwords and tokens. Run
`aptl lab info` later to reprint the same access summary.

`aptl lab start` defaults to the curated TechVault operational ACES SDL. List
the curated startup inputs with:

```bash
aptl lab scenarios
```

Start from a catalog id or an explicit project-local SDL path with:

```bash
aptl lab start --scenario techvault-operational
aptl lab start --scenario-path scenarios/techvault-operational.sdl.yaml
```

## Manage Lab

```bash
aptl lab status   # Show running containers and health
aptl lab info     # Show URLs, usernames, and .env credential references
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
