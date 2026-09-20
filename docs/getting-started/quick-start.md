# Quick Start

## Start Lab

```bash
pipx install aptl-labs
aptl lab init my-lab
cd my-lab
aptl lab start
```

The published wheel bundles the lab assets, so a PyPI install alone can run a
lab, no clone required. `aptl lab init <dir>` copies the Compose topology,
scenarios, and config templates out of the installed package into `<dir>`, your
lab project directory. [pipx](https://pipx.pypa.io/) isolates the CLI in its own
virtualenv, so the [PEP 668](https://peps.python.org/pep-0668/) system-`pip`
block on modern Debian/Ubuntu/WSL2 hosts never applies (`sudo apt install pipx`
to get it). To run from source instead, clone the repo and use a virtualenv
editable install
(`python3 -m venv .venv && source .venv/bin/activate && pip install -e .`; needs
`python3-venv`). See [Prerequisites](prerequisites.md).

`aptl lab start` creates `.env` automatically when it is missing and replaces
template placeholder values with lab credentials that match the running
containers. The startup output points to `.env` for passwords and tokens. Run
`aptl lab info` later to reprint the same access summary.

## Choose the execution boundary

`aptl lab start` runs the intentionally vulnerable range and its agent tools as
containers on the selected host Docker engine. A container escape or misuse of
a component with Docker authority can affect that host. Use this path for
development and supervised exercises on a dedicated, rebuildable machine; do
not treat an ordinary workstation containing unrelated credentials or
workloads as disposable lab infrastructure.

For agent-driven or multi-user exercises on a Linux KVM host, prefer
[`aptl seat start`](../reference/appliance-seat-launcher.md). A seat places the
rootful Docker daemon and the complete range inside a disposable VM, exposes
only signed loopback mappings, and separates users with distinct VM instances.
That is materially stronger isolation, not a perfect sandbox. An advanced
model with tool access can research and attempt a VM escape, so keep the host
kernel and QEMU/KVM patched and retain the same dedicated-host and network
controls where the consequence of host compromise matters.

`aptl lab start` defaults to the curated TechVault operational RAES SDL. List
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

The optional reverse engineering container uses host SSH when enabled:
`ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2027`. The default
TechVault scenario does not realize this service, so use the command only when
`reverse` appears in `aptl lab status`.

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
