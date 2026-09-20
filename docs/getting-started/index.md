# Getting Started

## Start the Lab

```bash
pipx install aptl-labs
aptl lab init my-lab
cd my-lab
aptl lab start
```

The published package includes the Compose topology, scenarios, config
templates, and container build contexts. `aptl lab init <dir>` materializes
those assets into a project directory, so no source clone is required.
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

The CLI handles SSH keys, SSL certificates, system requirements, and container startup.

`aptl lab start` runs the range directly on the selected host Docker engine.
For agent-driven or multi-user work on Linux/KVM, the disposable
[`aptl seat start`](../reference/appliance-seat-launcher.md) path provides a
stronger VM boundary around Docker and the lab. Neither containers nor a VM are
an absolute sandbox; advanced models with tool access can attempt escape chains.
Review the [execution-boundary guidance](quick-start.md#choose-the-execution-boundary)
before choosing a host.

## Lab Components

| Component | Access | Credentials |
|-----------|--------|-------------|
| Wazuh Dashboard | <https://localhost:443> | `admin` / your `INDEXER_PASSWORD` from `.env` |
| Victim (target) | `aptl container shell aptl-victim` | container shell (no host SSH port) |
| Kali (attacker) | `aptl container shell aptl-kali` | container shell (no host SSH port) |

## Network

Four isolated Docker networks:

- **Security** (172.20.0.0/24): Wazuh Manager (.10), Dashboard (.11), Indexer (.12), MISP (.16), TheHive (.18), Cortex (.22), Shuffle (.20/.21), Suricata (.50)
- **DMZ** (172.20.1.0/24): Web App (.20), Mail (.21), DNS (.22)
- **Internal** (172.20.2.0/24): AD DC (.10), PostgreSQL (.11), File Server (.12), Victim (.20), Workstation (.40)
- **Red Team** (172.20.4.0/24): Kali (.30)

## Prerequisites

- Docker with Compose and Buildx
- 8GB RAM for the curated scenarios; more than 20GB for the full `techvault-operational` stack
- Native Linux Docker Engine: `vm.max_map_count >= 262144`
- Docker Desktop on macOS, Windows, or WSL2: `aptl lab start` skips the host
  `sysctl` check because Docker manages it inside the Linux VM

Check [prerequisites.md](prerequisites.md) for details.

## Next Steps

- [Installation](installation.md) - Manual deployment steps
- [Quick Start](quick-start.md) - Basic operations
