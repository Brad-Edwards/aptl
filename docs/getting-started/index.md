# Getting Started

## Start the Lab

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
`python3-venv` package (`sudo apt install python3-venv`); see
[Prerequisites](prerequisites.md).

`aptl lab start` creates `.env` automatically when it is missing and replaces
template placeholder values with lab credentials that match the running
containers. The startup output points to `.env` for passwords and tokens. Run
`aptl lab info` later to reprint the same access summary.

The CLI handles SSH keys, SSL certificates, system requirements, and container startup.

**Note**: First run requires sudo password for SSL certificate permissions.

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

- Docker with Compose
- 8GB+ RAM
- Linux/WSL2: `vm.max_map_count >= 262144`

Check [prerequisites.md](prerequisites.md) for details.

## Next Steps

- [Installation](installation.md) - Manual deployment steps
- [Quick Start](quick-start.md) - Basic operations
