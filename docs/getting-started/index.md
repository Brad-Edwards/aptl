# Getting Started

## Start the Lab

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
pip install -e .
cp .env.example .env   # then replace every CHANGE_ME value
aptl lab start
```

`aptl lab start` refuses to run while `.env` still contains the
`.env.example` placeholder values.

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
