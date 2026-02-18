# Getting Started

## Start the Lab

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
pip install -e .
aptl lab start
```

Alternative: `./start-lab.sh`

Both handle SSH keys, SSL certificates, system requirements, MCP builds, and container startup. First run takes 5-10 minutes.

## Access

| Component | Access | Credentials |
|-----------|--------|-------------|
| Wazuh Dashboard | https://localhost:443 | admin / SecretPassword |
| Victim (target) | SSH port 2022 | labadmin / aptl_lab_key |
| Kali (attacker) | SSH port 2023 | kali / aptl_lab_key |
| Reverse engineering | SSH port 2027 | labadmin / aptl_lab_key |

## Prerequisites

- Docker with Compose
- Python 3.11+ (for CLI)
- 8GB+ RAM
- Linux/WSL2: `vm.max_map_count >= 262144`

See [Prerequisites](prerequisites.md) for details.

## Next Steps

- [Prerequisites](prerequisites.md) — System requirements
- [Installation](installation.md) — Manual deployment steps
- [Quick Start](quick-start.md) — Basic operations and testing
