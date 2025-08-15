# Getting Started

## Start the Lab

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
./start-lab.sh
```

Use the script. It handles SSH keys, SSL certificates, system requirements, and container startup.

**Note**: First run requires sudo password for SSL certificate permissions.

## Lab Components

| Component | Access | Credentials |
|-----------|--------|-------------|
| Wazuh Dashboard | <https://localhost:443> | admin / SecretPassword |
| Victim (target) | SSH port 2022 | labadmin / aptl_lab_key |
| Kali (attacker) | SSH port 2023 | kali / aptl_lab_key |

## Network

Isolated Docker network: `172.20.0.0/16`

- `172.20.0.10` - Wazuh Manager
- `172.20.0.11` - Wazuh Dashboard  
- `172.20.0.12` - Wazuh Indexer
- `172.20.0.20` - Victim
- `172.20.0.30` - Kali

## Prerequisites

- Docker with Compose
- 8GB+ RAM
- Linux/WSL2: `vm.max_map_count >= 262144`

Check [prerequisites.md](prerequisites.md) for details.

## Next Steps

- [Installation](installation.md) - Manual deployment steps
- [Quick Start](quick-start.md) - Basic operations
