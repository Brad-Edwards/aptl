# APTL

Docker lab: Wazuh SIEM + victim containers + Kali.

## Components

- Wazuh SIEM (172.20.0.10-12)
- Victim container (172.20.0.20)
- Kali container (172.20.0.30)
- MCP server (AI control)

## Setup

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
./start-lab.sh
```

**Access:**

- Wazuh: <https://localhost:443> (admin/SecretPassword)
- Victim SSH: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022`
- Kali SSH: `ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023`

## Requirements

- Docker + Docker Compose
- 8GB RAM, 20GB disk
- Ports: 443, 2022, 2023, 9200, 55000

## Documentation

- [Getting Started](getting-started/)
- [Architecture](architecture/)
- [Components](components/)
- [Troubleshooting](troubleshooting/)