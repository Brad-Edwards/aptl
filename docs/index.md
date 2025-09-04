# APTL

Docker lab: Wazuh SIEM + victim containers + Kali. Aurora extension adds VMs on dedicated hardware.

## Components

- Wazuh SIEM (172.20.0.10-12)
- Victim container (172.20.0.20)
- Minetest server (172.20.0.24)
- Minetest client (172.20.0.25)  
- Minecraft server (172.20.0.26)
- Reverse engineering container (172.20.0.27)
- Kali container (172.20.0.30)
- MCP servers for containers

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
- Minetest server SSH: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2024`
- Minetest client SSH: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2025`
- Minecraft server SSH: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2026`
- Reverse engineering container SSH: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2027`

## Requirements

- Docker + Docker Compose
- 8GB RAM, 20GB disk
- Ports: 443, 2022-2026, 9200, 25565, 55000

## Documentation

- [Getting Started](getting-started/)
- [Architecture](architecture/)
- [Components](components/)
- [Aurora VMs](aurora/)
- [Troubleshooting](troubleshooting/)
