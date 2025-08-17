# Architecture

## Network

```
172.20.0.0/16 Docker network

Containers:
├── wazuh.manager    172.20.0.10  (log processing)
├── wazuh.dashboard  172.20.0.11  (web UI)  
├── wazuh.indexer    172.20.0.12  (data storage)
├── victim           172.20.0.20  (target system)
├── juice-shop       172.20.0.21  (web app target)
└── kali             172.20.0.30  (attack platform)
```

## Ports

| Host | Container | Service |
|------|-----------|---------|
| 443 | dashboard:5601 | Wazuh web UI |
| 2022 | victim:22 | Victim SSH |
| 2024 | juice-shop:22 | Juice Shop SSH |
| 2023 | kali:22 | Kali SSH |
| 9200 | indexer:9200 | OpenSearch API |
| 55000 | manager:55000 | Wazuh API |

## Data Flow

1. Victim/Kali generate logs → Wazuh Manager (port 514)
2. Manager processes logs → Indexer (storage)
3. Dashboard queries Indexer → Web UI
4. MCP server controls Kali via SSH

## Components

**Wazuh SIEM:**
- Manager: Log processing, rules, alerts
- Indexer: OpenSearch data storage  
- Dashboard: Web interface

**Lab Environment:**
- Victim: Rocky Linux, SSH/HTTP/FTP services
- Juice Shop: OWASP Juice Shop vulnerable web app
- Kali: Attack tools, MCP integration
- Network: Isolated 172.20.0.0/16