# Lab Architecture

See [Configuration Management](./config-management.md) for how environment variables and runtime settings are managed across the lab.

## Network Topology

```mermaid
flowchart TD
    subgraph "Host System"
        H[Host Ports<br/>443, 2022, 2023, 9200, 55000]
    end
    
    subgraph "Docker Network 172.20.0.0/16"
        WM[Wazuh Manager<br/>172.20.0.10]
        WD[Wazuh Dashboard<br/>172.20.0.11] 
        WI[Wazuh Indexer<br/>172.20.0.12]
        V[Victim Container<br/>172.20.0.20]
        K[Kali Container<br/>172.20.0.30]
    end
    
    H --> WD
    H --> V
    H --> K
    H --> WI
    H --> WM
    
    V --> |Agent 1514| WM
    V --> |Syslog 514| WM
    K --> |Syslog 514| WM
    WM --> WI
    WI --> WD
    
    subgraph "AI Integration"
        MCP[MCP Servers]
        AI[AI Agents]
    end
    
    AI --> MCP
    MCP --> K
    MCP --> WM
    MCP --> WI
```

## Container Layout

| Container | IP | Purpose |
|-----------|----|---------| 
| wazuh.manager | 172.20.0.10 | Log processing, rules, alerts |
| wazuh.dashboard | 172.20.0.11 | Web interface |
| wazuh.indexer | 172.20.0.12 | OpenSearch data storage |
| victim | 172.20.0.20 | Target system with monitoring |
| kali | 172.20.0.30 | Attack platform |

## Ports

| Host | Container | Service |
|------|-----------|---------|
| 443 | dashboard:5601 | Wazuh web UI |
| 2022 | victim:22 | Victim SSH |
| 2023 | kali:22 | Kali SSH |
| 9200 | indexer:9200 | OpenSearch API |
| 55000 | manager:55000 | Wazuh API |

## Data Flow

1. **Victim** sends logs via:
   - Wazuh agent → Manager (port 1514)
   - rsyslog → Manager (port 514)
2. **Kali** sends logs → Manager (syslog port 514)
3. Manager processes logs → Indexer (storage)
4. Dashboard queries Indexer → Web UI
5. MCP server controls Kali via SSH

## Components

**Wazuh SIEM:**
- Manager: Log processing, rules, alerts
- Indexer: OpenSearch data storage  
- Dashboard: Web interface

**Lab Environment:**
- Victim: Rocky Linux, SSH, Wazuh agent, Falco eBPF monitoring
- Kali: Attack tools, MCP integration
- Network: Isolated 172.20.0.0/16