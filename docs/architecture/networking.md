# Network Architecture

Docker bridge network providing isolated lab environment for security testing.

## Network Configuration

**Network:** 172.20.0.0/16 (aptl-network)  
**Gateway:** 172.20.0.1  
**Driver:** bridge  

## Container IPs

| Container | IP | Hostname |
|-----------|----|---------| 
| wazuh.manager | 172.20.0.10 | wazuh.manager |
| wazuh.dashboard | 172.20.0.11 | wazuh.dashboard |
| wazuh.indexer | 172.20.0.12 | wazuh.indexer |
| victim | 172.20.0.20 | victim-host |
| reverse | 172.20.0.27 | reverse-host |
| kali | 172.20.0.30 | kali-redteam |

## Host Port Mappings

| Host Port | Container | Service |
|-----------|-----------|---------|
| 443 | dashboard:5601 | Wazuh Dashboard |
| 2022 | victim:22 | Victim SSH |
| 2023 | kali:22 | Kali SSH |
| 2027 | reverse:22 | Reverse Engineering SSH |
| 9200 | indexer:9200 | OpenSearch API |
| 55000 | manager:55000 | Wazuh API |

## Internal Communication

**Log Collection:**
- Victim → Manager (agent: 1514/tcp, syslog: 514/udp)
- Kali → Manager (syslog: 514/udp)

**SIEM Stack:**
- Manager ↔ Indexer (9200/tcp)
- Dashboard ↔ Indexer (9200/tcp)

**DNS Resolution:**
Containers can reach each other by hostname or IP address.

## Network Isolation

- Containers isolated from host network via Docker bridge
- Only mapped ports accessible from host
- Internal traffic unencrypted (lab environment)
- External internet access available (standard Docker behavior)