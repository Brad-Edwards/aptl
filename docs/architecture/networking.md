# Network Architecture

The lab uses four isolated Docker bridge networks. Multi-homed containers (Wazuh Manager, Kali) bridge networks as needed.

## Networks

| Network | Subnet | Gateway | Purpose |
|---------|--------|---------|---------|
| aptl-security | 172.20.0.0/24 | 172.20.0.1 | Wazuh SIEM, SOC tools, reverse engineering |
| aptl-dmz | 172.20.1.0/24 | 172.20.1.1 | Public-facing enterprise services |
| aptl-internal | 172.20.2.0/24 | 172.20.2.1 | Internal enterprise services, victim |
| aptl-redteam | 172.20.4.0/24 | 172.20.4.1 | Kali red team |

## Container IP Assignments

### aptl-security (172.20.0.0/24)

| Container | IP | Hostname |
|-----------|----|----------|
| wazuh.manager | 172.20.0.10 | wazuh.manager |
| wazuh.dashboard | 172.20.0.11 | wazuh.dashboard |
| wazuh.indexer | 172.20.0.12 | wazuh.indexer |
| reverse | 172.20.0.27 | reverse-host |

SOC profile containers (MISP, TheHive, Shuffle, Cortex) also reside on this network.

### aptl-dmz (172.20.1.0/24)

| Container | IP | Hostname |
|-----------|----|----------|
| wazuh.manager | 172.20.1.10 | — |
| webapp | 172.20.1.20 | — |
| mailserver | 172.20.1.21 | — |
| dns | 172.20.1.22 | — |
| kali | 172.20.1.30 | — |

### aptl-internal (172.20.2.0/24)

| Container | IP | Hostname |
|-----------|----|----------|
| ad | 172.20.2.10 | — |
| db | 172.20.2.11 | — |
| fileshare | 172.20.2.12 | — |
| victim | 172.20.2.20 | victim-host |
| webapp | 172.20.2.25 | — |
| mailserver | 172.20.2.26 | — |
| dns | 172.20.2.27 | — |
| wazuh.manager | 172.20.2.30 | — |
| kali | 172.20.2.35 | — |

### aptl-redteam (172.20.4.0/24)

| Container | IP | Hostname |
|-----------|----|----------|
| kali | 172.20.4.30 | kali-redteam |

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
- Reverse → Manager (syslog: 514/udp)

**SIEM Stack:**

- Manager ↔ Indexer (9200/tcp)
- Dashboard ↔ Indexer (9200/tcp)

**DNS Resolution:**

Containers on the same Docker network can reach each other by hostname or IP.

## Network Isolation

- Each network is an isolated Docker bridge
- Containers only communicate with others on their shared network(s)
- Multi-homed containers (Manager, Kali) bridge zones by design
- Only mapped ports are accessible from the host
- Standard Docker internet access is available from containers