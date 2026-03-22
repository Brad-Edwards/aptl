# Network Architecture

Four Docker bridge networks providing segmented lab environment.

## Networks

| Network | Subnet | Purpose |
|---------|--------|---------|
| aptl-security | 172.20.0.0/24 | SOC stack (Wazuh, MISP, TheHive, Cortex, Shuffle, Suricata mgmt) |
| aptl-dmz | 172.20.1.0/24 | Externally-reachable services (webapp, mail, DNS) |
| aptl-internal | 172.20.2.0/24 | Enterprise services (AD, DB, file server, victim, workstation) |
| aptl-redteam | 172.20.4.0/24 | Red team (Kali) |

## Container IPs

### Security Network (172.20.0.0/24)

| Container | IP | Service |
|-----------|----|---------|
| aptl-wazuh-manager | 172.20.0.10 | Log processing, rules, alerts |
| aptl-wazuh-dashboard | 172.20.0.11 | Web UI |
| aptl-wazuh-indexer | 172.20.0.12 | OpenSearch data storage |
| aptl-misp | 172.20.0.16 | Threat intelligence |
| aptl-misp-db | 172.20.0.17 | MISP database |
| aptl-thehive | 172.20.0.18 | Case management |
| aptl-shuffle-backend | 172.20.0.20 | SOAR backend |
| aptl-shuffle-frontend | 172.20.0.21 | SOAR frontend |
| aptl-cortex | 172.20.0.22 | Automated enrichment |
| aptl-dns | 172.20.0.25 | DNS (security interface) |
| aptl-reverse | 172.20.0.27 | Reverse engineering |
| aptl-suricata | 172.20.0.50 | IDS (security interface) |

### DMZ Network (172.20.1.0/24)

| Container | IP | Service |
|-----------|----|---------|
| aptl-wazuh-manager | 172.20.1.10 | Log collection from DMZ |
| aptl-webapp | 172.20.1.20 | Web application |
| aptl-mailserver | 172.20.1.21 | Email server |
| aptl-dns | 172.20.1.22 | DNS (DMZ interface) |
| aptl-kali | 172.20.1.30 | Red team (DMZ access) |
| aptl-suricata | 172.20.1.50 | IDS (DMZ tap) |

### Internal Network (172.20.2.0/24)

| Container | IP | Service |
|-----------|----|---------|
| aptl-ad | 172.20.2.10 | Samba AD domain controller |
| aptl-db | 172.20.2.11 | PostgreSQL database |
| aptl-fileshare | 172.20.2.12 | Samba file server |
| aptl-victim | 172.20.2.20 | Rocky Linux target |
| aptl-webapp | 172.20.2.25 | Web app (internal interface) |
| aptl-mailserver | 172.20.2.26 | Mail (internal interface) |
| aptl-dns | 172.20.2.27 | DNS (internal interface) |
| aptl-wazuh-manager | 172.20.2.30 | Log collection from internal |
| aptl-kali | 172.20.2.35 | Red team (internal access) |
| aptl-workstation | 172.20.2.40 | Developer workstation |
| aptl-suricata | 172.20.2.50 | IDS (internal tap) |

### Red Team Network (172.20.4.0/24)

| Container | IP | Service |
|-----------|----|---------|
| aptl-kali | 172.20.4.30 | Kali Linux attack platform |

## Multi-Homed Containers

Several containers connect to multiple networks:

- **Wazuh Manager**: security + dmz + internal (collects logs from all zones)
- **Kali**: redteam + dmz + internal (attack access to all zones)
- **Suricata**: security + dmz + internal (taps all zones)
- **DNS**: security + dmz + internal (resolves across all zones)
- **Webapp**: dmz + internal (serves DMZ, accesses internal DB)
- **Mail server**: dmz + internal

## Host Port Mappings

| Host Port | Container | Service |
|-----------|-----------|---------|
| 443 | aptl-wazuh-dashboard:5601 | Wazuh Dashboard |
| 2022 | aptl-victim:22 | Victim SSH |
| 2023 | aptl-kali:22 | Kali SSH |
| 2027 | aptl-reverse:22 | Reverse Engineering SSH |
| 9200 | aptl-wazuh-indexer:9200 | OpenSearch API |
| 55000 | aptl-wazuh-manager:55000 | Wazuh API |

## Internal Communication

**Log Collection:**
- Victim → Manager (agent: 1514/tcp, syslog: 514/udp)
- Kali → Manager (syslog: 514/udp)
- Enterprise containers → Manager (syslog: 514/udp)

**SIEM Stack:**
- Manager <-> Indexer (9200/tcp)
- Dashboard <-> Indexer (9200/tcp)

**DNS Resolution:**
- Containers use Docker internal DNS (127.0.0.11)
- Kali has `extra_hosts` entries for `techvault.local` domain (required for Kerberos)

## Network Isolation

- Containers isolated from host network via Docker bridge
- Only mapped ports accessible from host
- Internal traffic unencrypted (lab environment)
- Kali can reach DMZ and internal networks (simulates attacker with pivot access)

## Egress Controls (SAF-002)

Three of the four networks use Docker's `internal: true` flag to prevent containers from reaching the internet. This is a safety constraint: autonomous agents controlling Kali must not be able to scan or attack external targets.

| Network | `internal: true` | Rationale |
|---------|-------------------|-----------|
| aptl-security | No | SOC tools (MISP, Wazuh, Shuffle) need internet for threat feeds and rule updates |
| aptl-dmz | **Yes** | Contains attack targets and Kali entry point |
| aptl-internal | **Yes** | Contains AD, database, victim, workstation — all attack targets |
| aptl-redteam | **Yes** | Kali command center; must not reach the real internet |

### Multi-homed container egress

Containers connected to both an internal network and `aptl-security` (dns, wazuh.manager, suricata) retain internet access via the security network interface. Attack containers (kali, victim, webapp, ad, db, fileshare, workstation, mailserver) are only on internal networks and have no internet egress.

### Host port mappings

Docker `internal: true` blocks outbound container traffic (no MASQUERADE rules), but inbound host port mappings (docker-proxy/DNAT) continue to work. SSH access to victim (port 2022) and kali (port 2023) from the host is unaffected.

### Package pre-installation

Wazuh agent and Falco are pre-installed in container images at build time so that containers on internal networks do not need internet access at runtime. The runtime install scripts (`install-wazuh.sh`, `install-falco.sh`) detect pre-installed packages and skip downloads. If the packages are not pre-installed (e.g., using an older image), the scripts fall back to downloading from the internet, which will fail on internal networks.

### Upgrading from pre-SAF-002 deployments

Existing labs must be fully torn down before restarting with the new network configuration:

```bash
docker compose down    # remove old networks
docker compose up -d   # recreate with internal: true
```

Docker cannot change a network's `internal` flag in place. Rebuilding container images (`docker compose build`) is also required to pre-install Wazuh and Falco packages.
