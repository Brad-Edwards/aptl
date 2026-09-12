# Network Architecture

Four Docker bridge networks providing segmented lab environment.

This page describes the default TechVault / compatibility Docker Compose
topology. For dynamic RAES scenarios, the compiled SDL infrastructure plan is
the topology authority: networks, CIDR/gateway/IPAM, `internal` egress policy,
and node attachments must be realized through typed `DeploymentBackend`
operations as described in [ADR-046](../adrs/adr-046-dynamic-raes-scenario-realization.md).
Do not treat the fixed `docker-compose.yml` network block below as the source
of truth for a scenario whose compiled plan declares different segmentation.

## Networks

| Network | Subnet | Purpose |
|---------|--------|---------|
| aptl-security | 172.20.0.0/24 | SOC stack (Wazuh, MISP, TheHive, Cortex, Shuffle, Suricata mgmt) |
| aptl-dmz | 172.20.1.0/24 | Externally reachable services (webapp, mail, DNS) |
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
| 514/udp, 1514, 1515 | aptl-wazuh-manager | Syslog + agent enrollment |
| 2027 | aptl-reverse:22 | Reverse Engineering SSH |
| 3443, 3001 | aptl-shuffle-frontend | Shuffle SOAR UI |
| 5353/tcp, 5353/udp | aptl-dns:53 | TechVault DNS |
| 8080 | aptl-webapp:8080 | TechVault web app |
| 8443 | aptl-misp:443 | MISP UI |
| 9000 | aptl-thehive:9000 | TheHive UI |
| 9001 | aptl-cortex:9001 | Cortex UI |
| 9200 | aptl-wazuh-indexer:9200 | OpenSearch API |
| 55000 | aptl-wazuh-manager:55000 | Wazuh API |

The victim and kali containers publish no host ports; use
`aptl container shell aptl-victim` / `aptl container shell aptl-kali`.

### Host bind addresses

Per ADR-034 (Host Exposure Amendment), a host publication binds `127.0.0.1`
unless the service is deliberate attack surface. Two kinds of surface bind
loopback:

- **SOC / control-plane management**: Wazuh, MISP, TheHive, Cortex, Shuffle,
  the OTel collector, Tempo, the web control plane, and the two SSH surfaces
  (the Kali bridge on 2023 and the reverse-engineering workstation on 2027).
  The RE workstation runs with host-equivalent authority (`cgroup: host`,
  `SYS_ADMIN`, `/sys/fs/cgroup` read-write, `seccomp:unconfined`), so
  LAN-reachable SSH into it would be a host takeover path; kali's in-scenario
  pivot reaches it at `172.20.0.27` on the security network instead.
- **Host-side lab services**: published only so the operator can drive the lab
  locally. `dns` is the current member. `dig @localhost -p 5353 techvault.local
  SOA` is the operator path, and the in-range red team resolves against
  `172.20.1.22` / `172.20.2.27` over the Docker networks, so a LAN publish would
  add exposure without adding realism.

Deliberate victim targets (`webapp-proxy` on 8080) publish on all interfaces so
the in-range red team can reach them. A host firewall is not a substitute for
the bind address: Docker manages its own packet-filtering rules for published
ports, so the mapping in `docker-compose.yml` is the control.

There is no environment-variable opt-in for a non-loopback bind. ADR-034 keeps
the bind address a single deployment-boundary seam rather than a per-service
knob, so exposing one of these services on the LAN means making a deliberate,
reviewable edit to its mapping in `docker-compose.yml`. Do that only on a
network you control: these services ship with known lab credentials and
intentionally weak configuration, and reaching them from another machine is
enough to take over the lab host's SOC stack. `APTL_HP_*` and
`APTL_DNS_HOST_PORT` change the port only, never the bind address.

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
| aptl-internal | **Yes** | Contains AD, database, victim, workstation—all attack targets |
| aptl-redteam | **Yes** | Kali command center; must not reach the real internet |

For dynamic RAES realization, the equivalent safety property is carried by the
authored network's `internal` property and the backend-created network must
apply it directly. An `internal` network that is created without Docker's
internal flag is a SAF-002 regression even if the fixed Compose topology still
passes these tables.

### Multi-homed container egress

Containers connected to both an internal network and `aptl-security` (dns, wazuh.manager, suricata) retain internet access via the security network interface. Attack containers (kali, victim, webapp, ad, db, fileshare, workstation, mailserver) are only on internal networks and have no internet egress.

### Host port mappings

Docker `internal: true` blocks outbound container traffic (no MASQUERADE rules), but inbound host port mappings (docker-proxy/DNAT) continue to work for containers that publish them, such as the reverse engineering container (port 2027). The victim and kali containers publish no host ports; reach them with `aptl container shell`.

### Package pre-installation

Wazuh agent and Falco are pre-installed in container images at build time so that containers on internal networks do not need internet access at runtime. The runtime install scripts (`install-wazuh.sh`, `install-falco.sh`) detect pre-installed packages and skip downloads. If the packages are not pre-installed (for example, using an older image), the scripts fall back to downloading from the internet, which will fail on internal networks.

### Upgrading from pre-SAF-002 deployments

Existing labs must be fully torn down before restarting with the new network configuration:

```bash
docker compose down    # remove old networks
docker compose up -d   # recreate with internal: true
```

Docker cannot change a network's `internal` flag in place. Rebuilding container images (`docker compose build`) is also required to pre-install Wazuh and Falco packages.
