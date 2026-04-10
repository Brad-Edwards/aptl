# ADR-006: Four-Network Segmentation Architecture

## Status

accepted

## Date

2026-02-07

## Context

APTL v2.0 through v3.x used a flat Docker network where all containers could reach each other directly. This was simple to configure but had a fundamental problem for a purple team training lab: **it didn't model enterprise network segmentation**.

### Problems with Flat Networking

1. **No pivot requirement**: An attacker (Kali) could reach every container directly. Real enterprise attacks require discovering and exploiting paths between network zones — DMZ to internal, internal to management, etc.
2. **No zone-based detection**: Network IDS (Suricata) couldn't differentiate between expected traffic (web app → database on the internal network) and suspicious traffic (attacker → database from the DMZ). Without zones, all traffic is "internal."
3. **No realistic firewall rules**: Enterprise networks restrict traffic between zones. A flat network has no concept of "the database is only reachable from the internal network."
4. **No multi-homed containers**: Containers that bridge network zones (like a Wazuh Manager collecting logs from all zones, or Kali pivoting through the DMZ) had no architectural representation.

### Design Constraints

- Must work with Docker bridge networking (no external routers or VPNs)
- Static IPs required for predictable container addressing (MCP servers, documentation, Wazuh agent configs all reference specific IPs)
- Multi-homed containers must have a unique IP on each network they join
- Must support 19+ containers without IP conflicts

## Decision

Create **four Docker bridge networks** that model enterprise network zones:

### Network Layout

| Network | Name | Subnet | Purpose |
|---------|------|--------|---------|
| Security | `aptl-security` | 172.20.0.0/24 | SOC stack: Wazuh, MISP, TheHive, Cortex, Shuffle, Suricata management, reverse engineering |
| DMZ | `aptl-dmz` | 172.20.1.0/24 | Externally-reachable services: web app, mail server, DNS |
| Internal | `aptl-internal` | 172.20.2.0/24 | Enterprise services: AD, database, file server, victim, workstation |
| Red Team | `aptl-redteam` | 172.20.4.0/24 | Attack platform: Kali (isolated by default) |

Note: 172.20.3.0/24 is reserved for a future Endpoints subnet (Windows VM) but is not yet implemented.

### Multi-Homed Containers

Several containers bridge multiple networks to perform their function:

| Container | Networks | Rationale |
|-----------|----------|-----------|
| Wazuh Manager | security, dmz, internal | Collects logs from all zones |
| Kali | redteam, dmz, internal | Can reach DMZ and internal (simulates attacker with pivot access) |
| Suricata | security, dmz, internal | Taps network traffic on all zones |
| DNS | security, dmz, internal | Resolves names across all zones |
| Web App | dmz, internal | Serves DMZ, accesses internal database |
| Mail Server | dmz, internal | Receives external mail, uses internal AD |

### Static IP Allocation

Every container has a fixed IP on each network it joins. IPs are assigned in `docker-compose.yml` using `ipv4_address` under each service's `networks` block. The allocation scheme:

- `.10-.19`: Infrastructure services (Wazuh, AD, DB, file server)
- `.20-.29`: Application services (web app, mail, DNS, victim, workstation, Shuffle, Cortex, reverse)
- `.30-.39`: Access points (Kali, Wazuh Manager internal interface)
- `.50`: Suricata (consistent across all networks for easy identification)

### Why /24 Subnets

Each network uses a /24 (254 usable addresses), which is more than needed for the current ~19 containers. A /28 would suffice per zone. However, /24 was chosen for:

- Simplicity: Standard enterprise subnet size, familiar to practitioners
- Headroom: Adding containers doesn't require subnet resizing
- Readability: `172.20.2.20` (victim on internal) is easier to remember than cramped subnets

The /16 supernet (172.20.0.0/16) was noted as cosmetically oversized (review item #27) but declared "won't fix" — it works correctly, and changing it risks breaking existing deployments.

## Consequences

### Positive

- **Realistic attack paths**: Kali must traverse network boundaries, mirroring real enterprise attacks
- **Zone-based detection**: Suricata and Wazuh can correlate events by network zone, enabling detection rules like "internal host connecting to external C2"
- **Multi-homed visibility**: Wazuh Manager on all three collection networks can receive logs from every container without a separate log aggregation layer
- **Static addressing**: MCP servers, documentation, and Wazuh configs all reference stable IPs. No DNS dependency for core infrastructure.
- **Teachable**: The 4-zone model maps directly to enterprise network concepts students are learning

### Negative

- **Complexity**: 19 containers × multiple networks = many IP assignments to maintain. IP allocation must be manually coordinated in `docker-compose.yml`.
- **Docker DNS limitations**: Containers on different Docker networks can't resolve each other by hostname without explicit `extra_hosts` entries or a shared DNS server (hence the DNS container).
- **No dynamic routing**: Docker bridge networks don't support routing protocols. Inter-zone routing depends entirely on multi-homed containers. There's no firewall appliance enforcing zone boundaries — isolation relies on Docker network membership.
- **Port mapping complexity**: Host port mappings must be unique across all containers regardless of network. Multiple web servers can't both use host port 80.

### Risks

- Docker bridge networking doesn't provide true network isolation at the kernel level — containers on different bridge networks can't communicate by default, but a compromised multi-homed container (e.g., the web app on both DMZ and internal) provides a real lateral movement path
- Static IPs create a coupling between `docker-compose.yml` and every config file, script, and documentation page that references container addresses. The v4.4.0 documentation review found wrong IPs throughout the docs after the network migration.
