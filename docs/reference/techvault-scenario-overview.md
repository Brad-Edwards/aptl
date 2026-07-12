# TechVault Scenario Overview

TechVault is APTL's default scenario: an [ACES SDL](../sdl/index.md)-authored,
multi-tier enterprise range for a fictional company. It is built as a live-fire
purple-team environment, with intentionally vulnerable enterprise targets on one
side, a production-grade SOC stack on the other, and a Kali attacker positioned
between them.

This page summarizes what the running range actually contains. For the fictional
company backstory and OSINT-facing persona detail, see the
[TechVault Company Profile](techvault-company-profile.md). For the authoring
boundary and curated startup slices, see
[Curated ACES Variants](../sdl/techvault-curated-variants.md).

## Where the scenario is defined

- `scenarios/techvault-operational.sdl.yaml` is the canonical ACES SDL that
  public startup boots by default (nodes, vulnerabilities, accounts, content,
  and relationships).
- `scenarios/catalog.json` registers the operational default plus the four
  curated variants as startup aliases.

Compose profiles are realized from the nodes the SDL declares (including
dependency closure), not from a preset keyed off the scenario name.

## Fictional company

*TechVault Solutions* is a cloud-security and data-management SaaS ("Securing
your digital assets"), founded 2019, with 25 to 50 simulated employees. The
internal domain is `techvault.local` and the Active Directory realm is
`TECHVAULT.LOCAL`. A cast of employee personas (Sarah Mitchell as CEO, James
Rodriguez as CTO, Emily Chen as DevOps lead, and others) carries the planted
identity weaknesses used in the attack path.

## Topology

The range spans four Docker networks:

| Zone | CIDR | What lives there |
|---|---|---|
| Security | 172.20.0.0/24 | Wazuh (manager, indexer, dashboard), Suricata, MISP, TheHive, Cortex, Shuffle SOAR, observability, reverse-engineering host |
| DMZ | 172.20.1.0/24 | Vulnerable webapp, mail server, DNS |
| Internal | 172.20.2.0/24 | Samba AD DC, PostgreSQL, Samba file share, victim host, developer workstation |
| Red Team | 172.20.4.0/24 | Kali attack platform and capture sidecar |

### Enterprise targets

The Flask web app (served by Gunicorn), PostgreSQL 16, a Samba file share, the
Samba Active Directory domain controller, a docker-mailserver instance, a BIND
DNS server, a developer workstation, and a Rocky Linux victim host.

### Defensive and SOC stack

Wazuh SIEM (manager, OpenSearch indexer, and dashboard) with active response;
Suricata IDS running passively, with prevention driven through Wazuh active
response per [ADR-019](../adrs/adr-019-suricata-ids-only-prevention-via-wazuh-ar.md);
MISP threat intelligence (with its MariaDB and Redis backends plus a Suricata
IOC sync); TheHive case management (backed by Cassandra and Elasticsearch)
alongside Cortex; Shuffle SOAR (backend, frontend, orborus, and OpenSearch); and
an OpenTelemetry collector feeding Tempo and Grafana. Two off-node Wazuh
sidecars forward PostgreSQL and Suricata logs into the manager.

### Host-published ports

| Host port | Service |
|---|---|
| 443 | Wazuh dashboard |
| 8080 | TechVault web app |
| 8443 | MISP UI |
| 9000 | TheHive UI |
| 9001 | Cortex UI |
| 9200 | Wazuh indexer (OpenSearch API) |
| 55000 | Wazuh manager API |
| 3443, 3001 | Shuffle SOAR UI |
| 2027 | Reverse-engineering host SSH |
| 514/udp, 1514, 1515 | Wazuh syslog and agent enrollment |

## Planted vulnerabilities

Vulnerabilities are declared per node in the SDL and span the application,
infrastructure, and identity layers.

- **Web app**: SQL injection in login and search, command injection in the ping
  tool, reflected and stored XSS, file and user IDOR, admin authorization
  bypass, exposed `/.env` and `/debug` routes, weak JWT secret with no expiry,
  unrestricted upload with path traversal, a hardcoded Flask secret, and verbose
  error disclosure.
- **Active Directory**: weak and seasonal user passwords, an over-privileged
  contractor account, a still-enabled former-employee account, kerberoastable
  service accounts (`svc-sql`, `svc-web`), and service accounts with Domain
  Admin membership (`svc-backup`, and the DevOps user `emily.chen`).
- **File share**: guest-writable SMB shares leaking PII, HR and finance data, a
  WiFi password, and hardcoded deployment credentials.
- **Workstation**: bash-history credentials, a `.pgpass` file, hardcoded
  application and cloud secrets, a passwordless SSH private key, and passwordless
  sudo (also present on the victim and reverse-engineering hosts).

## Planted secrets

By design, secret-named values in this synthetic range are scenario content, not
real operator secrets. They are captured in full as `secret_fixture` values so
the range stays reproducible. For example, the PostgreSQL fixture credential
`techvault_db_pass` appears verbatim as `POSTGRES_PASSWORD` on the `db` node and
as `DB_PASSWORD` on the `webapp` node. The Active Directory, Flask, JWT, and
workstation secrets follow the same pattern. Only genuine operator secrets are
withheld.

## Curated startup variants

Startup defaults to `techvault-operational` (the full stack). Four curated
slices prove that Compose profiles are realized from declared node content rather
than the scenario name:

| Catalog id | Includes | Realized profiles |
|---|---|---|
| `techvault-attacker-target` | Kali and capture sidecar, one monitored victim, Wazuh core, OTEL core | `kali`, `victim`, `wazuh`, `otel` |
| `techvault-enterprise-web` | Vulnerable webapp, database, AD, workstation, Wazuh core, OTEL core | `enterprise`, `wazuh`, `otel` |
| `techvault-defensive-min` | Wazuh manager, indexer, dashboard, OTEL core | `wazuh`, `otel` |
| `techvault-observability-core` | OTEL collector, Tempo, Grafana | `otel` |

Select a variant with `aptl lab start --scenario <catalog id>`. See
[Curated ACES Variants](../sdl/techvault-curated-variants.md) for the full
authoring and proof detail.
