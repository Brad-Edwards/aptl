# Wazuh Sidecar (db) Steady-State Inventory

This directory is the SCN-010 / issue #343 inventory bundle for the TechVault
`wazuh-sidecar-db` container. It applies the ACES-owned asset inventory
methodology to the realized `aptl-wazuh-sidecar-db` container and uses the
completed misp-db, suricata, and webapp inventories as the granularity bar
(issue #330 depth).

`wazuh-sidecar-db` is the **first standalone Wazuh log-forwarding sidecar**
inventoried in TechVault. Before this pass it existed in the SDL only as a
docker-compose-derived scenario-level `forwarding_agents` stub
(`aptl-db-wazuh-agent`, per Brad-Edwards/aces#460) explicitly carrying "no
captured inventory bundle". Issue #343 commissions that bundle and promotes the
sidecar to a fully inventoried participant node,
`nodes.techvault.wazuh-sidecar-db`, which carries the asset-level facts (image,
build recipe, packages, CVEs, filesystem, identity, runtime, capabilities) that
the forwarding-agent registry entry cannot express. The cross-node forwarding
behaviour stays in the scenario-level `forwarding_agents` registry (now enriched
from the captured `ossec.conf`) and is resolved by the
`db-logs-forwarded-wazuh` and `wazuh-sidecar-db-forwards-wazuh-manager`
relationship edges. **No known ACES expressivity gap remains** for the
catalogued steady-state facts.

This capture is non-destructive. It used the already-running local `aptl`
project (soc profile) on 2026-06-06 and **did not run
`aptl lab stop -v && aptl lab start`**. Treat this bundle as a frozen
observation of that local steady state, **not as clean-lab rebuild proof**.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-wazuh-sidecar-db` |
| Compose service | `wazuh-sidecar-db` |
| TechVault profile | `soc` |
| Source class | `local-custom-build-forwarding-agent-sidecar` |
| Image | `aptl-wazuh-sidecar:local` (custom build from `containers/wazuh-sidecar/Dockerfile`) |
| Local image config ID | `aptl-wazuh-sidecar@sha256:1a9c99918f73a234721fe07ccafdcc6c49e1b3784a16ce86cdb2864636345d25` |
| Base image | `debian:12-slim` |
| Runtime OS | Debian GNU/Linux 12 (bookworm) |
| Agent | wazuh-agent 4.12.0-1 (revision rc1, `WAZUH_TYPE=agent`) |
| Role | Off-node log forwarder for the `db` node (ADR-020 carve-out) |
| Monitored source | `/logs/pg_log/postgresql.log` (syslog), read-only via shared `aptl_db_data` volume |
| Manager target | `wazuh.manager` TCP/1514 (events), TCP/1515 (enrollment); registered as agent `005 aptl-db-agent`, status Active |
| Reachable participant ports | none — no network listener; dials out only |
| Network identity | `security-net` 172.20.0.35 (only network) |
| Capabilities | default Docker set; **no CAP_NET_ADMIN** (aptl-firewall-drop AR wrapper present but inert) |
| Package inventory | 114 dpkg packages |
| Trivy vulnerability findings | 174 total: 5 critical, 14 high, 64 medium, 84 low, 7 unknown |
| Local identity | 19 users, 39 groups, 0 sudo rules (one added service account: `wazuh`) |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture commands are reproducible. | `capture-evidence.sh`, `normalize-syft-cyclonedx.jq` |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/syft-version.json`, `evidence/osquery-version.txt` |
| Compose intent and local-build image identity are recorded. | `evidence/compose-service.wazuh-sidecar-db.json`, `evidence/docker-inspect.image.json`, `evidence/docker-history.image.txt`, `evidence/docker-history.image.jsonl`, `evidence/source-checksums.txt`, `evidence/docker-buildx-imagetools.image.err` |
| Runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-security.json`, `evidence/docker-volume.db_data.json`, `evidence/docker-top.txt`, `evidence/docker-logs.wazuh-sidecar-db.txt`, `evidence/runtime-baseline.txt` |
| Filesystem manifest and stable-content checksums are recorded. | `evidence/filesystem-tree.txt.gz`, `evidence/filesystem-checksums.txt.xz` |
| Agent forwarding state is recorded. | `evidence/wazuh-agent-state.txt`, `evidence/language-manifests.txt` |
| Observer (manager) and attacker (kali) vantages are recorded. | `evidence/observer-discovery.wazuh-manager.txt`, `evidence/participant-discovery.kali.txt` |
| Package and CVE inventory are recorded. | `evidence/os-packages.txt`, `evidence/trivy-vulnerabilities.json.gz`, `evidence/trivy-vulnerability-list.json`, `evidence/trivy-vulnerability-counts.json` |
| Required + useful-optional SBOMs are recorded. | `evidence/trivy-sbom.cyclonedx.json.gz`, `evidence/syft-sbom.cyclonedx.json.gz` |
| osquery baseline (with unavailable tables noted) is recorded. | `evidence/osquery-processes.json`, `evidence/osquery-listening-ports.json`, `evidence/osquery-docker-containers.json`, `evidence/osquery-docker-images.json`, `evidence/osquery-apt-sources.json`, `evidence/osquery-installed-applications.json`, `evidence/osquery-programs.json` |
| Every committed evidence file is hashed. | `evidence/evidence-sha256sums.txt` |

## Reproduce

```shell
# Capture (non-destructive; lab must be running with the soc profile up)
bash docs/aces/inventory/wazuh-sidecar-db/capture-evidence.sh

# Validate the mapping ledger and check for unresolved gaps
aptl aces-inventory validate docs/aces/inventory/wazuh-sidecar-db
aptl aces-inventory gaps docs/aces/inventory/wazuh-sidecar-db

# Re-run the bundle's correspondence tests
pytest tests/test_wazuh_sidecar_db_inventory.py -q
```

The authored SDL node lives at
`scenarios/techvault/nodes/wazuh-sidecar-db.sdl.yaml`; its bulk blocks
(packages, CVEs, local identity) are derived directly from the committed
evidence files above.

## ACES Mapping Summary

| Surface | Encoding |
| --- | --- |
| Image / build / packages / CVEs / filesystem / identity / runtime / capabilities / network | `nodes.techvault.wazuh-sidecar-db` |
| Cross-node forwarding spec (tailed source, buffer policy, ship target) | `forwarding_agents.aptl-db-wazuh-agent` (Brad-Edwards/aces#460) |
| Log-origin + realized forwarding edges | `relationships.db-logs-forwarded-wazuh`, `relationships.wazuh-sidecar-db-forwards-wazuh-manager` |
| Local accounts | `accounts.wazuh-sidecar-db-local-*` |

All 23 catalogued facts in `mapping-ledger.yaml` are `encoded` /
`encoded_with_caveat`; none are blocked. No ACES expressivity issue is filed
because every catalogued participant/agent-observable fact maps to a current
ACES surface.

## Known Limits

These are recorded as first-class entries in `evidence/capture-limits.txt`:

- Non-destructive capture against the already-running lab; not clean-reset
  rebuild proof.
- `docker buildx imagetools inspect` fails for the local-only image tag; image
  identity is the local config ID plus the build recipe.
- `/logs` is the db container's PostgreSQL PGDATA (shared `aptl_db_data` volume)
  mounted read-only; only the monitored log path is recorded here, the full
  PGDATA content is the db asset's inventory (`docs/aces/inventory/db/`).
- `/var/ossec/etc/client.keys` is an in-range Wazuh agent registration fixture
  and is captured verbatim in `evidence/wazuh-agent-state.txt`; `/var/ossec/.ssh`
  remains path/metadata only.
- `ss`/`netstat` are not installed in the image; the no-network-listener fact is
  sourced from container-namespace osquery.
- Syft CycloneDX normalized by stripping `syft:location:*` properties; filesystem
  provenance is in the committed manifests.
- osquery `installed_applications` / `programs` tables unavailable in the
  digest-pinned Linux scanner image.

## Claims Framing

- This bundle establishes a *spec* for the sidecar at steady state, cited
  against observed reality at a single point in time.
- It does not prove byte-identical re-buildability; it provides the ground truth
  a future equivalence checker compares against.
- It does not cover behaviour over time or attack-induced transitions; any state
  present at the snapshot point is in scope.
- The `aptl-firewall-drop` active-response wrapper is present in the image but
  cannot run on this sidecar (no CAP_NET_ADMIN, and AR-on-sidecar acts on the
  wrong namespace per ADR-020); it is recorded as a capability/filesystem fact,
  not as a working prevention control.
