# Wazuh Sidecar (suricata) Steady-State Inventory

This directory is the SCN-010 / issue #344 inventory bundle for the TechVault
`wazuh-sidecar-suricata` container. It applies the ACES-owned asset inventory
methodology to the realized `aptl-wazuh-sidecar-suricata` container and uses
the completed wazuh-sidecar-db inventory (issue #343) as the direct precedent:
both sidecars run the **same** `aptl-wazuh-sidecar:local` image, so this bundle
follows that bundle's archetype at the same granularity bar (issue #330 depth).

`wazuh-sidecar-suricata` is the off-node Wazuh log-forwarding sidecar for the
`suricata` node. Before this pass it existed in the SDL only as a
docker-compose-derived scenario-level `forwarding_agents` stub
(`aptl-suricata-wazuh-agent`, per Brad-Edwards/aces#460) explicitly carrying
"no sidecar inventory bundle is in scope". Issue #344 commissions that bundle
and promotes the sidecar to a fully inventoried participant node,
`nodes.techvault.wazuh-sidecar-suricata`, which carries the asset-level facts
(image, build recipe, packages, CVEs, filesystem, identity, runtime,
capabilities) that the forwarding-agent registry entry cannot express. The
cross-node forwarding behaviour stays in the scenario-level `forwarding_agents`
registry (now enriched from the captured `ossec.conf`) and is resolved by the
`suricata-logs-forwarded-wazuh` and
`wazuh-sidecar-suricata-forwards-wazuh-manager` relationship edges.
**No known ACES expressivity gap remains** for the catalogued steady-state
facts.

This capture is non-destructive. It used the already-running local `aptl`
project (soc profile) on 2026-06-10 and **did not run
`aptl lab stop -v && aptl lab start`**. Treat this bundle as a frozen
observation of that local steady state, **not as clean-lab rebuild proof**.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-wazuh-sidecar-suricata` |
| Compose service | `wazuh-sidecar-suricata` |
| TechVault profile | `soc` |
| Source class | `local-custom-build-forwarding-agent-sidecar` |
| Image | `aptl-wazuh-sidecar:local` (custom build from `containers/wazuh-sidecar/Dockerfile`; same image as `wazuh-sidecar-db`) |
| Local image config ID | `aptl-wazuh-sidecar@sha256:de74ca155d35c0f8f50b9133320ae02cb0e0a73ef72ff0dececf949a0ab5fcd3` |
| Base image | `debian:12-slim` |
| Runtime OS | Debian GNU/Linux 12 (bookworm) |
| Agent | wazuh-agent 4.12.0-1 (revision rc1, `WAZUH_TYPE=agent`) |
| Role | Off-node log forwarder for the `suricata` node (ADR-020 carve-out) |
| Monitored source | `/logs/eve.json` (json), read-only via shared `aptl_suricata_logs` volume |
| Manager target | `wazuh.manager` TCP/1514 (events), TCP/1515 (enrollment); registered as agent `006 aptl-suricata-agent`, status Active |
| Reachable participant ports | none — no network listener; dials out only |
| Network identity | `security-net` 172.20.0.36 (only network) |
| Capabilities | default Docker set; **no CAP_NET_ADMIN** (aptl-firewall-drop AR wrapper present but inert) |
| Package inventory | 114 dpkg packages |
| Trivy vulnerability findings | 194 total: 5 critical, 17 high, 71 medium, 98 low, 3 unknown |
| Local identity | 19 users, 39 groups, 0 sudo rules (one added service account: `wazuh`) |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture commands are reproducible. | `capture-evidence.sh`, `normalize-syft-cyclonedx.jq` |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/syft-version.json`, `evidence/osquery-version.txt` |
| Compose intent and local-build image identity are recorded. | `evidence/compose-service.wazuh-sidecar-suricata.json`, `evidence/docker-inspect.image.json`, `evidence/docker-history.image.txt`, `evidence/docker-history.image.jsonl`, `evidence/source-checksums.txt`, `evidence/docker-buildx-imagetools.image.err` |
| Runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-security.json`, `evidence/docker-volume.suricata_logs.json`, `evidence/docker-top.txt`, `evidence/docker-logs.wazuh-sidecar-suricata.txt`, `evidence/runtime-baseline.txt` |
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
bash docs/aces/inventory/wazuh-sidecar-suricata/capture-evidence.sh

# Validate the mapping ledger and check for unresolved gaps
aptl aces-inventory validate docs/aces/inventory/wazuh-sidecar-suricata
aptl aces-inventory gaps docs/aces/inventory/wazuh-sidecar-suricata

# Re-run the bundle's correspondence tests
pytest tests/test_wazuh_sidecar_suricata_inventory.py -q
```

The authored SDL node lives at
`scenarios/techvault/nodes/wazuh-sidecar-suricata.sdl.yaml`; its bulk blocks
(packages, CVEs, local identity) are derived directly from the committed
evidence files above.

## ACES Mapping Summary

| Surface | Encoding |
| --- | --- |
| Image / build / packages / CVEs / filesystem / identity / runtime / capabilities / network | `nodes.techvault.wazuh-sidecar-suricata` |
| Cross-node forwarding spec (tailed source, buffer policy, ship target) | `forwarding_agents.aptl-suricata-wazuh-agent` (Brad-Edwards/aces#460) |
| Log-origin + realized forwarding edges | `relationships.suricata-logs-forwarded-wazuh`, `relationships.wazuh-sidecar-suricata-forwards-wazuh-manager` |
| Local accounts | `accounts.wazuh-sidecar-suricata-local-*` |

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
- `/logs` is the suricata container's log directory (shared `aptl_suricata_logs`
  volume) mounted read-only; only the monitored log path is recorded here, the
  full log directory content is the suricata asset's inventory
  (`docs/aces/inventory/suricata/`).
- `/var/ossec/etc/client.keys` (agent registration secret) and `/var/ossec/.ssh`
  are path/metadata only; content withheld (ADR-029).
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
