# MISP-to-Suricata Sync Steady-State Inventory

This directory is the SCN-010 / issue #349 inventory bundle for the TechVault
`misp-suricata-sync` container. It applies the ACES-owned asset inventory
methodology to the realized `aptl-misp-suricata-sync` container at the
established granularity bar (issue #330 depth; sidecar/companion archetype
precedents: wazuh-sidecar-db #343, misp-redis #348).

`misp-suricata-sync` is the lab's IOC-enforcement integration service: a
custom `python:3.11-slim` build running the `aptl-misp-suricata-sync` console
script (the repo's `aptl.services.misp_suricata_sync` package) as its single
PID 1 process. Every `SYNC_INTERVAL_SECONDS` (300) it pulls indicators tagged
`aptl:enforce` from the MISP HTTPS API (lab-CA-verified), translates them into
Suricata **alert-only** rules (ADR-019 — Suricata stays IDS), atomically
rewrites `/var/lib/suricata/rules/misp/misp-iocs.rules` on the shared host
bind, and triggers a Suricata rule reload over the shared unix-command socket.
Before this pass it existed in the SDL only as a 21-line node stub owned by
issue #349; this bundle replaces that stub with the fully inventoried
participant node `nodes.techvault.misp-suricata-sync`. The realized
integration edges are `relationships.misp-suricata-sync-queries-misp-api` and
`relationships.misp-suricata-sync-updates-suricata-rules`.
**No known ACES expressivity gap remains** for the catalogued steady-state
facts.

The runtime/mount evidence was recaptured after ADR-043 (issue #325) on a
clean-rebuilt lab — two consecutive `aptl lab stop -v && aptl lab start` cycles
preceded the capture — so the `/var/lib/suricata/rules/misp` mount now reflects
the shared `aptl_suricata_misp_rules` named volume rather than the pre-fix
`.aptl` host bind. The image-level evidence (SBOM, vulnerability scan, image
history, OS packages) is carried forward from the prior capture: the locally
built image and its trivy/package counts drift on every rebuild independently of
this change, and that drift is out of scope for #325.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-misp-suricata-sync` |
| Compose service | `misp-suricata-sync` |
| TechVault profile | `soc` |
| Source class | `local-custom-build-integration-service` |
| Image | `aptl-misp-suricata-sync:latest` (custom build from `containers/misp-suricata-sync/Dockerfile`) |
| Local image config ID | `aptl-misp-suricata-sync@sha256:71fc6bcd3af6b6654a566b14139d1aa06b7063b12c0eb282d0d40d49361580fb` |
| Base image | `python:3.11-slim` |
| Runtime OS | Debian GNU/Linux 13 (trixie) |
| Application | `aptl` 4.0.0 (pip; executed package `aptl.services.misp_suricata_sync`) on CPython 3.11.15 |
| Role | MISP-to-Suricata IOC sync (alert-only rules per ADR-019); runs as root for host-bind ownership compatibility |
| Sync loop | tag filter `aptl:enforce`, interval 300 s, sid_base 99000000; `ioc_count=0` at the snapshot |
| MISP target | `https://misp` (TCP/443), lab-CA TLS verification, MISP admin API key fixture |
| Suricata handoff | rules bind `.aptl/suricata/rules/misp` + unix-command socket `/var/run/suricata/suricata-command.socket` |
| Reachable participant ports | none — no network listener; dials out only |
| Network identity | `security-net` 172.20.0.19 (only network) |
| Capabilities | default Docker set; no cap_add |
| Package inventory | 110 dpkg packages; 62 pip distributions |
| Trivy vulnerability findings | 220 total: 2 critical, 19 high, 73 medium, 125 low, 1 unknown |
| Local identity | 18 users, 38 groups, 0 sudo rules (stock Debian slim set; no added service account) |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture commands are reproducible. | `capture-evidence.sh`, `normalize-syft-cyclonedx.jq` |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/syft-version.json`, `evidence/osquery-version.txt` |
| Compose intent and local-build image identity are recorded. | `evidence/compose-service.misp-suricata-sync.json`, `evidence/docker-inspect.image.json`, `evidence/docker-history.image.txt`, `evidence/docker-history.image.jsonl`, `evidence/source-checksums.txt`, `evidence/docker-buildx-imagetools.image.err` |
| Runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-security.json`, `evidence/docker-volume.suricata_command_socket.json`, `evidence/docker-top.txt`, `evidence/docker-logs.misp-suricata-sync.txt`, `evidence/runtime-baseline.txt` |
| Filesystem manifest and stable-content checksums are recorded. | `evidence/filesystem-tree.txt.gz`, `evidence/filesystem-checksums.txt.xz` |
| Sync service state and Python runtime are recorded. | `evidence/sync-service-state.txt`, `evidence/language-manifests.txt` |
| Observer (suricata) and attacker (kali) vantages are recorded. | `evidence/observer-discovery.suricata.txt`, `evidence/participant-discovery.kali.txt` |
| Package and CVE inventory are recorded. | `evidence/os-packages.txt`, `evidence/trivy-vulnerabilities.json.gz`, `evidence/trivy-vulnerability-list.json`, `evidence/trivy-vulnerability-counts.json` |
| Required + useful-optional SBOMs are recorded. | `evidence/trivy-sbom.cyclonedx.json.gz`, `evidence/syft-sbom.cyclonedx.json.gz` |
| osquery baseline (with unavailable tables noted) is recorded. | `evidence/osquery-processes.json`, `evidence/osquery-listening-ports.json`, `evidence/osquery-docker-containers.json`, `evidence/osquery-docker-images.json`, `evidence/osquery-apt-sources.json`, `evidence/osquery-installed-applications.json`, `evidence/osquery-programs.json` |
| Every committed evidence file is hashed. | `evidence/evidence-sha256sums.txt` |

## Reproduce

```shell
# Capture (non-destructive; lab must be running with the soc profile up)
bash docs/aces/inventory/misp-suricata-sync/capture-evidence.sh

# Validate the mapping ledger and check for unresolved gaps
aptl aces-inventory validate docs/aces/inventory/misp-suricata-sync
aptl aces-inventory gaps docs/aces/inventory/misp-suricata-sync

# Re-run the bundle's correspondence tests
pytest tests/test_misp_suricata_sync_inventory.py -q
```

The authored SDL node lives at
`scenarios/techvault/nodes/misp-suricata-sync.sdl.yaml`; its bulk blocks
(packages, CVEs, local identity) are derived directly from the committed
evidence files above.

## ACES Mapping Summary

| Surface | Encoding |
| --- | --- |
| Image / build / packages / CVEs / filesystem / identity / runtime / capabilities / network | `nodes.techvault.misp-suricata-sync` |
| MISP API access (https, lab CA, API-key auth) | `relationships.misp-suricata-sync-queries-misp-api` |
| Suricata rules/socket handoff | `relationships.misp-suricata-sync-updates-suricata-rules` |
| MISP admin API key | `secret_fixture` value on `runtime.environment` (identical to the `nodes.techvault.misp` `ADMIN_KEY` fixture) |

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
- `MISP_API_KEY` (= the disclosed `nodes.techvault.misp` `ADMIN_KEY`
  secret_fixture) and the base image's `GPG_KEY` are retained verbatim in
  committed evidence because they are TechVault scenario content.
- `/var/run/suricata` is the suricata asset's command-socket volume and the
  hash-list files in the rules bind are suricata authored content; both are
  recorded here as path/metadata with cross-references.
- The filesystem manifest is scoped to application surfaces; `__pycache__`
  bytecode and third-party site-packages trees are excluded (SBOMs + pip list
  evidence the dependency closure).
- `ss`/`netstat` are not installed in the image; the no-network-listener fact is
  sourced from container-namespace osquery.
- Syft CycloneDX normalized by stripping `syft:location:*` properties; filesystem
  provenance is in the committed manifests.
- osquery `installed_applications` / `programs` tables unavailable in the
  digest-pinned Linux scanner image.

## Claims Framing

- This bundle establishes a *spec* for the sync service at steady state, cited
  against observed reality at a single point in time.
- It does not prove byte-identical re-buildability; it provides the ground truth
  a future equivalence checker compares against.
- It does not cover behaviour over time or attack-induced transitions; any state
  present at the snapshot point is in scope. The generated rules file held
  `ioc_count=0` at the snapshot — enforcement-tag-driven rule population is
  attack-period dynamics, out of steady-state scope.
- Rules are alert-only by design (ADR-019: Suricata stays IDS; prevention runs
  through Wazuh active response), so this service is recorded as a detection
  enrichment path, not a prevention control.
