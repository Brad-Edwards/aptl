# TheHive Steady-State Inventory

This directory is the SCN-010 / issue #350 inventory bundle for the TechVault
`thehive` container. It applies the ACES-owned asset inventory methodology to
the realized `aptl-thehive` container at the established granularity bar (issue
#330 depth).

`thehive` is the lab's **SOC case-management application**: upstream
`strangebee/thehive:5.4` (TheHive 5.4.11, Play/Scala on Amazon Corretto 11),
serving HTTPS on 9000 (published `9000:9000`). It is inventoried as the
participant application node `nodes.techvault.thehive`. Its realized backends
are **Cassandra** (primary case/alert data, CQL/9042 —
`relationships.thehive-connects-cassandra`) and a **local Lucene** search index
(`index.search.backend = lucene`, the `thehive_index` volume). The deployed
`thehive-es` Elasticsearch is **not** used by TheHive (the `--es-hostnames` arg
is inert under the lucene backend), so no thehive→es relationship is encoded.
**No known ACES expressivity gap remains** for the catalogued steady-state
facts.

This capture is non-destructive. It used the already-running local `aptl`
project (soc profile) on 2026-06-10 and **did not run
`aptl lab stop -v && aptl lab start`**. Treat this bundle as a frozen
observation of that local steady state, **not as clean-lab rebuild proof**.

> **Secrets.** The Play application secret
> (`--secret aptl-thehive-lab-secret-key-2024-purple`) is a committed scenario
> fixture (present in `docker-compose.yml`) — it is encoded **verbatim** on the
> container command per the secret-fixture policy (a reproduction input, not a
> real operator secret). The generated HTTPS keystore (`/etc/thehive/keystore.p12`)
> and its password (`HTTPS_KEYSTORE_PASSWORD`, created at lab start) are operator
> secrets — recorded as metadata only with the value withheld (ADR-029).

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-thehive` |
| Compose service | `thehive` |
| TechVault profile | `soc` |
| Family | application |
| Source class | `upstream-registry-image-application` |
| Image | `strangebee/thehive:5.4` (upstream registry) |
| Registry digest | `strangebee/thehive@sha256:ba3212a89be79de6ec8e6e66b84f3c0801c3b8d726aacc767ad6257030df7a13` |
| Runtime OS | Debian GNU/Linux 12 (bookworm) |
| Application | TheHive 5.4.11 (Play 3.0.x / Scalligraph 5.4.11-1) on Amazon Corretto 11 |
| Backends | Cassandra (data, CQL/9042) + **local Lucene** index (`/opt/thp/thehive/index`); thehive-es is deployed but unused |
| Reachable participant ports | HTTPS `9000` (published to host `9000:9000`) |
| Network identity | `security-net` 172.20.0.18 (only network) |
| Memory limit | 1 GiB |
| Package inventory | 126 dpkg packages |
| Trivy vulnerability findings | 376 image-layer findings: 9 critical, 58 high, 152 medium, 156 low, 1 unknown |
| Local identity | 19 users, 39 groups, 0 sudo rules |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture commands are reproducible. | `capture-evidence.sh`, `normalize-syft-cyclonedx.jq` |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/syft-version.json`, `evidence/osquery-version.txt` |
| Upstream registry image identity is recorded. | `evidence/docker-inspect.image.json`, `evidence/docker-buildx-imagetools.image.raw.json`, `evidence/docker-buildx-imagetools.image.txt`, `evidence/docker-history.image.txt`, `evidence/docker-history.image.jsonl`, `evidence/source-checksums.txt` |
| Runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-security.json`, `evidence/docker-volume.thehive_data.json`, `evidence/docker-volume.thehive_index.json`, `evidence/docker-top.txt`, `evidence/docker-logs.thehive.txt`, `evidence/runtime-baseline.txt` |
| Application state (versions, auth config, backends) is recorded. | `evidence/thehive-state.txt` |
| Filesystem manifest and stable-content checksums are recorded. | `evidence/filesystem-tree.txt.gz`, `evidence/filesystem-checksums.txt.xz` |
| Application/runtime versions are recorded. | `evidence/language-manifests.txt` |
| Attacker (kali) vantage is recorded. | `evidence/participant-discovery.kali.txt` |
| Package and CVE inventory are recorded. | `evidence/os-packages.txt`, `evidence/trivy-vulnerabilities.json.gz`, `evidence/trivy-vulnerability-list.json`, `evidence/trivy-vulnerability-counts.json` |
| Required + useful-optional SBOMs are recorded. | `evidence/trivy-sbom.cyclonedx.json.gz`, `evidence/syft-sbom.cyclonedx.json.gz` |
| osquery baseline (with unavailable tables noted) is recorded. | `evidence/osquery-processes.json`, `evidence/osquery-listening-ports.json`, `evidence/osquery-docker-containers.json`, `evidence/osquery-docker-images.json`, `evidence/osquery-apt-sources.json`, `evidence/osquery-installed-applications.json`, `evidence/osquery-programs.json` |
| Every committed evidence file is hashed. | `evidence/evidence-sha256sums.txt` |

## Reproduce

```shell
# Capture (non-destructive; lab must be running with the soc profile up)
bash docs/aces/inventory/thehive/capture-evidence.sh

# Validate the mapping ledger and check for unresolved gaps
aptl aces-inventory validate docs/aces/inventory/thehive
aptl aces-inventory gaps docs/aces/inventory/thehive

# Re-run the bundle's correspondence tests
pytest tests/test_thehive_inventory.py -q
```

The authored SDL node lives at
`scenarios/techvault/nodes/thehive.sdl.yaml`; its application, package, CVE,
filesystem, and identity blocks are derived directly from the committed
evidence files above.

## ACES Mapping Summary

| Surface | Encoding |
| --- | --- |
| Image / build / packages / CVEs / filesystem / identity / runtime / network | `nodes.techvault.thehive` |
| TheHive web app + REST API (framework, base_path, routes) | `nodes.techvault.thehive.runtime.applications` |
| HTTPS listener | `nodes.techvault.thehive.runtime.service_listeners` (9000) |
| Play application secret (committed fixture) | `nodes.techvault.thehive.runtime.container.command` (`--secret`, kept) |
| Cassandra data connection | `relationships.thehive-connects-cassandra` (CQL/9042) |

All 19 catalogued facts in `mapping-ledger.yaml` are `encoded` /
`encoded_with_caveat`; none are blocked. No ACES expressivity issue is filed
because every catalogued participant/agent-observable fact maps to a current
ACES surface.

## Known Limits

These are recorded as first-class entries in `evidence/capture-limits.txt`:

- Non-destructive capture against the already-running lab; not clean-reset
  rebuild proof.
- The `thehive_data` and `thehive_index` volume contents are excluded from the
  filesystem manifest (top-level rows only); application state is in
  `thehive-state.txt`.
- `/etc/thehive/keystore.p12` (generated HTTPS keystore) and
  `HTTPS_KEYSTORE_PASSWORD` are operator secrets — metadata/empty only (ADR-029).
- The Play application secret is a committed scenario fixture, kept verbatim on
  the container command.
- TheHive uses local Lucene indexing (`index.search.backend = lucene`), not the
  deployed thehive-es; no thehive→es connection exists.
- Syft CycloneDX normalized by stripping `syft:location:*` properties.
- osquery `installed_applications` / `programs` tables unavailable in the
  digest-pinned Linux scanner image.

## Claims Framing

- This bundle establishes a *spec* for the application at steady state, cited
  against observed reality at a single point in time.
- It does not prove byte-identical re-buildability; it provides the ground truth
  a future equivalence checker compares against.
- It does not cover behaviour over time or attack-induced transitions; any state
  present at the snapshot point is in scope. The captured TheHive instance had no
  cases/alerts at the snapshot (fresh lab).
