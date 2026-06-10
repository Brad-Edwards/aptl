# Shuffle Frontend Steady-State Inventory

This directory is the SCN-010 / issue #354 inventory bundle for the TechVault
`shuffle-frontend` container. It applies the ACES-owned asset inventory
methodology to the realized `aptl-shuffle-frontend` container at the
established granularity bar (issue #330 depth).

`shuffle-frontend` is the **Shuffle SOAR web frontend**: upstream
`ghcr.io/shuffle/shuffle-frontend:latest`, an **nginx 1.29.3** server (Debian
13) that serves the pre-built React single-page app and reverse-proxies
`/api/v1|v2` to `shuffle-backend:5001`. It is inventoried as the participant
application node `nodes.techvault.shuffle-frontend`. On security-net
172.20.0.21; nginx HTTP/80 + HTTPS/443 are published to the host as `3001:3001`
and `3443:443`. **No known ACES expressivity gap remains** for the catalogued
steady-state facts.

This capture is non-destructive. It used the already-running local `aptl`
project (soc profile) on 2026-06-10 and **did not run
`aptl lab stop -v && aptl lab start`**. Treat this bundle as a frozen
observation of that local steady state, **not as clean-lab rebuild proof**.

> **TLS private key.** The nginx TLS private key (`/etc/nginx/privkey.pem`,
> lab-CA-signed, generated at lab start) is an **operator secret** — recorded as
> path/metadata only, excluded from checksums, content never emitted (ADR-029).
> The server certificate and lab CA are public.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-shuffle-frontend` |
| Compose service | `shuffle-frontend` |
| TechVault profile | `soc` |
| Family | application |
| Source class | `upstream-registry-image-application` |
| Image | `ghcr.io/shuffle/shuffle-frontend:latest` (upstream registry) |
| Registry digest | `ghcr.io/shuffle/shuffle-frontend@sha256:3c471f39c4d0a773ee22ed8575a68579ff08dd7123e94e70a2482973a4cc296f` (also in the node `source.version`) |
| Runtime OS | Debian GNU/Linux 13 (trixie) |
| Application | nginx 1.29.3 + pre-built static React SPA (no node runtime) |
| Reverse proxy | `/api/v1\|v2` → `http://shuffle-backend:5001` |
| Reachable participant ports | nginx HTTP `80` (host `3001`) + HTTPS `443` (host `3443`) |
| Network identity | `security-net` 172.20.0.21 (only network) |
| Package inventory | 150 dpkg packages |
| Trivy vulnerability findings | 392 image-layer findings: 7 critical, 64 high, 138 medium, 182 low, 1 unknown |
| Local identity | 19 users, 39 groups, 0 sudo rules |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture commands are reproducible. | `capture-evidence.sh`, `normalize-syft-cyclonedx.jq` |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/syft-version.json`, `evidence/osquery-version.txt` |
| Upstream registry image identity is recorded. | `evidence/docker-inspect.image.json`, `evidence/docker-buildx-imagetools.image.raw.json`, `evidence/docker-buildx-imagetools.image.txt`, `evidence/docker-history.image.txt`, `evidence/docker-history.image.jsonl`, `evidence/source-checksums.txt` |
| Runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-security.json`, `evidence/docker-top.txt`, `evidence/docker-logs.shuffle-frontend.txt`, `evidence/runtime-baseline.txt` |
| nginx config + TLS + listeners are recorded. | `evidence/frontend-state.txt` |
| Filesystem manifest and stable-content checksums are recorded. | `evidence/filesystem-tree.txt`, `evidence/filesystem-checksums.txt` |
| Application/runtime versions are recorded. | `evidence/language-manifests.txt` |
| Attacker (kali) vantage is recorded. | `evidence/participant-discovery.kali.txt` |
| Package and CVE inventory are recorded. | `evidence/os-packages.txt`, `evidence/trivy-vulnerabilities.json.gz`, `evidence/trivy-vulnerability-list.json`, `evidence/trivy-vulnerability-counts.json` |
| Required + useful-optional SBOMs are recorded. | `evidence/trivy-sbom.cyclonedx.json.gz`, `evidence/syft-sbom.cyclonedx.json.gz` |
| osquery baseline (with unavailable tables noted) is recorded. | `evidence/osquery-processes.json`, `evidence/osquery-listening-ports.json`, `evidence/osquery-docker-containers.json`, `evidence/osquery-docker-images.json`, `evidence/osquery-apt-sources.json`, `evidence/osquery-installed-applications.json`, `evidence/osquery-programs.json` |
| Every committed evidence file is hashed. | `evidence/evidence-sha256sums.txt` |

## Reproduce

```shell
# Capture (non-destructive; lab must be running with the soc profile up)
bash docs/aces/inventory/shuffle-frontend/capture-evidence.sh

# Validate the mapping ledger and check for unresolved gaps
aptl aces-inventory validate docs/aces/inventory/shuffle-frontend
aptl aces-inventory gaps docs/aces/inventory/shuffle-frontend

# Re-run the bundle's correspondence tests
pytest tests/test_shuffle_frontend_inventory.py -q
```

The authored SDL node lives at
`scenarios/techvault/nodes/shuffle-frontend.sdl.yaml`; its application, package,
CVE, filesystem, and identity blocks are derived directly from the committed
evidence files above.

## ACES Mapping Summary

| Surface | Encoding |
| --- | --- |
| Image / build / packages / CVEs / filesystem / identity / runtime / network | `nodes.techvault.shuffle-frontend` |
| Shuffle web UI (nginx + React SPA, routes) | `nodes.techvault.shuffle-frontend.runtime.applications` |
| HTTP / HTTPS listeners | `nodes.techvault.shuffle-frontend.runtime.service_listeners` (80, 443) |
| `/api` reverse-proxy to backend | `relationships.shuffle-frontend-proxies-backend` |

All 18 catalogued facts in `mapping-ledger.yaml` are `encoded` /
`encoded_with_caveat`; none are blocked. No ACES expressivity issue is filed
because every catalogued participant/agent-observable fact maps to a current
ACES surface.

## Known Limits

These are recorded as first-class entries in `evidence/capture-limits.txt`:

- Non-destructive capture against the already-running lab; not clean-reset
  rebuild proof.
- The nginx TLS private key is an operator secret — metadata only (ADR-029);
  the server certificate and lab CA are public.
- The nginx worker pool is N identical processes; one representative worker is
  encoded (count in its description) rather than duplicating identical rows.
- Upstream nginx-image shell variable references (`${NGINX_VERSION}` etc.) in the
  history-derived build instruction strings are normalized to the brace-free
  `$VAR` form to avoid collision with ACES `${...}` placeholders.
- Syft CycloneDX normalized by stripping `syft:location:*` properties.
- osquery `installed_applications` / `programs` tables unavailable in the
  digest-pinned Linux scanner image.

## Claims Framing

- This bundle establishes a *spec* for the frontend at steady state, cited
  against observed reality at a single point in time.
- It does not prove byte-identical re-buildability; it provides the ground truth
  a future equivalence checker compares against.
- It does not cover behaviour over time or attack-induced transitions; any state
  present at the snapshot point is in scope.
