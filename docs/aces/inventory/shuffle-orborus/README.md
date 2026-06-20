# Shuffle Orborus Steady-State Inventory

This directory is the SCN-010 / issue #355 inventory bundle for the TechVault
`shuffle-orborus` container. It applies the ACES-owned asset inventory
methodology to the realized `aptl-shuffle-orborus` container at the established
granularity bar (issue #330 depth).

`shuffle-orborus` is the **Shuffle SOAR worker orchestrator**: upstream
`ghcr.io/shuffle/shuffle-orborus:latest`, an **Alpine 3.22** image running the
`/orborus` **Go static binary** as PID 1. It polls `shuffle-backend:5001`
(`BASE_URL`) for execution jobs and spawns `shuffle-worker` containers
(`SHUFFLE_WORKER_IMAGE`) by driving the **host Docker daemon** through the
bind-mounted `/var/run/docker.sock` (read-write). It is inventoried as the
participant node `nodes.techvault.shuffle-orborus`. On `security-net` with a
DHCP address (172.20.0.6 at capture); it exposes **no inbound application
listener** and **publishes no host ports**.
**No known ACES expressivity gap remains** for the catalogued steady-state facts.

This capture is non-destructive. It used the already-running local `aptl`
project (soc profile) on 2026-06-11 and **did not run
`aptl lab stop -v && aptl lab start`**. Treat this bundle as a frozen
observation of that local steady state, **not as clean-lab rebuild proof**.

> **PRIVILEGED HOST-CONTROL SURFACE.** The writable `/var/run/docker.sock` bind
> is the dominant trust surface of this asset: full control of the host Docker
> daemon is **host-root-equivalent**. It is encoded as both a `runtime.mounts`
> bind and the `runtime.local_control_interfaces` entry
> `shuffle-orborus-docker-socket`, and recorded as a first-class capture limit.
> A compromise of orborus is effectively host-Docker root.

> **The `/orborus` binary was never executed.** Invoking it (even with
> `--version`) would start the orborus daemon and spawn worker containers via the
> host `docker.sock`. Binary identity comes from file metadata, the
> image-shipped `/orborus.go` source, and the trivy/syft go-module SBOM catalogue
> (139 Go modules), not a runtime version flag.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-shuffle-orborus` |
| Compose service | `shuffle-orborus` |
| TechVault profile | `soc` |
| Family | orchestration / worker |
| Source class | `upstream-registry-image-orchestrator` |
| Image | `ghcr.io/shuffle/shuffle-orborus:latest` (upstream registry) |
| Platform digest | `ghcr.io/shuffle/shuffle-orborus@sha256:e74e0246ba3acd0daaa8343e58da859f7908f06b9f51094a9cd9f9ea8cbf7a44` (realized amd64; in the node `source.version`) |
| Multi-arch index | `sha256:94e61e7916aea28351fce3851f26f14fb85204f1567a8807d137321418366dba` (`:latest` tag manifest list) |
| Runtime OS | Alpine Linux v3.22 |
| PID 1 | `/orborus` Go static binary (`./orborus`, root) |
| Host-control surface | `/var/run/docker.sock` bind (read-write) — host-root-equivalent |
| Outbound dependency | `http://shuffle-backend:5001` (`BASE_URL`, ESTABLISHED at capture) |
| Reachable participant ports | none (no inbound listener, no published ports) |
| Network identity | `security-net` DHCP 172.20.0.6 (only network) |
| Package inventory | 21 apk packages |
| Software components | 139 Go modules (SBOM go-module catalogue) |
| Trivy vulnerability findings | 126 image-layer findings: 3 critical, 38 high, 40 medium, 45 low |
| Local identity | 17 users, 35 groups, 0 sudo rules |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture commands are reproducible. | `capture-evidence.sh`, `normalize-syft-cyclonedx.jq` |
| Capture time, tool versions, and limits are recorded. | `evidence/captured-at-utc.txt`, `evidence/capture-limits.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt`, `evidence/syft-version.json`, `evidence/osquery-version.txt` |
| Upstream registry image identity is recorded. | `evidence/docker-inspect.image.json`, `evidence/docker-buildx-imagetools.image.raw.json`, `evidence/docker-buildx-imagetools.image.txt`, `evidence/docker-history.image.txt`, `evidence/docker-history.image.jsonl`, `evidence/source-checksums.txt` |
| Runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-security.json`, `evidence/docker-top.txt`, `evidence/docker-logs.shuffle-orborus.txt`, `evidence/runtime-baseline.txt` |
| The docker.sock control surface, PID 1, env, and outbound target are recorded. | `evidence/orborus-state.txt` |
| Filesystem manifest and stable-content checksums are recorded. | `evidence/filesystem-tree.txt` (curated), `evidence/filesystem-tree-full.txt.gz` (full rootfs), `evidence/filesystem-checksums.txt` |
| Application/runtime versions are recorded. | `evidence/language-manifests.txt` |
| Attacker (kali) vantage is recorded. | `evidence/participant-discovery.kali.txt` |
| Package and CVE inventory are recorded. | `evidence/os-packages.txt`, `evidence/trivy-vulnerabilities.json.gz`, `evidence/trivy-vulnerability-list.json`, `evidence/trivy-vulnerability-counts.json` |
| Required + useful-optional SBOMs are recorded. | `evidence/trivy-sbom.cyclonedx.json.gz`, `evidence/syft-sbom.cyclonedx.json.gz` |
| osquery baseline (with unavailable tables noted) is recorded. | `evidence/osquery-processes.json`, `evidence/osquery-listening-ports.json`, `evidence/osquery-docker-containers.json`, `evidence/osquery-docker-images.json`, `evidence/osquery-apt-sources.json`, `evidence/osquery-installed-applications.json`, `evidence/osquery-programs.json` |
| Every committed evidence file is hashed. | `evidence/evidence-sha256sums.txt` |

## Reproduce

```shell
# Capture (non-destructive; lab must be running with the soc profile up)
bash docs/aces/inventory/shuffle-orborus/capture-evidence.sh

# Validate the mapping ledger and check for unresolved gaps
aptl aces-inventory validate docs/aces/inventory/shuffle-orborus
aptl aces-inventory gaps docs/aces/inventory/shuffle-orborus

# Re-run the bundle's correspondence tests
pytest tests/test_shuffle_orborus_inventory.py -q
```

The authored SDL node lives at
`scenarios/techvault/nodes/shuffle-orborus.sdl.yaml`; its build, package, CVE,
filesystem, software-component, identity, runtime, and network blocks are derived
directly from the committed evidence files above.

## ACES Mapping Summary

| Surface | Encoding |
| --- | --- |
| Image / build / packages / CVEs / filesystem / identity / runtime / network | `nodes.techvault.shuffle-orborus` |
| Host Docker control socket (`/var/run/docker.sock`, rw) | `nodes.techvault.shuffle-orborus.runtime.local_control_interfaces.shuffle-orborus-docker-socket` + `runtime.mounts` |
| 139 embedded Go modules | `nodes.techvault.shuffle-orborus.runtime.software_components` |
| Docker embedded-DNS loopback sockets (only listeners) | `nodes.techvault.shuffle-orborus.runtime.service_listeners` |
| Outbound poll to `shuffle-backend:5001` | `relationships.orborus-polls-backend` |

All 18 catalogued facts in `mapping-ledger.yaml` are `encoded` /
`encoded_with_caveat`; none are blocked. No ACES expressivity issue is filed
because every catalogued participant/agent-observable fact maps to a current
ACES surface — including the writable Docker control socket, which the
`runtime.local_control_interfaces` surface (the shuffle-backend precedent)
already expresses.

## Known Limits

These are recorded as first-class entries in `evidence/capture-limits.txt`:

- Non-destructive capture against the already-running lab; not clean-reset
  rebuild proof.
- **Privileged host-control surface:** the writable `/var/run/docker.sock` bind
  grants host-root-equivalent control of the host Docker daemon.
- The `/orborus` Go binary was never executed (running it starts the daemon and
  spawns workers); binary identity is from metadata, the shipped `/orborus.go`
  source, and the SBOM go-module catalogue.
- The curated filesystem manifest (and the SDL `filesystem_inventory`) is scoped
  to the orborus application surface (`/orborus`, `/orborus.go`,
  `/etc/os-release`); the full Alpine rootfs manifest is retained as evidence in
  `filesystem-tree-full.txt.gz`, with package-level coverage in
  `os-packages.txt` and the SBOMs.
- `SHUFFLE_OPENSEARCH_URL` is an image-default env (no credentials) and no
  outbound opensearch connection was observed; only the orborus → backend edge
  is encoded.
- The only listeners are the backend-generated Docker embedded-DNS loopback
  sockets on 127.0.0.11; orborus binds no service.
- Syft CycloneDX normalized by stripping `syft:location:*` properties.
- Trivy/Syft CycloneDX SBOMs committed as deterministic gzip-minified JSON to
  satisfy the repository's added-file size gate (lossless).
- osquery `apt_sources` (apk target), `installed_applications`, and `programs`
  tables unavailable in the digest-pinned Linux scanner image.

## Claims Framing

- This bundle establishes a *spec* for orborus at steady state, cited against
  observed reality at a single point in time.
- It does not prove byte-identical re-buildability; it provides the ground truth
  a future equivalence checker compares against.
- It does not cover behaviour over time or attack-induced transitions; any state
  present at the snapshot point is in scope.
