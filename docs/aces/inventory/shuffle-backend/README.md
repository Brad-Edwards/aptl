# Shuffle Backend Inventory Methodology Test

This directory is the APTL #353 proof pass for the backend asset inventory
methodology now owned by ACES at
<https://github.com/Brad-Edwards/aces/blob/dev/docs/aces/inventory/asset-inventory-methodology.md>.
It is evidence for validating the methodology against TechVault's
`shuffle-backend`; it is not the final completion artifact for all SCN-010
asset inventory acceptance criteria.

The capture used an already-running local lab on 2026-05-20. It did not run
`aptl lab stop -v && aptl lab start`, because that would destroy the
user's current lab state. Treat the bundle as a methodology smoke test
until a clean-lab capture is intentionally performed.

## Asset Summary

| Field | Captured value |
| --- | --- |
| Container | `aptl-shuffle-backend` |
| Compose service | `shuffle-backend` |
| TechVault profile | `soc` |
| Source class | `upstream-image` |
| Image tag | `ghcr.io/shuffle/shuffle-backend:latest` |
| Image digest | `ghcr.io/shuffle/shuffle-backend@sha256:271b38ba5d2c68579f0d75b43d294b65626f57a7878eef545b8021c07b3e178d` |
| Image created | `2026-02-12T15:25:07Z` |
| Runtime OS | Alpine Linux 3.22.2 |
| Runtime command | `./shufflebackend` |
| Working directory | `/app` |
| Listener | `:::5001` |
| Network identity | `aptl_aptl-security`, IPv4 `172.20.0.20` |
| Data volume | `aptl_shuffle_data:/shuffle-database` |
| Privileged trust surface | `/var/run/docker.sock:/var/run/docker.sock:rw` |

## Evidence Bundle

| Claim | Evidence |
| --- | --- |
| Capture time and tool versions are recorded. | `evidence/captured-at-utc.txt`, `evidence/docker-version.json`, `evidence/docker-compose-version.json`, `evidence/trivy-version.txt` |
| Authored backend intent is represented by the Compose service slice. | `evidence/compose-service.shuffle-backend.json` |
| Immutable image identity and layers are recorded. | `evidence/docker-inspect.image.json`, `evidence/docker-history.image.txt` |
| Registry-visible OCI/SLSA provenance attestations are recorded. | `evidence/docker-buildx-imagetools.image.txt`, `evidence/docker-buildx-imagetools.image.raw.json`, `evidence/docker-buildx-imagetools.attestation-amd64.raw.json` |
| Realized runtime state is recorded. | `evidence/docker-inspect.container.json`, `evidence/docker-network.aptl-security.json`, `evidence/docker-volume.shuffle-data.json`, `evidence/docker-top.txt`, `evidence/runtime-baseline.txt` |
| OS packages and language manifests visible in the image are recorded. | `evidence/os-packages.txt`, `evidence/language-manifests.txt` |
| SBOM and vulnerability state are machine-readable. | `evidence/trivy-sbom.cyclonedx.json`, `evidence/trivy-vulnerabilities.json`, `evidence/trivy-vulnerability-list.json`, `evidence/trivy-vulnerability-counts.json` |
| Important filesystem paths are hashable. | `evidence/filesystem-tree.txt`, `evidence/filesystem-checksums.txt` |
| Evidence files have integrity checksums. | `evidence/evidence-sha256sums.txt` |
| Captured facts are mapped to current ACES surfaces or gap issues. | `mapping-ledger.yaml` |

## Capture Findings

- The runtime image is an upstream Shuffle backend image, not a local APTL
  build. The observed mutable tag is therefore insufficient by itself; the
  digest above is the reproducibility anchor.
- Docker Buildx reports attestation manifests for the upstream image's platform
  manifests; the amd64 attestation manifest contains an in-toto layer with SLSA
  provenance predicate type `https://slsa.dev/provenance/v0.2`.
  This is the in-toto layer with SLSA provenance recorded by the smoke pass.
- The container runs as `root`, exposes `5001/tcp`, and listens on IPv6
  wildcard `:::5001` inside the container.
- The service has a Docker socket bind. This is a load-bearing backend
  trust surface and should not be hidden inside SDL scenario prose.
- The service stores data at `/shuffle-database` on `aptl_shuffle_data`.
- Runtime dependency manifests are Go-oriented. No Python, pip, Node, npm,
  or Go compiler toolchain was observed in the runtime baseline.
- The Trivy evidence captured 86 vulnerabilities at the scan time:
  5 critical, 33 high, 41 medium, and 7 low.
- Secret env-var values in `docker inspect` evidence were redacted before
  committing the bundle.

## Maximal Specification Rule

For this TechVault exercise, the next pass does not decide whether these
facts are deliberate, accidental, portable, or elegant.
If a participant or agent can discover a fact from inside the range, the fact
must be captured and an ACES specification mapping must be attempted. That is
the capture boundary for this proof pass, not the semantic frame for the ACES SDL gap.

The current evidence already suggests candidate participant-discoverable
facts that need ACES mapping attempts:

- IP and DNS identity: `172.20.0.20`, `aptl-shuffle-backend`,
  `shuffle-backend`.
- Service exposure: Shuffle backend API on `5001/tcp`.
- Runtime identity: Alpine Linux 3.22.2, root user, `./shufflebackend`,
  working directory `/app`.
- Trust and filesystem surfaces: `/shuffle-database` and
  `/run/docker.sock`.
- Runtime package and application dependency inventory, including visible Go
  module manifests.
- Vulnerability and patch state when discoverable or inferable by in-range
  tooling.

Facts that ACES cannot express become ACES issues immediately after checking
for an existing issue that covers the gap.

The first filed gap is ACES #354: typed runtime configuration surfaces for
mounts, local sockets, process identity, and package inventory.
Run `aptl aces-inventory validate docs/aces/inventory/shuffle-backend` and
`aptl aces-inventory gaps docs/aces/inventory/shuffle-backend` to verify the
handoff ledger that later per-asset issues should expand before encoding.
Run `aptl aces-inventory schema` to inspect the current JSON Schema generated
from the Pydantic ledger model.

## Methodology Result

This pass supports the proposed issue sequencing:

- Use APTL #353 as the upstream-image proof asset.
- Use APTL #331 as the second upstream-image comparison asset.
- Use APTL #330 and APTL #332 to validate custom-build source capture.
- Keep ACES docs as the canonical methodology owner.

The main issue-breakdown risk is not the per-asset split; it is failing to
attempt maximal ACES specification after discovery. The per-asset tickets
should collect participant-discoverable facts and then either encode them in
ACES or create/link the ACES expressivity gap that blocks full specification.

## Known Limits

- The evidence came from a running lab, not a clean reset.
- Upstream image source Dockerfile and build arguments are outside this repo and
  were not reconstructed. Registry-visible in-toto/SLSA provenance attestations
  were captured for the image index, but this smoke pass did not verify
  signatures, transparency-log inclusion, or builder identity.
- Vulnerability results are time-sensitive to the Trivy database and
  advisory feeds.
- The SBOM and vulnerability evidence comes from scanner output and should be
  treated as scanner state tied to tool/database versions, not permanent truth.
- The capture does not assert dynamic Shuffle workflow behavior.
- Correspondence checks are planned in `mapping-ledger.yaml`; this pass does
  not yet prove that a future ACES encoding realizes equivalent runtime state.
- No ACES SDL encoding was created from this first proof pass; ACES #354 records
  the first typed SDL expressivity gap found during the mapping attempt.
