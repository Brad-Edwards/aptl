# TechVault inventory volatility policy

This document records which facts in the TechVault target-node inventories
(`victim`, `workstation`, `reverse`) are stable enough to pin to an exact value
and which ones churn on their own cadence and are therefore captured by shape
instead. It also records the build-reproducibility decisions taken so that the
facts we *do* pin stay meaningful across rebuilds.

The scope is the three custom-built target nodes captured under
`docs/aces/inventory/{victim,workstation,reverse}/`. It is a scenario-level
policy for TechVault, not an APTL-wide architecture decision record.

## Why this policy exists

An inventory is only useful if a re-capture that finds a *different* value means
something changed that we care about. If a fact churns every container restart
or every upstream database refresh, pinning its exact value turns the inventory
gate into a tripwire that fires on noise, and the temptation becomes to "just
update the number" without reading why it moved. We avoid that by classifying
each fact by its churn cadence and asserting it at the right level.

## Volatility classes

### Per-build (changes on every image rebuild)

The image ID and digest, the per-layer content digests, and the RootFS layer
digests change whenever the image is rebuilt, because they are content
addresses. The inventory pins the digest captured at inventory time and treats a
change as expected only on a deliberate rebuild, at which point the bundle is
re-captured. To keep *everything else* in the image reproducible across rebuilds
we pin the inputs that would otherwise drift — see
[Build-reproducibility decisions](#build-reproducibility-decisions).

### Per-recreate (changes every time the container is recreated)

A `docker compose up` that recreates a container assigns a new container ID and,
with it, a new network namespace and new Docker-managed identifiers:

- `NetworkSettings.SandboxKey` — a `/var/run/docker/netns/<hex>` path.
- Docker network ID, endpoint ID, and MAC address.
- `/home/labadmin/.ssh/authorized_keys` — populated at start from the host
  control-plane public key, so its bytes depend on the running lab's key.

### Per-boot or per-process (changes when a process restarts)

- Service-manager `main_pid` values, which depend on start order.
- Capture-the-flag nonces (`APTL{...}`), which the entrypoint regenerates.
- Ephemeral listening ports: the Docker embedded DNS resolver on `127.0.0.11`
  and the systemd notify and journal sockets bind to high ports chosen at boot.
  Only `22/tcp` (sshd) is a stable listener.

### Per-database (changes when an upstream feed refreshes)

- Trivy vulnerability counts and severity totals move when the Trivy
  vulnerability database refreshes (roughly daily), independently of the image.
- Software bill of materials (SBOM) component counts drift with the scanner's
  cataloger and database versions.

The scanners themselves are pinned by digest in the capture script, but their
databases are not, so the totals are treated as a point-in-time reading.

### Per-runtime (accumulates while the container runs)

Log files such as `/var/log/messages`, `/var/log/secure`, the `dnf*` logs, and
`/var/log/bash_history.log` grow and change digest as the container runs, and
`/var/ossec/etc/ossec.conf` is re-templated at start.

## What we pin

These facts are deterministic for a given image and lab topology, so the
inventory pins them to exact values and a change is a real signal:

- Build structure: instruction count, history layer count, RootFS layer count,
  and source-input count.
- Filesystem structure: the set of paths in the runtime inventory, plus each
  entry's mode and ownership (modes are now build-environment independent — see
  below).
- Deterministic content digests: configuration files, scripts, and the public
  keys under `/keys` (the control-plane public key and the kali pivot public
  key).
- The package set and its count.
- Local identity: users, groups, primary-group membership, and sudo rules.
- The service-manager unit set and each unit's steady state (active, failed,
  enabled, or disabled).

## Build-reproducibility decisions

### Pin the Falco version

The Dockerfiles install a pinned Falco release (`falco-0.44.1`). An unpinned
`falco` package pulls whatever build is current at rebuild time, which rewrites
the Falco configuration files and churns their captured digests for no
scenario-relevant reason. Bump the pin deliberately when a Falco upgrade is
intended.

### Pin image file modes

The Dockerfiles set file modes explicitly — `chmod 755` for scripts and
`COPY --chmod=644` for configuration and unit files — instead of relying on
`chmod +x` or the build context's own mode bits. Docker `COPY` preserves the
source file's mode bits, so a build host with a `umask` of `0002` would bake
group-writable files (`664`/`775`) while a host with `0022` would produce
`644`/`755`. Pinning the modes in the Dockerfile makes the captured modes
independent of the build host.

### Keep operator keys out of scenario containers

The operator control-plane private key (`aptl_lab_key`) is never mounted into a
scenario container. The target `/keys` directory holds only public material: the
control-plane public key and a dedicated scenario pivot key (`kali_pivot_key`)
that the kali node uses to reach the targets. The pivot key is scenario content
and is inventoried in full; the control-plane private key is not part of any
node's inventory.

## How the tests encode this

The inventory tests under `tests/test_{victim,workstation,reverse}_inventory.py`
follow the classification above:

- Volatile values are asserted by shape, not value. The SandboxKey is matched
  against `^/var/run/docker/netns/[0-9a-f]+$`, the flags against
  `APTL\{<role>_<node>_[0-9a-f]{32}\}`, and the listening-port check requires
  `22/tcp` plus the presence of ephemeral high ports rather than a fixed number.
- Trivy and SBOM evidence is checked for internal consistency (the summary
  counts equal the counts computed from the item list) and for being populated,
  not for an absolute total.
- The Software Description Language (SDL) `package_vulnerabilities`, service
  `main_pid` values, and log-file digests are a point-in-time snapshot taken at
  capture time. The tests compare the SDL against pinned constants — that is,
  they verify the SDL is internally consistent — rather than against
  live-drifting evidence, so steady drift does not break the gate. These
  snapshots are refreshed only on a deliberate re-capture.
