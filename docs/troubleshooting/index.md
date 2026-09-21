# Troubleshooting

Start with APTL's project-aware diagnostics. They preserve the selected
backend, realized scenario, runtime port mapping, and redaction boundaries.

## Quick Checks

```shell
aptl lab status
aptl lab info
aptl container list
aptl config validate
```

Read the final `aptl lab start` result before investigating an individual
container. It distinguishes ready, usable degradation, unusable degradation,
and failure, and names the component and safe operator action when available.

Inspect logs only for a container returned by `aptl container list`:

```shell
aptl container logs <container-name>
```

Do not attach `.env`, `.mcp.json`, private keys, authentication headers, or
unredacted generated configuration to a support report.

## Common First-Run Problems

### A service URL does not open

Run `aptl lab info` again and use the reported URL. Host ports can be remapped
when a default is already occupied, and the selected scenario can omit a
service entirely. If the service exists, compare `aptl lab status` with its
bounded logs:

```shell
aptl lab status
aptl container logs <container-name>
```

Use the generated trust root and service hostname reported for the project. Do
not bypass a certificate warning, use a client option that disables TLS
verification, or substitute a fixed port from an older document.

### Startup reports insufficient resources

The acquired TechVault stack can require more than 20GB of RAM, while smaller
curated scenarios use less. Increase the Docker engine's memory allocation or
choose another identity from `aptl lab scenarios`.

On a native Linux Docker Engine, startup also checks the OpenSearch
`vm.max_map_count` requirement. Apply the exact remediation printed by the
failed preflight. Docker Desktop and WSL2 manage the value inside their Linux
VM and do not use the host setting.

### A container shell fails

Container names depend on scenario realization. Confirm the target first:

```shell
aptl container list
aptl container shell <container-name>
```

Use `--shell /bin/sh` only when the image does not provide the default shell.
Host SSH is available only for a service that the scenario realizes and that
`aptl lab info` reports.

### MCP servers are unavailable

Confirm that startup completed the MCP phase and that the target exists in the
realized scenario. Start the client from the project root so it reads the
generated `.mcp.json`. Then inspect the client's connected-server and tool
list. A built server is not necessarily enabled for the selected scenario.

Contributors can rebuild all tracked artifacts with
`./mcp/build-all-mcps.sh`; released-package operators should let
`aptl lab start` own the build and configuration. See the
[MCP reference](../reference/mcp.md).

## Project-Scoped Recovery

Retry a normal lifecycle through the control plane:

```shell
aptl lab stop
aptl lab start --scenario <id>
```

For a confirmed full reset of this project's volume-backed data:

```shell
aptl lab stop -v
aptl lab start --scenario <id>
```

The destructive stop asks for confirmation. It removes project volumes but
does not prune the Docker daemon. Do not use `docker system prune` as APTL
recovery: it can remove resources belonging to other projects.

Do not replace recovery with raw `docker compose up`. `aptl lab start` owns
scenario realization, generated configuration, credentials, port selection,
readiness, MCP setup, and run recording. `aptl kill` is reserved for emergency
process or container termination; it is not normal teardown.

## Platform Issues

### Linux
```bash
# Docker permissions
sudo usermod -aG docker $USER
# Logout/login required
```

### macOS

Docker Desktop owns the Linux VM and its kernel settings. If another macOS
service occupies a requested host port, let APTL remap it and use the URL from
`aptl lab info`. Change or disable the other service only when you explicitly
need to pin that port.

### A container is `Up` but reports `unhealthy`, blocking `aptl lab start`

When `aptl lab start` fails with `dependency <name> failed to start:
container aptl-<name> is unhealthy` and `docker ps` shows the container
as `Up (unhealthy)`, there are two very different failure modes worth
distinguishing before assuming the tool is broken:

**1. Memory too tight—the service is being kernel-killed during warm-up.**
Check the deploy limit vs the service's needs:

```bash
docker inspect aptl-<name> --format 'Mem={{.HostConfig.Memory}} OOMKilled={{.State.OOMKilled}} RestartCount={{.RestartCount}}'
docker logs --tail 30 aptl-<name>
```

Signs: `RestartCount` climbing, entrypoint lines like `Killed  su ... bin/<service>`,
`OOMKilled` may stay `false` if the JVM/child was killed outside docker's
tracking. The fix is to raise `deploy.resources.limits.memory` on that
service in `docker-compose.yml`. Cortex 3.1.8 at 512m was one confirmed
case ([#723](https://github.com/Brad-Edwards/aptl/issues/723), fixed on
`dev`); watch for similar behavior on any service whose limit is 128m /
256m / 512m if its images are non-trivial (JVM, Play, Elasticsearch,
Cassandra, etc.).

**2. Container is running but the intended daemons have died silently.**
The container's PID 1 (often `s6` or a shell) survives, so docker still
reports `Up`, but the workload processes are gone and the healthcheck
port is closed.

```bash
docker exec aptl-<name> sh -c 'ls /proc/[0-9]*/comm | while read f; do read n < "$f"; echo "$(basename $(dirname $f)) $n"; done | sort -k2'
```

Compare the live process list against what the container is supposed to
run (for example, wazuh-manager should show `wazuh-analysisd`, `wazuh-modulesd`,
`wazuh-execd`, and a python API process—not just `s6-supervise` +
`filebeat`). If the intended daemons are missing, check the service's
own log directory (for example, `/var/ossec/logs/ossec.log` for Wazuh) for the
crash cause. Wazuh-manager silent-crash after startup is tracked in
[#725](https://github.com/Brad-Edwards/aptl/issues/725).

### `aptl lab start` fails because a Wazuh service did not become ready

A scenario that starts Wazuh needs it working, so Wazuh readiness is fatal.
After the containers start, `aptl lab start` authenticates to the Wazuh
indexer and manager APIs. It retries quietly while the APIs warm up. A clean
boot normally spends a few seconds in that state, because the manager API
starts listening after its container is already running. If a service is
still unready when the readiness budget ends, startup fails and names the
phase and reason for that service:

```
Authenticated Wazuh readiness validation failed after 300s:
  wazuh.manager at https://localhost:55000 transport phase failed:
  tls_handshake (curl exit 35). Inspect `aptl container logs aptl-wazuh-manager`.
```

Scenarios that don't declare Wazuh certificate or configuration artifacts
report the same reason in a slightly different form:

```
Wazuh Manager API did not become ready within 120s:
  wazuh.manager at https://localhost:55000 transport phase failed:
  tls_handshake (curl exit 35). Inspect `aptl container logs aptl-wazuh-manager`.
```

Read the phase first:

- **`transport`**: no HTTP response arrived. `tls_handshake` (curl exit 35) or
  `connection_reset` from a published port usually means nothing inside the
  container is listening yet. Docker accepts the connection on the host and
  then closes it. When this state lasts for the whole budget, the API never
  started. Inspect the container logs, and check that the container is not
  restarting or running out of memory.
- **`authentication`**: the API answered but did not issue a session.
  `credentials_rejected` (HTTP 401 or 403) means the API rejected the
  `INDEXER_USERNAME`/`INDEXER_PASSWORD` or `API_USERNAME`/`API_PASSWORD`
  values from `.env`. For the indexer, a retained `wazuh-indexer-data` volume
  can still hold an earlier admin password: run `aptl lab stop -v`, then
  `aptl lab start`, or restore the original `INDEXER_PASSWORD`.
- **`manager_status`**: the manager API authenticated but reported no running
  manager daemons. See the silent-daemon failure mode in the previous section.

The message never includes credentials, tokens, or response bodies.

### `aptl lab start` fails with "Existing network aptl_aptl-... does not match realized network"

Symptom on a machine that has run an older aptl-labs release before the
`org.aptl.realization.network=true` label was introduced:

```
Lab start failed: RAES runtime handoff failed: ...
  Existing network aptl_aptl-dmz does not match realized network dmz-net:
  label org.aptl.realization.network expected 'true', found ''.
```

The stale networks were created without the realization label the current
version expects. Current APTL teardown removes all networks carrying the
validated Compose project label, including older networks without the newer
realization label. Use the project-scoped reset and retry:

```bash
aptl lab stop
aptl lab start
```

If stop reports `lifecycle-owner-busy`, another start/stop/clean/kill or policy
operation still owns the project; wait for it to exit before retrying. If stop
reports a cleanup-verification or observation failure, restore the configured
local/SSH Docker connection and run stop again. Do not use a daemon-wide prune:
APTL cleanup is deliberately bounded by the validated project labels.

Tracked in [#722](https://github.com/Brad-Edwards/aptl/issues/722).

### macOS: Docker Desktop uninstall leftovers

If you uninstalled Docker Desktop and switched to Colima (or brew-installed
Docker), two leftover pieces silently break `aptl lab start`:

**Dead CLI plugin symlinks** in `~/.docker/cli-plugins/*` still point at
`/Applications/Docker.app/Contents/Resources/cli-plugins/...`. `docker
buildx` and `docker compose` then fail with `unknown command` even after
`brew install docker-buildx docker-compose`. Repoint them at the brew
binaries and drop the other dead symlinks:

```bash
ln -sf "$(brew --prefix docker-buildx)/bin/docker-buildx" ~/.docker/cli-plugins/docker-buildx
ln -sf "$(brew --prefix docker-compose)/bin/docker-compose" ~/.docker/cli-plugins/docker-compose
for f in ~/.docker/cli-plugins/*; do [ -L "$f" ] && [ ! -e "$f" ] && rm "$f"; done
```

**Stale `credsStore` in `~/.docker/config.json`.** Docker Desktop's
installer sets `"credsStore": "desktop"`, and `docker pull` on any image
requiring a credential lookup then fails with:

```
error getting credentials - err: exec: "docker-credential-desktop": executable file not found in $PATH
```

Remove that key from `~/.docker/config.json`. A minimal working config after
switching to Colima looks like:

```json
{
  "auths": {},
  "currentContext": "colima"
}
```

### WSL2
```bash
# Restart WSL2
wsl --shutdown
# Edit ~/.wslconfig:
[wsl2]
memory=8GB
processors=4
```
