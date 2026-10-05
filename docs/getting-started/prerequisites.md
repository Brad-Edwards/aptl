# Prerequisites

## Requirements

- RAM: the full `techvault` stack needs more than 20GB
- 20GB+ disk
- Docker Engine 28.0+ on a cgroup v2 host: native Linux, or the engine inside
  Docker Desktop (macOS, Windows, Linux) or Colima. Check with
  `docker version --format '{{.Server.Version}}'` and
  `docker info --format '{{.CgroupVersion}}'` (must print `2`). Nodes that run
  service units boot systemd inside their container, which needs a writable
  cgroup filesystem; APTL obtains one with `--security-opt
  writable-cgroups=true`, added in Engine 28.0. `aptl lab start` checks the
  daemon before creating anything and stops with a clear message on an older
  engine or a cgroup v1 host rather than falling back to a privileged container
  recipe
- Docker Compose 2.0+ (`docker compose version`)
- Docker Buildx (`docker buildx version`)
- Python 3.12+ (for the CLI)
- OpenSSH client. `ssh-keygen` must be on `PATH`. `aptl lab start` generates the
  lab SSH keys (the control-plane key and, for pack-backed scenarios, the
  scenario's `ssh_key_bundle` keypairs) with it, and hardens them per-platform
  (POSIX mode on Linux/macOS, NTFS ACLs via `icacls` on Windows). Preinstalled on
  Linux and macOS; on Windows enable the built-in **OpenSSH Client** optional
  feature (Settings → Apps → Optional features), or use Git for Windows / WSL2.
- Node.js 20+ and npm (for the MCP servers, the AI-agent control plane that
  `aptl lab start` builds via `mcp/build-all-mcps.sh`; without them the lab
  still boots but reports `degraded` with MCP servers unavailable)
- Git (only for the from-source dev install; `pipx install aptl-labs` needs no clone)

## Install Docker

**Native Linux Docker Engine:**
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

Sign out and back in after changing Docker group membership.

The official Docker installer above includes Compose and Buildx. If you use
Ubuntu's distribution packages instead, install all three explicitly:

```bash
sudo apt install docker.io docker-compose-v2 docker-buildx
```

Docker CE repositories name the last package `docker-buildx-plugin` instead.
Distribution packages can lag behind Docker's own releases; confirm the server
reports Engine 28.0 or newer before starting a lab.

**macOS (Docker Desktop):** Install Docker Desktop and allocate enough memory
in Settings -> Resources. The full `techvault` stack needs more
than 20GB.

**macOS (Colima alternative, no Docker Desktop):** If you cannot use Docker
Desktop (licensing, corporate policy, or preference), Colima runs a Docker
Engine in a `lima` VM. APTL can select that Docker transport, but this is not
an independently qualified containment or full-TechVault workload profile. The APTL host
check calls out this path when Docker Buildx is missing; the full setup is:

```bash
brew install docker docker-buildx docker-compose colima
mkdir -p ~/.docker/cli-plugins
ln -sf "$(brew --prefix docker-buildx)/bin/docker-buildx" ~/.docker/cli-plugins/docker-buildx
ln -sf "$(brew --prefix docker-compose)/bin/docker-compose" ~/.docker/cli-plugins/docker-compose
colima start --cpu 4 --memory 8 --disk 60
```

Bump the resources for the full `techvault` stack (see the
RAM/disk requirements above). `colima start` also sets the active `docker`
context to `colima`; verify with `docker context ls`.

**Windows:** Install Docker Desktop with the WSL2 backend enabled. Run APTL from
PowerShell, Windows Terminal, Git Bash, or a WSL2 shell; keep Docker Desktop
running before `aptl lab start`.

**Linux Docker Desktop:** Install Docker Desktop and use the Desktop-managed
engine. It behaves like the macOS/Windows Docker VM for host sysctls.

## System Config

`aptl lab start` enforces `vm.max_map_count` only when Docker is a native Linux
engine. Docker Desktop on macOS, Windows, or WSL2 manages the setting inside its
Linux VM, so there is no host `sysctl` step for those platforms.

**Native Linux Docker Engine:**
```bash
# Required for OpenSearch
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
```

You do not need to reserve a fixed list of ports. `aptl lab start` probes each
host port requested by the realized scenario and remaps a service when its
default is occupied. Read the start summary or run `aptl lab info` for the
actual URLs and ports. Pin a port only through the matching documented
`APTL_HP_*` or `APTL_DNS_HOST_PORT` runtime setting.

## Python environment

Install the CLI into a virtualenv, not the system Python. Modern
Debian/Ubuntu/WSL2 hosts mark the system interpreter as externally managed and
block system-wide `pip` under [PEP 668](https://peps.python.org/pep-0668/), so
`pip install -e .` against the system Python fails with
`error: externally-managed-environment`.

For released installs on any OS, prefer `pipx install aptl-labs`.

**macOS gotcha—pipx bound to the system Python 3.9.** `aptl-labs` requires
Python 3.12+ (declared in `pyproject.toml`). If your `pipx` was installed
against the Command Line Tools Python (`/usr/bin/python3`, which is 3.9),
`pipx install aptl-labs` fails with:

```
ERROR: Could not find a version that satisfies the requirement aptl-labs (from versions: none)
```

The real cause is the "Ignored the following versions that require a
different python version" line further up in pip's output—every published
`aptl-labs` release is filtered out by the Python-version gate. Recover with
a scoped standalone Python that pipx fetches just for this venv:

```bash
pipx install --python 3.12 --fetch-missing-python aptl-labs
```

Alternatively, `brew install python@3.12` and use that interpreter.

For source installs, create a virtualenv. On Debian/Ubuntu/WSL2, install the
`venv` module first (Debian ships it separately from `python3`):

```bash
sudo apt install python3-venv   # or python3-full
```

Then create and activate the virtualenv from the repo root on Linux/macOS:

```bash
python3 -m venv .venv && source .venv/bin/activate
```

On Windows PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

`.venv` is gitignored. Re-run `source .venv/bin/activate` in each new shell
on Linux/macOS or `.\.venv\Scripts\Activate.ps1` in each new PowerShell before
using `aptl`.

## Verify

```bash
docker --version
docker compose version
docker buildx version
docker ps
```

## Tested execution profiles and limits

The [2026-09-20 candidate QA](../testing/issue-956-candidate-254bc40f-manual-qa.md)
exercised wheel and source installs on one Ubuntu 24.04 x86_64 host with Python
3.12.3, Docker Engine 29.5.0 and Compose 5.1.3. The full TechVault startup and
live-gate checks passed for that candidate. This is functional QA of that exact
release candidate, not a general host-containment or later-version guarantee.
The Docker daemon kernel and host kernel were not recorded together in that
report, so its evidence alone does not qualify a `native-docker` containment
claim.

The [one-host KVM seat acceptance](../reviews/1162-seat-acceptance.md) exercised
one signed image with eight vCPUs, 32 GiB RAM and a 128 GiB virtual disk. It
verified guest startup, authenticated host MCP access, offline restart and
scoped stop on one Linux/KVM host. That record does not include the exact host
OS, kernel and QEMU versions or the independent-machine qualification needed
for a broader seat profile. The signed image and a successful boot establish
identity and operation, not freedom from VM escape.

| Selection | Host resources and limits | Evidence status |
| --- | --- | --- |
| Native Linux Docker | The CLI and Docker-authorized services can control the selected daemon; project files are mounted into workloads and realized services may publish host ports. A daemon socket mount is root-equivalent on that daemon. | The candidate QA above shows functionality on one versioned host; [boundary classification tests](https://github.com/OpenRAE/lilrae/blob/876c493adb8919ed83a86899596897b4d0d07b57/tests/test_execution_boundary.py) check local-kernel matching and unknown cases. Host containment is not qualified. |
| Docker Desktop or another Docker VM | The CLI, project credentials and any published-port forwarding still touch the physical host. VM resource, device, network and sharing settings depend on the selected runtime. | No exact Desktop/Colima/Windows full-TechVault and containment matrix is recorded here. A `docker-vm-unverified` label is an observation, not proof. |
| SSH/remote Docker | The CLI controls a remote daemon; service ports are on that host, while project-local files and credentials remain on the CLI machine unless an explicit transport moves them. | The selected transport is reported; remote host isolation and port reachability are not inferred. |
| Optional VM seat | QEMU/KVM uses `/dev/kvm`, reserved CPU/RAM/disk and only declared loopback host-to-guest mappings. New desktop seats need `bwrap`, `nsenter`, `slirp4netns` and `/dev/net/tun`; they add no default outbound controls. Rootful Docker workloads inside one guest share that guest's authority. | The one-host acceptance above supports only its tested historical image and host. [VM-only containment](../adrs/adr-060-vm-only-seat-containment.md) is the contract; internal guest zones are deferred. |

Unsupported or unverified combinations cannot satisfy a *required* seat
containment profile: an unreadable/overridden Docker endpoint, missing or
unverified signed launch, unavailable KVM, or missing outer-host observation
must fail the applicable seat gate. A direct `aptl lab start` does not create a
seat. A scenario requiring its own VM node is also separate from the outer
seat VM and must be admitted and realized by the backend as a scenario
requirement. Internal guest zone isolation and default-deny guest egress are
not provided by the current VM-only seat; see [ADR-060](../adrs/adr-060-vm-only-seat-containment.md)
and [issue #1127](https://github.com/OpenRAE/lilrae/issues/1127).
