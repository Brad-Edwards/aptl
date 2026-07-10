# Prerequisites

## Requirements

- RAM: 8GB runs the smaller curated scenarios; the full `techvault-operational` stack needs more than 20GB
- 20GB+ disk
- Docker Engine 20.10+ on native Linux, or Docker Desktop on macOS, Windows, or Linux
- Docker Compose 2.0+ (`docker compose version`)
- Python 3.11+ (for the CLI)
- Node.js 18+ and npm (for the MCP servers, the AI-agent control plane that
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

**macOS (Docker Desktop):** Install Docker Desktop and allocate enough memory
in Settings -> Resources. The full `techvault-operational` stack needs more
than 20GB.

**macOS (Colima alternative, no Docker Desktop):** If you cannot use Docker
Desktop (licensing, corporate policy, or preference), Colima runs the same
Docker Engine in a `lima` VM and APTL supports it directly. The APTL host
check calls out this path when Docker Buildx is missing; the full setup is:

```bash
brew install docker docker-buildx docker-compose colima
mkdir -p ~/.docker/cli-plugins
ln -sf "$(brew --prefix docker-buildx)/bin/docker-buildx" ~/.docker/cli-plugins/docker-buildx
ln -sf "$(brew --prefix docker-compose)/bin/docker-compose" ~/.docker/cli-plugins/docker-compose
colima start --cpu 4 --memory 8 --disk 60
```

Bump the resources for the full `techvault-operational` stack (see the
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

**Check ports available:**
```bash
netstat -tlnp | grep -E "(443|2027|8443|9000|9001|9200|55000)"
```

You do not have to free these by hand: `aptl lab start` probes every published
host port and, if a default is already in use (Windows reserves UDP 5353 for
mDNS; an editor's automatic port-forwarding may hold others), publishes that
service on a free port instead and prints the real ports under "Host port
remaps" in the start summary. Use the reported ports (for example, the Wazuh Dashboard
URL, or `dig @localhost -p <reported-port> techvault.local SOA`). Pin a specific
port with the matching `APTL_HP_*` / `APTL_DNS_HOST_PORT` variable to override.

## Python environment

Install the CLI into a virtualenv, not the system Python. Modern
Debian/Ubuntu/WSL2 hosts mark the system interpreter as externally managed and
block system-wide `pip` under [PEP 668](https://peps.python.org/pep-0668/), so
`pip install -e .` against the system Python fails with
`error: externally-managed-environment`.

For released installs on any OS, prefer `pipx install aptl-labs`.

**macOS gotcha—pipx bound to the system Python 3.9.** `aptl-labs` requires
Python 3.11+ (declared in `pyproject.toml`). If your `pipx` was installed
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
docker ps
```
