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

**macOS:** Install Docker Desktop and allocate enough memory in
Settings -> Resources. The full `techvault-operational` stack needs more than
20GB.

**Windows:** Install Docker Desktop with the WSL2 backend enabled. Run APTL from
PowerShell, Windows Terminal, Git Bash, or a WSL2 shell; keep Docker Desktop
running before `aptl lab start`.

**Linux Docker Desktop:** Install Docker Desktop and use the Desktop-managed
engine. It behaves like the macOS/Windows Docker VM for host sysctls.

## System Config

`aptl lab start` enforces `vm.max_map_count` only when Docker is a native Linux
engine. Docker Desktop on macOS, Windows, WSL2, or Linux manages the setting
inside its Linux VM, so there is no host `sysctl` step for those platforms.

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

## Python environment

Install the CLI into a virtualenv, not the system Python. Modern
Debian/Ubuntu/WSL2 hosts mark the system interpreter as externally managed and
block system-wide `pip` under [PEP 668](https://peps.python.org/pep-0668/), so
`pip install -e .` against the system Python fails with
`error: externally-managed-environment`.

For released installs on any OS, prefer `pipx install aptl-labs`.

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
