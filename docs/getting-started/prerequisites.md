# Prerequisites

## Requirements

- RAM: 8GB runs the smaller curated scenarios; the full `techvault-operational` stack needs more than 20GB
- 20GB+ disk
- Docker Engine 20.10+
- Docker Compose 2.0+
- Python 3.11+ (for the CLI)
- Node.js 18+ and npm (for the MCP servers, the AI-agent control plane that
  `aptl lab start` builds via `mcp/build-all-mcps.sh`; without them the lab
  still boots but reports `degraded` with MCP servers unavailable)
- Git (only for the from-source dev install; `pipx install aptl-labs` needs no clone)

## Install Docker

**Linux:**
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

**macOS/Windows:** Install Docker Desktop

## System Config

**Linux/WSL2:**
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

**Debian/Ubuntu/WSL2:** install the `venv` module first (Debian ships it
separately from `python3`):

```bash
sudo apt install python3-venv   # or python3-full
```

Then create and activate the virtualenv from the repo root:

```bash
python3 -m venv .venv && source .venv/bin/activate
```

`.venv` is gitignored. Re-run `source .venv/bin/activate` in each new shell
before using `aptl`.

## Verify

```bash
docker --version
docker compose version
docker ps
```
