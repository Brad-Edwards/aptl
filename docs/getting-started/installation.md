# Installation

## Python CLI (Recommended)

```bash
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
pipx install aptl-labs
aptl lab start
```

Clone the repo even when you install the published package: `aptl lab start`
reads the Compose topology, scenarios, and config templates from the checkout.
[pipx](https://pipx.pypa.io/) installs the CLI into its own virtualenv, so the
[PEP 668](https://peps.python.org/pep-0668/) system-`pip` block on modern
Debian/Ubuntu/WSL2 hosts never applies (`sudo apt install pipx` to get it).

To develop against the source tree, install it editable in a virtualenv
instead of the `pipx` line (needs `python3-venv` on Debian/Ubuntu; see
[Prerequisites](prerequisites.md)):

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

`aptl lab start` creates `.env` automatically when it is missing and replaces
template placeholder values with lab credentials that match the running
containers. The startup output points to `.env` for passwords and tokens. Run
`aptl lab info` later to reprint the same access summary.

The CLI handles SSH keys, SSL certificates, system requirements, image pulling, container startup, service readiness checks, and connection info generation.

## Manual Steps

If you need to run steps individually:

1. Generate SSH keys: `./scripts/generate-ssh-keys.sh`
2. Set vm.max_map_count (Linux/WSL2): `sudo sysctl -w vm.max_map_count=262144`
3. Generate SSL certificates: `docker compose -f generate-indexer-certs.yml run --rm generator`
4. Start lab: `aptl lab start`

> Step 4 must be `aptl lab start`, not a raw `docker compose up`: `aptl lab
> start` also renders the credentialized Wazuh config from the checked-in
> templates into the gitignored `.aptl/config/` tree (ADR-028), which the
> manager and dashboard containers bind-mount. There is no standalone command
> for that render, so `docker compose --profile wazuh ... up` on a fresh
> checkout fails at the `.aptl/config/...` bind mounts. (Once a lab has been
> started, raw `docker compose up -d` reuses the already-rendered config.)

## MCP Integration

Build MCP servers for AI agent control:
```bash
cd mcp/mcp-red && npm install && npm run build && cd ../..
cd mcp/mcp-wazuh && npm install && npm run build && cd ../..
```

See [MCP Integration](../components/mcp-integration.md) for configuration details.

## Verification

Access lab components:

- Wazuh Dashboard: <https://localhost:443> (`admin` / your `INDEXER_PASSWORD` from `.env`)
- Access summary: `aptl lab info`
- Victim shell: `aptl container shell aptl-victim`
- Kali shell: `aptl container shell aptl-kali`
- Reverse engineering SSH: `ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2027`
