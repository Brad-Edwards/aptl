# CI/CD Remote Deployment

APTL can auto-deploy to a remote host via GitHub Actions. This is optional — the default is local Docker Compose (`aptl lab start`).

## How It Works

The `deploy.yml` workflow:

1. Connects to a remote host via SSH (optionally through Tailscale)
2. Syncs the project files with `rsync`
3. Installs the Python CLI
4. Starts the lab with `docker compose up`
5. Verifies containers are running

Deployment targets are configured as **GitHub Environments** — each contributor can set up their own target without modifying any committed files.

## Setting Up a Deployment Target

### 1. Create a GitHub Environment

Go to **Settings > Environments > New environment** in the APTL repo.

Name it something descriptive: `brad-dragondev`, `team-lab-aws`, `ci-staging`.

### 2. Set Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DEPLOY_HOST` | Yes | IP address or hostname of the target machine |
| `DEPLOY_USER` | Yes | SSH username on the target |
| `DEPLOY_DIR` | No | Remote project directory (default: `/opt/aptl`) |
| `DEPLOY_VIA_TAILSCALE` | No | Set to `true` if the target is on a Tailscale network |

### 3. Set Secrets

| Secret | Required | Description |
|--------|----------|-------------|
| `DEPLOY_SSH_KEY` | Yes | Private SSH key with access to the target host |
| `TS_OAUTH_CLIENT_ID` | Only if Tailscale | Tailscale OAuth client ID ([create one here](https://login.tailscale.com/admin/settings/oauth)) |
| `TS_OAUTH_SECRET` | Only if Tailscale | Tailscale OAuth client secret |

### 4. Prepare the Target Host

The target host needs:

- Docker Engine + Docker Compose v2
- Python 3.11+ with pip
- SSH access for the configured user
- Enough resources (8GB+ RAM for core lab, 20GB+ for full stack)

```bash
# Create the project directory
sudo mkdir -p /opt/aptl
sudo chown $USER:$USER /opt/aptl
```

## Triggering Deploys

### Manual Dispatch

Go to **Actions > Deploy Lab > Run workflow** and select your environment from the dropdown.

Or via CLI:

```bash
gh workflow run deploy.yml -f environment=brad-dragondev
```

### Auto-Deploy on Push to Dev

Set a **repository variable** (not environment variable) to auto-deploy on every push to `dev`:

```bash
gh variable set DEFAULT_DEPLOY_ENVIRONMENT --body "brad-dragondev" --repo Brad-Edwards/aptl
```

To disable auto-deploy:

```bash
gh variable delete DEFAULT_DEPLOY_ENVIRONMENT --repo Brad-Edwards/aptl
```

If `DEFAULT_DEPLOY_ENVIRONMENT` is not set, the deploy job is skipped entirely — only the existing SonarCloud analysis runs.

## Tailscale Setup

If your target host is on a Tailscale network (not publicly accessible):

1. Set `DEPLOY_VIA_TAILSCALE=true` in your environment variables
2. Create a Tailscale OAuth client at [admin console](https://login.tailscale.com/admin/settings/oauth) with `Devices: Write` scope
3. Add `TS_OAUTH_CLIENT_ID` and `TS_OAUTH_SECRET` to your environment secrets
4. Add an ACL tag `tag:ci` in your Tailscale policy and grant it access to your target host
5. Use the Tailscale IP (e.g., `100.x.y.z`) as `DEPLOY_HOST`

## What Gets Deployed

The workflow syncs the full project via rsync, excluding:

- `.git/` (history)
- `node_modules/` (rebuilt on remote)
- `__pycache__/`, `.venv/` (Python artifacts)
- `runs/` (experiment data)
- `research/` (local research files)
- `.env` (secrets — seeded from `.env.example` on first deploy)
- `.aptl/` (runtime state)

The lab is started with profiles matching `aptl.json` in the repo, plus the `otel` profile for observability.

## Multiple Environments

Each contributor can create their own environment. The workflow supports any number:

- `brad-dragondev` — Tailscale box at home
- `alice-ec2` — AWS EC2 instance
- `ci-staging` — shared team lab server

The same workflow YAML serves all targets. Only the GitHub Environment secrets and variables differ.
