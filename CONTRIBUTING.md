# Contributing to APTL

APTL is an active purple-team lab and autonomous cyber-operations research
project. Contributions are useful when they make the lab safer, more
reproducible, easier to operate, easier to test, or more precise for scenario
authors and agent integrations.

## Before Opening a Pull Request

- For small documentation fixes, typo fixes, and narrow test improvements, a
  pull request is enough.
- For lab topology changes, attack-path changes, detection logic changes, MCP
  API changes, scenario runtime changes, or container configuration changes,
  open an issue first. Those changes can affect safety boundaries,
  reproducibility, and documented workflows.
- Keep unrelated changes in separate pull requests.
- Base pull requests on `dev`, not `main`. `main` is the stable release line;
  `dev` is the integration branch.
- Do not add red-team capability enhancements to the public repository unless
  the maintainer has explicitly accepted the scope first.

## Development Setup

Prerequisites:

- Python 3.11 or newer
- Docker and Docker Compose
- Node.js and npm for MCP server and web UI work
- [pre-commit](https://pre-commit.com/)

Set up the Python control plane:

```shell
git clone https://github.com/Brad-Edwards/aptl.git
cd aptl
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

Build the MCP servers when working on agent integrations:

```shell
./mcp/build-all-mcps.sh
```

Install the web UI dependencies when working under `web/`:

```shell
cd web
npm install
```

## Making Changes

1. Fork the repository and create a branch from `dev`.
2. Make the smallest coherent change that solves the issue.
3. Add or update tests when behavior changes.
4. Update scenarios, schemas, documentation, or examples when the public
   surface changes.
5. Give the PR a [Conventional Commit](https://www.conventionalcommits.org)
   title (`feat:`, `fix:`, etc.); release-please derives the changelog and
   version from it. Do not edit `CHANGELOG.md`.
6. Run the relevant checks locally.
7. Open a pull request against `dev` with a concrete description of what
   changed and why.

## Verification

The local hygiene and secret check operates on staged files:

```shell
git add <files-you-intend-to-commit>
pre-commit run
```

Local commit hooks run secret detection and fast file hygiene only. Full Python,
MCP and web suites, dependency-lock freshness, complexity and prose checks run in
CI/CD. Run only the exact tests relevant to a change while developing. Do not
run bare `pytest`, package-wide `npm test`, `pre-commit run --all-files`, or the
whole-tree `.pre-commit-ci.yaml` configuration locally.

Examples of targeted checks:

```shell
pytest tests/test_specific_behavior.py
pytest -m fuzz tests/test_specific_fuzz_behavior.py
cd mcp/aptl-mcp-common && npx vitest run tests/specific.test.ts
cd mcp/mcp-red && npx vitest run tests/specific.test.ts
cd web && npx vitest run tests/specific.test.ts
```

When test files changed, `bash tools/run-targeted-tests.sh` derives those
targets from the branch and worktree. You can instead pass explicit Python test
paths to the script. CI/CD remains the authority for full suites, coverage,
whole-tree lint, dependency checks, and prose/build gates.

When changing files under `mcp/aptl-mcp-common`, run targeted common and
dependent-server tests while iterating. CI/CD rebuilds and tests every dependent
MCP because they consume the local package.

CI also runs the non-Docker Python suite plus `aptl --help` and
`aptl lab init` on Ubuntu and macOS. Windows runs the portable Python contract
suite plus the same CLI smoke commands, excluding POSIX-only file-mode,
ownership, signal, and Unix-socket tests. Hosted runners do not provide the
Docker Desktop/nested-virtualization environment needed to prove full lab boot
on macOS or Windows, so `aptl lab start` remains a manual platform-validation
gate.

When changing `docker-compose.yml`, container Dockerfiles, or files under
`config/`, run only focused contract tests locally. CI/CD owns the clean lab
stop/start validation so local verification does not expand into a full system
run.

## Safety Boundaries

APTL intentionally runs vulnerable services and gives agents access to
penetration-testing tools. Keep contributions bounded to authorized lab use.
Do not include real credentials, production secrets, private target data, or
instructions for using the project against systems you do not own or have
permission to test.

The repository contains intentional test credentials for lab functionality.
Those are not production secrets. New credentials should be dummy values unless
the design explicitly renders or generates them at runtime.

## Host Privilege Escalation

Host-side APTL code must not silently escalate privileges. Do not add `sudo -n`,
passwordless-sudo assumptions, or hidden sudo repair paths. If a host action
truly needs elevated privileges, either prompt for explicit consent before
running it or stop and print the exact command for the user to run. Scenario
containers may still model sudo behavior as lab content; that is separate from
operator host escalation.

## Changelog

Release notes and version bumps are generated by
[release-please](https://github.com/googleapis/release-please) from Conventional
Commit PR titles. Do not hand-edit `CHANGELOG.md`. See
[Releasing](docs/releasing.md).

## Security Reports

Do not open public issues for suspected security vulnerabilities. See
[SECURITY.md](SECURITY.md).

## Community Expectations

Participation in this project is covered by
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
