---
id: DEP-008
title: "Self-Contained Distribution of Lab Assets from Installed Package"
status: ACTIVE
type: FUNCTIONAL
priority: SHOULD
wave: 2
created_at: 2026-07-06T08:00:25.969813Z
updated_at: 2026-07-06T18:33:10.977695Z
---

# DEP-008: Self-Contained Distribution of Lab Assets from Installed Package

## Statement

The platform shall bundle all lab assets required to run a lab, comprising the Docker Compose definition (docker-compose.yml), scenario definitions (scenarios/), configuration files (config/: Wazuh/Suricata configs, cert templates, active-response lists), and container build contexts (all Dockerfiles and build contexts under containers/), as installed package data shipped in the aptl-labs wheel, and shall provide a materialization entry point (for example, `aptl lab init <dir>`) that copies those assets out of the installed package into a working directory. All src/aptl code that currently reads lab assets via current-working-directory-relative paths (including but not limited to core/certs.py, suricata_seed.py, credentials.py, env.py, continuity.py, docker_compose.py, snapshot.py, _soc_ca_io.py) shall instead resolve those assets against the materialized working directory or installed package data rather than assuming the current working directory is a repository checkout. As a result, `pipx install aptl-labs` followed by `aptl lab init` and `aptl lab start` shall produce a working lab without a git clone of the repository.

## Rationale

PyPI publication (#651, #656) installs the `aptl` CLI but not the lab assets, so the documented flow still requires `git clone` before `aptl lab start`; the wheel currently packages only src/aptl ([tool.hatch.build.targets.wheel] packages = ["src/aptl"]). This mirrors the aces-sdl corpus-bundling fix (aces#537): the fix is to ship the assets in the wheel and resolve them from package data, not from an assumed repo checkout. Without it, the PyPI release only removes the `pip install -e .` step and does not deliver a standalone-installable lab, undercutting SYS-001's self-contained, locally deployable goal. This is an architecture change to how the CLI locates its assets, not a packaging tweak. Tracked by GitHub issue #659 (follows #651, #656).

## Traceability

- DOCUMENTS → GITHUB_ISSUE `659` (aptl-labs on PyPI still requires a full git clone to run the lab)
- IMPLEMENTS → CODE_FILE `hatch_build.py` (Wheel build hook: bundle git-tracked lab assets into aptl/_labdata)
- IMPLEMENTS → CODE_FILE `src/aptl/_asset_manifest.py` (Shared dependency-free lab-asset manifest (build hook + runtime))
- IMPLEMENTS → CODE_FILE `src/aptl/core/assets.py` (Asset resolution + materialization boundary (bundle/checkout))
- IMPLEMENTS → CODE_FILE `src/aptl/cli/lab_init.py` (aptl lab init command (materialize a standalone lab project))
- TESTS → TEST `tests/test_assets.py` (Asset resolution + materialization + secret-exclusion tests)
- TESTS → TEST `tests/test_hatch_build_hook.py` (Build-hook selection + wheel-content regression tests)
- TESTS → TEST `tests/test_lab_init_cli.py` (aptl lab init CLI end-to-end tests)
