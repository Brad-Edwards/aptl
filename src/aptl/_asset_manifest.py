"""Single source of truth for the bundled lab-asset manifest (DEP-008).

This module is imported by *two* consumers that run in different
environments, so it must stay dependency-free (standard library only):

* ``aptl.core.assets`` (runtime) — decides what a source checkout
  materializes into a lab project directory.
* ``hatch_build.py`` (build time) — decides what the wheel ships under
  ``aptl/_labdata/``. The build environment only has build backend
  dependencies, so this module must not import pydantic, typer, or any
  other runtime dependency.

Keeping the manifest here means the wheel's bundled asset set and a
checkout's materialized set can never drift.
"""

from __future__ import annotations

# Top-level asset roots bundled into the wheel and materialized by
# ``aptl lab init``. Each tracked file maps to the same relative path.
# Derived from docker-compose.yml build contexts and bind mounts plus the
# host-side steps in ``aptl lab start`` (issue #659):
#   - several services build with ``context: .`` and
#     ``COPY pyproject.toml README.md src`` + ``pip install .``
#     (misp-suricata-sync, web API), so those + ``hatch_build.py`` (a declared
#     wheel build hook) are needed;
#   - ``web/`` is its own build context and ``scripts/`` is bind-mounted;
#   - ``mcp/`` holds ``build-all-mcps.sh`` and the MCP server sources that the
#     ``build_mcps`` start step compiles (needs node/npm on the host);
#   - ``.mcp.json.example`` seeds MCP client config; ``.dockerignore`` keeps
#     build contexts lean.
# ``keys/`` and ``.aptl/`` are generated at lab start (zero tracked files) and
# are intentionally absent.
ASSET_ROOTS: tuple[str, ...] = (
    "docker-compose.yml",
    ".dockerignore",
    "generate-indexer-certs.yml",
    ".env.example",
    ".mcp.json.example",
    "pyproject.toml",
    "README.md",
    "hatch_build.py",
    "src",
    "scenarios",
    "config",
    "containers",
    "web",
    "scripts",
    "mcp",
)

# Presence of this file marks a full lab-distribution build context. Minimal
# package build contexts — e.g. the service container images that
# ``COPY pyproject.toml README.md src`` then ``pip install .`` — do not carry
# it, so the build hook skips asset bundling there (issue #659 review): those
# images must still load the declared hook (hatch_build.py is copied in), but
# must not pull the multi-megabyte lab bundle into a service wheel.
DISTRIBUTION_MARKER = "docker-compose.yml"

# Directory names never bundled even beneath a tracked root. Only consulted
# by the no-git walk fallback; ``git ls-files`` already omits every one.
# Mirrors the gitignored secret/state and dev-artifact directories so a
# fallback selection cannot ship them.
EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {
        "__pycache__",
        "node_modules",
        ".venv",
        "dist",
        "build",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".hypothesis",
        ".git",
        "soc_certs",
        "lab-ssh",
        "wazuh_indexer_ssl_certs",
    }
)

EXCLUDED_SUFFIXES: tuple[str, ...] = (".pyc", ".pyo")

# Where the bundle lives inside the wheel / installed package.
LABDATA_DIRNAME = "_labdata"
LABDATA_PREFIX = f"aptl/{LABDATA_DIRNAME}"
