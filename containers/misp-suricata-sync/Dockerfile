# MISP-to-Suricata IOC sync service.
# Generates Suricata `alert` rules (per ADR-019) from MISP indicators
# carrying the configured enforcement tag, writes them to a dedicated
# rules file, and triggers Suricata rule reload via its unix-command
# socket.

FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml /app/
COPY README.md /app/
# hatch_build.py is a declared wheel build hook in pyproject.toml, so
# `pip install .` requires it in the build context (issue #659). It no-ops
# here because this minimal context has no docker-compose.yml, so no lab
# assets are bundled into the service image.
COPY hatch_build.py /app/
COPY src /app/src

# Third-party dependencies come from the hash-verified export generated from
# uv.lock, so this image cannot resolve a different artifact than the one the
# lock pins. The project itself then installs with --no-deps and pulls nothing
# from a registry; `-e` links to the /app/src tree already COPYed above rather
# than duplicating it under site-packages (issue #847).
COPY requirements/runtime.txt /app/requirements/runtime.txt

RUN pip install --no-cache-dir --require-hashes -r requirements/runtime.txt \
    && pip install --no-cache-dir -e . --no-deps --no-build-isolation \
    && apt-get purge -y git \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Run as root: the service writes misp-iocs.rules into the shared
# suricata_misp_rules named volume (ADR-043), whose tree the Suricata image
# entrypoint chowns to its own UID; running as root keeps the write and the
# atomic file replacement working regardless of that ownership. The lab
# follows this pattern broadly (see ADR-020 for the in-process Wazuh
# agents); the sync container's only inputs are MISP HTTPS responses and its
# own env config.

ENTRYPOINT ["aptl-misp-suricata-sync"]
