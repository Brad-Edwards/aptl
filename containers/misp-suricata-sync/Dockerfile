# MISP-to-Suricata IOC sync service.
# Generates Suricata `alert` rules (per ADR-019) from MISP indicators
# carrying the configured enforcement tag, writes them to a dedicated
# rules file, and triggers Suricata rule reload via its unix-command
# socket.

FROM python:3.14-slim@sha256:c3e521df8b2b498a7a682e7e18676771cb80c6b75b8699af886b2d554ce40151

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
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
    && python -m pip uninstall --yes pip \
    && apt-get purge -y git \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Run unprivileged (issue #1193). TechVault realizes this service as a
# base-container-materialized node (ADR-048), so this image is not on the
# runtime path; a deployment that does run it alongside Suricata passes the
# Suricata UID/GID (`--user`) so it can replace misp-iocs.rules in the shared
# suricata_misp_rules volume (ADR-043) and reach the unix-command socket.
RUN useradd --system --uid 10001 --user-group --no-create-home --home-dir /nonexistent aptl
USER 10001:10001

ENTRYPOINT ["aptl-misp-suricata-sync"]
