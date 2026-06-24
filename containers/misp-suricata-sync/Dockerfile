# MISP-to-Suricata IOC sync service.
# Generates Suricata `alert` rules (per ADR-019) from MISP indicators
# carrying the configured enforcement tag, writes them to a dedicated
# rules file, and triggers Suricata rule reload via its unix-command
# socket.

FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml /app/
COPY src /app/src

RUN pip install --no-cache-dir . \
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
