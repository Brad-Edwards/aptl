# MISP-to-Suricata IOC sync service.
# Generates Suricata `alert` rules (per ADR-019) from MISP indicators
# carrying the configured enforcement tag, writes them to a dedicated
# rules file, and triggers Suricata rule reload via its unix-command
# socket.

FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml /app/
COPY src /app/src

RUN pip install --no-cache-dir .

# Run as root: the service writes to a bind-mounted host directory
# (./config/suricata/rules/misp), and dropping to an unprivileged UID would
# mismatch the host operator's ownership and break atomic file replacement.
# The lab follows this pattern broadly (see ADR-020 for the in-process Wazuh
# agents); the sync container's only inputs are MISP HTTPS responses and its
# own env config.

ENTRYPOINT ["aptl-misp-suricata-sync"]
