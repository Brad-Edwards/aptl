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

USER nobody

ENTRYPOINT ["aptl-misp-suricata-sync"]
