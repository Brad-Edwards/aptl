# APTL Wazuh Agent Sidecar
#
# Lightweight sidecar that ships log files from a target container into the
# APTL Wazuh manager. Used for services whose container images we cannot or
# should not modify (postgres, suricata, mailserver) and for
# minimally-built service containers (fileshare, ad, dns, webapp) where
# adding the agent in-band would balloon the image surface.
#
# Each instance of the sidecar mounts the target's log volume read-only at
# /logs and is configured at start-up via three environment variables:
#
#   WAZUH_MANAGER  - hostname of the manager (typically wazuh.manager)
#   AGENT_NAME     - logical agent name registered with the manager
#   LOG_PATHS      - comma-separated paths under /logs to monitor
#                    e.g. "/logs/log.smbd,/logs/log.winbindd"
#
# A custom localfile block is generated for each path so the manager sees
# the source of every event without needing decoder changes per sidecar.

FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        gnupg \
        lsb-release \
        ca-certificates \
        procps \
        netcat-openbsd && \
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    WAZUH_MANAGER=PLACEHOLDER apt-get install -y wazuh-agent=4.12.0-1 && \
    apt-get purge -y curl gnupg && \
    apt-get autoremove -y && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY ossec.conf.template /opt/wazuh-sidecar/ossec.conf.template
COPY entrypoint.sh /opt/wazuh-sidecar/entrypoint.sh
RUN chmod +x /opt/wazuh-sidecar/entrypoint.sh

ENTRYPOINT ["/opt/wazuh-sidecar/entrypoint.sh"]
