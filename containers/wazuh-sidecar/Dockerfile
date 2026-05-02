# APTL Wazuh Agent Sidecar
#
# Lightweight sidecar that ships log files from a target container into the
# APTL Wazuh manager. As of #248 this image is used only for the carve-out
# cases: postgres (db) — alpine + postgres user isolation makes in-process
# disproportionately costly — and suricata, whose deployment is governed
# by ADR-019. The other four service containers (webapp / fileshare / ad /
# dns) now run wazuh-agent in-process; see ADR-020.
#
# Build context: the repo root (so COPY can pull from
# containers/_wazuh-agent/, the directory shared with the in-process
# targets). Compose declares this via `build: { context: ., dockerfile:
# containers/wazuh-sidecar/Dockerfile }`.
#
# Configured at start-up via three environment variables:
#   WAZUH_MANAGER  - hostname of the manager (typically wazuh.manager)
#   AGENT_NAME     - logical agent name registered with the manager
#   LOG_PATHS      - comma-separated paths under /logs to monitor

FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

COPY containers/_wazuh-agent/install.sh /tmp/install-wazuh.sh
RUN /tmp/install-wazuh.sh && rm /tmp/install-wazuh.sh && \
    # Sidecar-only image trim: the install.sh helper keeps curl/gnupg
    # because target containers (webapp / dns / fileshare / ad) often
    # need them anyway; the sidecar image has no other use for them
    # so purge here to keep the image small.
    apt-get purge -y curl gnupg && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

COPY containers/_wazuh-agent/ossec.conf.template /opt/aptl/wazuh/ossec.conf.template
COPY containers/_wazuh-agent/wazuh-agent.sh      /opt/aptl/wazuh/wazuh-agent.sh
RUN chmod +x /opt/aptl/wazuh/wazuh-agent.sh

# Active-response wrapper + kali whitelist (issue #249, ADR-021). Even
# though the remaining sidecars (db, suricata) aren't AR's primary
# enforcement targets, ship the wrapper + whitelist consistently so
# any AR rule that fires against a sidecar agent honors the carve-out.
COPY containers/_wazuh-agent/aptl-firewall-drop.sh         /var/ossec/active-response/bin/aptl-firewall-drop
COPY config/wazuh_cluster/etc/lists/active-response-whitelist /var/ossec/etc/lists/active-response-whitelist
RUN chmod 755 /var/ossec/active-response/bin/aptl-firewall-drop && \
    chmod 640 /var/ossec/etc/lists/active-response-whitelist && \
    chown root:wazuh /var/ossec/active-response/bin/aptl-firewall-drop \
                     /var/ossec/etc/lists/active-response-whitelist

ENTRYPOINT ["/opt/aptl/wazuh/wazuh-agent.sh"]
