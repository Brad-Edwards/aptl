# Samba file server with AD-integrated shares.
# Contains intentionally misconfigured shares and planted sensitive files.
#
# Build context: repo root (issue #248 — shared Wazuh agent files come
# from containers/_wazuh-agent/). Compose declares
# `build: { context: ., dockerfile: containers/fileshare/Dockerfile }`.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    samba \
    smbclient \
    rsyslog \
    net-tools \
    iptables \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# In-process Wazuh agent (replaces wazuh-sidecar-fileshare; #248).
COPY containers/_wazuh-agent/install.sh                    /tmp/install-wazuh.sh
COPY containers/_wazuh-agent/aptl-firewall-drop.sh         /tmp/aptl-firewall-drop.sh
COPY config/wazuh_cluster/etc/lists/active-response-whitelist /tmp/active-response-whitelist
RUN /tmp/install-wazuh.sh && \
    rm /tmp/install-wazuh.sh /tmp/aptl-firewall-drop.sh /tmp/active-response-whitelist
COPY containers/_wazuh-agent/ossec.conf.template /opt/aptl/wazuh/ossec.conf.template
COPY containers/_wazuh-agent/wazuh-agent.sh      /opt/aptl/wazuh/wazuh-agent.sh
RUN chmod +x /opt/aptl/wazuh/wazuh-agent.sh

COPY containers/fileshare/setup-shares.sh   /opt/setup-shares.sh
COPY containers/fileshare/smb.conf          /etc/samba/smb.conf
COPY containers/fileshare/supervisord.conf  /etc/supervisor/conf.d/fileshare.conf
RUN chmod +x /opt/setup-shares.sh

EXPOSE 139 445

# setup-shares.sh runs once-per-container provisioning, then exec's
# supervisord which manages samba + the in-process Wazuh agent.
ENTRYPOINT ["/opt/setup-shares.sh"]
