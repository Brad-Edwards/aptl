# Internal DNS server for techvault.local
#
# Build context: repo root (so the Dockerfile can pull shared Wazuh agent
# files from `containers/_wazuh-agent/`; issue #248). Compose declares
# `build: { context: ., dockerfile: containers/dns/Dockerfile }`.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    bind9 \
    bind9-utils \
    dnsutils \
    rsyslog \
    iptables \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/named && chown bind:bind /var/log/named

# In-process Wazuh agent (replaces wazuh-sidecar-dns; #248).
COPY containers/_wazuh-agent/install.sh /tmp/install-wazuh.sh
RUN /tmp/install-wazuh.sh && rm /tmp/install-wazuh.sh
COPY containers/_wazuh-agent/ossec.conf.template /opt/aptl/wazuh/ossec.conf.template
COPY containers/_wazuh-agent/wazuh-agent.sh      /opt/aptl/wazuh/wazuh-agent.sh
RUN chmod +x /opt/aptl/wazuh/wazuh-agent.sh

# Active-response wrapper + kali whitelist (issue #249, ADR-021).
COPY containers/_wazuh-agent/aptl-firewall-drop.sh         /var/ossec/active-response/bin/aptl-firewall-drop
COPY config/wazuh_cluster/etc/lists/active-response-whitelist /var/ossec/etc/lists/active-response-whitelist
RUN chmod 755 /var/ossec/active-response/bin/aptl-firewall-drop && \
    chmod 640 /var/ossec/etc/lists/active-response-whitelist && \
    chown root:wazuh /var/ossec/active-response/bin/aptl-firewall-drop \
                     /var/ossec/etc/lists/active-response-whitelist

# DNS config + supervisord config (per-container assets from containers/dns/).
COPY containers/dns/named.conf       /etc/bind/named.conf
COPY containers/dns/zones/           /etc/bind/zones/
COPY containers/dns/supervisord.conf /etc/supervisor/conf.d/dns.conf

EXPOSE 53 53/udp

# supervisord owns lifecycle: it runs named and the in-process Wazuh agent.
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
