FROM jasonish/suricata:8.0@sha256:7ca2546f7f2735f621b981b6a5ec84fb962984636f7629a1a2fa6a324d4b6840

# The runtime bypasses the upstream entrypoint's network-dependent updater.
# Prepare only product rules already present in this pinned image. The upstream
# updater filters disabled protocols; a file URL prevents its default remote
# source selection, and the build step has no network access.
RUN --network=none tar --sort=name -cf /tmp/suricata-builtin.tar -C /usr/share/suricata/rules . \
    && suricata-update --url file:///tmp/suricata-builtin.tar --no-test --no-reload --fail \
    && test -s /var/lib/suricata/rules/suricata.rules \
    && suricata -T -S /var/lib/suricata/rules/suricata.rules \
    && rm /tmp/suricata-builtin.tar

COPY containers/_wazuh-agent/install-rhel.sh /tmp/install-wazuh.sh
COPY containers/_wazuh-agent/wazuh.repo /tmp/wazuh.repo
COPY containers/_wazuh-agent/aptl-firewall-drop.sh /tmp/aptl-firewall-drop.sh
COPY config/wazuh_cluster/etc/lists/active-response-whitelist /tmp/active-response-whitelist
COPY containers/_wazuh-agent/install-active-response.sh /tmp/install-active-response.sh
RUN sh /tmp/install-wazuh.sh && rm /tmp/install-wazuh.sh /tmp/wazuh.repo /tmp/aptl-firewall-drop.sh /tmp/active-response-whitelist /tmp/install-active-response.sh
