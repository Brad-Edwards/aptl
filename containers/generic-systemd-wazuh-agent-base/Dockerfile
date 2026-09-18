FROM aptl/generic-systemd-base:latest

COPY containers/_wazuh-agent/install-rhel.sh /tmp/install-wazuh.sh
COPY containers/_wazuh-agent/wazuh.repo /tmp/wazuh.repo
COPY containers/_wazuh-agent/aptl-firewall-drop.sh /tmp/aptl-firewall-drop.sh
COPY config/wazuh_cluster/etc/lists/active-response-whitelist /tmp/active-response-whitelist
COPY containers/_wazuh-agent/install-active-response.sh /tmp/install-active-response.sh
RUN sh /tmp/install-wazuh.sh && rm /tmp/install-wazuh.sh /tmp/wazuh.repo /tmp/aptl-firewall-drop.sh /tmp/active-response-whitelist /tmp/install-active-response.sh
