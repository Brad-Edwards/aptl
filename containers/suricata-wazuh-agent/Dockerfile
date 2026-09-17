FROM jasonish/suricata:7.0@sha256:0364b6f31192bc27a84dd471f60de22781d88e4d9511fbd3413e56ba4e150ac8

COPY containers/_wazuh-agent/install-rhel.sh /tmp/install-wazuh.sh
COPY containers/_wazuh-agent/wazuh.repo /tmp/wazuh.repo
COPY containers/_wazuh-agent/aptl-firewall-drop.sh /tmp/aptl-firewall-drop.sh
COPY config/wazuh_cluster/etc/lists/active-response-whitelist /tmp/active-response-whitelist
COPY containers/_wazuh-agent/install-active-response.sh /tmp/install-active-response.sh
RUN sh /tmp/install-wazuh.sh && rm /tmp/install-wazuh.sh /tmp/wazuh.repo /tmp/aptl-firewall-drop.sh /tmp/active-response-whitelist /tmp/install-active-response.sh
