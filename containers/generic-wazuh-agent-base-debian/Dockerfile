FROM debian:13@sha256:f324c7ff54321e8d9c588493a20244965938ce0aa50bbd1022d38010e9ffc4b1

COPY containers/_wazuh-agent/install.sh /tmp/install-wazuh.sh
COPY containers/_wazuh-agent/aptl-firewall-drop.sh /tmp/aptl-firewall-drop.sh
COPY config/wazuh_cluster/etc/lists/active-response-whitelist /tmp/active-response-whitelist
COPY containers/_wazuh-agent/install-active-response.sh /tmp/install-active-response.sh
RUN /tmp/install-wazuh.sh && rm /tmp/install-wazuh.sh /tmp/aptl-firewall-drop.sh /tmp/active-response-whitelist /tmp/install-active-response.sh
