FROM aptl/generic-systemd-base:latest

# Rocky's conventional /var/log/secure and /var/log/messages are produced by
# rsyslog. Install it while the image still has package-repository access;
# scenario runtime networks can deliberately remove that egress before a
# declared Wazuh file source is configured.
RUN dnf -y install rsyslog && dnf clean all

COPY containers/_wazuh-agent/install-rhel.sh /tmp/install-wazuh.sh
COPY containers/_wazuh-agent/wazuh.repo /tmp/wazuh.repo
COPY containers/_wazuh-agent/aptl-firewall-drop.sh /tmp/aptl-firewall-drop.sh
COPY config/wazuh_cluster/etc/lists/active-response-whitelist /tmp/active-response-whitelist
COPY containers/_wazuh-agent/install-active-response.sh /tmp/install-active-response.sh
RUN sh /tmp/install-wazuh.sh && rm /tmp/install-wazuh.sh /tmp/wazuh.repo /tmp/aptl-firewall-drop.sh /tmp/active-response-whitelist /tmp/install-active-response.sh
