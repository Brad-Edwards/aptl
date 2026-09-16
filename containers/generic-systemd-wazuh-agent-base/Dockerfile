FROM aptl/generic-systemd-base:latest

COPY containers/_wazuh-agent/install-rhel.sh /tmp/install-wazuh.sh
COPY containers/_wazuh-agent/wazuh.repo /tmp/wazuh.repo
RUN sh /tmp/install-wazuh.sh && rm /tmp/install-wazuh.sh /tmp/wazuh.repo
