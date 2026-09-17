FROM aptl/generic-systemd-base-debian:latest

COPY containers/_wazuh-agent/install.sh /tmp/install-wazuh.sh
RUN /tmp/install-wazuh.sh && rm /tmp/install-wazuh.sh
