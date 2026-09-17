FROM jasonish/suricata@sha256:d64c491f6eb5d03b6562d873b3c5303e4c17d5dc1d75b3761a68319f11527dc3

COPY containers/_wazuh-agent/install-rhel.sh /tmp/install-wazuh.sh
COPY containers/_wazuh-agent/wazuh.repo /tmp/wazuh.repo
RUN sh /tmp/install-wazuh.sh && rm /tmp/install-wazuh.sh /tmp/wazuh.repo
