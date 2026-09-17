FROM aptl/generic-samba-ad-base:latest

COPY containers/_wazuh-agent/install.sh /tmp/install-wazuh.sh
RUN apt-get update \
    && apt-get install -y --no-install-recommends rsyslog \
    && rm -rf /var/lib/apt/lists/* \
    && /tmp/install-wazuh.sh \
    && rm /tmp/install-wazuh.sh
