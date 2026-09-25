FROM debian:13@sha256:9cc080028c43b27d2074d63a5f9caf7166d731494965616c1a6d2827a004585c

COPY containers/_wazuh-agent/install.sh /tmp/install-wazuh.sh
COPY containers/_wazuh-agent/aptl-firewall-drop.sh /tmp/aptl-firewall-drop.sh
COPY config/wazuh_cluster/etc/lists/active-response-whitelist /tmp/active-response-whitelist
COPY containers/_wazuh-agent/install-active-response.sh /tmp/install-active-response.sh
RUN /tmp/install-wazuh.sh && rm /tmp/install-wazuh.sh /tmp/aptl-firewall-drop.sh /tmp/active-response-whitelist /tmp/install-active-response.sh
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        python3-flask python3-gunicorn python3-psycopg2 python3-jwt iptables \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete
