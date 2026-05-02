# TechVault Solutions Web Application
# Intentionally vulnerable for purple team testing.
#
# Build context: repo root (issue #248 — shared Wazuh agent files come
# from containers/_wazuh-agent/). Compose declares
# `build: { context: ., dockerfile: containers/webapp/Dockerfile }`.
FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    iputils-ping \
    net-tools \
    curl \
    rsyslog \
    iptables \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# In-process Wazuh agent (replaces wazuh-sidecar-webapp; #248).
COPY containers/_wazuh-agent/install.sh /tmp/install-wazuh.sh
RUN /tmp/install-wazuh.sh && rm /tmp/install-wazuh.sh
COPY containers/_wazuh-agent/ossec.conf.template /opt/aptl/wazuh/ossec.conf.template
COPY containers/_wazuh-agent/wazuh-agent.sh      /opt/aptl/wazuh/wazuh-agent.sh
RUN chmod +x /opt/aptl/wazuh/wazuh-agent.sh

# Active-response wrapper + kali whitelist (issue #249, ADR-021).
# Installs at the agent's canonical AR script path so wazuh-execd can
# invoke it by name. The whitelist file lives next to Wazuh's CDB list
# directory; the wrapper reads it directly with grep -Fxq.
COPY containers/_wazuh-agent/aptl-firewall-drop.sh         /var/ossec/active-response/bin/aptl-firewall-drop
COPY config/wazuh_cluster/etc/lists/active-response-whitelist /var/ossec/etc/lists/active-response-whitelist
RUN chmod 755 /var/ossec/active-response/bin/aptl-firewall-drop && \
    chmod 640 /var/ossec/etc/lists/active-response-whitelist && \
    chown root:wazuh /var/ossec/active-response/bin/aptl-firewall-drop \
                     /var/ossec/etc/lists/active-response-whitelist

WORKDIR /app

COPY containers/webapp/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY containers/webapp/app/ ./
COPY containers/webapp/entrypoint.sh /entrypoint.sh
COPY containers/webapp/supervisord.conf /etc/supervisor/conf.d/webapp.conf
RUN chmod +x /entrypoint.sh

RUN mkdir -p /var/log/gunicorn

EXPOSE 8080

ENV FLASK_APP=app.py
ENV FLASK_ENV=production

ENTRYPOINT ["/entrypoint.sh"]
