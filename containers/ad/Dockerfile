# Samba Active Directory Domain Controller
# Provides techvault.local domain with users, groups, and intentional weaknesses.
#
# Build context: repo root. The Dockerfile pulls supervisord/samba assets from
# `containers/ad/` and the shared Wazuh agent assets from
# `containers/_wazuh-agent/` (issue #248). Compose declares this via
# `build: { context: ., dockerfile: containers/ad/Dockerfile }`.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV SAMBA_DOMAIN=TECHVAULT
ENV SAMBA_REALM=TECHVAULT.LOCAL
ENV SAMBA_ADMIN_PASSWORD=Admin123!

RUN apt-get update && apt-get install -y \
    samba \
    samba-dsdb-modules \
    samba-vfs-modules \
    krb5-user \
    krb5-config \
    winbind \
    libnss-winbind \
    libpam-winbind \
    ldb-tools \
    ldap-utils \
    dnsutils \
    net-tools \
    iproute2 \
    iptables \
    supervisor \
    rsyslog \
    procps \
    && rm -rf /var/lib/apt/lists/*

# In-process Wazuh agent (replaces the wazuh-sidecar-ad container; #248).
COPY containers/_wazuh-agent/install.sh /tmp/install-wazuh.sh
RUN /tmp/install-wazuh.sh && rm /tmp/install-wazuh.sh
COPY containers/_wazuh-agent/ossec.conf.template /opt/aptl/wazuh/ossec.conf.template
COPY containers/_wazuh-agent/wazuh-agent.sh      /opt/aptl/wazuh/wazuh-agent.sh
RUN chmod +x /opt/aptl/wazuh/wazuh-agent.sh

# Copy provisioning scripts and supervisord config from the per-container subdir.
COPY containers/ad/setup-ad.sh        /opt/setup-ad.sh
COPY containers/ad/provision-users.sh /opt/provision-users.sh
RUN chmod +x /opt/setup-ad.sh /opt/provision-users.sh
COPY containers/ad/supervisord.conf /etc/supervisor/conf.d/samba.conf

EXPOSE 53 53/udp 88 88/udp 135 139 389 389/udp 445 464 464/udp 636 3268 3269

ENTRYPOINT ["/opt/setup-ad.sh"]
