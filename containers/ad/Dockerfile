# Samba Active Directory Domain Controller
# Provides techvault.local domain with users, groups, and intentional weaknesses
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
    supervisor \
    rsyslog \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Copy provisioning scripts
COPY setup-ad.sh /opt/setup-ad.sh
COPY provision-users.sh /opt/provision-users.sh
RUN chmod +x /opt/setup-ad.sh /opt/provision-users.sh

# Copy supervisord config
COPY supervisord.conf /etc/supervisor/conf.d/samba.conf

EXPOSE 53 53/udp 88 88/udp 135 139 389 389/udp 445 464 464/udp 636 3268 3269

ENTRYPOINT ["/opt/setup-ad.sh"]
