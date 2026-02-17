# Samba file server with AD-integrated shares
# Contains intentionally misconfigured shares and planted sensitive files
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    samba \
    smbclient \
    rsyslog \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

COPY setup-shares.sh /opt/setup-shares.sh
COPY smb.conf /etc/samba/smb.conf
RUN chmod +x /opt/setup-shares.sh

EXPOSE 139 445

ENTRYPOINT ["/opt/setup-shares.sh"]
