# APTL backend substrate for an authored Active Directory identity authority.
# Domain identity and accounts are supplied later from the admitted plan; this
# image contains no scenario-specific realm, users, groups, or credentials.
FROM ubuntu:22.04@sha256:0e0a0fc6d18feda9db1590da249ac93e8d5abfea8f4c3c0c849ce512b5ef8982

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        krb5-user \
        ldb-tools \
        samba \
        samba-dsdb-modules \
        samba-vfs-modules \
        tini \
        winbind \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete

COPY provider-start.sh /usr/local/sbin/aptl-samba-provider-start
COPY provision-domain.sh /usr/local/sbin/aptl-provision-samba-domain
RUN chmod 0755 \
        /usr/local/sbin/aptl-samba-provider-start \
        /usr/local/sbin/aptl-provision-samba-domain

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/sbin/aptl-samba-provider-start"]
