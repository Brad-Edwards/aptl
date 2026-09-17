# APTL backend substrate for an authored Active Directory identity authority.
# Domain identity and accounts are supplied later from the admitted plan; this
# image contains no scenario-specific realm, users, groups, or credentials.
FROM ubuntu:26.04@sha256:513c074113a871b51a8d16ab445c88779d6452d937a164fb5cc479f32668a41d

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        krb5-user \
        ldb-tools \
        samba \
        samba-ad-dc \
        samba-ad-provision \
        samba-dsdb-modules \
        samba-vfs-modules \
        smbclient \
        python3-samba \
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
