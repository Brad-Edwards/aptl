# APTL Debian substrate with the offline TechVault package closure. Services,
# configuration, identities, and scenario content are still materialized from
# the admitted plan; no first-boot package repository is reachable or needed.
FROM debian:13@sha256:f324c7ff54321e8d9c588493a20244965938ce0aa50bbd1022d38010e9ffc4b1
# gnupg: debian:12 ships gpgv (verify-only) but not the full gpg binary
# apt-key needs for some bookworm InRelease signature paths — without it,
# a materialized node's own first `apt-get update` intermittently fails
# with "Unknown error executing apt-key" (issue #581, caught only by a
# real fresh-machine boot with no pre-existing apt cache to mask it).
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus gnupg \
        bind9 dnsutils iptables postgresql samba python3-pip python3-venv \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete
COPY requirements/runtime.txt /tmp/aptl-runtime-requirements.txt
RUN python3 -m venv /opt/aptl/venv \
    && /opt/aptl/venv/bin/pip install --require-hashes \
        -r /tmp/aptl-runtime-requirements.txt \
    && rm /tmp/aptl-runtime-requirements.txt
ENV PATH="/opt/aptl/venv/bin:${PATH}"
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
