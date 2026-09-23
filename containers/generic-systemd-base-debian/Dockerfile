# APTL Debian substrate with the offline TechVault package closure. Services,
# configuration, identities, and scenario content are still materialized from
# the admitted plan; no first-boot package repository is reachable or needed.
FROM debian:13@sha256:9cc080028c43b27d2074d63a5f9caf7166d731494965616c1a6d2827a004585c
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
