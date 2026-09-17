# APTL backend substrate for nodes that require Node.js 22 and systemd-managed
# services.  The product/runtime state remains materialized from the admitted
# scenario; this image supplies only the selected language + init/SSH substrate.
FROM node:22-bookworm@sha256:8a34c4ab3ea2c5cd194f07e317b2a8f09461d3c8b05c4e34c8ccd56d56024c4d
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus gnupg openssh-server \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
