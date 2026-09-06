# APTL generic Debian systemd base substrate (ADR-048). OS + init only, no
# product, no baked service. For apt-family nodes that declare service units so
# systemd runs their units. Validated locally against Docker with APTL's systemd
# run flags (issue #955): env container=docker, cgroupns=private, security-opt
# writable-cgroups=true, tmpfs /run+/run/lock+/tmp, NO added capabilities,
# default seccomp, /sbin/init. Reaches `systemctl is-system-running` = running
# with zero failed units -- the retired recipe booted this image `degraded` with
# six failed units, because holding CAP_SYS_ADMIN made systemd attempt host
# operations (dev-hugepages.mount, sys-fs-fuse-connections.mount, logind) that
# then failed. Requires Docker Engine 28.0+ for `writable-cgroups`.
FROM debian:12@sha256:9344f8b8992482f80cba753f323adeaf17690076c095ccff6cc9536be98185dc
# gnupg: debian:12 ships gpgv (verify-only) but not the full gpg binary
# apt-key needs for some bookworm InRelease signature paths — without it,
# a materialized node's own first `apt-get update` intermittently fails
# with "Unknown error executing apt-key" (issue #581, caught only by a
# real fresh-machine boot with no pre-existing apt cache to mask it).
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus gnupg \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
