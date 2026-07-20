# APTL generic Debian systemd base substrate (ADR-048). OS + init only, no
# product, no baked service. For apt-family nodes that declare service units so
# systemd runs their units. Validated locally against Docker with APTL's systemd
# run flags (env container=docker, cgroupns=host, /sys/fs/cgroup:rw, tmpfs
# /run+/run/lock+/tmp, cap SYS_ADMIN, seccomp:unconfined, /sbin/init).
FROM debian:12
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
