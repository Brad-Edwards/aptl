# APTL generic systemd base substrate (ADR-048).
#
# A GENERIC operating-system + init image: no product, no scenario, no baked
# service. It exists only so the generic materializer can start a node
# container in which declared `service_manager_units` actually run under
# systemd (`systemctl enable/start`, verified by `systemctl is-active`).
#
# Validated locally against Docker with the run flags APTL uses for its systemd
# nodes (issue #955): cgroupns=private, security-opt writable-cgroups=true,
# tmpfs /run+/run/lock+/tmp, NO added capabilities, the daemon's default seccomp
# profile, AppArmor docker-default, /usr/sbin/init. Reaches
# `systemctl is-system-running` = running with zero failed units.
#
# systemd needs a WRITABLE cgroup filesystem, not a privileged one. Docker
# Engine 28.0+ is required: `writable-cgroups=true` (moby#48828) clears the
# read-only flag on the container's own namespace-scoped cgroup2 mount, which
# replaces the retired cgroup-v1-era recipe (host cgroup namespace plus a
# read-write bind of the host's /sys/fs/cgroup).
FROM rockylinux:9@sha256:d7be1c094cc5845ee815d4632fe377514ee6ebcf8efaed6892889657e5ddaaa6

RUN dnf -y install systemd systemd-sysv && dnf clean all && \
    (cd /lib/systemd/system/sysinit.target.wants/; \
        for i in *; do [ "$i" = systemd-tmpfiles-setup.service ] || rm -f "$i"; done) && \
    (cd /lib/systemd/system/multi-user.target.wants/; \
        for i in *; do [ "$i" = systemd-user-sessions.service ] || rm -f "$i"; done) && \
    rm -f /etc/systemd/system/*.wants/* \
          /lib/systemd/system/local-fs.target.wants/* \
          /lib/systemd/system/sockets.target.wants/*udev* \
          /lib/systemd/system/basic.target.wants/* && \
    systemctl set-default multi-user.target
# systemd-user-sessions.service is the only unit in multi-user.target.wants
# kept above: it removes /run/nologin at boot, and without it PAM denies
# every non-root SSH login forever (issue #581, root-caused via a real
# fresh-VM boot: this getty/console-stripping wildcard was sweeping it up
# along with the units it's meant to strip).

CMD ["/usr/sbin/init"]
