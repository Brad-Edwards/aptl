# APTL generic systemd base substrate (ADR-047).
#
# A GENERIC operating-system + init image: no product, no scenario, no baked
# service. It exists only so the generic materializer can start a node
# container in which declared `service_manager_units` actually run under
# systemd (`systemctl enable/start`, verified by `systemctl is-active`).
#
# Validated locally against Docker with the run flags APTL already uses for its
# systemd nodes (cgroupns=host, /sys/fs/cgroup:rw, tmpfs /run+/tmp,
# cap SYS_ADMIN/SYS_NICE/SYS_RESOURCE, seccomp:unconfined, /usr/sbin/init).
FROM rockylinux:9

RUN dnf -y install systemd systemd-sysv && dnf clean all && \
    (cd /lib/systemd/system/sysinit.target.wants/; \
        for i in *; do [ "$i" = systemd-tmpfiles-setup.service ] || rm -f "$i"; done) && \
    rm -f /lib/systemd/system/multi-user.target.wants/* \
          /etc/systemd/system/*.wants/* \
          /lib/systemd/system/local-fs.target.wants/* \
          /lib/systemd/system/sockets.target.wants/*udev* \
          /lib/systemd/system/basic.target.wants/* && \
    systemctl set-default multi-user.target

CMD ["/usr/sbin/init"]
