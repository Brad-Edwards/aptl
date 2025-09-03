# Base victim container using Rocky Linux 9 (RHEL-compatible)
FROM rockylinux:9

# Build arguments for agent installation
ARG INSTALL_WAZUH=true
ARG INSTALL_FALCO=true

# Set as environment variables for runtime
ENV INSTALL_WAZUH=${INSTALL_WAZUH}
ENV INSTALL_FALCO=${INSTALL_FALCO}

RUN dnf install -y epel-release && \
    dnf update -y && \
    dnf install -y \
    rsyslog \
    openssh-server \
    sudo \
    systemd \
    systemd-sysv \
    iproute \
    iproute-tc \
    hostname \
    procps-ng \
    openssh-clients \
    net-tools \
    gnupg \
    && dnf clean all

RUN (cd /lib/systemd/system/sysinit.target.wants/; for i in *; do [ $i == systemd-tmpfiles-setup.service ] || rm -f $i; done); \
    rm -f /lib/systemd/system/multi-user.target.wants/*;\
    rm -f /etc/systemd/system/*.wants/*;\
    rm -f /lib/systemd/system/local-fs.target.wants/*; \
    rm -f /lib/systemd/system/sockets.target.wants/*udev*; \
    rm -f /lib/systemd/system/sockets.target.wants/*initctl*; \
    rm -f /lib/systemd/system/basic.target.wants/*;\
    rm -f /lib/systemd/system/anaconda.target.wants/*;

RUN systemctl set-default multi-user.target

RUN systemctl enable rsyslog sshd systemd-user-sessions && \
    systemctl enable systemd-user-sessions.service && \
    ln -sf /usr/lib/systemd/system/systemd-user-sessions.service /etc/systemd/system/multi-user.target.wants/

RUN mkdir /var/run/sshd && \
    ssh-keygen -A && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && \
    sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

RUN useradd -m -s /bin/bash labadmin && \
    usermod -aG wheel labadmin && \
    echo "labadmin ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/labadmin && \
    chmod 440 /etc/sudoers.d/labadmin

RUN mkdir -p /home/labadmin/.ssh && \
    chmod 700 /home/labadmin/.ssh && \
    chown -R labadmin:labadmin /home/labadmin/.ssh

RUN mkdir -p /opt/purple-team/scripts /opt/purple-team/installers /etc/rsyslog.d

COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

# Copy container-specific scripts
COPY install-wazuh.sh /opt/purple-team/scripts/
RUN chmod +x /opt/purple-team/scripts/install-wazuh.sh

COPY install-falco.sh /opt/purple-team/scripts/
RUN chmod +x /opt/purple-team/scripts/install-falco.sh

COPY install-all.sh /opt/purple-team/scripts/
RUN chmod +x /opt/purple-team/scripts/install-all.sh


COPY ossec.conf.template /opt/purple-team/scripts/

RUN mkdir -p /etc/falco/config.d
COPY falco_custom.yaml /etc/falco/config.d/

COPY lab-install.service /etc/systemd/system/
RUN systemctl enable lab-install.service

# Expose only SSH and syslog
EXPOSE 22 514

VOLUME ["/var/log", "/home"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

CMD ["/usr/sbin/init"]