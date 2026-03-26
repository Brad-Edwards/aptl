# Workstation container built on shared Rocky Linux 9 base
# Build context must be ./containers/ so both base/ and workstation/ are accessible
FROM rockylinux:9 AS base

# ---- Shared base layer (from containers/base/Dockerfile.rocky) ----

ARG INSTALL_WAZUH=true
ARG INSTALL_FALCO=true
ARG INSTALL_XSIAM=false

ENV INSTALL_WAZUH=${INSTALL_WAZUH}
ENV INSTALL_FALCO=${INSTALL_FALCO}
ENV INSTALL_XSIAM=${INSTALL_XSIAM}

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
    git \
    postgresql \
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
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# Create labadmin account (standard lab admin)
RUN useradd -m -s /bin/bash labadmin && \
    usermod -aG wheel labadmin && \
    echo "labadmin ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/labadmin && \
    chmod 440 /etc/sudoers.d/labadmin

RUN mkdir -p /home/labadmin/.ssh && \
    chmod 700 /home/labadmin/.ssh && \
    chown -R labadmin:labadmin /home/labadmin/.ssh

# Create dev-user account (michael.thompson's workstation)
RUN useradd -m -s /bin/bash dev-user && \
    echo "dev-user:Summer2024" | chpasswd && \
    usermod -aG wheel dev-user && \
    echo "dev-user ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/dev-user && \
    chmod 440 /etc/sudoers.d/dev-user

RUN mkdir -p /opt/purple-team/scripts /etc/rsyslog.d

# Copy shared base scripts and configs
COPY base/scripts/entrypoint-base.sh /opt/purple-team/scripts/
RUN chmod +x /opt/purple-team/scripts/entrypoint-base.sh

COPY base/scripts/ossec.conf.template /opt/purple-team/scripts/

RUN mkdir -p /etc/falco/config.d
COPY base/falco_custom.yaml /etc/falco/config.d/

# Pre-install Wazuh agent and Falco at build time so containers on internal
# Docker networks (SAF-002: internal: true) do not need internet at runtime.
# Runtime install scripts detect pre-installed packages and skip downloads.
RUN rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH && \
    printf '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\npriority=1\n' \
    > /etc/yum.repos.d/wazuh.repo && \
    dnf install -y wazuh-agent-4.12.0 && \
    dnf clean all && \
    killall wazuh-execd wazuh-agentd wazuh-syscheckd wazuh-logcollector wazuh-modulesd 2>/dev/null || true && \
    rm -f /var/ossec/var/run/*.pid

RUN rpm --import https://falco.org/repo/falcosecurity-packages.asc && \
    printf '[falco]\nname=Falco repository\nbaseurl=https://download.falco.org/packages/rpm\ngpgcheck=1\ngpgkey=https://falco.org/repo/falcosecurity-packages.asc\nenabled=1\n' \
    > /etc/yum.repos.d/falco.repo && \
    dnf install -y falco && \
    dnf clean all

# ---- Workstation-specific layer ----

# Setup planted credential artifacts
COPY workstation/setup-workstation.sh /opt/purple-team/scripts/
RUN chmod +x /opt/purple-team/scripts/setup-workstation.sh
RUN /opt/purple-team/scripts/setup-workstation.sh

COPY workstation/entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

COPY workstation/install-wazuh.sh /opt/purple-team/scripts/
RUN chmod +x /opt/purple-team/scripts/install-wazuh.sh

COPY workstation/install-falco.sh /opt/purple-team/scripts/
RUN chmod +x /opt/purple-team/scripts/install-falco.sh

COPY workstation/install-all.sh /opt/purple-team/scripts/
RUN chmod +x /opt/purple-team/scripts/install-all.sh

COPY workstation/lab-install.service /etc/systemd/system/
RUN systemctl enable lab-install.service

EXPOSE 22

VOLUME ["/var/log", "/home"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

CMD ["/usr/sbin/init"]
