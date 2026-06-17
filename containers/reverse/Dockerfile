# Reverse engineering container built on shared Ubuntu 22.04 base
# Build context must be ./containers/ so both base/ and reverse/ are accessible
FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# ---- Shared base layer (from containers/base/Dockerfile.ubuntu) ----

RUN apt-get update && \
    apt-get install -y \
    rsyslog \
    openssh-server \
    sudo \
    systemd \
    systemd-sysv \
    iproute2 \
    hostname \
    procps \
    openssh-client \
    net-tools \
    gnupg \
    curl \
    wget \
    ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN (cd /lib/systemd/system/sysinit.target.wants/; for i in *; do [ $i == systemd-tmpfiles-setup.service ] || rm -f $i; done); \
    rm -f /lib/systemd/system/multi-user.target.wants/*;\
    rm -f /etc/systemd/system/*.wants/*;\
    rm -f /lib/systemd/system/local-fs.target.wants/*; \
    rm -f /lib/systemd/system/sockets.target.wants/*udev*; \
    rm -f /lib/systemd/system/sockets.target.wants/*initctl*; \
    rm -f /lib/systemd/system/basic.target.wants/*;\
    rm -f /lib/systemd/system/anaconda.target.wants/*;

RUN systemctl set-default multi-user.target

RUN systemctl enable rsyslog ssh systemd-user-sessions && \
    systemctl enable systemd-user-sessions.service && \
    ln -sf /usr/lib/systemd/system/systemd-user-sessions.service /etc/systemd/system/multi-user.target.wants/

RUN mkdir /var/run/sshd && \
    ssh-keygen -A && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && \
    sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

RUN useradd -m -s /bin/bash labadmin && \
    usermod -aG sudo labadmin && \
    echo "labadmin ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/labadmin && \
    chmod 440 /etc/sudoers.d/labadmin

RUN mkdir -p /home/labadmin/.ssh && \
    chmod 700 /home/labadmin/.ssh && \
    chown -R labadmin:labadmin /home/labadmin/.ssh

RUN mkdir -p /opt/purple-team/scripts /etc/rsyslog.d

# Copy shared base scripts and configs. Modes are pinned explicitly (chmod 755
# for scripts, COPY --chmod=644 for configs) instead of relying on `chmod +x`
# or the build context's file modes: COPY preserves source mode bits, so a
# builder umask of 0002 would otherwise bake group-writable files and churn the
# ACES inventory's captured modes between environments (SEC #417).
COPY base/scripts/entrypoint-base.sh /opt/purple-team/scripts/
RUN chmod 755 /opt/purple-team/scripts/entrypoint-base.sh

COPY --chmod=644 base/scripts/ossec.conf.template /opt/purple-team/scripts/

RUN mkdir -p /etc/falco/config.d
COPY --chmod=644 base/falco_custom.yaml /etc/falco/config.d/

# ---- Reverse-specific layer ----

COPY reverse/entrypoint.sh /usr/local/bin/
RUN chmod 755 /usr/local/bin/entrypoint.sh

COPY reverse/install-wazuh.sh /opt/purple-team/scripts/
RUN chmod 755 /opt/purple-team/scripts/install-wazuh.sh

COPY reverse/install-falco.sh /opt/purple-team/scripts/
RUN chmod 755 /opt/purple-team/scripts/install-falco.sh

COPY reverse/install-all.sh /opt/purple-team/scripts/
RUN chmod 755 /opt/purple-team/scripts/install-all.sh

COPY reverse/setup-reverse-tools.sh /opt/purple-team/scripts/
RUN chmod 755 /opt/purple-team/scripts/setup-reverse-tools.sh

COPY --chmod=644 reverse/reverse-tools-install.service /etc/systemd/system/
RUN systemctl enable reverse-tools-install.service

EXPOSE 22 514

VOLUME ["/var/log", "/home"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

CMD ["/usr/sbin/init"]
