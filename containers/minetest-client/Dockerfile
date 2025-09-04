# Minetest client container using Ubuntu 22.04 LTS
# Based on victim container template with minetest client capabilities
FROM ubuntu:22.04

# Build arguments for agent installation
ARG INSTALL_WAZUH=true
ARG INSTALL_FALCO=true

# Set as environment variables for runtime
ENV INSTALL_WAZUH=${INSTALL_WAZUH}
ENV INSTALL_FALCO=${INSTALL_FALCO}

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

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

# Configure SSH (keep password auth disabled for SSH)
RUN mkdir /var/run/sshd && \
    ssh-keygen -A && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && \
    sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# Create labadmin user (SSH key auth only)
RUN useradd -m -s /bin/bash labadmin && \
    usermod -aG sudo labadmin && \
    echo "labadmin ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/labadmin && \
    chmod 440 /etc/sudoers.d/labadmin

RUN mkdir -p /home/labadmin/.ssh && \
    chmod 700 /home/labadmin/.ssh && \
    chown -R labadmin:labadmin /home/labadmin/.ssh

# Create rdpuser for GUI access (password auth)
RUN useradd -m -s /bin/bash rdpuser && \
    usermod -aG sudo rdpuser && \
    echo "rdpuser:rdppass123" | chpasswd && \
    echo "rdpuser ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/rdpuser && \
    chmod 440 /etc/sudoers.d/rdpuser

RUN mkdir -p /opt/purple-team/scripts /etc/rsyslog.d

COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

COPY install-wazuh.sh /opt/purple-team/scripts/
RUN chmod +x /opt/purple-team/scripts/install-wazuh.sh

COPY install-falco.sh /opt/purple-team/scripts/
RUN chmod +x /opt/purple-team/scripts/install-falco.sh

COPY install-all.sh /opt/purple-team/scripts/
RUN chmod +x /opt/purple-team/scripts/install-all.sh

COPY setup-gameclient.sh /opt/purple-team/scripts/
RUN chmod +x /opt/purple-team/scripts/setup-gameclient.sh

COPY ossec.conf.template /opt/purple-team/scripts/

RUN mkdir -p /etc/falco/config.d
COPY falco_custom.yaml /etc/falco/config.d/

COPY minetest-client-install.service /etc/systemd/system/
RUN systemctl enable minetest-client-install.service

# Expose SSH, syslog, and VNC port
EXPOSE 22 514 5901

VOLUME ["/var/log", "/home"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

CMD ["/usr/sbin/init"]