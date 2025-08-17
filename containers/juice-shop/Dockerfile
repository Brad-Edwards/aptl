# Base victim container using Rocky Linux 9 (RHEL-compatible)
FROM rockylinux:9

# Install packages and OWASP Juice Shop dependencies
RUN dnf install -y epel-release && \
    dnf update -y && \
    dnf install -y \
    rsyslog \
    openssh-server \
    sudo \
    systemd \
    systemd-sysv \
    iproute \
    hostname \
    nodejs \
    npm \
    git \
    && dnf clean all

# Configure systemd for container use
RUN (cd /lib/systemd/system/sysinit.target.wants/; for i in *; do [ $i == systemd-tmpfiles-setup.service ] || rm -f $i; done); \
    rm -f /lib/systemd/system/multi-user.target.wants/*;\
    rm -f /etc/systemd/system/*.wants/*;\
    rm -f /lib/systemd/system/local-fs.target.wants/*; \
    rm -f /lib/systemd/system/sockets.target.wants/*udev*; \
    rm -f /lib/systemd/system/sockets.target.wants/*initctl*; \
    rm -f /lib/systemd/system/basic.target.wants/*;\
    rm -f /lib/systemd/system/anaconda.target.wants/*;

# Set systemd default target to multi-user (not graphical)
RUN systemctl set-default multi-user.target

# Enable essential services including user sessions (removes /run/nologin)
RUN systemctl enable rsyslog sshd systemd-user-sessions && \
    systemctl enable systemd-user-sessions.service && \
    ln -sf /usr/lib/systemd/system/systemd-user-sessions.service /etc/systemd/system/multi-user.target.wants/

# Configure SSH (secure by default)
RUN mkdir /var/run/sshd && \
    ssh-keygen -A && \
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && \
    sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# Create lab maintainer user with passwordless sudo
RUN useradd -m -s /bin/bash labadmin && \
    usermod -aG wheel labadmin && \
    echo "labadmin ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/labadmin && \
    chmod 440 /etc/sudoers.d/labadmin

# Create .ssh directory for lab maintainer
RUN mkdir -p /home/labadmin/.ssh && \
    chmod 700 /home/labadmin/.ssh && \
    chown -R labadmin:labadmin /home/labadmin/.ssh

# Create directories for scripts and configs
RUN mkdir -p /opt/purple-team/scripts /etc/rsyslog.d

# Copy entrypoint script
COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

# Install OWASP Juice Shop
RUN git clone https://github.com/juice-shop/juice-shop.git /opt/juice-shop && \
    cd /opt/juice-shop && \
    npm install --only=prod && \
    chown -R labadmin:labadmin /opt/juice-shop

# Create systemd service for Juice Shop
RUN cat <<'EOF' > /etc/systemd/system/juice-shop.service
[Unit]
Description=OWASP Juice Shop
After=network.target

[Service]
Type=simple
User=labadmin
WorkingDirectory=/opt/juice-shop
ExecStart=/usr/bin/npm start
Restart=always
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

# Enable Juice Shop service
RUN ln -s /etc/systemd/system/juice-shop.service /etc/systemd/system/multi-user.target.wants/juice-shop.service

# Expose SSH, syslog, and Juice Shop web port
EXPOSE 22 514 3000

# Volume for persistent data
VOLUME ["/var/log", "/home"]

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Use systemd as init
CMD ["/usr/sbin/init"]