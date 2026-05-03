# APTL Kali Red Team Container
FROM kalilinux/kali-last-release:latest

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Set timezone to avoid tzdata prompts
ENV TZ=UTC

RUN apt-get update && \
    apt-get install -y kali-archive-keyring && \
    apt-get update && \
    apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" && \
    apt-get install -y \
        kali-linux-core \
        kali-tools-top10 \
        rsyslog \
        openssh-server \
        iputils-ping && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# AD/Enterprise attack tools for TechVault scenario
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3-impacket impacket-scripts \
        ldap-utils \
        smbclient \
        smbmap \
        enum4linux \
        bloodhound.py && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash -G sudo kali && \
    echo 'kali:kali' | chpasswd && \
    echo 'kali ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && \
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#AuthorizedKeysFile/AuthorizedKeysFile/' /etc/ssh/sshd_config && \
    echo 'AllowUsers kali' >> /etc/ssh/sshd_config

RUN mkdir -p /home/kali/operations && \
    chown -R kali:kali /home/kali/operations && \
    mkdir -p /home/kali/.msf4 && \
    mkdir -p /home/kali/.john && \
    mkdir -p /home/kali/.hashcat && \
    chown -R kali:kali /home/kali/.msf4 /home/kali/.john /home/kali/.hashcat && \
    # Fix dumpcap permissions for packet capture
    chmod 755 /usr/bin/dumpcap && \
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap

RUN apt-get update && \
    apt-get install -y ca-certificates curl gnupg && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" > /etc/apt/sources.list.d/nodesource.list && \
    apt-get update && \
    apt-get install -y nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN sudo -u kali ssh-keygen -t rsa -b 2048 -f /home/kali/.ssh/id_rsa -N "" && \
    chown -R kali:kali /home/kali/.ssh/

# Pre-install Wazuh agent at build time so the container does not need internet
# at runtime (SAF-002: internal: true on attack networks).
# Runtime install script detects pre-installed package and skips download.
RUN apt-get update && \
    apt-get install -y curl gnupg lsb-release && \
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
      gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && \
    chmod 644 /usr/share/keyrings/wazuh.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list && \
    apt-get update && \
    apt-get install -y wazuh-agent=4.12.0-1 && \
    apt-get clean && rm -rf /var/lib/apt/lists/* && \
    killall wazuh-execd wazuh-agentd wazuh-syscheckd wazuh-logcollector wazuh-modulesd 2>/dev/null || true && \
    rm -f /var/ossec/var/run/*.pid

# Copy installation scripts to proper location
RUN mkdir -p /opt/kali-redteam/scripts
COPY install-scripts/ /opt/kali-redteam/scripts/
RUN chmod +x /opt/kali-redteam/scripts/*.sh

# Copy user scripts
COPY --chown=kali:kali scripts/ /home/kali/

RUN chmod +x /home/kali/*.sh

RUN mkdir -p /etc/rsyslog.d

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

USER kali
WORKDIR /home/kali

RUN echo 'export PATH="$PATH:/usr/local/bin"' >> ~/.bashrc

USER root

# Entrypoint handles sshd, Wazuh install, and keepalive directly
ENTRYPOINT ["/entrypoint.sh"]
