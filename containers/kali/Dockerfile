# APTL Kali Red Team Container
FROM kalilinux/kali-rolling:latest

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Set timezone to avoid tzdata prompts
ENV TZ=UTC

# Fix Kali GPG keys and update packages
RUN apt-get update --allow-insecure-repositories && \
    apt-get install -y --allow-unauthenticated kali-archive-keyring && \
    apt-get update && \
    apt-get upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" && \
    apt-get install -y \
        git \
        python3-pip \
        golang \
        kali-tools-top10 \
        bind9-dnsutils \
        sshpass \
        rsyslog \
        openssh-server \
        curl \
        wget \
        vim \
        nano \
        sudo \
        && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create kali user with sudo privileges
RUN useradd -m -s /bin/bash -G sudo kali && \
    echo 'kali:kali' | chpasswd && \
    echo 'kali ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo 'AllowUsers kali' >> /etc/ssh/sshd_config

# Set up working directory
RUN mkdir -p /home/kali/operations && \
    chown -R kali:kali /home/kali/operations

# Install Node.js (useful for various tools)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs

# Generate SSH keys for kali user
RUN sudo -u kali ssh-keygen -t rsa -b 2048 -f /home/kali/.ssh/id_rsa -N "" && \
    chown -R kali:kali /home/kali/.ssh/

# Copy red team logging and simulation scripts
COPY --chown=kali:kali scripts/ /home/kali/

# Make scripts executable
RUN chmod +x /home/kali/*.sh

# Configure rsyslog (will be configured at runtime based on SIEM type)
RUN mkdir -p /etc/rsyslog.d

# Copy and configure entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose SSH port
EXPOSE 22

# Switch to kali user for final setup
USER kali
WORKDIR /home/kali

# Set up environment  
RUN echo 'export PATH="$PATH:/usr/local/bin"' >> ~/.bashrc

# Back to root for entrypoint
USER root

# Entrypoint will handle service startup and configuration
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D"]