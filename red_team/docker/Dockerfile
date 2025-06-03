FROM kalilinux/kali-rolling

# Update and upgrade the system
RUN apt-get update && apt-get upgrade -y && apt-get autoremove -y

# Install essential packages
RUN apt-get install -y \
    curl \
    wget \
    git \
    python3 \
    python3-pip \
    vim \
    nano \
    tmux \
    netcat-traditional \
    iputils-ping \
    net-tools

# Install common CTF tools
RUN apt-get install -y \
    # Web exploitation
    burpsuite \
    sqlmap \
    dirb \
    nikto \
    # Network tools
    nmap \
    wireshark \
    tcpdump \
    # Password cracking
    hydra \
    john \
    hashcat \
    # Forensics
    binwalk \
    foremost \
    exiftool \
    # Reverse engineering
    gdb \
    radare2 \
    # Cryptography
    openssl \
    # Exploitation
    metasploit-framework \
    # Misc
    wordlists

# Create a working directory for CTF challenges
WORKDIR /ctf

# Create a directory for shared files
RUN mkdir -p /shared

# Clean up to reduce image size
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Keep the container running
CMD ["tail", "-f", "/dev/null"]
