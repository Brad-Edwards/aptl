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
        openssh-server \
        iputils-ping \
        # OBS-003 behavioural capture (ADR-033):
        #   auditd        — syscall / process / file events
        #   acct          — process accounting (accton + pacct)
        #   tcpdump       — per-session pcap
        #   bsdmainutils  — provides script(1) for full PTY recording
        #   libcap2-bin   — provides capsh (drops CAP_AUDIT_CONTROL
        #                   before spawning sshd so the kali user
        #                   can't disable audit via sudo)
        #   acl           — provides setfacl (entrypoint grants kali
        #                   user write access to the captures volume
        #                   root without widening for everyone)
        auditd \
        acct \
        tcpdump \
        bsdmainutils \
        libcap2-bin \
        acl && \
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

# sshd configuration. AcceptEnv APTL_* + ForceCommand wire the OBS-003
# per-session capture: every SSH session arrives with APTL_SESSION_ID
# (and APTL_RUN_ID / APTL_TRACE_ID when a scenario is active), and the
# kali user's effective login command is the per-session wrapper that
# starts script(1) + tcpdump for that session.
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && \
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#AuthorizedKeysFile/AuthorizedKeysFile/' /etc/ssh/sshd_config && \
    echo 'AllowUsers kali' >> /etc/ssh/sshd_config && \
    echo '' >> /etc/ssh/sshd_config && \
    echo '# OBS-003 / ADR-033: per-session capture wiring' >> /etc/ssh/sshd_config && \
    echo 'AcceptEnv APTL_SESSION_ID APTL_RUN_ID APTL_TRACE_ID' >> /etc/ssh/sshd_config && \
    echo 'Match User kali' >> /etc/ssh/sshd_config && \
    echo '    ForceCommand /usr/local/bin/aptl-wrap-shell.sh' >> /etc/ssh/sshd_config

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

# Copy user scripts.
# The prior `install-scripts/` directory (Wazuh-agent + ossec.conf
# template + install-all.sh) was removed under ADR-033 — no boot-time
# Wazuh install survives on this container.
COPY --chown=kali:kali scripts/ /home/kali/

# OBS-003: shell wrapper (run-by-root via sshd ForceCommand) and audit
# rules live outside the kali user's home so an agent shell escape
# can't trivially overwrite them.
# tcpdump gets explicit capabilities so the kali-user-invoked wrapper
# can capture packets without sudo (codex finding-6 — `tcpdump -i any`
# from a non-root user otherwise fails silently). Mirrors the existing
# pattern for dumpcap above.
RUN install -m 0755 /home/kali/aptl-wrap-shell.sh /usr/local/bin/aptl-wrap-shell.sh && \
    rm -f /home/kali/aptl-wrap-shell.sh && \
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/tcpdump
COPY audit/aptl.rules /etc/audit/rules.d/aptl.rules
RUN chmod 0640 /etc/audit/rules.d/aptl.rules && \
    chown root:root /etc/audit/rules.d/aptl.rules

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ADR-033 §2 / issue #293: container healthcheck script. Installed to
# /usr/local/bin (root-owned, outside the kali user's home — the same
# hardening pattern as aptl-wrap-shell.sh above). docker-compose.yml
# wires it as the kali service healthcheck; it verifies sshd, the
# OBS-003 ForceCommand wrapper, and the entrypoint's boot-readiness
# marker rather than merely that port 22 is open.
COPY healthcheck.sh /usr/local/bin/aptl-healthcheck.sh
RUN chmod 0755 /usr/local/bin/aptl-healthcheck.sh && \
    chown root:root /usr/local/bin/aptl-healthcheck.sh

EXPOSE 22

USER kali
WORKDIR /home/kali

RUN echo 'export PATH="$PATH:/usr/local/bin"' >> ~/.bashrc

USER root

# Entrypoint starts sshd (via capsh dropping CAP_AUDIT_CONTROL),
# auditd (rules loaded at boot before the cap is dropped), process
# accounting, and a keepalive sleep. The kali service sets
# `init: true` in docker-compose.yml so PID 1 is Docker's bundled
# init (docker-init / tini), which reaps orphaned children — the
# keepalive sleep is its child, not PID 1 (ADR-033 §2 / issue #293).
# Wazuh agent + rsyslog-to-SIEM
# forwarding from prior versions were removed under ADR-033
# (non-contamination): red activity must not bleed into the blue
# SIEM. The experimental record lives in the docker named volume
# `kali_captures:/var/log/aptl/captures/<run_id>/<session_id>/` and
# is harvested out by the MCP server via `docker cp` into
# `.aptl/runs/<run_id>/kali-side/<session_id>/` on the host.
ENTRYPOINT ["/entrypoint.sh"]
