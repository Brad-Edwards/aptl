# Scope-admitted Kali SSH/PTY capture broker.
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        openssh-client \
        openssh-server \
    && useradd --uid 1000 --create-home --shell /bin/sh kali \
    && passwd -d kali \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY containers/kali-capture/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY containers/kali-capture/broker.py /usr/local/bin/broker.py
COPY containers/kali-capture/sshd_config /etc/aptl/sshd_config
RUN chmod 0555 /usr/local/bin/entrypoint.sh /usr/local/bin/broker.py \
    && chmod 0444 /etc/aptl/sshd_config

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
