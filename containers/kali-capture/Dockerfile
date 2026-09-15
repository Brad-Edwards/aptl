# Scope-admitted Kali SSH/PTY capture broker.
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

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
