# APTL Kali Capture Sidecar (ADR-041 / issue #305)
#
# Owns the kali_captures volume read-write.  The Kali workload mounts
# the same volume read-only, so the kali user (including after sudo su -)
# cannot delete or modify capture evidence.
#
# The aptl.rules file is bind-mounted at runtime via docker-compose.yml
# (kali-capture service volumes:) so the canonical rule text is never
# duplicated between the kali and kali-capture images.
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        auditd \
        acct \
        tcpdump \
        libcap2-bin \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY containers/kali-capture/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY containers/kali-capture/writer.py /usr/local/bin/writer.py
RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/writer.py

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
