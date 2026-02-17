# Internal DNS server for techvault.local
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    bind9 \
    bind9-utils \
    dnsutils \
    rsyslog \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/named && chown bind:bind /var/log/named

COPY named.conf /etc/bind/named.conf
COPY zones/ /etc/bind/zones/

EXPOSE 53 53/udp

CMD ["named", "-g", "-c", "/etc/bind/named.conf", "-u", "bind"]
