FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

# Apply every pending Alpine update first, as operator-access-proxy does. The
# pinned base predates them; currently they are libcrypto3, libssl3 and zlib,
# whose 1.3.2-r1 fixes CVE-2026-85091. Then add the pinned packages.
RUN apk upgrade --no-cache \
    && apk add --no-cache python3=3.14.8-r0 \
    && adduser -D -H -u 65532 proxy

COPY containers/appliance-egress-proxy/proxy.py /usr/local/bin/aptl-egress-proxy

USER 65532:65532
ENTRYPOINT ["python3", "/usr/local/bin/aptl-egress-proxy"]
