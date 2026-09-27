FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

RUN apk add --no-cache iproute2=7.0.0-r0 nftables=1.1.6-r1 python3=3.14.7-r1 \
    && adduser -D -H -u 65532 boundary

COPY containers/network-boundary-helper/helper.py /usr/local/bin/aptl-boundary-helper
COPY containers/network-boundary-helper/probe.py /usr/local/bin/aptl-boundary-probe

ENTRYPOINT ["python3", "/usr/local/bin/aptl-boundary-helper"]
