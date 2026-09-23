FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

RUN apk add --no-cache python3=3.14.7-r1 \
    && adduser -D -H -u 65532 proxy

COPY containers/appliance-egress-proxy/proxy.py /usr/local/bin/aptl-egress-proxy

USER 65532:65532
ENTRYPOINT ["python3", "/usr/local/bin/aptl-egress-proxy"]
