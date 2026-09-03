FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk add --no-cache python3=3.12.13-r0 \
    && adduser -D -H -u 65532 proxy

COPY containers/appliance-egress-proxy/proxy.py /usr/local/bin/aptl-egress-proxy

USER 65532:65532
ENTRYPOINT ["python3", "/usr/local/bin/aptl-egress-proxy"]
