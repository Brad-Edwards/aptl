FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

RUN apk add --no-cache python3=3.12.13-r0 \
    && adduser -D -H -u 65532 proxy

COPY containers/appliance-egress-proxy/proxy.py /usr/local/bin/aptl-egress-proxy

USER 65532:65532
ENTRYPOINT ["python3", "/usr/local/bin/aptl-egress-proxy"]
