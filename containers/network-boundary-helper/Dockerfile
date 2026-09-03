FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

RUN apk add --no-cache nftables=1.1.3-r0 python3=3.12.13-r0 \
    && adduser -D -H -u 65532 boundary

COPY containers/network-boundary-helper/helper.py /usr/local/bin/aptl-boundary-helper

ENTRYPOINT ["python3", "/usr/local/bin/aptl-boundary-helper"]
