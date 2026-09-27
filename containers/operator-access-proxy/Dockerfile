# APTL backend apparatus: a byte relay publishing one declared operator
# interactive-access endpoint on the host loopback. See proxy.py.
FROM python:3.14-alpine@sha256:9e9fde4d32eedce0b661d9ab91e826b62dddf28e928c230ec55f1866cac66b01

COPY containers/operator-access-proxy/proxy.py /usr/local/bin/aptl-operator-access-proxy
RUN chmod 0555 /usr/local/bin/aptl-operator-access-proxy

USER 65532:65532
ENTRYPOINT ["python3", "/usr/local/bin/aptl-operator-access-proxy"]
