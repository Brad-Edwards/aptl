# APTL backend apparatus: a byte relay publishing one declared operator
# interactive-access endpoint on the host loopback. See proxy.py.
FROM python:3.14-alpine@sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72

# The relay is stdlib-only. Apply published Alpine fixes and remove the base
# image's pip, which this process never runs and whose vendored libraries would
# otherwise ship unpatched (issue #1193).
RUN apk upgrade --no-cache && python3 -m pip uninstall --yes pip
COPY containers/operator-access-proxy/proxy.py /usr/local/bin/aptl-operator-access-proxy
RUN chmod 0555 /usr/local/bin/aptl-operator-access-proxy

USER 65532:65532
ENTRYPOINT ["python3", "/usr/local/bin/aptl-operator-access-proxy"]
