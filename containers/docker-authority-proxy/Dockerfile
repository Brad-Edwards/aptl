# APTL backend apparatus: the mediated Docker authority a declared
# orchestration workload reaches instead of the host's own socket. See proxy.py.
FROM python:3.14-alpine@sha256:c6ead215bfd31f1e433d968853b7a769989117115b728874824e6c0a27cb96fc

COPY containers/docker-authority-proxy/proxy.py /usr/local/bin/aptl-docker-authority-proxy
RUN chmod 0555 /usr/local/bin/aptl-docker-authority-proxy

# The proxy reaches the daemon socket through its group and needs nothing else.
# It never runs as root: a privileged proxy in front of a privileged API would
# move the boundary rather than establish one.
USER 65532:65532
ENTRYPOINT ["python3", "/usr/local/bin/aptl-docker-authority-proxy"]
