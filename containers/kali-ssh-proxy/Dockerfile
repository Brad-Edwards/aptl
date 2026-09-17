FROM python:3.14-alpine@sha256:c6ead215bfd31f1e433d968853b7a769989117115b728874824e6c0a27cb96fc

COPY containers/kali-ssh-proxy/proxy.py /usr/local/bin/aptl-ssh-proxy
RUN chmod 0555 /usr/local/bin/aptl-ssh-proxy

USER 65532:65532
ENTRYPOINT ["python3", "/usr/local/bin/aptl-ssh-proxy"]
