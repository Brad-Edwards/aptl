FROM python:3.12-alpine

COPY proxy.py /usr/local/bin/aptl-ssh-proxy
RUN chmod 0555 /usr/local/bin/aptl-ssh-proxy

USER 65532:65532
ENTRYPOINT ["python3", "/usr/local/bin/aptl-ssh-proxy"]
