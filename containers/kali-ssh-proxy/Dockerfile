FROM python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df

COPY proxy.py /usr/local/bin/aptl-ssh-proxy
RUN chmod 0555 /usr/local/bin/aptl-ssh-proxy

USER 65532:65532
ENTRYPOINT ["python3", "/usr/local/bin/aptl-ssh-proxy"]
