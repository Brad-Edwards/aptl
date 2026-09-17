FROM debian:12@sha256:9344f8b8992482f80cba753f323adeaf17690076c095ccff6cc9536be98185dc

COPY containers/_wazuh-agent/install.sh /tmp/install-wazuh.sh
RUN /tmp/install-wazuh.sh && rm /tmp/install-wazuh.sh
