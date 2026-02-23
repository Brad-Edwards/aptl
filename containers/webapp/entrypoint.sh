#!/bin/bash
set -e

# Configure rsyslog forwarding to Wazuh manager
SIEM_IP="${SIEM_IP:-172.20.2.30}"
cat > /etc/rsyslog.d/90-forward.conf <<EOF
*.* @${SIEM_IP}:514
EOF

# Monitor gunicorn access log and forward via syslog
cat > /etc/rsyslog.d/80-gunicorn.conf <<EOF
module(load="imfile")
input(type="imfile"
      File="/var/log/gunicorn/access.log"
      Tag="gunicorn"
      Severity="info"
      Facility="local6")
EOF

# Start rsyslog
rsyslogd

# Start gunicorn with access log to file AND stdout (tee)
exec gunicorn \
    --bind 0.0.0.0:8080 \
    --workers 2 \
    --access-logfile /var/log/gunicorn/access.log \
    --error-logfile - \
    app:app
