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

# Generate CTF flags
python3 -c "
import os, hashlib
key = os.environ.get('APTL_FLAG_KEY', 'aptl-flag-key-2024')
for level, path, mode in [('user', '/app/user.txt', 0o644), ('root', '/root/root.txt', 0o600)]:
    nonce = os.urandom(16).hex()
    flag = f'APTL{{{level}_webapp_{nonce}}}'
    sig = hashlib.md5(f'{key}:webapp:{level}:{nonce}'.encode()).hexdigest()
    token = f'aptl:v1:webapp:{level}:{nonce}:{sig}'
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(f'===== APTL CTF Flag =====\nFlag:  {flag}\nToken: {token}\n==========================\n')
    os.chmod(path, mode)
print('CTF flags generated for webapp')
"

# Start gunicorn with access log to file AND stdout (tee)
exec gunicorn \
    --bind 0.0.0.0:8080 \
    --workers 2 \
    --access-logfile /var/log/gunicorn/access.log \
    --error-logfile - \
    app:app
