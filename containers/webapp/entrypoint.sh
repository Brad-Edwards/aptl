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

# Hand off to supervisord — it owns gunicorn, rsyslog, and the in-process
# Wazuh agent (issue #248). Previously this script started rsyslog in the
# background and exec'd gunicorn directly.
exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
