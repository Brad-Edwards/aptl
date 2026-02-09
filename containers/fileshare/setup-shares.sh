#!/bin/bash
set -e

echo "=== Setting up TechVault file shares ==="

# Create share directories
mkdir -p /srv/shares/{public,engineering,finance,hr,it-backups,shared}
mkdir -p /var/log/samba

# Configure rsyslog forwarding
if [ -n "$SIEM_IP" ]; then
    cat > /etc/rsyslog.d/90-forward.conf <<EOF
*.* @${SIEM_IP}:514
EOF
fi

# Plant sensitive files that attackers should find

# Engineering share - source code with hardcoded creds
mkdir -p /srv/shares/engineering/deployments
cat > /srv/shares/engineering/deployments/deploy.sh <<'EOF'
#!/bin/bash
# Production deployment script - DO NOT SHARE
DB_HOST=db.techvault.local
DB_USER=techvault
DB_PASS=techvault_db_pass
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ssh deploy@$DB_HOST "pg_dump techvault > /tmp/backup.sql"
EOF

cat > /srv/shares/engineering/deployments/README.md <<'EOF'
# Deployment Guide
1. Run deploy.sh from the CI server
2. Credentials are in the script (TODO: move to vault)
3. SSH key is in /srv/shares/it-backups/deploy_key
EOF

# Finance share - sensitive financial data
mkdir -p /srv/shares/finance/reports
cat > /srv/shares/finance/reports/q3-revenue.csv <<'EOF'
Customer,MRR,ARR,Contract_End
Meridian Financial,4500,54000,2025-06-30
Apex Manufacturing,2200,26400,2025-03-15
Coastal Healthcare,6800,81600,2025-12-31
NorthStar Logistics,800,9600,2025-01-31
Summit Education,1500,18000,2025-09-30
Redwood Legal,5200,62400,2025-07-15
EOF

# HR share - employee PII
mkdir -p /srv/shares/hr/employees
cat > /srv/shares/hr/employees/directory.csv <<'EOF'
Name,Email,SSN_Last4,Salary,Start_Date
Sarah Mitchell,sarah.mitchell@techvault.local,4521,185000,2019-01-15
James Rodriguez,james.rodriguez@techvault.local,7832,175000,2019-01-15
Emily Chen,emily.chen@techvault.local,3214,145000,2020-03-01
Michael Thompson,michael.thompson@techvault.local,9876,130000,2021-06-15
David Kim,david.kim@techvault.local,5543,140000,2022-01-10
Jessica Williams,jessica.williams@techvault.local,1122,85000,2022-09-01
Robert Martinez,robert.martinez@techvault.local,6677,95000,2023-02-15
EOF

# IT-Backups - old SSH keys and database dumps
mkdir -p /srv/shares/it-backups/keys
cat > /srv/shares/it-backups/keys/README <<'EOF'
Old SSH keys from server migration. TODO: rotate and delete.
EOF
# Generate a dummy SSH key for the planted file
ssh-keygen -t rsa -b 2048 -f /srv/shares/it-backups/keys/deploy_key -N "" -q 2>/dev/null || true

cat > /srv/shares/it-backups/db_backup_20240115.sql <<'EOF'
-- PostgreSQL dump from production
-- Server: db.techvault.local
-- Database: techvault
-- Dumped by: svc-backup

CREATE TABLE users (
    id serial PRIMARY KEY,
    username varchar(100),
    email varchar(255),
    password_hash varchar(255)
);

INSERT INTO users VALUES (1, 'admin', 'admin@techvault.local', '0192023a7bbd73250516f069df18b500');
-- hash is MD5 of 'admin123'
EOF

# Public share - company docs
cat > /srv/shares/public/welcome.txt <<'EOF'
Welcome to TechVault Solutions file server.
For access to department shares, contact IT at david.kim@techvault.local.
EOF

# Shared drive - miscellaneous
cat > /srv/shares/shared/wifi-passwords.txt <<'EOF'
Office WiFi: TechVault-Corp / Vault2024Secure
Guest WiFi: TechVault-Guest / Welcome2024
Server Room: TechVault-Infra / Infra$ecure99
EOF

cat > /srv/shares/shared/meeting-notes-q3.txt <<'EOF'
Q3 Planning Meeting Notes
- James mentioned we need to rotate the admin password on the portal
- Emily will handle the AWS credential rotation next sprint
- The contractor account is still active - Jessica to follow up
- Database backup script has hardcoded creds - low priority fix
EOF

# Set permissions (intentionally loose on some shares)
chmod -R 777 /srv/shares/public
chmod -R 777 /srv/shares/shared
chmod -R 755 /srv/shares/engineering
chmod -R 750 /srv/shares/finance
chmod -R 750 /srv/shares/hr
chmod -R 700 /srv/shares/it-backups

# Create a samba user for guest access
echo -e "guest\nguest" | smbpasswd -a -s nobody 2>/dev/null || true

# Create service user for testing
useradd -M svc-fileshare 2>/dev/null || true
echo -e "FileShare2024!\nFileShare2024!" | smbpasswd -a -s svc-fileshare 2>/dev/null || true

echo "=== File shares configured ==="

# Start rsyslog in background
rsyslogd

# Start samba
exec smbd --foreground --no-process-group --log-stdout
