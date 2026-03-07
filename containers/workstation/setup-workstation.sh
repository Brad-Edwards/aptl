#!/bin/bash
# Plants credential artifacts WS-01 through WS-05 in /home/dev-user/
# Run during Docker build to bake artifacts into the image.
set -e

echo "=== Setting up workstation credential artifacts ==="

HOMEDIR="/home/dev-user"

# --- WS-01: .bash_history with leaked credentials ---
cat > "$HOMEDIR/.bash_history" << 'EOF'
ls -la
cd projects/techvault-portal
git pull origin main
cat .env
ssh labadmin@172.20.2.20
sshpass -p 'LabAdmin2024!' ssh labadmin@172.20.2.20
psql -h 172.20.2.11 -U techvault -d techvault -W
psql -h db.techvault.local -U techvault -d techvault -c "SELECT * FROM customers LIMIT 5"
curl -X POST http://172.20.2.25:8080/login -d "username=admin&password=admin123"
scp labadmin@172.20.2.20:/etc/passwd ./audit/
ssh contractor.temp@172.20.2.10 -p Welcome1!
cat ~/.pgpass
git push origin feature/customer-export
sudo systemctl restart techvault-portal
docker logs aptl-webapp --tail 50
EOF
chmod 600 "$HOMEDIR/.bash_history"

# --- WS-03: SSH keypair (passwordless, authorized on victim) ---
mkdir -p "$HOMEDIR/.ssh"
ssh-keygen -t rsa -b 2048 -f "$HOMEDIR/.ssh/id_rsa" -N "" -q
chmod 700 "$HOMEDIR/.ssh"
chmod 600 "$HOMEDIR/.ssh/id_rsa"
chmod 644 "$HOMEDIR/.ssh/id_rsa.pub"

# --- WS-03 cont: known_hosts ---
cat > "$HOMEDIR/.ssh/known_hosts" << 'EOF'
172.20.2.20 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7fake...
172.20.2.11 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8fake...
172.20.2.10 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC9fake...
app.techvault.local ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7fake...
db.techvault.local ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8fake...
dc.techvault.local ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC9fake...
EOF
chmod 644 "$HOMEDIR/.ssh/known_hosts"

# --- WS-05: .pgpass ---
cat > "$HOMEDIR/.pgpass" << 'EOF'
172.20.2.11:5432:techvault:techvault:techvault_db_pass
db.techvault.local:5432:techvault:techvault:techvault_db_pass
EOF
chmod 600 "$HOMEDIR/.pgpass"

# --- WS-02: .config/credentials.json ---
mkdir -p "$HOMEDIR/.config"
cat > "$HOMEDIR/.config/credentials.json" << 'EOF'
{
  "webapp": {
    "url": "http://172.20.2.25:8080",
    "username": "admin",
    "password": "admin123",
    "api_key": "tvault-api-key-2024-admin"
  },
  "database": {
    "host": "172.20.2.11",
    "port": 5432,
    "name": "techvault",
    "username": "techvault",
    "password": "techvault_db_pass"
  },
  "ad": {
    "domain": "TECHVAULT.LOCAL",
    "dc": "172.20.2.10",
    "admin_user": "Administrator",
    "admin_password": "Admin123!"
  }
}
EOF
chmod 600 "$HOMEDIR/.config/credentials.json"

# --- WS-04: projects/techvault-portal/.env ---
mkdir -p "$HOMEDIR/projects/techvault-portal"
cat > "$HOMEDIR/projects/techvault-portal/.env" << 'EOF'
# TechVault Portal Configuration
FLASK_ENV=production
DB_HOST=172.20.2.11
DB_PORT=5432
DB_NAME=techvault
DB_USER=techvault
DB_PASSWORD=techvault_db_pass
JWT_SECRET=techvault-jwt-weak
API_KEY=tvault-api-key-2024-admin
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
BACKUP_BUCKET=techvault-backups-prod
SECRET_KEY=techvault-secret-key-2024
EOF
chmod 600 "$HOMEDIR/projects/techvault-portal/.env"

# --- WS-04 cont: projects/techvault-portal/deploy.sh ---
cat > "$HOMEDIR/projects/techvault-portal/deploy.sh" << 'EOFSCRIPT'
#!/bin/bash
# TechVault Portal Deployment Script
# Last updated: 2024-01-10 by michael.thompson

set -e

DB_HOST="172.20.2.11"
DB_USER="techvault"
DB_PASS="techvault_db_pass"
DB_NAME="techvault"

AWS_KEY="AKIAIOSFODNN7EXAMPLE"
AWS_SECRET="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
S3_BUCKET="techvault-backups-prod"

echo "Deploying TechVault Portal..."

# Backup database before deploy
PGPASSWORD=$DB_PASS pg_dump -h $DB_HOST -U $DB_USER $DB_NAME > /tmp/pre-deploy-backup.sql

# Upload backup to S3
AWS_ACCESS_KEY_ID=$AWS_KEY AWS_SECRET_ACCESS_KEY=$AWS_SECRET \
  aws s3 cp /tmp/pre-deploy-backup.sql s3://$S3_BUCKET/backups/

# Deploy application
cd /opt/techvault-portal
git pull origin main
pip install -r requirements.txt
sudo systemctl restart techvault-portal

echo "Deploy complete!"
EOFSCRIPT
chmod 755 "$HOMEDIR/projects/techvault-portal/deploy.sh"

# --- Onboarding notes ---
mkdir -p "$HOMEDIR/Documents"
cat > "$HOMEDIR/Documents/onboarding-notes.txt" << 'EOF'
TechVault Engineering Onboarding Notes
=======================================
Author: Michael Thompson
Date: 2024-01-15

Welcome to the team! Here's what you need to get started:

1. AD Account Setup
   - Domain: TECHVAULT.LOCAL
   - Your account should already be provisioned by IT
   - Default password for new accounts: Welcome1!
   - Please change on first login (but honestly most people don't)

2. VPN Access
   - Use your AD credentials
   - Contractor accounts (like contractor.temp) have VPN + RDP access
   - Ask IT if you need additional access groups

3. Development Environment
   - Clone the portal repo: git clone git@github.com:techvault/portal.git
   - Copy .env.example to .env and fill in DB credentials
   - DB host: 172.20.2.11, user: techvault, ask me for password if needed
   - JWT secret for local dev: techvault-jwt-weak

4. SSH Access to Servers
   - app server (victim): 172.20.2.20, use labadmin account
   - Keep your SSH key in ~/.ssh/id_rsa (no passphrase for convenience)
   - The deploy key on the fileshare (/IT-Backups/keys/) also works

5. Important
   - DO NOT commit credentials to git (I know the .env has some... working on it)
   - The deploy.sh script has hardcoded creds -- legacy issue, will fix "soon"
   - Password rotation is overdue -- Jessica mentioned it in the last meeting
EOF
chmod 644 "$HOMEDIR/Documents/onboarding-notes.txt"

# Set ownership
chown -R dev-user:dev-user "$HOMEDIR"

echo "=== Workstation credential artifacts planted ==="
