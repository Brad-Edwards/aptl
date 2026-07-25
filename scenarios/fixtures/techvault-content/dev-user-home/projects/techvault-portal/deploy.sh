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
