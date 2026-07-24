#!/bin/bash
# Production deployment script - DO NOT SHARE
DB_HOST=db.techvault.local
DB_USER=techvault
DB_PASS=techvault_db_pass
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ssh deploy@$DB_HOST "pg_dump techvault > /tmp/backup.sql"
