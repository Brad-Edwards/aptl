#!/bin/bash
# Provision TechVault Solutions AD users, groups, and intentional weaknesses
# Based on personas from notes/techvault/infrastructure-plan.md

REALM="${SAMBA_REALM:-TECHVAULT.LOCAL}"

echo "=== Provisioning TechVault AD users and groups ==="

# Create Organizational Units
samba-tool ou create "OU=TechVault,DC=techvault,DC=local" --description="TechVault Solutions" 2>/dev/null || true
samba-tool ou create "OU=Executives,OU=TechVault,DC=techvault,DC=local" 2>/dev/null || true
samba-tool ou create "OU=Engineering,OU=TechVault,DC=techvault,DC=local" 2>/dev/null || true
samba-tool ou create "OU=Sales,OU=TechVault,DC=techvault,DC=local" 2>/dev/null || true
samba-tool ou create "OU=Operations,OU=TechVault,DC=techvault,DC=local" 2>/dev/null || true
samba-tool ou create "OU=ServiceAccounts,OU=TechVault,DC=techvault,DC=local" 2>/dev/null || true

# Create Groups
samba-tool group add "Domain Admins" --description="Domain Administrators" 2>/dev/null || true
samba-tool group add "IT-Admins" --description="IT Administrators" 2>/dev/null || true
samba-tool group add "Engineering" --description="Engineering Team" 2>/dev/null || true
samba-tool group add "Sales" --description="Sales Team" 2>/dev/null || true
samba-tool group add "HR" --description="Human Resources" 2>/dev/null || true
samba-tool group add "Finance" --description="Finance Team" 2>/dev/null || true
samba-tool group add "Executives" --description="Executive Team" 2>/dev/null || true
samba-tool group add "VPN-Users" --description="VPN Access Group" 2>/dev/null || true
samba-tool group add "Remote-Desktop" --description="Remote Desktop Users" 2>/dev/null || true

# --- Executive Team ---

# Sarah Mitchell - CEO (strong password)
samba-tool user create sarah.mitchell 'S3cur3C30!' \
    --given-name="Sarah" --surname="Mitchell" --job-title="CEO" \
    --department="Executive" --company="TechVault Solutions" \
    --mail="sarah.mitchell@techvault.local" 2>/dev/null || true
samba-tool group addmembers "Executives" sarah.mitchell 2>/dev/null || true

# James Rodriguez - CTO (strong password)
samba-tool user create james.rodriguez 'R0dr1gu3z#CTO' \
    --given-name="James" --surname="Rodriguez" --job-title="CTO" \
    --department="Executive" --company="TechVault Solutions" \
    --mail="james.rodriguez@techvault.local" 2>/dev/null || true
samba-tool group addmembers "Executives" james.rodriguez 2>/dev/null || true
samba-tool group addmembers "IT-Admins" james.rodriguez 2>/dev/null || true

# Lisa Chang - VP Sales
samba-tool user create lisa.chang 'SalesVP2024!' \
    --given-name="Lisa" --surname="Chang" --job-title="VP of Sales" \
    --department="Sales" --company="TechVault Solutions" \
    --mail="lisa.chang@techvault.local" 2>/dev/null || true
samba-tool group addmembers "Executives" lisa.chang 2>/dev/null || true
samba-tool group addmembers "Sales" lisa.chang 2>/dev/null || true

# --- Engineering Team ---

# Emily Chen - DevOps Lead (has Domain Admin - intentional over-privilege)
samba-tool user create emily.chen 'DevOps#2024' \
    --given-name="Emily" --surname="Chen" --job-title="DevOps Lead" \
    --department="Engineering" --company="TechVault Solutions" \
    --mail="emily.chen@techvault.local" 2>/dev/null || true
samba-tool group addmembers "Engineering" emily.chen 2>/dev/null || true
samba-tool group addmembers "IT-Admins" emily.chen 2>/dev/null || true
samba-tool group addmembers "Domain Admins" emily.chen 2>/dev/null || true

# Michael Thompson - Senior Developer (weak password - vulnerability)
samba-tool user create michael.thompson 'Summer2024' \
    --given-name="Michael" --surname="Thompson" --job-title="Senior Developer" \
    --department="Engineering" --company="TechVault Solutions" \
    --mail="michael.thompson@techvault.local" 2>/dev/null || true
samba-tool group addmembers "Engineering" michael.thompson 2>/dev/null || true

# David Kim - Security Engineer
samba-tool user create david.kim 'K1mS3c!Eng' \
    --given-name="David" --surname="Kim" --job-title="Security Engineer" \
    --department="Engineering" --company="TechVault Solutions" \
    --mail="david.kim@techvault.local" 2>/dev/null || true
samba-tool group addmembers "Engineering" david.kim 2>/dev/null || true
samba-tool group addmembers "IT-Admins" david.kim 2>/dev/null || true

# --- Sales & Operations ---

# Jessica Williams - Customer Success (very weak password - vulnerability)
samba-tool user create jessica.williams 'password123' \
    --given-name="Jessica" --surname="Williams" --job-title="Customer Success Manager" \
    --department="Operations" --company="TechVault Solutions" \
    --mail="jessica.williams@techvault.local" 2>/dev/null || true
samba-tool group addmembers "Sales" jessica.williams 2>/dev/null || true
samba-tool group addmembers "VPN-Users" jessica.williams 2>/dev/null || true

# Robert Martinez - Marketing Manager
samba-tool user create robert.martinez 'M@rketing2024' \
    --given-name="Robert" --surname="Martinez" --job-title="Marketing Manager" \
    --department="Sales" --company="TechVault Solutions" \
    --mail="robert.martinez@techvault.local" 2>/dev/null || true
samba-tool group addmembers "Sales" robert.martinez 2>/dev/null || true

# --- Service Accounts (intentional weaknesses for Kerberoasting) ---

# SQL Service Account - has SPN set (Kerberoastable)
samba-tool user create svc-sql 'SqlService2024!' \
    --given-name="SQL" --surname="Service" \
    --description="SQL Server Service Account" 2>/dev/null || true
samba-tool user setexpiry svc-sql --noexpiry 2>/dev/null || true
# Set SPN for Kerberoasting
samba-tool spn add MSSQLSvc/db.techvault.local:1433 svc-sql 2>/dev/null || true
samba-tool spn add MSSQLSvc/db.techvault.local svc-sql 2>/dev/null || true

# Web Service Account - has SPN set (Kerberoastable)
samba-tool user create svc-web 'WebApp2024' \
    --given-name="Web" --surname="Service" \
    --description="Web Application Service Account" 2>/dev/null || true
samba-tool user setexpiry svc-web --noexpiry 2>/dev/null || true
samba-tool spn add HTTP/webapp.techvault.local svc-web 2>/dev/null || true

# Backup Service Account - overly privileged (vulnerability)
samba-tool user create svc-backup 'Backup#2024' \
    --given-name="Backup" --surname="Service" \
    --description="Backup Service - NEEDS PRIVILEGE REVIEW" 2>/dev/null || true
samba-tool user setexpiry svc-backup --noexpiry 2>/dev/null || true
samba-tool group addmembers "Domain Admins" svc-backup 2>/dev/null || true

# --- Contractor account (abandoned, no MFA - vulnerability) ---
samba-tool user create contractor.temp 'Welcome1!' \
    --given-name="Temp" --surname="Contractor" --job-title="External Contractor" \
    --description="Temporary contractor - TODO: disable after project ends" 2>/dev/null || true
samba-tool group addmembers "VPN-Users" contractor.temp 2>/dev/null || true
samba-tool group addmembers "Remote-Desktop" contractor.temp 2>/dev/null || true
samba-tool group addmembers "Engineering" contractor.temp 2>/dev/null || true

# --- Disabled account with password that hasn't been rotated ---
samba-tool user create former.employee 'OldPassword1' \
    --given-name="Former" --surname="Employee" --job-title="Former Employee" \
    --description="Account should have been deleted in Q2" 2>/dev/null || true
# Note: account is enabled (should be disabled - vulnerability)

echo "=== TechVault AD users provisioned ==="
echo ""
echo "Intentional weaknesses:"
echo "  - jessica.williams: password123 (weak password)"
echo "  - michael.thompson: Summer2024 (seasonal password)"
echo "  - contractor.temp: Welcome1! (default contractor password, over-privileged)"
echo "  - former.employee: OldPassword1 (stale account, should be disabled)"
echo "  - svc-sql: Kerberoastable (SPN set on MSSQLSvc)"
echo "  - svc-web: Kerberoastable (SPN set on HTTP)"
echo "  - svc-backup: Domain Admin service account (over-privileged)"
echo "  - emily.chen: DevOps with Domain Admin (over-privileged)"
