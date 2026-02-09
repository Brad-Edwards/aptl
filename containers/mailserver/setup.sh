#!/bin/bash
# Mail server post-start configuration
# Creates mailboxes for TechVault employees

# Wait for the mail server to be ready
sleep 10

# Create user mailboxes (docker-mailserver uses setup.sh script)
# These accounts allow receiving phishing test emails
setup email add sarah.mitchell@techvault.local TvMail2024!
setup email add james.rodriguez@techvault.local TvMail2024!
setup email add emily.chen@techvault.local TvMail2024!
setup email add michael.thompson@techvault.local TvMail2024!
setup email add david.kim@techvault.local TvMail2024!
setup email add jessica.williams@techvault.local TvMail2024!
setup email add robert.martinez@techvault.local TvMail2024!
setup email add info@techvault.local TvMail2024!
setup email add support@techvault.local TvMail2024!
setup email add security@techvault.local TvMail2024!

echo "Mail accounts provisioned for techvault.local"
