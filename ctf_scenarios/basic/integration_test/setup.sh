#!/bin/bash

# Basic CTF Scenario Setup Script
# Sets up SUID privilege escalation and vulnerable web server on victim

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Parse SSH connection details from lab_connections.txt
LAB_CONNECTIONS="${LAB_CONNECTIONS:-$SCRIPT_DIR/../../../lab_connections.txt}"

if [ ! -f "$LAB_CONNECTIONS" ]; then
    echo -e "${RED}Error: lab_connections.txt not found at $LAB_CONNECTIONS${NC}"
    echo "Please ensure the lab is running and lab_connections.txt exists"
    exit 1
fi

# Extract SSH details for victim
SSH_KEY=$(grep -E "Victim:.*ssh" "$LAB_CONNECTIONS" | sed -n 's/.*-i \([^ ]*\).*/\1/p' | head -1)
SSH_USER=$(grep -E "Victim:.*ssh" "$LAB_CONNECTIONS" | sed -n 's/.*ssh -i [^ ]* \([^@]*\)@.*/\1/p' | head -1)
SSH_HOST=$(grep -E "Victim:.*ssh" "$LAB_CONNECTIONS" | sed -n 's/.*@\([^ ]*\).*/\1/p' | head -1)
SSH_PORT=$(grep -E "Victim:.*ssh" "$LAB_CONNECTIONS" | sed -n 's/.*-p \([0-9]*\).*/\1/p' | head -1)

# Expand tilde in SSH_KEY path
SSH_KEY="${SSH_KEY/#\~/$HOME}"

# Validate extracted values
if [ -z "$SSH_KEY" ] || [ -z "$SSH_USER" ] || [ -z "$SSH_HOST" ] || [ -z "$SSH_PORT" ]; then
    echo -e "${RED}Error: Failed to parse SSH connection details from lab_connections.txt${NC}"
    echo "Found: KEY=$SSH_KEY, USER=$SSH_USER, HOST=$SSH_HOST, PORT=$SSH_PORT"
    exit 1
fi

if [ ! -f "$SSH_KEY" ]; then
    echo -e "${RED}Error: SSH key not found at $SSH_KEY${NC}"
    exit 1
fi

echo -e "${GREEN}=== Basic CTF Scenario Setup ===${NC}"
echo -e "Target: $SSH_USER@$SSH_HOST:$SSH_PORT"
echo -e "SSH Key: $SSH_KEY"
echo ""

# SSH options for automation
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"

# 1. Compile SUID binary locally
echo -e "${YELLOW}[*] Compiling SUID binary locally...${NC}"

if [ ! -f "$SCRIPT_DIR/backup_util.c" ]; then
    cat > "$SCRIPT_DIR/backup_util.c" << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <file_to_backup>\n", argv[0]);
        return 1;
    }
    
    char command[256];
    snprintf(command, sizeof(command), "/bin/cp %s /tmp/backup_%d", argv[1], getuid());
    
    // Vulnerable: doesn't properly sanitize input
    system(command);
    
    printf("Backup created\n");
    return 0;
}
EOF
fi

gcc -o "$SCRIPT_DIR/backup_util" "$SCRIPT_DIR/backup_util.c" 2>/dev/null
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to compile SUID binary locally${NC}"
    exit 1
fi
echo -e "${GREEN}[+] SUID binary compiled${NC}"

# 2. Deploy to victim
echo -e "${YELLOW}[*] Deploying scenario to victim container...${NC}"

# Copy files to victim
echo "  - Copying SUID binary..."
scp $SSH_OPTS -P "$SSH_PORT" -i "$SSH_KEY" "$SCRIPT_DIR/backup_util" "$SSH_USER@$SSH_HOST:/tmp/"
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to copy backup_util to victim${NC}"
    exit 1
fi

echo "  - Copying web application..."
scp $SSH_OPTS -P "$SSH_PORT" -i "$SSH_KEY" "$SCRIPT_DIR/vulnerable_app.py" "$SSH_USER@$SSH_HOST:/tmp/"
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to copy vulnerable_app.py to victim${NC}"
    exit 1
fi

echo "  - Copying setup script..."
scp $SSH_OPTS -P "$SSH_PORT" -i "$SSH_KEY" "$SCRIPT_DIR/victim_setup.sh" "$SSH_USER@$SSH_HOST:/tmp/"
if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Failed to copy setup script to victim${NC}"
    exit 1
fi

# Execute setup on victim
echo -e "${YELLOW}[*] Executing setup on victim...${NC}"
ssh $SSH_OPTS -p "$SSH_PORT" -i "$SSH_KEY" "$SSH_USER@$SSH_HOST" "bash /tmp/victim_setup.sh"

if [ $? -ne 0 ]; then
    echo -e "${RED}Error: Setup execution failed on victim${NC}"
    exit 1
fi

# Verify setup
echo ""
echo -e "${YELLOW}[*] Verifying setup...${NC}"

# Check SUID binary
echo -n "  - SUID binary: "
ssh $SSH_OPTS -p "$SSH_PORT" -i "$SSH_KEY" "$SSH_USER@$SSH_HOST" "ls -la /usr/local/bin/backup 2>/dev/null | grep -q '^-rws' && echo 'OK' || echo 'FAILED'"

# Check web service
echo -n "  - Web service: "
ssh $SSH_OPTS -p "$SSH_PORT" -i "$SSH_KEY" "$SSH_USER@$SSH_HOST" "curl -s -o /dev/null -w '%{http_code}' http://localhost:8080 2>/dev/null | grep -q '200' && echo 'OK (port 8080)' || echo 'FAILED'"

# Check Wazuh agent
echo -n "  - Wazuh agent: "
ssh $SSH_OPTS -p "$SSH_PORT" -i "$SSH_KEY" "$SSH_USER@$SSH_HOST" "sudo systemctl is-active --quiet wazuh-agent && echo 'OK' || echo 'FAILED (manual start may be needed)'"

# Clean up local files (optional)
# rm -f "$SCRIPT_DIR/backup_util" "$SCRIPT_DIR/vulnerable_app.py" "$SCRIPT_DIR/victim_setup.sh"

echo ""
echo -e "${GREEN}=== Scenario Deployment Complete ===${NC}"
echo ""
echo "Attack Vectors:"
echo "  1. Initial Access: Web app at http://172.20.0.20:8080"
echo "     Example: curl 'http://172.20.0.20:8080/ping?ip=127.0.0.1;id'"
echo ""
echo "  2. Privilege Escalation: /usr/local/bin/backup (SUID)"
echo "     Example: backup ';/bin/bash -p'"
echo ""
echo -e "${YELLOW}Target ready for exploitation!${NC}"