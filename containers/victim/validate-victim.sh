#!/bin/bash

# Victim Container Validation Script
# Run from deployment system or Kali container to verify victim is operational

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
VICTIM_IP=""
SSH_KEY=""
SSH_PORT="22"
SIEM_IP=""
SIEM_TYPE="qradar"
VERBOSE=false

# Parse arguments
usage() {
    echo "Usage: $0 -h <victim-ip> -k <ssh-key-path> [-p <ssh-port>] [-s <siem-ip>] [-t <siem-type>] [-v]"
    echo "  -h: Victim host IP address"
    echo "  -k: Path to labadmin SSH private key"
    echo "  -p: SSH port (default: 22)"
    echo "  -s: SIEM IP address (optional, for log forwarding test)"
    echo "  -t: SIEM type (qradar/splunk, default: qradar)"
    echo "  -v: Verbose output"
    exit 1
}

while getopts "h:k:p:s:t:v" opt; do
    case $opt in
        h) VICTIM_IP="$OPTARG" ;;
        k) SSH_KEY="$OPTARG" ;;
        p) SSH_PORT="$OPTARG" ;;
        s) SIEM_IP="$OPTARG" ;;
        t) SIEM_TYPE="$OPTARG" ;;
        v) VERBOSE=true ;;
        *) usage ;;
    esac
done

# Validate required arguments
if [ -z "$VICTIM_IP" ] || [ -z "$SSH_KEY" ]; then
    echo -e "${RED}Error: Victim IP and SSH key are required${NC}"
    usage
fi

if [ ! -f "$SSH_KEY" ]; then
    echo -e "${RED}Error: SSH key file not found: $SSH_KEY${NC}"
    exit 1
fi

# SSH command alias
SSH_CMD="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p $SSH_PORT -i $SSH_KEY labadmin@$VICTIM_IP"

echo "=== APTL Victim Container Validation ==="
echo "Target: $VICTIM_IP"
echo ""

# Test 1: SSH Connectivity
echo -n "1. Testing SSH connectivity... "
if $SSH_CMD "echo 'SSH OK' >/dev/null 2>&1"; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
    echo "   Cannot establish SSH connection to labadmin@$VICTIM_IP"
    exit 1
fi

# Test 2: Verify labadmin sudo access
echo -n "2. Verifying labadmin sudo access... "
if $SSH_CMD "sudo whoami" 2>/dev/null | grep -q "root"; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
    echo "   labadmin does not have passwordless sudo"
    exit 1
fi

# Test 3: Check system info
echo -n "3. Gathering system information... "
HOSTNAME=$($SSH_CMD "hostname" 2>/dev/null)
OS_VERSION=$($SSH_CMD "cat /etc/redhat-release 2>/dev/null || echo 'Unknown'" 2>/dev/null)
KERNEL=$($SSH_CMD "uname -r" 2>/dev/null)
echo -e "${GREEN}PASS${NC}"
if [ "$VERBOSE" = true ]; then
    echo "   Hostname: $HOSTNAME"
    echo "   OS: $OS_VERSION"
    echo "   Kernel: $KERNEL"
fi

# Test 4: Verify essential services
echo "4. Checking essential services:"

# SSH
echo -n "   - SSH daemon... "
if $SSH_CMD "sudo systemctl is-active sshd" 2>/dev/null | grep -q "active"; then
    echo -e "${GREEN}RUNNING${NC}"
else
    echo -e "${RED}NOT RUNNING${NC}"
fi

# Rsyslog
echo -n "   - Rsyslog... "
if $SSH_CMD "sudo systemctl is-active rsyslog" 2>/dev/null | grep -q "active"; then
    echo -e "${GREEN}RUNNING${NC}"
else
    echo -e "${RED}NOT RUNNING${NC}"
fi

# Test 5: Check rsyslog configuration
if [ ! -z "$SIEM_IP" ]; then
    echo "5. Checking SIEM log forwarding configuration:"
    
    # Determine expected port
    if [ "$SIEM_TYPE" = "splunk" ]; then
        SIEM_PORT="5514"
    else
        SIEM_PORT="514"
    fi
    
    echo -n "   - Rsyslog forwarding rule... "
    if $SSH_CMD "sudo grep -q \"@@$SIEM_IP:$SIEM_PORT\" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null"; then
        echo -e "${GREEN}CONFIGURED${NC}"
    else
        echo -e "${YELLOW}NOT FOUND${NC}"
        echo "     Expected: *.* @@$SIEM_IP:$SIEM_PORT"
    fi
    
    # Test network connectivity to SIEM
    echo -n "   - Network connectivity to SIEM... "
    if $SSH_CMD "timeout 5 bash -c \"echo >/dev/tcp/$SIEM_IP/$SIEM_PORT\" 2>/dev/null"; then
        echo -e "${GREEN}REACHABLE${NC}"
    else
        echo -e "${RED}UNREACHABLE${NC}"
        echo "     Cannot connect to $SIEM_IP:$SIEM_PORT"
    fi
    
    # Send test log
    echo -n "   - Sending test log entry... "
    TEST_MSG="VICTIM_VALIDATION: Test from $HOSTNAME at $(date +%s)"
    $SSH_CMD "logger -p auth.info '$TEST_MSG'" 2>/dev/null
    echo -e "${GREEN}SENT${NC}"
    if [ "$VERBOSE" = true ]; then
        echo "     Message: $TEST_MSG"
    fi
else
    echo "5. Skipping SIEM tests (no SIEM IP provided)"
fi

# Test 6: Security checks
echo "6. Security configuration checks:"

# SSH root login
echo -n "   - SSH root login disabled... "
if $SSH_CMD "sudo grep -E '^PermitRootLogin no' /etc/ssh/sshd_config" >/dev/null 2>&1; then
    echo -e "${GREEN}SECURE${NC}"
else
    echo -e "${YELLOW}WARNING${NC} (root login may be enabled)"
fi

# SSH password auth
echo -n "   - SSH password auth disabled... "
if $SSH_CMD "sudo grep -E '^PasswordAuthentication no' /etc/ssh/sshd_config" >/dev/null 2>&1; then
    echo -e "${GREEN}SECURE${NC}"
else
    echo -e "${YELLOW}WARNING${NC} (password auth may be enabled)"
fi

# Test 7: Container-specific checks (if applicable)
echo -n "7. Checking if running in container... "
if $SSH_CMD "grep -q docker /proc/1/cgroup 2>/dev/null || [ -f /.dockerenv ]" 2>/dev/null; then
    echo -e "${GREEN}YES${NC}"
    
    # Check for systemd
    echo -n "   - Systemd as init... "
    if $SSH_CMD "ps -p 1 -o comm=" 2>/dev/null | grep -q "systemd"; then
        echo -e "${GREEN}YES${NC}"
    else
        echo -e "${YELLOW}NO${NC} (may cause issues)"
    fi
else
    echo "NO (running on VM/bare metal)"
fi

# Summary
echo ""
echo "=== Validation Summary ==="
echo -e "${GREEN}✓${NC} SSH connectivity verified"
echo -e "${GREEN}✓${NC} labadmin access confirmed"
echo -e "${GREEN}✓${NC} System information retrieved"

if [ ! -z "$SIEM_IP" ]; then
    echo -e "${YELLOW}!${NC} SIEM log forwarding should be verified in $SIEM_TYPE console"
fi

echo ""
echo "Victim container at $VICTIM_IP is operational"