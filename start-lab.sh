#!/bin/bash
set -e

# APTL Local Lab Startup Script
# Orchestrates the complete lab startup process

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo " Starting APTL Local Purple Team Lab"
echo "=========================================="

# Step 1: Generate SSH keys
echo ""
echo "Step 1: Generating SSH keys..."
./scripts/generate-ssh-keys.sh

# Step 1.5: Setup Kali MCP server
echo ""
echo "Step 1.5: Setting up MCP server..."
cd mcp-red
if [ ! -d "node_modules" ]; then
    echo "Installing MCP server dependencies..."
    npm install
fi
if [ ! -d "build" ]; then
    echo "Building MCP server..."
    npm run build
fi
cd ..

# Step 1.6: Setup Wazuh MCP server
echo ""
echo "Step 1.6: Setting up Wazuh MCP server..."
cd mcp-blue
if [ ! -d "node_modules" ]; then
    echo "Installing MCP server dependencies..."
    npm install
fi
if [ ! -d "build" ]; then
    echo "Building MCP server..."
    npm run build
fi
cd ..

# Step 2: Check system requirements
echo ""
echo "Step 2: Checking system requirements..."
# Check max_map_count
current_max_map=$(sysctl vm.max_map_count | awk '{print $3}')
if [ "$current_max_map" -lt 262144 ]; then
    echo "vm.max_map_count is too low ($current_max_map). OpenSearch requires at least 262144."
    echo "Please run: sudo sysctl -w vm.max_map_count=262144"
    exit 1
else
    echo "vm.max_map_count is adequate ($current_max_map)"
fi

# Step 3: Sync Wazuh dashboard configuration
echo ""
echo "Step 3: Syncing Wazuh dashboard configuration..."
API_PASSWORD=$(grep "API_PASSWORD=" docker-compose.yml | head -1 | cut -d'=' -f2)
if [ -f "./config/wazuh_dashboard/wazuh.yml" ]; then
    echo "Updating wazuh.yml with current API password..."
    sed -i "s/password: \".*\"/password: \"$API_PASSWORD\"/" ./config/wazuh_dashboard/wazuh.yml
    echo "Configuration synced"
else
    echo "Warning: wazuh.yml not found, dashboard may not connect properly"
fi

# Step 4: Generate SSL certificates for Wazuh
echo ""
echo "Step 4: Generating SSL certificates for Wazuh..."
if [ ! -d "./config/wazuh_indexer_ssl_certs" ]; then
    echo "Generating new certificates..."
    docker compose -f generate-indexer-certs.yml run --rm generator
    echo "Fixing certificate permissions..."
    sudo chown -R $(id -u):$(id -g) ./config/wazuh_indexer_ssl_certs/
    sudo chmod -R 644 ./config/wazuh_indexer_ssl_certs/*.pem
else
    echo "Certificates already exist"
fi

# Step 5: Build and start containers
echo ""
echo "Step 5: Building and starting containers..."
echo "This may take several minutes on first run..."

# Pull base images to show progress
echo "Pulling base images..."
docker pull wazuh/wazuh-manager:4.12.0
docker pull wazuh/wazuh-indexer:4.12.0
docker pull wazuh/wazuh-dashboard:4.12.0
docker pull kalilinux/kali-last-release:latest
docker pull rockylinux:9

# Build and start services
docker compose up --build -d

echo ""
echo "Step 5: Waiting for services to be ready..."

# Wait for Wazuh Indexer to be ready
echo "Waiting for Wazuh Indexer to start (this can take 2-5 minutes)..."
timeout=300
while [ $timeout -gt 0 ]; do
    if curl -k -s -f https://localhost:9200 -u admin:SecretPassword >/dev/null 2>&1; then
        echo "Wazuh Indexer is ready"
        break
    fi
    echo "   Indexer still starting... (${timeout}s remaining)"
    sleep 10
    timeout=$((timeout - 10))
done

if [ $timeout -le 0 ]; then
    echo "Wazuh Indexer startup timeout - may still be initializing"
fi

# Wait for Wazuh Manager API
echo "Waiting for Wazuh Manager API..."
timeout=120
while [ $timeout -gt 0 ]; do
    if curl -k -s -f https://localhost:55000 -u wazuh-wui:MyS3cr37P450r.*- >/dev/null 2>&1; then
        echo "Wazuh Manager API is ready"
        break
    fi
    echo "   Manager API still starting... (${timeout}s remaining)"
    sleep 5
    timeout=$((timeout - 5))
done

# Wait for SSH services
echo "Waiting for SSH services..."
sleep 10

# Test SSH connectivity
test_ssh() {
    local container=$1
    local port=$2
    local user=$3
    
    if ssh -i ~/.ssh/aptl_lab_key -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
           ${user}@localhost -p ${port} "echo 'SSH OK'" 2>/dev/null; then
        echo "SSH to $container ($user@localhost:$port) is ready"
        return 0
    else
        echo "SSH to $container not ready yet"
        return 1
    fi
}

# Test SSH connections
test_ssh "victim" "2022" "labadmin" || echo "   → Victim SSH may need more time"
test_ssh "kali" "2023" "kali" || echo "   → Kali SSH may need more time"

# Function to output to both console and file
output_both() {
    echo "$1" | tee -a lab_connections.txt
}

# Clear previous connections file
> lab_connections.txt

output_both ""
output_both "=========================================="
output_both "  APTL Local Lab Started Successfully!"
output_both "=========================================="
output_both ""
output_both "   Service URLs:"
output_both "   Wazuh Dashboard: https://localhost:443"
output_both "   Wazuh Indexer: https://localhost:9200"
output_both "   Wazuh API: https://localhost:55000"
output_both ""
output_both "   Default Credentials:"
output_both "   Dashboard: admin / SecretPassword"
output_both "   API: wazuh-wui / MyS3cr37P450r.*-"
output_both ""
output_both "   SSH Access:"
output_both "   Victim:       ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022"
output_both "   Kali:         ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023"
output_both ""
output_both "   Container IPs:"
output_both "   wazuh.manager:   172.20.0.10"
output_both "   wazuh.dashboard: 172.20.0.11" 
output_both "   wazuh.indexer:   172.20.0.12"
output_both "   victim:          172.20.0.20"  
output_both "   kali:            172.20.0.30"
output_both ""
output_both "   MCP Servers:"
output_both "   Red Team Config: ./mcp-red/docker-lab-config.json"
output_both "   Blue Team Config: ./mcp-blue/wazuh-api-config.json"
output_both "   Status: Built and ready"
output_both ""
output_both "   Management Commands:"
output_both "   View logs:    docker compose logs -f [service]"
output_both "   Stop lab:     docker compose down"
output_both "   Restart:      docker compose restart [service]"
output_both "   Full cleanup: docker compose down -v"
output_both ""
output_both "   Connection info saved to: lab_connections.txt"
output_both ""