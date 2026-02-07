#!/bin/bash
set -e

# APTL Local Lab Startup Script
# Orchestrates the complete lab startup process

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo " Starting APTL Local Purple Team Lab"
echo "=========================================="

# Load credentials from .env file
echo ""
echo "Loading credentials from .env..."
if [ ! -f ".env" ]; then
    echo "Error: .env not found. Copy .env.example to .env and fill in your values."
    exit 1
fi
set -a
source .env
set +a

# Validate required environment variables
MISSING_VARS=""
for var in INDEXER_USERNAME INDEXER_PASSWORD API_USERNAME API_PASSWORD; do
    if [ -z "${!var}" ]; then
        MISSING_VARS="$MISSING_VARS $var"
    fi
done
if [ -n "$MISSING_VARS" ]; then
    echo "Error: Required environment variables are not set in .env:$MISSING_VARS"
    exit 1
fi

# Read configuration and build profile list
echo ""
echo "Reading lab configuration..."
if [ ! -f "aptl.json" ]; then
    echo "Error: aptl.json not found. Please create configuration file."
    exit 1
fi

# Check if jq is available
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed. Please install jq to parse configuration."
    exit 1
fi

# Build profile list based on enabled containers
PROFILES=""
for container in wazuh victim kali reverse; do
    enabled=$(jq -r ".containers.${container}" aptl.json 2>/dev/null)
    if [ "$enabled" = "true" ]; then
        # Convert underscores to hyphens for profile names
        profile_name=$(echo "$container" | sed 's/_/-/g')
        PROFILES="$PROFILES --profile $profile_name"
        echo "   Enabled: $container"
    else
        echo "   Disabled: $container"
    fi
done

if [ -z "$PROFILES" ]; then
    echo "Error: No containers enabled in aptl.json"
    exit 1
fi

echo "   Profiles to deploy:$PROFILES"

# Step 1: Generate SSH keys
echo ""
echo "Step 1: Generating SSH keys..."
./scripts/generate-ssh-keys.sh


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

# Step 3: Sync config files with credentials from .env
echo ""
echo "Step 3: Syncing configuration files with .env credentials..."
if [ -f "./config/wazuh_dashboard/wazuh.yml" ]; then
    echo "Updating wazuh.yml with API password..."
    sed -i "s/password: \".*\"/password: \"${API_PASSWORD}\"/" ./config/wazuh_dashboard/wazuh.yml
    echo "Dashboard configuration synced"
else
    echo "Warning: wazuh.yml not found, dashboard may not connect properly"
fi
if [ -f "./config/wazuh_cluster/wazuh_manager.conf" ]; then
    echo "Updating wazuh_manager.conf with cluster key..."
    sed -i "s|<key>.*</key>|<key>${WAZUH_CLUSTER_KEY}</key>|" ./config/wazuh_cluster/wazuh_manager.conf
    echo "Manager configuration synced"
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
docker compose $PROFILES up --build -d

echo ""
echo "Step 5: Waiting for services to be ready..."

# Wait for Wazuh Indexer to be ready
echo "Waiting for Wazuh Indexer to start (this can take 2-5 minutes)..."
timeout=300
while [ $timeout -gt 0 ]; do
    if curl -k -s -f https://localhost:9200 -u "${INDEXER_USERNAME}:${INDEXER_PASSWORD}" >/dev/null 2>&1; then
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
    if docker exec aptl-wazuh.manager-1 curl -k -s -f https://localhost:55000 -u "${API_USERNAME}:${API_PASSWORD}" >/dev/null 2>&1; then
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

# Test SSH connections for enabled containers
echo "Testing SSH connectivity for enabled containers..."
if [ "$(jq -r '.containers.victim' aptl.json)" = "true" ]; then
    test_ssh "victim" "2022" "labadmin" || echo "   → Victim SSH may need more time"
fi
if [ "$(jq -r '.containers.kali' aptl.json)" = "true" ]; then
    test_ssh "kali" "2023" "kali" || echo "   → Kali SSH may need more time"
fi
if [ "$(jq -r '.containers.reverse' aptl.json)" = "true" ]; then
    test_ssh "reverse" "2027" "labadmin" || echo "   → Reverse SSH may need more time"
fi

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
output_both "   Wazuh API: https://172.20.0.10:55000 (internal only)"
output_both ""
output_both "   Default Credentials:"
output_both "   Dashboard: ${INDEXER_USERNAME} / ${INDEXER_PASSWORD}"
output_both "   API: ${API_USERNAME} / ${API_PASSWORD}"
output_both ""
output_both "   SSH Access:"
if [ "$(jq -r '.containers.victim' aptl.json)" = "true" ]; then
    output_both "   Victim:          ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2022"
fi
if [ "$(jq -r '.containers.kali' aptl.json)" = "true" ]; then
    output_both "   Kali:            ssh -i ~/.ssh/aptl_lab_key kali@localhost -p 2023"
fi
if [ "$(jq -r '.containers.reverse' aptl.json)" = "true" ]; then
    output_both "   Reverse:         ssh -i ~/.ssh/aptl_lab_key labadmin@localhost -p 2027"
fi
output_both ""
output_both "   Container IPs:"
if [ "$(jq -r '.containers.wazuh' aptl.json)" = "true" ]; then
    output_both "   wazuh.manager:   172.20.0.10"
    output_both "   wazuh.dashboard: 172.20.0.11" 
    output_both "   wazuh.indexer:   172.20.0.12"
fi
if [ "$(jq -r '.containers.victim' aptl.json)" = "true" ]; then
    output_both "   victim:          172.20.0.20"
fi
if [ "$(jq -r '.containers.kali' aptl.json)" = "true" ]; then
    output_both "   kali:            172.20.0.30"
fi
if [ "$(jq -r '.containers.reverse' aptl.json)" = "true" ]; then
    output_both "   reverse:         172.20.0.27"
fi
output_both ""
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

# build all mcp servers
echo "Building all MCP servers..."
./mcp/build-all-mcps.sh