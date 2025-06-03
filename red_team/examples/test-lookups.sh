#!/bin/bash

# Test script for Kali CTF MCP Server
# This script demonstrates how to perform whois and DNS lookups using the MCP server

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required for this script. Please install it first."
    echo "You can install it with: apt-get install jq"
    exit 1
fi

# Get the directory of the script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is required for this script. Please install Docker first."
    exit 1
fi

# Check if the Kali container exists and is running
if ! docker ps --filter "name=kali-ctf" --format "{{.Names}}" | grep -q "kali-ctf"; then
    if docker ps -a --filter "name=kali-ctf" --format "{{.Names}}" | grep -q "kali-ctf"; then
        echo "Kali container exists but is not running. Starting it..."
        docker start kali-ctf
    else
        echo "Kali container does not exist. Creating and starting it..."
        docker run -d --name kali-ctf kalilinux/kali-rolling tail -f /dev/null
    fi
else
    echo "Kali container is already running."
fi

# Check if required tools are installed in the container
if ! docker exec kali-ctf which whois dig &> /dev/null; then
    echo "Installing required tools in the container..."
    docker exec kali-ctf apt-get update
    docker exec kali-ctf apt-get install -y whois dnsutils
else
    echo "Required tools are already installed."
fi

# Check if the MCP server is running
if ! pgrep -f "node.*build/index.js" > /dev/null; then
    echo "Starting the MCP server..."
    cd "$PROJECT_DIR" && node build/index.js &
    SERVER_PID=$!
    echo "MCP server started with PID: $SERVER_PID"
    # Give the server time to start
    sleep 5
else
    echo "MCP server is already running."
    SERVER_PID=""
fi

# Function to perform a whois lookup
perform_whois_lookup() {
    local domain=$1
    echo -e "\nPerforming WHOIS lookup for $domain..."
    
    # Execute the command directly in the container
    echo -e "\nWHOIS Result:"
    echo "============="
    docker exec kali-ctf whois "$domain" || echo "Error: Failed to execute whois command"
}

# Function to perform a DNS lookup
perform_dns_lookup() {
    local domain=$1
    echo -e "\nPerforming DNS lookup for $domain..."
    
    # Execute the command directly in the container
    echo -e "\nDNS Lookup Result:"
    echo "=================="
    docker exec kali-ctf dig "$domain" +short || echo "Error: Failed to execute dig command"
}

# Test domains
DOMAINS=("example.com" "google.com")

# Perform lookups for each domain
for domain in "${DOMAINS[@]}"; do
    perform_whois_lookup "$domain"
    perform_dns_lookup "$domain"
done

# Clean up
if [ -n "$SERVER_PID" ]; then
    echo -e "\nShutting down the MCP server..."
    kill $SERVER_PID
    echo "MCP server stopped."
fi

echo -e "\nAll tests completed!"

# Note: This script is for demonstration purposes only.
# In a real scenario, you would use the MCP client SDK or Cursor/Cline to interact with the MCP server.
