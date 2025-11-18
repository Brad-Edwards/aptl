#!/bin/bash

# Build common dependency first
cd ./mcp/aptl-mcp-common && npm install && npm run build
cd ../mcp-red && npm install && npm run build
cd ../mcp-wazuh && npm install && npm run build
cd ../..