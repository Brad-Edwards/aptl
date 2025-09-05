#!/bin/bash

cd ./mcp/aptl-mcp-common && npm install && npm run build
cd ../mcp-red && npm install && npm run build
cd ../mcp-blue && npm install && npm run build
cd ../mcp-reverse && npm install && npm run build
cd ../mcp-wazuh && npm install && npm run build
cd ../mcp-windows-re && npm install && npm run build
cd ..