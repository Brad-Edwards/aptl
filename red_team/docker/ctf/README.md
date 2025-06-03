# OWASP Juice Shop CTF Environment for APTL

This directory contains the configuration for setting up an OWASP Juice Shop CTF environment that can be used with APTL.

## Overview

[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) is a deliberately vulnerable web application designed for security training. It includes a wide variety of web vulnerabilities and challenges, making it an excellent platform for testing APTL's capabilities in a CTF environment.

## Setup

The environment is configured using Docker Compose, which sets up two containers:

1. **Kali Linux Container**: Contains security tools and the APTL MCP server
2. **OWASP Juice Shop Container**: The vulnerable web application

## Starting the Environment

To start the environment, run the following command from the `aptl/docker` directory:

```bash
docker-compose up -d
```

This will start both containers in detached mode.

## Accessing the CTF

The OWASP Juice Shop application is accessible at:

- From your host machine: <http://localhost:3000>
- From the Kali container: <http://juice-shop:3000>

## Using APTL with the CTF

APTL can interact with the CTF environment using both interactive and non-interactive sessions.

### Non-Interactive Commands

You can use the `execute_command` tool to run commands in the Kali container:

```javascript
use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "execute_command",
  arguments: {
    command: "nmap -sV juice-shop"
  }
})
```

### Interactive Sessions

For more complex interactions, you can use the interactive session tools:

```javascript
// Create a session
const sessionResponse = await use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "create_session",
  arguments: {
    name: "ctf-session",
    workingDir: "/ctf"
  }
});

// Extract the session ID
const sessionIdMatch = sessionResponse.match(/Session created with ID: ([a-f0-9-]+)/);
const sessionId = sessionIdMatch ? sessionIdMatch[1] : null;

// Run commands in the session
await use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "send_input",
  arguments: {
    sessionId: sessionId,
    input: "curl -s http://juice-shop:3000"
  }
});
```

## Example Challenges

Here are some example challenges you can try with APTL:

### 1. Reconnaissance

Use APTL to scan the Juice Shop application and identify open ports and services:

```javascript
use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "execute_command",
  arguments: {
    command: "nmap -sV -p- juice-shop"
  }
})
```

### 2. Finding Hidden Content

Use APTL to discover hidden directories and files:

```javascript
use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "execute_command",
  arguments: {
    command: "dirb http://juice-shop:3000 /usr/share/dirb/wordlists/common.txt"
  }
})
```

### 3. SQL Injection

Use APTL to test for SQL injection vulnerabilities:

```javascript
// Create an interactive session
const sessionId = "YOUR_SESSION_ID"; // Replace with actual session ID

// Run sqlmap
await use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "send_input",
  arguments: {
    sessionId: sessionId,
    input: "sqlmap -u 'http://juice-shop:3000/rest/products/search?q=apple' --batch --dbs"
  }
});
```

## CTF Scoring

OWASP Juice Shop includes a built-in scoring system. You can track your progress by:

1. Accessing the Juice Shop application in a browser
2. Clicking on the "Score Board" button (may be hidden)
3. Viewing the challenges and their status

## Resources

- [OWASP Juice Shop GitHub Repository](https://github.com/juice-shop/juice-shop)
- [OWASP Juice Shop Documentation](https://pwning.owasp-juice.shop/)
- [OWASP Juice Shop CTF Extension](https://github.com/juice-shop/juice-shop-ctf)
