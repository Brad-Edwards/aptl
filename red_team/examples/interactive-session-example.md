# Interactive Session Example for Cursor/Cline

This example demonstrates how to use the interactive session tools to run interactive commands in the Kali Linux environment through Cursor or Cline.

## Creating a Session

First, create a new interactive terminal session:

```javascript
use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "create_session",
  arguments: {
    name: "metasploit-session",
    workingDir: "/ctf",
    initialCommand: "echo 'Interactive session started'"
  }
})
```

This will return a response with a session ID that you'll need for subsequent commands:

```
Session created with ID: 12345678-1234-1234-1234-123456789abc

Initial output:
Interactive session started
```

## Sending Input to the Session

Once you have a session ID, you can send commands to it:

```javascript
use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "send_input",
  arguments: {
    sessionId: "12345678-1234-1234-1234-123456789abc", // Replace with your actual session ID
    input: "nmap -T4 -F 172.17.0.1" // Scan the host machine
  }
})
```

This will execute the command in the session and return the output:

```
Starting Nmap 7.93 ( https://nmap.org ) at 2025-04-06 21:30 UTC
Nmap scan report for 172.17.0.1
Host is up (0.00042s latency).
Not shown: 99 closed tcp ports
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 0.08 seconds
```

## Getting Output from the Session

If you need to get output from the session without sending a command:

```javascript
use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "get_output",
  arguments: {
    sessionId: "12345678-1234-1234-1234-123456789abc", // Replace with your actual session ID
    wait: true, // Wait for output if none is available
    timeout: 5000 // Wait up to 5 seconds
  }
})
```

## Running Metasploit Framework

Here's an example of running Metasploit Framework interactively:

```javascript
// First, create a session
use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "create_session",
  arguments: {
    name: "metasploit-session",
    workingDir: "/ctf"
  }
})

// Start Metasploit console
use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "send_input",
  arguments: {
    sessionId: "YOUR_SESSION_ID", // Replace with your actual session ID
    input: "msfconsole"
  }
})

// Wait for Metasploit to load, then search for exploits
use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "send_input",
  arguments: {
    sessionId: "YOUR_SESSION_ID", // Replace with your actual session ID
    input: "search type:exploit platform:windows"
  }
})

// Use a specific exploit
use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "send_input",
  arguments: {
    sessionId: "YOUR_SESSION_ID", // Replace with your actual session ID
    input: "use exploit/windows/smb/ms17_010_eternalblue"
  }
})

// Show options for the exploit
use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "send_input",
  arguments: {
    sessionId: "YOUR_SESSION_ID", // Replace with your actual session ID
    input: "show options"
  }
})
```

## Listing Active Sessions

To see all active sessions:

```javascript
use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "list_sessions",
  arguments: {}
})
```

## Terminating a Session

When you're done with a session, terminate it:

```javascript
use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "terminate_session",
  arguments: {
    sessionId: "12345678-1234-1234-1234-123456789abc" // Replace with your actual session ID
  }
})
```

## Complete Example: Interactive Shell Script

Here's a complete example of running an interactive shell script that asks for multiple inputs:

```javascript
// Create a session
const sessionResponse = await use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "create_session",
  arguments: {
    name: "interactive-session",
    workingDir: "/ctf"
  }
});

// Extract the session ID from the response
const sessionIdMatch = sessionResponse.match(/Session created with ID: ([a-f0-9-]+)/);
const sessionId = sessionIdMatch ? sessionIdMatch[1] : null;

if (!sessionId) {
  console.error("Failed to extract session ID");
  return;
}

// Create an interactive shell script
await use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "send_input",
  arguments: {
    sessionId: sessionId,
    input: `cat > interactive.sh << 'EOF'
#!/bin/bash
echo "What is your name?"
read name
echo "What is your age?"
read age
echo "Hello, $name! You are $age years old."
EOF`
  }
});

// Make the script executable and run it
const startResponse = await use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "send_input",
  arguments: {
    sessionId: sessionId,
    input: "chmod +x interactive.sh && ./interactive.sh"
  }
});

console.log(startResponse); // Shows "What is your name?"

// Provide the first input (name)
const nameResponse = await use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "send_input",
  arguments: {
    sessionId: sessionId,
    input: "Alice"
  }
});

console.log(nameResponse); // Shows "What is your age?"

// Provide the second input (age)
const ageResponse = await use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "send_input",
  arguments: {
    sessionId: sessionId,
    input: "30"
  }
});

console.log(ageResponse); // Shows "Hello, Alice! You are 30 years old."

// Terminate the session
await use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "terminate_session",
  arguments: {
    sessionId: sessionId
  }
});
```

This example demonstrates a truly interactive session where we:

1. Create a shell script that asks for multiple inputs
2. Run the script
3. Provide the first input (name) when prompted
4. Provide the second input (age) when prompted
5. See the final output that uses both inputs

## Example: Running an Nmap Scan

Here's an example of running an Nmap scan on the host machine:

```javascript
// Create a session
const sessionResponse = await use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "create_session",
  arguments: {
    name: "nmap-session",
    workingDir: "/ctf"
  }
});

// Extract the session ID from the response
const sessionIdMatch = sessionResponse.match(/Session created with ID: ([a-f0-9-]+)/);
const sessionId = sessionIdMatch ? sessionIdMatch[1] : null;

if (!sessionId) {
  console.error("Failed to extract session ID");
  return;
}

// Run nmap scan on the host machine
const scanResponse = await use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "send_input",
  arguments: {
    sessionId: sessionId,
    input: "nmap -T4 -F 172.17.0.1"
  }
});

console.log("Nmap scan results:");
console.log(scanResponse);

// Terminate the session
await use_mcp_tool({
  server_name: "kali-ctf",
  tool_name: "terminate_session",
  arguments: {
    sessionId: sessionId
  }
});
```

## Notes

- Interactive sessions are useful for tools that require ongoing interaction, like Metasploit, sqlmap, or hydra.
- Each session runs in its own terminal in the Kali Linux container.
- Sessions will automatically time out after 30 minutes of inactivity.
- You can have multiple sessions running simultaneously.
