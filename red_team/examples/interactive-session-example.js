#!/usr/bin/env node

/**
 * This example demonstrates how to use the interactive session tools
 * to run interactive commands in the Kali Linux environment.
 * 
 * It creates a session, runs an interactive shell script that asks for
 * multiple inputs, and displays the results.
 */

const { spawn } = require('child_process');
const readline = require('readline');

// Get the host IP address
function getHostIp() {
    // In a Docker container, the host is usually accessible via the gateway
    return '172.17.0.1';
}

// Create a session and run interactive commands
async function runInteractiveExample() {
    console.log('Starting interactive session example...');
    
    // Start the MCP server if it's not already running
    const serverProcess = spawn('node', ['../build/index.js'], {
        env: { ...process.env, CONTAINER_NAME: 'kali-ctf' },
        stdio: 'pipe'
    });
    
    // Set up readline interface for user input
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    
    // Buffer for storing server output
    let outputBuffer = '';
    let sessionId = null;
    
    // Handle server output
    serverProcess.stdout.on('data', (data) => {
        const output = data.toString();
        outputBuffer += output;
        
        // Check if we have a complete JSON response
        if (output.includes('\n')) {
            try {
                // Parse the JSON response
                const lines = outputBuffer.split('\n');
                for (const line of lines) {
                    if (line.trim()) {
                        const response = JSON.parse(line);
                        
                        // Handle the response based on the method
                        if (response.method === 'create_session' && response.result) {
                            // Extract session ID from the response
                            const match = response.result.content[0].text.match(/Session created with ID: ([a-f0-9-]+)/);
                            if (match) {
                                sessionId = match[1];
                                console.log(`\nSession created with ID: ${sessionId}`);
                                console.log('Initial output:');
                                console.log(response.result.content[0].text.split('\n\nInitial output:\n')[1]);
                                
                                // Create an interactive shell script
                                console.log('\nCreating an interactive shell script...');
                                sendCommand(`cat > interactive.sh << 'EOF'
#!/bin/bash
echo "What is your name?"
read name
echo "What is your age?"
read age
echo "Hello, $name! You are $age years old."
EOF`);
                            }
                        } else if (response.method === 'send_input' && response.result) {
                            // Display the output from the command
                            console.log(response.result.content[0].text);
                            
                            // Handle different stages of the interactive script
                            if (response.result.content[0].text === '') {
                                // Script created successfully, make it executable and run it
                                console.log('\nMaking the script executable and running it...');
                                sendCommand('chmod +x interactive.sh && ./interactive.sh');
                            } else if (response.result.content[0].text === 'What is your name?') {
                                // Prompt for name, provide input
                                console.log('\nProviding name: Alice');
                                sendCommand('Alice');
                            } else if (response.result.content[0].text === 'What is your age?') {
                                // Prompt for age, provide input
                                console.log('\nProviding age: 30');
                                sendCommand('30');
                            } else if (response.result.content[0].text.includes('Hello, Alice! You are 30 years old.')) {
                                // Script completed, terminate the session
                                console.log('\nInteractive script completed successfully. Terminating session...');
                                terminateSession();
                            }
                        } else if (response.method === 'terminate_session' && response.result) {
                            console.log('\nSession terminated successfully.');
                            console.log('Interactive session example completed.');
                            
                            // Exit the process
                            serverProcess.kill();
                            rl.close();
                            process.exit(0);
                        }
                    }
                }
                
                // Clear the buffer
                outputBuffer = '';
            } catch (error) {
                // Incomplete JSON, keep buffering
            }
        }
    });
    
    // Handle server errors
    serverProcess.stderr.on('data', (data) => {
        console.error(`Server error: ${data.toString()}`);
    });
    
    // Handle server exit
    serverProcess.on('close', (code) => {
        console.log(`Server process exited with code ${code}`);
        rl.close();
        process.exit(code);
    });
    
    // Function to send a command to the server
    function sendCommand(command) {
        const request = {
            jsonrpc: '2.0',
            id: Date.now().toString(),
            method: 'send_input',
            params: {
                name: 'send_input',
                arguments: {
                    sessionId,
                    input: command
                }
            }
        };
        
        serverProcess.stdin.write(JSON.stringify(request) + '\n');
    }
    
    // Function to terminate the session
    function terminateSession() {
        const request = {
            jsonrpc: '2.0',
            id: Date.now().toString(),
            method: 'terminate_session',
            params: {
                name: 'terminate_session',
                arguments: {
                    sessionId
                }
            }
        };
        
        serverProcess.stdin.write(JSON.stringify(request) + '\n');
    }
    
    // Create a new session
    const createSessionRequest = {
        jsonrpc: '2.0',
        id: Date.now().toString(),
        method: 'create_session',
        params: {
            name: 'create_session',
            arguments: {
                name: 'interactive-script-session',
                workingDir: '/ctf',
                initialCommand: 'echo "Interactive session started"'
            }
        }
    };
    
    // Send the create session request
    serverProcess.stdin.write(JSON.stringify(createSessionRequest) + '\n');
    
    // Handle user input
    rl.on('line', (input) => {
        if (sessionId) {
            sendCommand(input);
        }
    });
}

// Run the example
runInteractiveExample().catch(console.error);
