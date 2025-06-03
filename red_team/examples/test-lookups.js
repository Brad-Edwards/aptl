// Example script to test the Kali CTF MCP server with whois and DNS lookups
// This demonstrates how to use the MCP server to perform basic network reconnaissance

// Note: This is a demonstration script. In a real scenario, you would use the MCP
// server through Cursor/Cline's interface, not through direct API calls.

// This script requires the Docker CLI to be installed and the Kali container to be running
// It directly executes commands in the container rather than using the MCP SDK
// which might not be available or compatible

// Import required modules
import { exec } from 'child_process';
import { promisify } from 'util';

// Promisify exec for easier use with async/await
const execAsync = promisify(exec);

// Check if the Kali container is running and has the required tools
async function checkContainer() {
  try {
    // Check if container is running
    const { stdout } = await execAsync('docker ps --filter "name=kali-ctf" --format "{{.Names}}"');
    
    if (stdout.trim() === 'kali-ctf') {
      console.log('Kali container is running.');
      
      // Check if required tools are installed
      try {
        await execAsync('docker exec kali-ctf which whois dig');
        console.log('Required tools are installed.');
        return true;
      } catch (toolsError) {
        console.log('Required tools are not installed. Installing them...');
        try {
          await execAsync('docker exec kali-ctf apt-get update');
          await execAsync('docker exec kali-ctf apt-get install -y whois dnsutils');
          console.log('Tools installed successfully.');
          return true;
        } catch (installError) {
          console.error('Failed to install required tools:', installError.message);
          return false;
        }
      }
    } else {
      console.log('Kali container is not running. Starting it...');
      try {
        // Try to start an existing container
        await execAsync('docker start kali-ctf');
        console.log('Kali container started.');
        
        // Install required tools
        console.log('Installing required tools...');
        try {
          await execAsync('docker exec kali-ctf apt-get update');
          await execAsync('docker exec kali-ctf apt-get install -y whois dnsutils');
          console.log('Tools installed successfully.');
          return true;
        } catch (installError) {
          console.error('Failed to install required tools:', installError.message);
          return false;
        }
      } catch (startError) {
        console.log('Could not start existing container. Creating a new one...');
        try {
          // Create and start a new container
          await execAsync('docker run -d --name kali-ctf kalilinux/kali-rolling tail -f /dev/null');
          console.log('New Kali container created and started.');
          
          // Install required tools
          console.log('Installing required tools...');
          await execAsync('docker exec kali-ctf apt-get update');
          await execAsync('docker exec kali-ctf apt-get install -y whois dnsutils');
          console.log('Tools installed successfully.');
          
          return true;
        } catch (createError) {
          console.error('Failed to create and start Kali container:', createError.message);
          return false;
        }
      }
    }
  } catch (error) {
    console.error('Error checking container status:', error.message);
    return false;
  }
}

// Function to perform a whois lookup
async function performWhoisLookup(domain) {
  console.log(`\nPerforming WHOIS lookup for ${domain}...`);
  
  try {
    const { stdout, stderr } = await execAsync(`docker exec kali-ctf whois ${domain}`);
    
    console.log('\nWHOIS Result:');
    console.log('=============');
    console.log(stdout);
    
    if (stderr) {
      console.error('STDERR:', stderr);
    }
    
    return stdout;
  } catch (error) {
    console.error('WHOIS lookup failed:', error.message);
    return `Error: ${error.message}`;
  }
}

// Function to perform a DNS lookup
async function performDnsLookup(domain) {
  console.log(`\nPerforming DNS lookup for ${domain}...`);
  
  try {
    const { stdout, stderr } = await execAsync(`docker exec kali-ctf dig ${domain} +short`);
    
    console.log('\nDNS Lookup Result:');
    console.log('=================');
    console.log(stdout);
    
    if (stderr) {
      console.error('STDERR:', stderr);
    }
    
    return stdout;
  } catch (error) {
    console.error('DNS lookup failed:', error.message);
    return `Error: ${error.message}`;
  }
}

// Main function to run the tests
async function runTests() {
  try {
    // Check and ensure the container is running
    const containerReady = await checkContainer();
    if (!containerReady) {
      console.error('Failed to prepare the Kali container. Exiting.');
      return;
    }
    
    // Test domains
    const domains = ['example.com', 'google.com'];
    
    // Perform lookups for each domain
    for (const domain of domains) {
      await performWhoisLookup(domain);
      await performDnsLookup(domain);
    }
    
    console.log('\nAll tests completed successfully!');
  } catch (error) {
    console.error('Test failed:', error);
  }
}

// Run the tests
runTests().catch(console.error);
