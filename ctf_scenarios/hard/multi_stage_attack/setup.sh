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