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