#!/bin/bash
# setup_cross_site_scripting.sh

echo "[+] Setting up Cross-Site Scripting scenario..."

sudo apt-get update -qq
sudo apt-get install -y apache2 php

sudo mkdir -p /var/www/html/xss
cat <<'PHP' | sudo tee /var/www/html/xss/index.php > /dev/null
<!DOCTYPE html>
<html>
<head><title>XSS Lab</title></head>
<body>
  <h2>Search</h2>
  <form method="GET">
    <input type="text" name="q" placeholder="Search">
    <input type="submit" value="Go">
  </form>
  <?php
  if (isset($_GET['q'])) {
      $term = $_GET['q'];
      echo "<p>Results for: $term</p>"; // VULNERABLE OUTPUT
  }
  ?>
</body>
</html>
PHP

sudo chown -R www-data:www-data /var/www/html/xss
sudo chmod -R 755 /var/www/html/xss

sudo systemctl start apache2
sudo systemctl enable apache2

echo "[+] Cross-Site Scripting scenario deployed!"
echo "[+] Target: http://localhost/xss/index.php?q=<script>alert(1)</script>"
