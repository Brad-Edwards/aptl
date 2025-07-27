# Intermediate CTF Scenario 3: Cross-Site Scripting

## Overview
Reflected XSS vulnerability in a simple PHP search page. Trainees practice crafting XSS payloads and basic session hijacking techniques.

## Scenario Details
- **Difficulty**: Intermediate
- **Attack Vectors**: Reflected XSS, session hijacking, client-side exploitation
- **Skills Tested**: XSS payload crafting, browser exploitation, web defense analysis
- **Expected Time**: 15-20 minutes

## Setup

### Prerequisites
- Apache2 web server
- PHP

### Setup Script
```bash
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
```

### Manual Setup Steps
1. Install Apache2 and PHP
2. Place the vulnerable `index.php` under `/var/www/html/xss/`
3. Start the Apache service

## Attack Methodology
1. Discover the `/xss/` page
2. Inject payloads via the `q` parameter, e.g. `<script>alert('XSS')</script>`
3. Attempt to steal cookies or perform session hijacking

### Key Commands
```bash
curl "http://<target_ip>/xss/index.php?q=<script>alert(1)</script>"
```

## Blue Team Detection Signatures
- Monitor Apache logs for `<script>` tags in query parameters
- Look for suspicious user-agent strings or repeated payloads

## Cleanup

### Cleanup Script
```bash
#!/bin/bash
# cleanup_cross_site_scripting.sh

echo "[+] Cleaning up Cross-Site Scripting scenario..."

sudo rm -rf /var/www/html/xss
sudo systemctl stop apache2
sudo systemctl disable apache2

echo "[+] Cross-Site Scripting scenario cleaned up!"
```

### Manual Cleanup Steps
1. Remove `/var/www/html/xss/`
2. Stop Apache service

## Reset to Basic State

### Reset Script
```bash
#!/bin/bash
# reset_cross_site_scripting.sh

echo "[+] Resetting Cross-Site Scripting to basic state..."

./cleanup_cross_site_scripting.sh
sleep 2
./setup_cross_site_scripting.sh

echo "[+] Cross-Site Scripting scenario reset complete!"
```

## Investigation Opportunities
- Detect XSS payloads in logs
- Analyze browser-based exploitation attempts

## Security Notes
- Contains intentionally vulnerable code for educational use only
- Deploy only in isolated lab environments
