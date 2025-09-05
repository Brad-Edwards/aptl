#!/bin/bash

echo "[*] Starting CTF scenario setup on victim..."

# 1. Set up SUID binary
echo "[*] Setting up SUID binary..."
sudo cp /tmp/backup_util /usr/local/bin/backup
sudo chown root:root /usr/local/bin/backup
sudo chmod 4755 /usr/local/bin/backup
rm -f /tmp/backup_util
echo "[+] SUID binary installed at /usr/local/bin/backup"

# 2. Set up web application
echo "[*] Setting up vulnerable web service..."
# Create unprivileged user for web service
sudo useradd -r -s /bin/bash -d /var/www/simple_app -m webservice 2>/dev/null || true
sudo mkdir -p /var/www/simple_app
sudo cp /tmp/vulnerable_app.py /var/www/simple_app/app.py
sudo chown webservice:webservice /var/www/simple_app/app.py
sudo chmod +x /var/www/simple_app/app.py

# 3. Create systemd service for persistence
if command -v systemctl &> /dev/null; then
    sudo tee /etc/systemd/system/ctf-web.service > /dev/null << 'EOF'
[Unit]
Description=CTF Vulnerable Web Application
After=network.target

[Service]
Type=simple
User=webservice
WorkingDirectory=/var/www/simple_app
ExecStart=/usr/bin/python3 /var/www/simple_app/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable ctf-web.service
    sudo systemctl start ctf-web.service
    
    # Wait for service to start
    sleep 3
    
    if sudo systemctl is-active --quiet ctf-web.service; then
        echo "[+] Web service started successfully"
    else
        echo "[!] Failed to start web service via systemd, trying manual start"
        nohup python3 /var/www/simple_app/app.py > /var/www/simple_app/server.log 2>&1 &
    fi
else
    # Fallback for non-systemd
    nohup python3 /var/www/simple_app/app.py > /var/www/simple_app/server.log 2>&1 &
    echo "[+] Web service started in background"
fi

# Clean up transferred files (but not the SUID binary we just installed)
# 4. Place the flag
echo "[*] Placing CTF flag..."
echo "APTL{basic_suid_and_web_pwn_complete}" | sudo tee /root/flag.txt > /dev/null
sudo chmod 600 /root/flag.txt
echo "[+] Flag placed in /root/flag.txt"

rm -f /tmp/vulnerable_app.py /tmp/victim_setup.sh /tmp/backup_util.tmp 2>/dev/null

echo ""
echo "[+] CTF Scenario Setup Complete!"
echo ""
echo "Services configured:"
echo "  - Web Application: http://172.20.0.20:8080"
echo "  - SUID Binary: /usr/local/bin/backup"

