#!/bin/bash
# setup_privilege_escalation.sh

echo "[+] Setting up Privilege Escalation scenario..."

# Create low-privilege user
sudo useradd -m -s /bin/bash lowpriv
echo "lowpriv:userpass123" | sudo chpasswd

# Create flag files
echo "APTL{pr1v_3sc_sudo_m4st3r}" | sudo tee /root/flag.txt > /dev/null
sudo chmod 600 /root/flag.txt

echo "APTL{suid_b1n4ry_pwn3d}" | sudo tee /root/suid_flag.txt > /dev/null
sudo chmod 600 /root/suid_flag.txt

# Create vulnerable sudo configuration
echo "lowpriv ALL=(ALL) NOPASSWD: /usr/bin/find" | sudo tee -a /etc/sudoers > /dev/null
echo "lowpriv ALL=(ALL) NOPASSWD: /usr/bin/vim" | sudo tee -a /etc/sudoers > /dev/null

# Create vulnerable SUID binary
cat << 'EOF' | sudo tee /tmp/vulnerable_binary.c > /dev/null
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }
    
    char command[256];
    snprintf(command, sizeof(command), "/bin/cat %s", argv[1]);
    
    setuid(0);  // Set effective UID to root
    system(command);  // Vulnerable system call
    
    return 0;
}
EOF

# Compile and set SUID
sudo gcc /tmp/vulnerable_binary.c -o /usr/local/bin/readfile
sudo chmod 4755 /usr/local/bin/readfile
sudo rm /tmp/vulnerable_binary.c

# Create writable script for PATH manipulation
sudo mkdir -p /opt/scripts
cat << 'EOF' | sudo tee /opt/scripts/backup.sh > /dev/null
#!/bin/bash
echo "Running backup script..."
ls /home/$USER/
echo "Backup completed."
EOF

sudo chmod 755 /opt/scripts/backup.sh
sudo chown root:root /opt/scripts/backup.sh

# Add cron job that runs as root but uses relative path
echo "*/5 * * * * root cd /opt/scripts && ./backup.sh" | sudo tee -a /etc/crontab > /dev/null

# Create directory with interesting files
sudo mkdir -p /var/backups/secrets
echo "admin_password: super_secret_pass" | sudo tee /var/backups/secrets/admin.conf > /dev/null
echo "database_key: db_secret_key_123" | sudo tee /var/backups/secrets/db.conf > /dev/null
sudo chmod 644 /var/backups/secrets/*

# Set up environment for user
sudo -u lowpriv mkdir -p /home/lowpriv/.ssh
echo "Welcome to the system! Your goal is to gain root access." | sudo tee /home/lowpriv/README.txt > /dev/null
echo "Try checking for privilege escalation opportunities..." | sudo tee -a /home/lowpriv/README.txt > /dev/null

# Create history file with hints
sudo -u lowpriv cat << 'EOF' > /home/lowpriv/.bash_history
ls -la
ps aux
sudo -l
find / -perm -u=s -type f 2>/dev/null
EOF

sudo chown lowpriv:lowpriv /home/lowpriv/.bash_history

echo "[+] Privilege Escalation scenario deployed!"
echo "[+] Low privilege user: lowpriv"
echo "[+] Password: userpass123"
echo "[+] Vulnerabilities:"
echo "    - Sudo misconfiguration (/usr/bin/find, /usr/bin/vim)"
echo "    - SUID binary: /usr/local/bin/readfile"
echo "    - Cron PATH manipulation potential"
echo "[+] Flags: /root/flag.txt, /root/suid_flag.txt"