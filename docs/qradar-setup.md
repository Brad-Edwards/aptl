# qRadar Installation and Configuration

After infrastructure deployment, you need to install and configure qRadar manually.

## Installation Process

### Step 1: Transfer qRadar ISO

```bash
# Transfer qRadar ISO (~8 minutes for 5GB file)
scp -i ~/.ssh/purple-team-key files/750-QRADAR-QRFULL-2021.06.12.20250509154206.iso ec2-user@SIEM_IP:/tmp/

# SSH to SIEM instance
ssh -i ~/.ssh/purple-team-key ec2-user@SIEM_IP
```

### Step 2: Prepare System

```bash
# Step 1: Prepare system (handles reboots if needed) - takes ~15 mins to complete after the instance is ready
./prepare_for_qradar.sh

# If system reboots, wait ~2 minutes then SSH back and run prepare script again
# Continue until you see "System ready for qRadar installation!"
```

### Step 3: Install qRadar

```bash
# Step 2: Install qRadar (only after system is ready)
./install_qradar.sh
```

## Installation Details

Installation takes **1-2 hours**. During installation, choose:

- Software installation
- "All-In-One" console  
- Default settings
- Your timezone and city
- Set passwords (don't forget them)

**Note**: Installation appears stuck on "Installing DSM rpms:" but it's working. Takes 30+ minutes.

The installation script may end with `no server running on /tmp/tmux-0/default [exited]`. This is normal - it just means the tmux session completed. qRadar may still be running successfully.

## Verify Installation

To verify qRadar is working after installation:

```bash
# Check if qRadar service is running
sudo systemctl status hostcontext

# If active (running), qRadar is working - access the web interface via HTTPS
```

## Configure qRadar for Red Team Logging

After qRadar installation is complete, configure it to properly separate red team activities from victim logs:

```bash
# SSH to qRadar instance
ssh -i ~/.ssh/purple-team-key ec2-user@SIEM_IP

# Run the configuration guide
./configure_qradar_logsources.sh
```

This script provides step-by-step instructions for:

1. **Creating Red Team Log Source**: Separates Kali logs from victim logs
2. **Setting Up Custom Properties**:
   - `RedTeamActivity` - Type of red team activity (commands/network/auth)
   - `RedTeamCommand` - Actual command executed  
   - `RedTeamTarget` - Target of the activity
3. **Configuring Log Parsing**: Extract red team metadata from logs
4. **Verifying Setup**: Ensure red team logs are properly categorized

## Manual Steps Required in qRadar Console

- Navigate to Admin > Data Sources > Log Sources
- Create "APTL-Kali-RedTeam" log source
- Set up custom properties for red team activity classification
- Configure parsing rules for red team log extraction

## Benefits of Red Team Log Separation

This red team log separation allows you to:

- Filter logs by red team vs victim activity
- Search for specific attack types and commands
- Correlate red team actions with SIEM detections

## Web Access

Once installation is complete:

- **Web UI**: `https://SIEM_IP`
- **Login**: admin/(password you set during installation)

![Offences in qRadar](../assets/images/qradar_offences.png)