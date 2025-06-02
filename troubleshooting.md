<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Troubleshooting

## Common Issues

### SSH Permission Denied

```bash
chmod 400 ~/.ssh/purple-team-key
```

### qRadar Installation Fails

- Ensure 24GB+ RAM (t3a.2xlarge has 32GB)
- Verify ISO file integrity
- Check license key validity
- Package conflicts: Script automatically removes conflicting cloud packages

### Log Forwarding Not Working

Check victim machine log forwarding:

```bash
# SSH to victim machine
ssh -i ~/.ssh/purple-team-key ec2-user@VICTIM_IP

# Check rsyslog status
sudo systemctl status rsyslog

# Check rsyslog forwarding attempts
sudo journalctl -u rsyslog -f

# Should show successful forwarding, not "Connection timed out"
```

Verify qRadar is receiving logs:

```bash
# SSH to qRadar SIEM
ssh -i ~/.ssh/purple-team-key ec2-user@SIEM_IP

# Check if qRadar is listening on port 514
sudo netstat -tlnp | grep :514
```

Manual fix if automatic setup failed:

```bash
# On victim machine, check rsyslog config
tail /etc/rsyslog.conf

# Should show: *.* @@SIEM_IP:514
# If missing, add it manually:
echo "*.* @@SIEM_INTERNAL_IP:514" | sudo tee -a /etc/rsyslog.conf
sudo systemctl restart rsyslog
```

### No Logs Visible in qRadar

- Verify victim machine IP in qRadar Log Activity filters
- Check time synchronization between machines
- Generate test logs: `logger "TEST MESSAGE - $(date)"`
- Restart rsyslog: `sudo systemctl restart rsyslog`

### Security Group Issues

- Ensure TCP port 514 is open between victim and SIEM security groups
- Both UDP and TCP should be allowed for syslog (port 514)
- Check AWS Console → EC2 → Security Groups

### Terraform Errors

- Verify AWS credentials: `aws sts get-caller-identity`
- Check region availability for instance types
- Ensure your IP is correctly formatted (CIDR notation)
- EBS volume cycle error: Remove `depends_on` from SIEM instance if present

## Log Forwarding Debugging

Step-by-step debugging process:

### 1. Test network connectivity

```bash
# From victim machine
telnet SIEM_IP 514
# Should connect successfully
```

### 2. Check rsyslog configuration

```bash
# Verify config syntax
sudo rsyslogd -N1

# Check forwarding rule exists
grep "@@" /etc/rsyslog.conf
```

### 3. Monitor real-time forwarding

```bash
# Watch rsyslog attempts
sudo journalctl -u rsyslog -f

# Generate test in another terminal
logger "DEBUGGING TEST - $(date)"
```

### 4. Verify qRadar reception

- qRadar Log Activity should show new events
- Filter by victim machine source IP
- Look for recent timestamps

## Getting Help

- Check `lab_connections.txt` for current connection info
- Review AWS Console for instance status
- Check security group rules if connections fail
- Use `terraform plan` to verify changes before applying
