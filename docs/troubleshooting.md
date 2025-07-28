# Troubleshooting

## Instance Setup Status

### Kali Instance

```bash
# Check if setup completed
ls -la /home/kali/kali_setup_complete

# Monitor setup progress  
sudo tail -f /var/log/user-data.log

# Check for running package installation
ps aux | grep -E "(apt|dpkg|unattended-upgrade)"
```

**Common timing:**
- Package updates: 5-15 minutes
- Script creation: 1-2 minutes
- Red team tools: Available after setup completes

### Victim Instance

```bash
# Check setup status
ls -la /home/ec2-user/victim_setup_complete

# Monitor progress
sudo tail -f /var/log/user-data.log
```

## qRadar Installation Issues

### Installation Appears Stuck

**Problem**: Installation appears stuck on "Installing DSM rpms:"
**Solution**: This is normal behavior. The process takes 30+ minutes. Be patient.

### Tmux Session Errors

**Problem**: Installation script ends with `no server running on /tmp/tmux-0/default [exited]`
**Solution**: This is normal - it means the tmux session completed. Check if qRadar is running:

```bash
sudo systemctl status hostcontext
```

### System Reboots During Preparation

**Problem**: System reboots while running `./prepare_for_qradar.sh`
**Solution**: 
1. Wait ~2 minutes for instance to come back online
2. SSH back into the instance
3. Run `./prepare_for_qradar.sh` again
4. Continue until you see "System ready for qRadar installation!"

## Log Forwarding Issues

### Logs Not Appearing in SIEM

**Check connectivity:**
```bash
# From victim machine, test connection to SIEM
nc -zv SIEM_IP 514
telnet SIEM_IP 514
```

**Check rsyslog service:**
```bash
# Check rsyslog status
sudo systemctl status rsyslog

# View rsyslog logs
journalctl -u rsyslog -f

# Restart rsyslog if needed
sudo systemctl restart rsyslog
```

**Generate test events:**
```bash
# SSH to victim machine
ssh -i ~/.ssh/purple-team-key ec2-user@VICTIM_IP

# Run test event generator
./generate_test_events.sh
```

## Network Connectivity Issues

### SSH Connection Refused

**Check security groups:**
1. Verify your IP is correctly set in `terraform.tfvars`
2. Ensure security groups allow SSH (port 22) from your IP
3. Check if instance is running: `aws ec2 describe-instances`

**Update your IP:**
```bash
# Get your current IP
curl ipinfo.io/ip

# Update terraform.tfvars with new IP
# Re-run terraform apply
```

### Web Interface Not Accessible

**For qRadar web interface:**
1. Verify qRadar installation completed successfully
2. Check if hostcontext service is running: `sudo systemctl status hostcontext`
3. Ensure security groups allow HTTPS (port 443) from your IP
4. Try both HTTP and HTTPS protocols

## Performance Issues

### Instance Running Slowly

**Check system resources:**
```bash
# Check CPU and memory usage
top
htop

# Check disk usage
df -h

# Check running processes
ps aux | head -20
```

**For qRadar specifically:**
- qRadar requires significant resources (t3a.2xlarge minimum)
- Initial startup can take 10-15 minutes
- Performance improves after initial configuration

### Network Latency

- Choose AWS region closest to your location
- Consider upgrading instance types for better network performance
- Monitor CloudWatch metrics for network utilization

## Common Error Messages

### "Permission denied (publickey)"

**Problem**: SSH key authentication failing
**Solutions:**
1. Verify key file permissions: `chmod 400 ~/.ssh/purple-team-key`
2. Check if correct key is being used
3. Verify instance has started completely

### "Connection timed out"

**Problem**: Network connectivity issues
**Solutions:**
1. Check security group rules
2. Verify your IP address in terraform.tfvars
3. Confirm instance is in running state

### "No space left on device"

**Problem**: Disk space exhausted
**Solutions:**
1. Check disk usage: `df -h`
2. Clean up log files: `sudo journalctl --vacuum-time=1d`
3. Remove unnecessary files from /tmp
4. Consider increasing EBS volume size

## Getting Help

### Log Locations

Key log files to check:
- **Instance setup**: `/var/log/user-data.log`
- **System logs**: `journalctl -f`
- **rsyslog**: `journalctl -u rsyslog -f`
- **SSH logs**: `/var/log/auth.log` or `/var/log/secure`

### Debugging Steps

1. **Verify Infrastructure**: Check AWS console for instance status
2. **Check Network**: Verify security groups and connectivity
3. **Monitor Logs**: Use log files to identify specific issues
4. **Test Components**: Use provided test scripts to verify functionality
5. **Restart Services**: Try restarting problematic services

### Reset and Retry

If issues persist:

1. **Destroy and rebuild**: Use `terraform destroy` then `terraform apply`
2. **Check configuration**: Verify terraform.tfvars settings
3. **Update dependencies**: Ensure latest Terraform and AWS CLI versions