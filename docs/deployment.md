# Infrastructure Deployment

Infrastructure deployment requires two phases for security (UUID-based bucket naming):

## Phase 1: Bootstrap Infrastructure

```bash
cd infrastructure/bootstrap
terraform init
terraform apply
./create_backend.sh           # Generates backend.tf with UUID bucket name
terraform init -migrate-state # Migrates state to S3
```

## Phase 2: Main Infrastructure  

```bash
cd ../
terraform init
terraform apply
./create_backend.sh           # Generates backend.tf with UUID bucket name
terraform init -migrate-state # Migrates state to S3
```

## Deployment Timing

**Setup timing:**

- Bootstrap deployment: 2-3 minutes
- Main infrastructure deployment: 3-5 minutes  
- Instance configuration: 10-20 minutes per instance (background process)

**Note**: SSH access is available immediately after main infrastructure deployment, but user_data scripts continue configuring instances. Scripts and tools become available once setup completes.

## Accessing the Lab

After deployment, connection information is saved to `lab_connections.txt`:

```bash
cat lab_connections.txt
```

### SIEM Access

- SSH: `ssh -i ~/.ssh/purple-team-key ec2-user@SIEM_IP`
- Web UI: `https://SIEM_IP` (after installation)
- Login: admin/(password you set)

### Victim Machine

- SSH: `ssh -i ~/.ssh/purple-team-key ec2-user@VICTIM_IP`
- RDP: Use any RDP client to connect to `VICTIM_IP`

### Kali Linux Red Team

- SSH: `ssh -i ~/.ssh/purple-team-key kali@KALI_IP`

## Monitoring Instance Setup

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

## Cleanup

Destroy infrastructure in reverse order:

```bash
# Destroy main infrastructure first
cd infrastructure
terraform destroy

# Then destroy bootstrap
cd bootstrap
terraform destroy
```

This will permanently delete all resources and data.

## Log Forwarding Verification

The victim machine automatically forwards logs to the selected SIEM. No manual configuration required.

### Verify Log Forwarding

1. Check the SIEM log activity page
2. Filter by Source IP = your victim machine IP
3. Generate test events:

```bash
# SSH to victim machine
ssh -i ~/.ssh/purple-team-key ec2-user@VICTIM_IP

# Run test event generator
./generate_test_events.sh
```