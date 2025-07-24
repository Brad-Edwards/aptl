<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Roadmap: Splunk Integration (v1.1)

## Overview

Add Splunk as an alternative SIEM option alongside qRadar, allowing users to choose their preferred SIEM platform during deployment.

## Implementation Plan

### 1. Variable Configuration

Add to `variables.tf`:

```hcl
variable "siem_type" {
  description = "Type of SIEM to deploy (qradar or splunk)"
  type        = string
  default     = "qradar"
  validation {
    condition     = contains(["qradar", "splunk"], var.siem_type)
    error_message = "SIEM type must be either 'qradar' or 'splunk'"
  }
}

variable "splunk_ami" {
  description = "AMI ID for Splunk instance"
  type        = string
  default     = ""  # Will use data source to find latest
}
```

### 2. Splunk Instance Configuration

In `main.tf`, modify SIEM instance to support both types:

```hcl
# Use conditional logic to deploy appropriate SIEM
resource "aws_instance" "siem" {
  ami           = var.siem_type == "qradar" ? var.siem_ami : data.aws_ami.splunk.id
  instance_type = var.siem_type == "qradar" ? "t3a.2xlarge" : "t3.large"  # Splunk needs less
  # ... rest of configuration

  user_data = var.siem_type == "qradar" ? local.qradar_userdata : local.splunk_userdata
}
```

### 3. Splunk User Data Script

Create simple Splunk setup in `main.tf`:

```hcl
locals {
  splunk_userdata = <<-EOF
    #!/bin/bash
    # Download and install Splunk
    wget -O splunk.tgz 'https://download.splunk.com/products/splunk/releases/9.1.2/linux/splunk-9.1.2-b6b9c8185839-Linux-x86_64.tgz'
    tar xvzf splunk.tgz -C /opt
    
    # Accept license and start
    /opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt --seed-passwd ChangeMePlease123!
    
    # Enable boot start
    /opt/splunk/bin/splunk enable boot-start
    
    # Configure to receive syslog
    /opt/splunk/bin/splunk add udp 514 -sourcetype syslog -auth admin:ChangeMePlease123!
    
    # Create setup completion script
    cat > /home/ec2-user/splunk_info.txt << 'SCRIPT'
    Splunk Web Interface: https://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8000
    Username: admin
    Password: ChangeMePlease123! (CHANGE THIS!)
    
    To change password:
    /opt/splunk/bin/splunk edit user admin -password <newpassword> -auth admin:ChangeMePlease123!
    SCRIPT
    EOF
}
```

### 4. Update Victim Log Forwarding

Modify victim user_data to detect SIEM type:

```bash
# In victim user_data
SIEM_TYPE="${var.siem_type}"
if [ "$SIEM_TYPE" = "splunk" ]; then
  # Splunk uses standard syslog
  echo "*.* @$SIEM_IP:514" | sudo tee -a /etc/rsyslog.conf
else
  # qRadar uses TCP
  echo "*.* @@$SIEM_IP:514" | sudo tee -a /etc/rsyslog.conf
fi
```

### 5. Update Documentation

Add to README.md:

- Splunk deployment option in terraform.tfvars
- Splunk-specific access instructions
- Cost comparison (Splunk on t3.large is cheaper)
- Note about Splunk free license limitations

### 6. Testing Scripts

Update event generators to work with both SIEMs:

- Same log format works for both
- Add Splunk-specific search examples
- Include SPL (Splunk Processing Language) queries

## Benefits

- Choice of SIEM platform
- Lower cost option with Splunk
- Simpler installation process
- No ISO transfer required
- Faster deployment time

## Considerations

- Splunk free license limited to 500MB/day
- Different query languages (SPL vs AQL)
- Different UI/UX between platforms
- Both are temporary/trial versions
