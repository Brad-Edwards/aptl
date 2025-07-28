# Getting Started

## Prerequisites

1. **AWS Account** with programmatic access configured
2. **Terraform** installed (version 1.0 or later)
3. **AWS CLI** configured with your credentials
4. **qRadar CE ISO file** (see IBM requirements below)

## Quick Start

### 1. Clone and Configure

```bash
git clone <repository-url>
cd purple-team-lab
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:

```hcl
aws_region    = "us-east-1"
allowed_ip    = "YOUR_IP/32"  # Get your IP: curl ipinfo.io/ip
aws_profile   = "your-aws-profile"  # Optional
```

### 2. Get qRadar Files

You must obtain the qRadar CE ISO file and license key before proceeding.

1. Sign up for IBM ID at: <https://www.ibm.com/community/101/qradar/ce/>
2. Download ISO file: `750-QRADAR-QRFULL-2021.06.12.20250509154206.iso` (~5GB)
3. Download license key file: `qradar_trial.license`
4. Create files directory: `mkdir files`
5. Place both files in the `files/` directory

## Important Notes

This is a lab environment, not for production use. qRadar trial license expires in 30 days. See IBM's [qRadar Community Edition](https://www.ibm.com/community/101/qradar/ce/) for more information.

### Test Credentials Notice

This repository contains **intentional test credentials** for security training and CTF scenarios. These credentials are:

- **Hardcoded by design** for lab functionality
- **Not production secrets** - they are dummy/test values only
- **Safe for educational use** in isolated lab environments
- **Covered by GitGuardian whitelist** (see `.gitguardian.yaml`)

Common test credentials used:
- Default lab password: `None4you!`
- Test usernames: `admin`, `test`, `demo`
- Lab-specific keys and tokens for scenario functionality

**⚠️ These are NOT real production credentials and pose no security risk.**

## DISCLAIMER

- The author takes no responsibility for your use of this lab.
- You are solely responsible for whether you are in compliance with the laws of your jurisdiction
- You are solely responsible for following the terms and conditions of any services or applications you use.

## Cost Estimation

- t3a.2xlarge (qRadar SIEM): ~$220/month
- t3.micro (Victim): ~$7/month
- t3.micro (Kali Linux): ~$7/month
- Storage: ~$50/month (250GB root + 200GB /store + 30GB victim)
- Elastic IPs: $3.65/month
- Total: ~$287/month

Stop instances when not in use to save ~85% on compute costs.

## Security Considerations

- Access restricted to your IP address only
- All instances in public subnet for lab simplicity
- Change default passwords immediately
- Use strong SSH keys and rotate regularly