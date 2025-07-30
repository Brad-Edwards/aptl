<!-- SPDX-License-Identifier: BUSL-1.1 -->

# qRadar AMI Creation Checklist

This checklist outlines the steps to create a reusable Amazon Machine Image (AMI) with qRadar Community Edition preinstalled. Using a prebuilt AMI speeds up lab deployments by avoiding the lengthy installation every time Terraform creates the SIEM instance.

## 1. Launch Base Instance

- [ ] Start from the RHEL 8.8 AMI used for the current deployment (`qradar_ami` in `terraform.tfvars`)
- [ ] Instance type `t3a.2xlarge` (32 GB RAM)
- [ ] Root volume: 250 GB gp3
- [ ] Additional 200 GB gp3 EBS volume mounted at `/store`
- [ ] Security group allowing SSH (22), HTTPS (443) and syslog (514)
- [ ] Attach SSH key for administrative access

## 2. Prepare System

- [ ] Copy qRadar ISO and license key to `/tmp`
- [ ] Run the setup preparation script from `infrastructure/modules/qradar` (`prepare_for_qradar.sh`)
- [ ] Reboot if prompted and rerun the script until "System ready for qRadar installation" appears
- [ ] Verify SELinux is disabled and `/store` is mounted correctly
- [ ] Create 8 GB swap file if not already present

## 3. Install qRadar

- [ ] Execute `install_qradar.sh` to start the installer
- [ ] Choose **Software Installation** and **All-In-One** console options
- [ ] Accept defaults for other prompts and set the desired timezone and passwords
- [ ] Wait for installation to complete (1–2 hours)

## 4. Initial Configuration

- [ ] Log into the qRadar web console on port 443
- [ ] Complete the first-time setup wizard and confirm services are running
- [ ] Run `configure_qradar_logsources.sh` to create the APTL log source and custom properties

## 5. Cleanup Before Imaging

- [ ] Remove the ISO from `/tmp` and unmount `/iso` if mounted
- [ ] Clear shell history and temporary logs as needed
- [ ] Optionally run `sudo cloud-init clean` and remove SSH host keys so new instances generate fresh keys

## 6. Create the AMI

- [ ] Stop the instance from the AWS console or CLI
- [ ] Create an image named `APTL-qradar-ready` (or similar)
- [ ] Note the resulting AMI ID

## 7. Update Terraform

- [ ] Set `qradar_ami` in `terraform.tfvars` to the new AMI ID
- [ ] Redeploy infrastructure to verify the SIEM boots correctly without running the long installation process

---

Following this checklist will produce a reusable qRadar AMI that significantly reduces lab setup time.
