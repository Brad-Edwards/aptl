# Base Victim AMI Plan

This document outlines a proposed approach for creating a reusable "victim" Amazon Machine Image (AMI) and incorporating it as the initial default image in the Terraform configuration. Having a prebuilt AMI speeds up deployments and ensures consistent tooling across lab environments.

## Goals

- Build a minimal RHEL based AMI with all packages and test scripts required for purple team scenarios.
- Use that AMI as the default `victim_ami` variable value while still allowing overrides.
- Document a repeatable process to rebuild the AMI when updates or patches are needed.

## High-Level Steps

1. **Create a Packer Template**
   - Use [Packer](https://www.packer.io/) to automate AMI creation.
   - Base the build on the official RHEL 8.x AMI (the same image currently referenced in `terraform.tfvars.example`).
   - In the Packer provisioners, mirror the steps from `infrastructure/modules/victim/user_data.sh` to install packages and drop the event generation scripts.
   - Output an AMI tagged with `aptl-victim-base`.

2. **Store AMI Information**
   - Record the resulting AMI ID in documentation or a parameter file for easy reference.
   - Optionally output an SSM Parameter to store the AMI ID for automation.

3. **Update Terraform Defaults**
   - Set the `victim_ami` variable default (in `variables.tf` or a new `terraform.tfvars`) to the newly built AMI.
   - Keep the variable so users can override with their own AMI if desired.

4. **Usage in the Lab**
   - When deploying the lab, Terraform will launch the victim EC2 instance using the base AMI by default.
   - The user data script can remain for any runtime configuration (e.g., pointing to the chosen SIEM).

5. **Maintenance Process**
   - Rebuild the AMI periodically or when new tooling is needed.
   - Version AMIs with a date or semantic version tag to track updates.
   - Update the default `victim_ami` value and changelog whenever a new AMI is released.

## Future Considerations

- Evaluate using AWS Systems Manager for patching to keep the AMI secure between rebuilds.
- Provide a smaller testing AMI without heavy packages for lightweight scenarios.
- Eventually publish the AMI to the AWS Marketplace or a public account for easier community use.

