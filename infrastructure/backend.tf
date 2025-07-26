# SPDX-License-Identifier: BUSL-1.1

terraform {
  backend "s3" {
    # Note: These values must be provided via backend config or init command
    # Run: terraform init -backend-config="bucket=<bootstrap-bucket-name>" -backend-config="dynamodb_table=<bootstrap-table-name>"
    # Or create backend.hcl with these values from bootstrap outputs
    key     = "environments/dev/terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
  }
} 