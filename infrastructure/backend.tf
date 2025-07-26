# SPDX-License-Identifier: BUSL-1.1

terraform {
  backend "s3" {
    bucket         = "aptl-shared-storage"
    key            = "dev/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "aptl-terraform-locks"
  }
} 