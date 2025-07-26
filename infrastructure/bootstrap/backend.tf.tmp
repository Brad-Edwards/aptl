# SPDX-License-Identifier: BUSL-1.1
# Backend configuration for bootstrap

terraform {
  backend "s3" {
    bucket         = "aptl-shared-7a62a0d4-83fe-d271-b97c-c2d81acdf082"
    key            = "bootstrap/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "aptl-terraform-locks-7a62a0d4-83fe-d271-b97c-c2d81acdf082"
  }
}
