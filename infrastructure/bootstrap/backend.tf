# SPDX-License-Identifier: BUSL-1.1

terraform {
  backend "s3" {
    bucket         = "aptl-bootstrap-7a62a0d4-83fe-d271-b97c-c2d81acdf082"
    key            = "terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "aptl-bootstrap-locks-7a62a0d4-83fe-d271-b97c-c2d81acdf082"
  }
}
