# SPDX-License-Identifier: BUSL-1.1

terraform {
  backend "s3" {
    bucket         = "aptl-main-c656289e-f8e1-ae4f-74d2-383e98ec44e2"
    key            = "terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "aptl-main-locks-c656289e-f8e1-ae4f-74d2-383e98ec44e2"
  }
}
