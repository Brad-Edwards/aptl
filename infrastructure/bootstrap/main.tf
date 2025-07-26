# SPDX-License-Identifier: BUSL-1.1
# Bootstrap infrastructure for APTL
# Run this first to create S3 bucket for state and file storage

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.2.0"
}

provider "aws" {
  region = "us-east-1"
}

# Single S3 bucket for both Terraform state and persistent files (like qRadar ISO)
resource "aws_s3_bucket" "aptl_shared" {
  bucket = "aptl-shared-storage"
  
  tags = {
    Name        = "APTL Shared Storage"
    Environment = "shared"
    Purpose     = "terraform-state-and-persistent-files"
  }
}

resource "aws_s3_bucket_versioning" "aptl_shared_versioning" {
  bucket = aws_s3_bucket.aptl_shared.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "aptl_shared_encryption" {
  bucket = aws_s3_bucket.aptl_shared.id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "aptl_shared_pab" {
  bucket = aws_s3_bucket.aptl_shared.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# DynamoDB table for state locking
resource "aws_dynamodb_table" "aptl_locks" {
  name           = "aptl-terraform-locks"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    Name        = "APTL Terraform Locks"
    Environment = "shared"
  }
}

# Output the bucket name
output "shared_bucket_name" {
  value = aws_s3_bucket.aptl_shared.bucket
  description = "S3 bucket for Terraform state and persistent files (ISOs, etc.)"
}

output "dynamodb_table_name" {
  value = aws_dynamodb_table.aptl_locks.name
  description = "DynamoDB table for Terraform state locking"
}