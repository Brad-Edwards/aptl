# SPDX-License-Identifier: BUSL-1.1
# Bootstrap infrastructure for APTL
# Run this first to create S3 bucket for state and file storage

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.4"
    }
  }
  required_version = ">= 1.2.0"
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile != "" ? var.aws_profile : null
}

# Generate UUID for unique bucket naming to prevent enumeration
resource "random_uuid" "bucket_suffix" {}

# S3 bucket for bootstrap Terraform state
resource "aws_s3_bucket" "aptl_bootstrap" {
  bucket = "aptl-bootstrap-${random_uuid.bucket_suffix.result}"
  
  tags = {
    Name        = "APTL Bootstrap State"
    Environment = "bootstrap"
    Purpose     = "terraform-state"
  }
}

resource "aws_s3_bucket_versioning" "aptl_bootstrap_versioning" {
  bucket = aws_s3_bucket.aptl_bootstrap.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "aptl_bootstrap_encryption" {
  bucket = aws_s3_bucket.aptl_bootstrap.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "aptl_bootstrap_pab" {
  bucket = aws_s3_bucket.aptl_bootstrap.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# DynamoDB table for state locking
resource "aws_dynamodb_table" "aptl_bootstrap_locks" {
  name           = "aptl-bootstrap-locks-${random_uuid.bucket_suffix.result}"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  tags = {
    Name        = "APTL Bootstrap Terraform Locks"
    Environment = "bootstrap"
  }
}

# ECR repository for container images
resource "aws_ecr_repository" "kali_red_team" {
  name                 = "aptl/kali-red-team"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name        = "APTL Kali Red Team Container"
    Environment = "bootstrap"
    Purpose     = "container-registry"
  }
}

resource "aws_ecr_lifecycle_policy" "kali_red_team_policy" {
  repository = aws_ecr_repository.kali_red_team.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 10 images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["v"]
          countType     = "imageCountMoreThan"
          countNumber   = 10
        }
        action = {
          type = "expire"
        }
      },
      {
        rulePriority = 2
        description  = "Delete untagged images older than 1 day"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 1
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

# Output the bucket name
output "bootstrap_bucket_name" {
  value = aws_s3_bucket.aptl_bootstrap.bucket
  description = "S3 bucket for bootstrap Terraform state"
}

output "dynamodb_table_name" {
  value = aws_dynamodb_table.aptl_bootstrap_locks.name
  description = "DynamoDB table for bootstrap Terraform state locking"
}

output "bootstrap_bucket_region" {
  value = var.aws_region
  description = "AWS region where the bootstrap S3 bucket is deployed"
}

# Container registry outputs
output "ecr_repository_url" {
  description = "ECR repository URL for Kali Red Team container"
  value = aws_ecr_repository.kali_red_team.repository_url
}

output "ecr_repository_name" {
  description = "ECR repository name for Kali Red Team container"
  value = aws_ecr_repository.kali_red_team.name
}