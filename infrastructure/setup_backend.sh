#!/bin/bash
# SPDX-License-Identifier: BUSL-1.1
# Setup script to configure main infrastructure backend from bootstrap outputs
# Run this after applying bootstrap infrastructure

set -e

BOOTSTRAP_DIR="bootstrap"
export AWS_PROFILE="brad-edwards-dev"

echo "Setting up main infrastructure backend from bootstrap..."

# Validate bootstrap exists and is applied
if [ ! -d "$BOOTSTRAP_DIR" ]; then
    echo "❌ Error: Bootstrap directory not found at $BOOTSTRAP_DIR"
    exit 1
fi

if [ ! -f "$BOOTSTRAP_DIR/terraform.tfstate" ]; then
    echo "❌ Error: Bootstrap terraform.tfstate not found"
    echo "   Run 'terraform apply' in the bootstrap/ directory first"
    exit 1
fi

# Extract bootstrap outputs
echo "📤 Reading bootstrap outputs..."
BUCKET_NAME=$(cd "$BOOTSTRAP_DIR" && terraform output -raw shared_bucket_name)
DYNAMODB_TABLE=$(cd "$BOOTSTRAP_DIR" && terraform output -raw dynamodb_table_name)
BUCKET_REGION=$(cd "$BOOTSTRAP_DIR" && terraform output -raw shared_bucket_region)

echo "✅ Bootstrap Configuration:"
echo "   S3 Bucket: $BUCKET_NAME"
echo "   DynamoDB Table: $DYNAMODB_TABLE"
echo "   Region: $BUCKET_REGION"

# Create backend config file
echo "📝 Creating backend.hcl..."
cat > backend.hcl << EOF
bucket         = "$BUCKET_NAME"
dynamodb_table = "$DYNAMODB_TABLE"
region         = "$BUCKET_REGION"
EOF

# Update terraform.tfvars with bootstrap bucket name
echo "📝 Updating terraform.tfvars..."
if [ -f terraform.tfvars ]; then
    # Remove existing bootstrap_bucket_name if it exists
    grep -v "^bootstrap_bucket_name" terraform.tfvars > terraform.tfvars.tmp || true
    mv terraform.tfvars.tmp terraform.tfvars
fi

# Add bootstrap_bucket_name to terraform.tfvars
echo "bootstrap_bucket_name = \"$BUCKET_NAME\"" >> terraform.tfvars

echo "🔄 Initializing Terraform with shared backend..."
terraform init -backend-config=backend.hcl -reconfigure

echo "✅ Setup complete!"
echo ""
echo "The main infrastructure is now configured to use the shared S3 bucket."
echo "You can now run: terraform plan && terraform apply"