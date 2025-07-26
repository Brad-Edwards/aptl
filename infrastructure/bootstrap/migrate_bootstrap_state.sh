#!/bin/bash
# SPDX-License-Identifier: BUSL-1.1
# Migrate bootstrap state from local to S3
# Run this AFTER initial bootstrap deployment with local state

set -e

# Set AWS profile
export AWS_PROFILE="brad-edwards-dev"

echo "🔄 Migrating bootstrap state to S3..."

# Check if local state exists
if [ ! -f "terraform.tfstate" ]; then
    echo "❌ Error: No local terraform.tfstate found"
    echo "   Deploy bootstrap with local state first: terraform apply"
    exit 1
fi

# Remove backend.tf temporarily to read from local state
if [ -f "backend.tf" ]; then
    echo "📝 Temporarily removing backend.tf to read local state..."
    mv backend.tf backend.tf.tmp
fi

# Get bucket info from local state
echo "📤 Reading bootstrap outputs from local state..."
BUCKET_NAME=$(terraform output -raw shared_bucket_name)
DYNAMODB_TABLE=$(terraform output -raw dynamodb_table_name)
BUCKET_REGION=$(terraform output -raw shared_bucket_region)

echo "✅ Bootstrap Configuration:"
echo "   S3 Bucket: $BUCKET_NAME"
echo "   DynamoDB Table: $DYNAMODB_TABLE"
echo "   Region: $BUCKET_REGION"

# Create backend.tf with actual values
echo "📝 Creating backend.tf with S3 configuration..."
cat > backend.tf << EOF
# SPDX-License-Identifier: BUSL-1.1
# Backend configuration for bootstrap

terraform {
  backend "s3" {
    bucket         = "$BUCKET_NAME"
    key            = "bootstrap/terraform.tfstate"
    region         = "$BUCKET_REGION"
    encrypt        = true
    dynamodb_table = "$DYNAMODB_TABLE"
  }
}
EOF

# Migrate state to S3
echo "🚀 Migrating state to S3..."
terraform init -migrate-state

# Verify migration
echo "✅ State migration complete!"
echo ""
echo "Bootstrap state is now stored in: s3://$BUCKET_NAME/bootstrap/terraform.tfstate"
echo ""
echo "You can now proceed to setup the main infrastructure:"
echo "  cd ../infrastructure"
echo "  ./setup_backend.sh"