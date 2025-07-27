#!/bin/bash
# SPDX-License-Identifier: BUSL-1.1
# Create backend.tf from terraform outputs

set -e

if [ ! -f "terraform.tfstate" ]; then
    echo "❌ Error: No terraform.tfstate found"
    echo "   Run 'terraform apply' first"
    exit 1
fi

echo "📤 Reading bootstrap outputs..."
BUCKET_NAME=$(terraform output -raw bootstrap_bucket_name)
DYNAMODB_TABLE=$(terraform output -raw dynamodb_table_name)
AWS_REGION=$(terraform output -raw bootstrap_bucket_region)

echo "📝 Creating backend.tf..."
cat > backend.tf << EOF
# SPDX-License-Identifier: BUSL-1.1

terraform {
  backend "s3" {
    bucket         = "$BUCKET_NAME"
    key            = "terraform.tfstate"
    region         = "$AWS_REGION"
    encrypt        = true
    dynamodb_table = "$DYNAMODB_TABLE"
  }
}
EOF

echo "✅ Created backend.tf with:"
echo "   Bucket: $BUCKET_NAME"
echo "   Table: $DYNAMODB_TABLE"
echo ""
echo "Now run: terraform init -migrate-state"