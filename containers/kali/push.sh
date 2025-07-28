#!/bin/bash
set -e

# APTL Kali Container Push Script
echo "=== Pushing APTL Kali Red Team Container to ECR ==="

# Read ECR URI from Terraform bootstrap state
TERRAFORM_STATE="../../infrastructure/bootstrap/terraform.tfstate"

if [ ! -f "$TERRAFORM_STATE" ]; then
    echo "❌ Error: Terraform state file not found at $TERRAFORM_STATE"
    echo "Run terraform apply in infrastructure/bootstrap/ directory first."
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "❌ Error: jq is required but not installed."
    echo "Install with: sudo apt-get install jq"
    exit 1
fi

ECR_URI=$(jq -r '.outputs.ecr_repository_url.value' "$TERRAFORM_STATE")

if [ "$ECR_URI" = "null" ] || [ -z "$ECR_URI" ]; then
    echo "❌ Error: Could not read ECR repository URL from Terraform state."
    echo "Ensure ECR repository is deployed via Terraform."
    exit 1
fi

# Extract region from ECR URI
AWS_REGION=$(echo "$ECR_URI" | cut -d'.' -f4)

echo "ECR URI: $ECR_URI"
echo "Region: $AWS_REGION"
echo ""

# Check if local image exists
if ! docker image inspect aptl/kali-red-team:latest >/dev/null 2>&1; then
    echo "❌ Local image aptl/kali-red-team:latest not found."
    echo "Run ./build.sh first to build the image."
    exit 1
fi

# Login to ECR
echo "🔐 Logging into ECR..."
aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $(echo "$ECR_URI" | cut -d'/' -f1)

if [ $? -ne 0 ]; then
    echo "❌ ECR login failed. Check AWS credentials and permissions."
    exit 1
fi

echo "✅ ECR login successful"

# Get git commit for tagging
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Tag for ECR
echo "🏷️  Tagging images for ECR..."
docker tag aptl/kali-red-team:latest $ECR_URI:latest
docker tag aptl/kali-red-team:latest $ECR_URI:$GIT_COMMIT

# Push images
echo "⬆️  Pushing to ECR..."
echo "Pushing $ECR_URI:latest..."
docker push $ECR_URI:latest

echo "Pushing $ECR_URI:$GIT_COMMIT..."
docker push $ECR_URI:$GIT_COMMIT

echo ""
echo "✅ Push complete!"
echo ""
echo "Images pushed:"
echo "  - $ECR_URI:latest"
echo "  - $ECR_URI:$GIT_COMMIT"
echo ""
echo "To pull on EC2:"
echo "  docker pull $ECR_URI:latest"