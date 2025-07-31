#!/bin/bash
set -e

# APTL Kali Container Build Script
echo "=== Building APTL Kali Red Team Container ==="

# Get AWS account ID for ECR URL
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "")
AWS_REGION=${AWS_REGION:-us-east-1}

if [ -z "$AWS_ACCOUNT_ID" ]; then
    echo "Warning: Could not get AWS Account ID. Using local tag only."
    ECR_URI="aptl/kali-red-team"
else
    ECR_URI="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/aptl/kali-red-team"
fi

# Build arguments
BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

echo "Building container image..."
echo "ECR URI: $ECR_URI"
echo "Build Date: $BUILD_DATE"
echo "Git Commit: $GIT_COMMIT"

# Build the container
docker build \
    --build-arg BUILD_DATE="$BUILD_DATE" \
    --build-arg GIT_COMMIT="$GIT_COMMIT" \
    -t aptl/kali-red-team:latest \
    -t aptl/kali-red-team:$GIT_COMMIT \
    .

# Tag for ECR if we have AWS credentials
if [ -n "$AWS_ACCOUNT_ID" ]; then
    docker tag aptl/kali-red-team:latest $ECR_URI:latest
    docker tag aptl/kali-red-team:latest $ECR_URI:$GIT_COMMIT
    echo "Tagged for ECR: $ECR_URI"
fi

echo ""
echo "✅ Build complete!"
echo ""
echo "Local tags:"
echo "  - aptl/kali-red-team:latest"
echo "  - aptl/kali-red-team:$GIT_COMMIT"

if [ -n "$AWS_ACCOUNT_ID" ]; then
    echo ""
    echo "ECR tags:"
    echo "  - $ECR_URI:latest"
    echo "  - $ECR_URI:$GIT_COMMIT"
    echo ""
    echo "To push to ECR:"
    echo "  aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
    echo "  docker push $ECR_URI:latest"
fi

