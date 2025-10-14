#!/bin/bash

# Google Workspace CSE KACLS Endpoint Setup Script
# This script sets up the necessary GCP resources

set -e

echo "=== Google Workspace CSE KACLS Setup ==="
echo ""

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo "Error: gcloud CLI is not installed"
    echo "Install from: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Get configuration
read -p "Enter your GCP Project ID: " PROJECT_ID
read -p "Enter KMS location [us-central1]: " KMS_LOCATION
KMS_LOCATION=${KMS_LOCATION:-us-central1}
read -p "Enter your email address for authorization: " USER_EMAIL

echo ""
echo "Configuration:"
echo "  Project ID: $PROJECT_ID"
echo "  KMS Location: $KMS_LOCATION"
echo "  Authorized Email: $USER_EMAIL"
echo ""
read -p "Continue with this configuration? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Setup cancelled"
    exit 1
fi

# Set project
echo ""
echo "Setting GCP project..."
gcloud config set project $PROJECT_ID

# Enable required APIs
echo ""
echo "Enabling required GCP APIs..."
gcloud services enable cloudkms.googleapis.com
gcloud services enable run.googleapis.com
gcloud services enable cloudbuild.googleapis.com

# Create KMS key ring and key
echo ""
echo "Creating KMS key ring and key..."
gcloud kms keyrings create cse-keyring \
    --location=$KMS_LOCATION \
    2>/dev/null || echo "Key ring already exists"

gcloud kms keys create cse-key \
    --location=$KMS_LOCATION \
    --keyring=cse-keyring \
    --purpose=encryption \
    2>/dev/null || echo "Key already exists"

# Create .env file for local testing
echo ""
echo "Creating .env.example file..."
cat > .env.example <<EOF
GCP_PROJECT_ID=$PROJECT_ID
KMS_LOCATION=$KMS_LOCATION
KMS_KEYRING=cse-keyring
KMS_KEY=cse-key
ALLOWED_EMAILS=$USER_EMAIL
PORT=8080
EOF

echo ""
echo "Setup complete!"
echo ""
echo "Next steps:"
echo "1. Copy .env.example to .env if testing locally"
echo "2. Run './deploy.sh' to deploy to Cloud Run"
echo "3. Configure Google Workspace Admin Console with the Cloud Run URL"
