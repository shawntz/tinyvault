#!/bin/bash

# TinyVault - Deploy from Docker Hub to Google Cloud Run
# This script pulls the pre-built image from Docker Hub instead of building from source

set -e

echo "=== Deploying TinyVault from Docker Hub to Cloud Run ==="
echo ""

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo "Error: gcloud CLI is not installed"
    echo "Install from: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Get configuration
read -p "Enter your GCP Project ID: " PROJECT_ID
read -p "Enter Cloud Run region [us-central1]: " REGION
REGION=${REGION:-us-central1}
read -p "Enter KMS location [us-central1]: " KMS_LOCATION
KMS_LOCATION=${KMS_LOCATION:-us-central1}
read -p "Enter authorized email address: " USER_EMAIL
read -p "Enter service name [cse-kacls]: " SERVICE_NAME
SERVICE_NAME=${SERVICE_NAME:-cse-kacls}
read -p "Enter Docker image tag [latest]: " DOCKER_TAG
DOCKER_TAG=${DOCKER_TAG:-latest}

# Identity Provider configuration
echo ""
echo "Identity Provider Configuration:"
read -p "Enter IdP name (e.g., Google, Okta) [Google]: " IDP_NAME
IDP_NAME=${IDP_NAME:-Google}
read -p "Enter IdP Client ID (leave empty for Google Identity): " IDP_CLIENT_ID
read -p "Enter IdP Discovery URI [https://accounts.google.com/.well-known/openid-configuration]: " IDP_DISCOVERY_URI
IDP_DISCOVERY_URI=${IDP_DISCOVERY_URI:-https://accounts.google.com/.well-known/openid-configuration}
read -p "Enter IdP Audience [cse-authorization]: " IDP_AUDIENCE
IDP_AUDIENCE=${IDP_AUDIENCE:-cse-authorization}

# Okta-specific configuration (only needed for Okta IdP)
if [[ $IDP_NAME == "Okta" ]] || [[ $IDP_NAME == "okta" ]]; then
    read -p "Enter Okta domain (e.g., acme.okta.com): " OKTA_DOMAIN
else
    OKTA_DOMAIN=""
fi

# Custom domain configuration
echo ""
read -p "Do you want to use a custom domain? (y/n): " -n 1 -r
echo
USE_CUSTOM_DOMAIN=$REPLY

if [[ $USE_CUSTOM_DOMAIN =~ ^[Yy]$ ]]; then
    read -p "Enter your root domain (e.g., acme.com): " ROOT_DOMAIN
    read -p "Enter subdomain [secure]: " SUBDOMAIN
    SUBDOMAIN=${SUBDOMAIN:-secure}
    CUSTOM_DOMAIN="${SUBDOMAIN}.${ROOT_DOMAIN}"
    echo "Custom domain: $CUSTOM_DOMAIN"
fi

echo ""
echo "Deployment Configuration:"
echo "  Project: $PROJECT_ID"
echo "  Region: $REGION"
echo "  Service Name: $SERVICE_NAME"
echo "  KMS Location: $KMS_LOCATION"
echo "  Authorized Email: $USER_EMAIL"
echo "  Docker Image: shawnschwartz/tinyvault:$DOCKER_TAG"
echo "  IdP Name: $IDP_NAME"
echo "  IdP Client ID: ${IDP_CLIENT_ID:-(not set)}"
echo "  IdP Discovery URI: $IDP_DISCOVERY_URI"
if [[ $USE_CUSTOM_DOMAIN =~ ^[Yy]$ ]]; then
    echo "  Custom Domain: $CUSTOM_DOMAIN"
fi
echo ""
read -p "Deploy with this configuration? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled"
    exit 1
fi

# Set project
gcloud config set project $PROJECT_ID

# Deploy to Cloud Run using pre-built Docker Hub image
echo ""
echo "Deploying to Cloud Run from Docker Hub..."
echo "Image: shawnschwartz/tinyvault:$DOCKER_TAG"
echo ""

gcloud run deploy $SERVICE_NAME \
    --image shawnschwartz/tinyvault:$DOCKER_TAG \
    --platform managed \
    --region $REGION \
    --allow-unauthenticated \
    --set-env-vars "VERSION=$DOCKER_TAG,GCP_PROJECT_ID=$PROJECT_ID,KMS_LOCATION=$KMS_LOCATION,KMS_KEYRING=cse-keyring,KMS_KEY=cse-key,ALLOWED_EMAILS=$USER_EMAIL,IDP_NAME=$IDP_NAME,IDP_CLIENT_ID=$IDP_CLIENT_ID,IDP_DISCOVERY_URI=$IDP_DISCOVERY_URI,IDP_AUDIENCE=$IDP_AUDIENCE,OKTA_DOMAIN=$OKTA_DOMAIN" \
    --memory 512Mi \
    --cpu 1 \
    --max-instances 3 \
    --min-instances 0 \
    --timeout 300

# Get the service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME \
    --region $REGION \
    --format 'value(status.url)')

# Allow public access for Google Workspace to reach the endpoint
# Note: --allow-unauthenticated flag already enables public access
# This command is redundant but kept for completeness
echo ""
echo "Verifying public access for Google Workspace..."
gcloud run services add-iam-policy-binding $SERVICE_NAME \
    --region=$REGION \
    --member=allUsers \
    --role=roles/run.invoker 2>/dev/null || echo "✓ Public access already configured via --allow-unauthenticated"

echo ""
echo "========================================="
echo "Deployment successful!"
echo "========================================="
echo ""
echo "Default Cloud Run URL: $SERVICE_URL"

# Set up custom domain if requested
if [[ $USE_CUSTOM_DOMAIN =~ ^[Yy]$ ]]; then
    echo ""
    echo "Setting up custom domain: $CUSTOM_DOMAIN"
    echo ""

    # Create domain mapping (using beta for region support)
    gcloud beta run domain-mappings create \
        --service $SERVICE_NAME \
        --domain $CUSTOM_DOMAIN \
        --region $REGION 2>&1 | tee /tmp/domain-mapping-output.txt

    echo ""
    echo "========================================="
    echo "Custom Domain Configuration"
    echo "========================================="
    echo ""
    echo "Add these DNS records to your domain provider:"
    echo ""
    echo "Record Type: CNAME"
    echo "Name: $SUBDOMAIN"
    echo "Value: ghs.googlehosted.com"
    echo ""
    echo "After adding the DNS record:"
    echo "1. Wait 5-15 minutes for DNS propagation"
    echo "2. Cloud Run will automatically provision SSL certificate"
    echo "3. Your endpoint will be available at: https://$CUSTOM_DOMAIN"
    echo ""
    echo "To check status:"
    echo "  gcloud beta run domain-mappings describe $CUSTOM_DOMAIN --region $REGION"
    echo ""

    FINAL_URL="https://$CUSTOM_DOMAIN"
else
    FINAL_URL=$SERVICE_URL
fi

echo ""
echo "========================================="
echo "Next Steps"
echo "========================================="
echo ""
echo "1. Test the endpoint:"
echo "   curl $FINAL_URL/health"
echo ""

if [[ $USE_CUSTOM_DOMAIN =~ ^[Yy]$ ]]; then
    echo "2. Add DNS records (see above)"
    echo ""
    echo "3. After DNS propagation, configure in Google Workspace Admin Console:"
else
    echo "2. Configure in Google Workspace Admin Console:"
fi

echo "   - Go to: Security > Access and data control > Data protection"
echo "   - Click: Client-side encryption > Add external key service"
echo "   - Enter Service URL: $FINAL_URL"
echo "   - Test the connection"
echo "   - Enable CSE for your account"
echo ""
echo "Cost estimate: ~$0.10-0.50/month (mostly free tier)"
echo ""
echo "✅ Deployment from Docker Hub complete!"
echo ""
