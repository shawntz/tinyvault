# 🔐 TinyVault

**DIY Google Workspace encryption for ~$0.10/month**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker Hub](https://img.shields.io/badge/docker-tinyvault-blue.svg)](https://hub.docker.com/r/shawnschwartz/tinyvault)
[![Cloud Run](https://img.shields.io/badge/deploy-Cloud%20Run-4285F4.svg)](https://cloud.google.com/run)

> ⚠️ **IMPORTANT DISCLAIMER**: TinyVault is an **unaudited, open-source project** for personal use and learning. It has NOT been professionally audited or certified for compliance (HIPAA, PCI, FedRAMP, etc.). While it uses secure Google Cloud components, TinyVault itself is a DIY solution. **Use at your own risk.** For mission-critical or regulated data, consider professionally audited enterprise solutions.

---

## 💡 What is TinyVault?

TinyVault is a **lightweight, self-hosted KACLS endpoint** for Google Workspace Client-Side Encryption (CSE). It enables you to encrypt Gmail, Drive, Calendar, and Meet content with your own encryption keys—without paying thousands of dollars for enterprise CSE partner solutions.

**Best for**: Personal use, small teams, learning, non-critical data
**NOT for**: HIPAA/PCI/regulated data (without your own compliance work), mission-critical enterprise use (without hardening)

### The Problem

Google Workspace CSE requires a third-party key service. Google's official partners charge:
- **$10-30 per user/month** minimum
- **Enterprise-only pricing** (often 50+ user minimums)
- **Annual contracts** starting at $6,000+

For individuals or small teams, this is prohibitively expensive.

### The Solution

TinyVault lets you run your own CSE endpoint for **~$0.10-0.50/month** using:
- Google Cloud Run (serverless, free tier available)
- Google Cloud KMS (secure key storage, FIPS 140-2 validated)
- Your own infrastructure and control

---

## ✨ Features

- 🔒 **Secure**: Uses Google Cloud KMS for key management (FIPS 140-2 validated)
- 💰 **Cheap**: Runs in Cloud Run free tier (~$0.10-0.50/month for single user)
- 🚀 **Simple**: Deploy in under 5 minutes with automated scripts
- 🌐 **Custom Domains**: Professional setup with your own domain
- 🐳 **Docker Ready**: Pre-built containers on Docker Hub
- 📝 **Well Documented**: Comprehensive guides and troubleshooting
- 🔓 **Open Source**: MIT licensed, contribute and customize freely

---

## 📋 Prerequisites

1. **Google Cloud Account** with billing enabled (free tier works)
2. **Google Workspace** account (Business Standard or higher for CSE support)
3. **gcloud CLI** installed ([installation guide](https://cloud.google.com/sdk/docs/install))
4. **Admin access** to Google Workspace Admin Console

---

## 🚀 Quick Start

### Option 1: Automated Deployment (Recommended)

```bash
# Clone the repository
git clone https://github.com/shawntz/tinyvault.git
cd tinyvault

# Run setup script
chmod +x setup.sh deploy.sh
./setup.sh

# Deploy to Cloud Run
./deploy.sh
```

The deployment script will:
- ✅ Build and deploy to Cloud Run
- ✅ Configure environment variables
- ✅ Optionally set up custom domain (e.g., `secure.yourdomain.com`)
- ✅ Provide your KACLS endpoint URL

### Option 2: Deploy Pre-Built Image from Docker Hub (Fastest)

Skip building! Deploy the pre-built Docker image directly to Cloud Run:

```bash
# Clone the repository
git clone https://github.com/shawntz/tinyvault.git
cd tinyvault

# Run setup (one time only)
chmod +x setup.sh deploy-dockerhub.sh
./setup.sh

# Deploy from Docker Hub
./deploy-dockerhub.sh
```

This is **faster** than Option 1 since it pulls the pre-built image instead of building on Cloud Run.

### Option 3: Run Locally with Docker

```bash
# Pull the image
docker pull shawnschwartz/tinyvault:latest

# Run with your configuration
docker run -d \
  -p 8080:8080 \
  -e GCP_PROJECT_ID=your-project \
  -e KMS_LOCATION=us-central1 \
  -e KMS_KEYRING=cse-keyring \
  -e KMS_KEY=cse-key \
  -e ALLOWED_EMAILS=your-email@gmail.com \
  -v /path/to/service-account.json:/app/key.json \
  -e GOOGLE_APPLICATION_CREDENTIALS=/app/key.json \
  --name tinyvault \
  shawnschwartz/tinyvault:latest
```

See [DOCKER.md](DOCKER.md) for full Docker documentation.

---

## 📖 Setup Guide

### 1. Initial Setup

Run the setup script to configure GCP resources:

```bash
./setup.sh
```

This will:
- Enable required GCP APIs (Cloud KMS, Cloud Run, Cloud Build)
- Create KMS key ring and encryption key
- Generate example configuration file

You'll be prompted for:
- **GCP Project ID**
- **KMS location** (default: `us-central1`)
- **Your email address** for authorization

### 2. Deploy to Cloud Run

```bash
./deploy.sh
```

During deployment, you'll configure:
- Cloud Run region
- Service name
- **Custom domain** (optional but recommended)

**Recommended**: Use a custom subdomain like:
- `secure.yourdomain.com` (default, privacy-focused)
- `vault.yourdomain.com` (security-focused)
- `cse.yourdomain.com` (technical)

The script handles domain mapping and provides DNS instructions.

### 3. Configure DNS (if using custom domain)

Add this CNAME record at your DNS provider:

```
Type: CNAME
Name: secure (or your chosen subdomain)
Value: ghs.googlehosted.com
TTL: 3600
```

Cloud Run will automatically provision an SSL certificate via Let's Encrypt (5-15 minutes).

### 4. Test Your Endpoint

```bash
# Test health endpoint
curl https://secure.yourdomain.com/health

# Should return: {"status":"healthy"}
```

### 5. Configure Google Workspace

1. Go to **Google Workspace Admin Console** ([admin.google.com](https://admin.google.com))
2. Navigate to: **Security > Access and data control > Data protection > Client-side encryption**
3. Click **Add external key service**
4. Enter:
   - **Service name**: TinyVault (or any name)
   - **Service URL**: `https://secure.yourdomain.com`
   - **Authentication**: OAuth 2.0
5. **Test the connection** (should succeed)
6. **Enable CSE** for your account

### 6. Use CSE in Gmail/Drive

**Gmail:**
1. Compose a new email
2. Click the lock icon > "Additional encryption"
3. Select your TinyVault key service
4. Compose and send encrypted email

**Google Drive:**
1. Create or upload a document
2. Click Share > Advanced > "Client-side encryption"
3. Select TinyVault
4. Share securely

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `GCP_PROJECT_ID` | Your GCP project ID | `my-project-123456` |
| `KMS_LOCATION` | KMS key location | `us-central1` |
| `KMS_KEYRING` | KMS key ring name | `cse-keyring` |
| `KMS_KEY` | KMS crypto key name | `cse-key` |
| `ALLOWED_EMAILS` | Comma-separated authorized emails | `user@gmail.com,team@company.com` |
| `PORT` | Service port (Cloud Run sets automatically) | `8080` |

### Adding More Users

Update the Cloud Run service to add more authorized emails:

```bash
gcloud run services update cse-kacls \
  --region us-central1 \
  --set-env-vars "ALLOWED_EMAILS=user1@gmail.com,user2@gmail.com,user3@gmail.com"
```

### Custom Domain Management

Check domain mapping status:

```bash
gcloud run domain-mappings describe secure.yourdomain.com --region us-central1
```

Update or remove domain mapping:

```bash
# Remove domain
gcloud run domain-mappings delete secure.yourdomain.com --region us-central1

# Add new domain
gcloud run domain-mappings create \
  --service cse-kacls \
  --domain new-subdomain.yourdomain.com \
  --region us-central1
```

---

## 🏗️ Architecture

```
┌─────────────────┐
│  Google Workspace│
│  (Gmail, Drive) │
└────────┬────────┘
         │ KACLS Protocol
         │ (wrap/unwrap keys)
         ▼
┌─────────────────┐
│   TinyVault    │
│  (Cloud Run)    │
│  - Flask API    │
│  - OAuth2 auth  │
└────────┬────────┘
         │
         │ Encrypt/Decrypt
         ▼
┌─────────────────┐
│ Google Cloud KMS│
│  (Master Keys)  │
└─────────────────┘
```

### How It Works

1. **Client-side encryption**: Google Workspace encrypts content in your browser/app with a Data Encryption Key (DEK)
2. **Key wrapping**: Workspace calls TinyVault to wrap (encrypt) the DEK
3. **KMS encryption**: TinyVault uses Google Cloud KMS to encrypt the DEK with your master key
4. **Storage**: Wrapped DEK is stored with the encrypted content
5. **Decryption**: Reverse process to unwrap and decrypt content

**Important**: Your master encryption key **never leaves Google Cloud KMS**. All operations happen securely within Google's infrastructure.

---

## 🔒 Security

### Security Maturity Level

**Current Status**: ⚠️ **Prototype / Personal Use**

TinyVault is:
- ❌ **NOT security audited** by third-party professionals
- ❌ **NOT penetration tested**
- ❌ **NOT certified** for any compliance framework (HIPAA, PCI, FedRAMP, SOC 2, etc.)
- ❌ **NOT recommended** for production enterprise use without significant hardening
- ❌ **NOT a replacement** for professionally audited enterprise CSE solutions

TinyVault IS:
- ✅ **Good for**: Personal use, learning, experimentation, non-critical data
- ✅ **Open source**: Code is transparent and auditable (by you or security professionals you hire)
- ✅ **Based on secure components**: Uses Google Cloud KMS and Cloud Run

**If you need compliance certification**, you are responsible for:
- Hiring security auditors
- Penetration testing
- Code review
- Compliance documentation
- Risk assessment
- Incident response planning

### What IS Secure (Google Cloud Components)

The underlying Google Cloud infrastructure TinyVault uses:

**Google Cloud KMS** (where keys are stored):
- ✅ FIPS 140-2 Level 3 validated hardware security modules
- ✅ ISO/IEC 27001 certified
- ✅ SOC 2/3 compliant
- ✅ HIPAA eligible (with BAA)
- ✅ PCI DSS compliant

**Google Cloud Run** (where TinyVault runs):
- ✅ HTTPS enforced (TLS 1.2+)
- ✅ Automatic SSL certificates
- ✅ ISO 27001, SOC 2/3 certified
- ✅ Infrastructure security managed by Google

### What IS NOT Secure (TinyVault Application)

**TinyVault application code**:
- ⚠️ No professional security audit
- ⚠️ No penetration testing
- ⚠️ No formal threat modeling
- ⚠️ No security certifications
- ⚠️ Minimal input validation
- ⚠️ No rate limiting by default
- ⚠️ No WAF (Web Application Firewall) by default
- ⚠️ Unauthenticated Cloud Run endpoint (by design for KACLS protocol)

### Security Architecture

**What's good**:
- ✅ Master encryption keys **never leave Google Cloud KMS** (FIPS 140-2 validated HSMs)
- ✅ Keys are **never exposed** to the application or stored anywhere except KMS
- ✅ OAuth2 token verification for incoming requests
- ✅ Email-based authorization (restrict to specific users)
- ✅ All KMS operations logged via Cloud Audit Logs
- ✅ HTTPS-only connections enforced by Cloud Run
- ✅ Encrypted data at rest (wrapped DEKs stored with encrypted content)

**What could be better**:
- ⚠️ No rate limiting (could be DDoS'd)
- ⚠️ Cloud Run endpoint is public (required for Google Workspace, but increases attack surface)
- ⚠️ No request signing/validation beyond OAuth2 token
- ⚠️ No anomaly detection
- ⚠️ No intrusion detection
- ⚠️ Minimal monitoring by default

### Security Recommendations by Use Case

#### ✅ Personal Use (1-5 people, non-sensitive data)
- Current security is **adequate**
- Follow the basic security checklist below
- Accept that this is DIY software

#### ⚠️ Small Team (5-20 people, somewhat sensitive data)
- Current security is **marginal**
- **Add**: Rate limiting, WAF (Cloud Armor), monitoring alerts
- **Consider**: Security code review by a professional
- **Accept risk**: This is not enterprise-grade

#### ❌ Enterprise / Regulated Data (HIPAA, PCI, etc.)
- Current security is **insufficient**
- **Required**: Full security audit, penetration testing, compliance documentation
- **Required**: Hire security professionals to harden
- **Recommended**: Use a professionally audited CSE partner instead

### Minimum Security Checklist

Before using TinyVault, at minimum:

- [ ] Set `ALLOWED_EMAILS` to specific users (never leave empty)
- [ ] Use a custom domain with SSL
- [ ] Enable Cloud Audit Logs for KMS
- [ ] Set up alerting for unusual KMS activity
- [ ] Review Cloud Run logs weekly
- [ ] Use least-privilege IAM roles
- [ ] Keep dependencies updated (Dependabot helps automatically)
- [ ] Review and merge Dependabot security PRs promptly
- [ ] Monitor GitHub Security tab for alerts
- [ ] Understand you're using unaudited software
- [ ] Have a backup plan if TinyVault fails
- [ ] Don't use for data you can't afford to lose access to

### Automated Security Tooling

TinyVault includes **automated security scanning** to help catch vulnerabilities:

#### 🤖 Dependabot
- ✅ **Weekly dependency updates** for Python, Docker, GitHub Actions
- ✅ **Automatic security patch PRs** when vulnerabilities are found
- ✅ Groups minor/patch updates to reduce PR noise
- 📍 Configuration: `.github/dependabot.yml`

#### 🔍 CodeQL Analysis
- ✅ **Automatic code scanning** on every push and PR
- ✅ **Weekly scheduled scans** for new vulnerability patterns
- ✅ Detects: SQL injection, XSS, insecure crypto, etc.
- 📍 Configuration: `.github/workflows/security.yml`

#### 🛡️ Dependency Review
- ✅ **Blocks PRs** with high-severity vulnerabilities
- ✅ **Automatic comments** on PRs with security findings
- ✅ Runs on all pull requests

#### 🔐 Python Security Audit
- ✅ **Safety**: Checks dependencies against CVE database
- ✅ **Bandit**: Static analysis for Python security issues
- ✅ Generates reports as artifacts

**View alerts:** `https://github.com/shawntz/tinyvault/security`

**Important:** ⚠️ Automated tools only catch **known** vulnerabilities. They are NOT a substitute for professional security audits. See [SECURITY.md](SECURITY.md) for details.

---

## 💰 Cost Breakdown

### Single User

| Service | Usage | Cost/Month |
|---------|-------|------------|
| Cloud Run | ~1000 requests | **$0.00** (free tier) |
| Cloud KMS | Key storage | $0.06 |
| Cloud KMS | ~1000 operations | $0.00 (free tier) |
| **Total** | | **~$0.06-0.10** |

### Small Team (5 users)

| Service | Usage | Cost/Month |
|---------|-------|------------|
| Cloud Run | ~5000 requests | **$0.00** (free tier) |
| Cloud KMS | Key storage | $0.06 |
| Cloud KMS | ~5000 operations | $0.02 |
| **Total** | | **~$0.08-0.20** |

### Free Tier Limits

- **Cloud Run**: 2M requests/month, 360,000 GB-seconds compute
- **Cloud KMS**: 20,000 operations/month (encrypt/decrypt)

**You'll likely stay in free tier** unless you have >10 active users.

### Enterprise CSE Comparison

| Solution | Cost (1 user/year) | Cost (5 users/year) |
|----------|-------------------|---------------------|
| **TinyVault** | **$1-2** | **$2-5** |
| Enterprise CSE Partner | $120-360 | $600-1800 |
| **Savings** | **99%** | **99%** |

---

## 🛠️ API Endpoints

TinyVault implements the Google Workspace KACLS protocol:

### `GET /health`

Health check endpoint for monitoring.

**Response:**
```json
{"status": "healthy"}
```

### `POST /v1/wrap`

Wraps (encrypts) a data encryption key using KMS.

**Request:**
```json
{
  "key": "base64-encoded-plaintext-DEK",
  "authorization": {
    "resource_name": "resource-identifier",
    "user_email": "user@example.com"
  }
}
```

**Response:**
```json
{
  "wrappedKey": "base64-encoded-wrapped-DEK",
  "status": "success"
}
```

### `POST /v1/unwrap`

Unwraps (decrypts) a data encryption key using KMS.

**Request:**
```json
{
  "wrappedKey": "base64-encoded-wrapped-DEK",
  "authorization": {
    "resource_name": "resource-identifier",
    "user_email": "user@example.com"
  }
}
```

**Response:**
```json
{
  "key": "base64-encoded-plaintext-DEK",
  "status": "success"
}
```

### `POST /v1/privileged_unwrap`

Admin unwrap for privileged access scenarios (e.g., compliance, audit).

**Request:**
```json
{
  "wrappedKey": "base64-encoded-wrapped-DEK",
  "reason": "Legal hold request #12345"
}
```

**Response:**
```json
{
  "key": "base64-encoded-plaintext-DEK",
  "status": "success"
}
```

---

## 🐳 Docker Deployment

### Pull from Docker Hub

```bash
docker pull shawnschwartz/tinyvault:latest
```

### Run Locally

```bash
# Using service account key
docker run -d \
  -p 8080:8080 \
  -e GCP_PROJECT_ID=your-project \
  -e KMS_LOCATION=us-central1 \
  -e KMS_KEYRING=cse-keyring \
  -e KMS_KEY=cse-key \
  -e ALLOWED_EMAILS=your@email.com \
  -v $(pwd)/service-account-key.json:/app/key.json \
  -e GOOGLE_APPLICATION_CREDENTIALS=/app/key.json \
  --name tinyvault \
  shawnschwartz/tinyvault:latest
```

### Docker Compose

```yaml
version: '3.8'

services:
  tinyvault:
    image: shawnschwartz/tinyvault:latest
    ports:
      - "8080:8080"
    environment:
      - GCP_PROJECT_ID=your-project
      - KMS_LOCATION=us-central1
      - KMS_KEYRING=cse-keyring
      - KMS_KEY=cse-key
      - ALLOWED_EMAILS=your@email.com
      - GOOGLE_APPLICATION_CREDENTIALS=/app/key.json
    volumes:
      - ./service-account-key.json:/app/key.json:ro
    restart: unless-stopped
```

See [DOCKER.md](DOCKER.md) for complete Docker documentation.

---

## 📊 Monitoring & Logging

### View Logs

```bash
# Cloud Run logs
gcloud run logs read cse-kacls --region us-central1 --limit 50

# KMS audit logs
gcloud logging read "resource.type=cloudkms_cryptokeyversion" --limit 50

# Filter for errors
gcloud run logs read cse-kacls --region us-central1 | grep ERROR
```

### Set Up Alerts

Create Cloud Monitoring alerts for:

1. **High error rate** (>5% of requests failing)
2. **Unusual KMS activity** (sudden spike in operations)
3. **Unauthorized access attempts** (401/403 responses)

```bash
# Example: Alert on error rate
gcloud alpha monitoring policies create \
  --notification-channels=YOUR_CHANNEL_ID \
  --display-name="TinyVault Error Rate" \
  --condition-threshold-value=0.05 \
  --condition-display-name="Error rate > 5%"
```

### Performance Metrics

Monitor via Cloud Console:
- Request count
- Request latency (p50, p95, p99)
- Error rate
- Container instance count
- KMS operation count

---

## 🔧 Troubleshooting

### "Permission denied" when accessing KMS

**Fix**: Grant the Cloud Run service account KMS permissions:

```bash
# Get service account email
gcloud run services describe cse-kacls \
  --region us-central1 \
  --format="value(spec.template.spec.serviceAccountName)"

# Grant KMS permissions
gcloud kms keys add-iam-policy-binding cse-key \
  --location us-central1 \
  --keyring cse-keyring \
  --member serviceAccount:PROJECT_NUMBER-compute@developer.gserviceaccount.com \
  --role roles/cloudkms.cryptoKeyEncrypterDecrypter
```

### Connection test fails in Workspace Admin Console

1. Verify endpoint is accessible: `curl https://your-url/health`
2. Check Cloud Run allows unauthenticated access (required for Workspace to connect)
3. Review Cloud Run logs for errors during connection test
4. Ensure `ALLOWED_EMAILS` includes the test user's email

### "Invalid token" errors in logs

Check that `ALLOWED_EMAILS` matches the email in the OAuth token:

```bash
gcloud run services describe cse-kacls \
  --region us-central1 \
  --format="value(spec.template.spec.containers[0].env)"
```

### Custom domain SSL not provisioning

1. Verify DNS record is correct: `dig secure.yourdomain.com`
2. Wait 15-30 minutes for DNS propagation
3. Check domain mapping status:
   ```bash
   gcloud run domain-mappings describe secure.yourdomain.com --region us-central1
   ```
4. Ensure domain is verified in Google Search Console

### High KMS costs

Check operation count:

```bash
gcloud logging read "resource.type=cloudkms_cryptokeyversion" \
  --format="table(timestamp,protoPayload.methodName)" \
  --freshness=30d
```

If unusually high:
- Review authorized users (compromised account?)
- Check for automated scripts making excessive requests
- Consider caching wrapped keys (advanced)

---

## 🚀 Advanced Usage

### Multiple Environments

Run separate instances for dev/staging/prod:

```bash
# Deploy staging
gcloud run deploy cse-kacls-staging \
  --source . \
  --region us-central1 \
  --set-env-vars "GCP_PROJECT_ID=project,KMS_KEYRING=cse-staging,..."

# Deploy production
gcloud run deploy cse-kacls \
  --source . \
  --region us-central1 \
  --set-env-vars "GCP_PROJECT_ID=project,KMS_KEYRING=cse-prod,..."
```

### Key Rotation

Rotate KMS keys periodically for security:

```bash
# Create new key version
gcloud kms keys versions create \
  --key cse-key \
  --keyring cse-keyring \
  --location us-central1

# Set as primary
gcloud kms keys update cse-key \
  --keyring cse-keyring \
  --location us-central1 \
  --primary-version VERSION_NUMBER

# Disable old version (after grace period)
gcloud kms keys versions disable OLD_VERSION \
  --key cse-key \
  --keyring cse-keyring \
  --location us-central1
```

**Note**: Old key versions must remain enabled to decrypt existing content.

### Multi-Region Deployment

Deploy to multiple regions for redundancy:

```bash
# Deploy to us-central1
gcloud run deploy cse-kacls --region us-central1 --source .

# Deploy to europe-west1
gcloud run deploy cse-kacls --region europe-west1 --source .

# Use Global Load Balancer to route traffic
```

### Require Cloud Run Authentication

For extra security, require IAM authentication:

```bash
# Remove public access
gcloud run services remove-iam-policy-binding cse-kacls \
  --region us-central1 \
  --member="allUsers" \
  --role="roles/run.invoker"

# Grant specific service account
gcloud run services add-iam-policy-binding cse-kacls \
  --region us-central1 \
  --member="serviceAccount:workspace-cse@project.iam.gserviceaccount.com" \
  --role="roles/run.invoker"
```

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone repo
git clone https://github.com/shawntz/tinyvault.git
cd tinyvault

# Install dependencies
pip install -r requirements.txt

# Set up environment
cp .env.example .env
nano .env

# Run locally
python app.py
```

### Running Tests

```bash
# Install dev dependencies
pip install pytest pytest-flask

# Run tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html
```

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

### What This Means

- ✅ Use commercially
- ✅ Modify and distribute
- ✅ Private use
- ✅ No warranty provided

---

## 🙏 Acknowledgments

- Google Cloud Platform for KMS and Cloud Run
- Google Workspace for CSE APIs
- The Flask community for excellent documentation
- Everyone who makes expensive software free and accessible

---

## ⚠️ Disclaimer

### Legal & Affiliation

**Not affiliated with Google.** Google, Google Workspace, Google Cloud, Gmail, Google Drive, and Cloud Run are trademarks of Google LLC. TinyVault is an independent, open-source project.

### No Warranty

This software is provided **"AS IS" WITHOUT WARRANTY OF ANY KIND**, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. See the [MIT License](LICENSE) for full terms.

### Use at Your Own Risk

- ⚠️ TinyVault has **NOT been professionally security audited**
- ⚠️ TinyVault has **NOT been penetration tested**
- ⚠️ TinyVault is **NOT certified** for any compliance framework
- ⚠️ The authors and contributors are **NOT liable** for data loss, security breaches, or compliance failures
- ⚠️ You are **solely responsible** for evaluating the security and suitability for your use case

### Security Responsibility

**You are responsible for**:
- Understanding the security limitations
- Performing your own security assessment
- Implementing additional security controls as needed
- Maintaining and monitoring your deployment
- Compliance with applicable laws and regulations
- Data backup and disaster recovery

### Not a Professional Service

TinyVault is a **DIY hobby project**, not a professional managed service. There is:
- ❌ No SLA (Service Level Agreement)
- ❌ No guaranteed uptime
- ❌ No professional support (community support only)
- ❌ No liability for failures
- ❌ No warranty of fitness for any particular use

### Appropriate Use

**Use TinyVault for**:
- ✅ Personal experimentation and learning
- ✅ Non-critical data protection
- ✅ Understanding how CSE works
- ✅ Saving money on personal use cases

**DO NOT use TinyVault for** (without extensive hardening and professional security review):
- ❌ HIPAA-protected health information
- ❌ PCI DSS payment card data
- ❌ Mission-critical business data
- ❌ Data you can't afford to lose
- ❌ Regulated financial data
- ❌ Government classified information
- ❌ Any compliance-required use case

### Test Before Production

**Always**:
- Test thoroughly with non-sensitive data first
- Understand how to recover if TinyVault fails
- Have backups of critical data
- Monitor logs and alerts
- Keep dependencies updated
- Review security best practices regularly

**By using TinyVault, you acknowledge and accept these risks.**

---

## 📞 Support

- **Documentation**: This README and inline code comments
- **Issues**: [GitHub Issues](https://github.com/shawntz/tinyvault/issues)
- **Discussions**: [GitHub Discussions](https://github.com/shawntz/tinyvault/discussions)

For security vulnerabilities, please email: [Your security contact email]

---

## 📦 Versioning

TinyVault uses **automated date-based semantic versioning**: `YYYY.MM.PATCH`

### Version Format

- **YYYY**: Year (e.g., 2025)
- **MM**: Month (01-12, zero-padded)
- **PATCH**: Auto-incrementing number for each release in that month

### Examples

- `2025.01.0` - First release in January 2025
- `2025.01.1` - Second release in January 2025
- `2025.10.0` - First release in October 2025

### How It Works

1. Every push to `main` automatically generates a new version
2. GitHub Actions calculates the version based on current date
3. Auto-increments the patch number for the current month
4. Creates a Git tag and GitHub release
5. Builds and pushes Docker images with that version tag

### Docker Tags

Every release creates two Docker tags:
```bash
shawnschwartz/tinyvault:2025.10.0  # Specific version
shawnschwartz/tinyvault:latest     # Always points to latest
```

### Using Specific Versions

```bash
# Pull specific version
docker pull shawnschwartz/tinyvault:2025.10.0

# Deploy specific version to Cloud Run
gcloud run deploy cse-kacls \
  --image shawnschwartz/tinyvault:2025.10.0 \
  --region us-central1
```

See [CHANGELOG.md](CHANGELOG.md) for version history.

---

## 🗺️ Roadmap

- [ ] Multi-key support (different keys per user/department)
- [ ] Web UI for management
- [ ] Automated key rotation
- [ ] Terraform deployment templates
- [ ] AWS KMS support
- [ ] Azure Key Vault support
- [ ] HashiCorp Vault integration
- [ ] Metrics dashboard
- [ ] Slack/Discord notifications for KMS events

---

**Made with ❤️ for the open source community**

*Save thousands on enterprise CSE. Encrypt everything.*
