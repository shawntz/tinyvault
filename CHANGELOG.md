# Changelog

All notable changes to TinyVault will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Versioning Scheme

TinyVault uses **date-based semantic versioning**: `YYYY.MM.PATCH`

- **YYYY**: Year (e.g., 2025)
- **MM**: Month (e.g., 01 for January, 10 for October)
- **PATCH**: Auto-incrementing patch number for each release in that month (starts at 0)

**Examples:**
- `2025.01.0` - First release in January 2025
- `2025.01.1` - Second release in January 2025
- `2025.02.0` - First release in February 2025

**Versions are automatically generated** on each push to `main` via GitHub Actions.

---

## [Unreleased]

### Planned
- Unit and integration tests
- AWS KMS support
- Azure Key Vault support
- Terraform deployment templates
- Web UI for management
- Rate limiting
- Enhanced monitoring and alerting

---

## [2025.10.0] - 2025-10-14

### Added
- Initial public release of TinyVault
- Flask-based KACLS endpoint implementation
- Google Cloud KMS integration for key wrapping/unwrapping
- OAuth2 token verification for authentication
- Email-based authorization system
- Automated deployment scripts:
  - `setup.sh` - GCP resource setup
  - `deploy.sh` - Deploy from source to Cloud Run
  - `deploy-dockerhub.sh` - Deploy from Docker Hub (fastest)
- Docker support with multi-platform builds (amd64, arm64)
- Custom domain support via Cloud Run domain mapping
- Health check endpoint (`/health`)
- Comprehensive documentation (README, SECURITY, CONTRIBUTING)
- GitHub Actions workflow for automated Docker Hub publishing
- Automated date-based semantic versioning
- MIT License

### Security
- FIPS 140-2 validated key storage via Google Cloud KMS
- HTTPS-only enforcement via Cloud Run
- OAuth2 service account token verification
- Email-based access control
- Cloud Audit Logs integration for KMS operations
- Comprehensive security disclaimers and warnings

### Infrastructure
- Google Cloud Run deployment support
- Docker containerization (multi-arch)
- Environment-based configuration
- Automated SSL certificate provisioning via Let's Encrypt
- GitHub Actions CI/CD pipeline
- Docker Hub image registry

### Documentation
- Detailed README with security warnings
- Security policy and vulnerability reporting process
- Contributing guidelines
- Compliance information (what IS and ISN'T certified)
- Use case recommendations (personal vs enterprise)
- Cost breakdown and comparison

---

## Version History

- **2025.10.0** - Initial public release (October 2025)
