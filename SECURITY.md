# Security Policy

> ⚠️ **IMPORTANT**: TinyVault is an **unaudited, open-source project** for personal use and learning. It has NOT been professionally security audited, penetration tested, or certified for any compliance framework. This security policy is for community-driven security improvements, not a guarantee of security. **Use at your own risk.**

## Security Maturity

**Current Status**: Prototype / Personal Use Only

- ❌ No professional security audit
- ❌ No penetration testing
- ❌ No compliance certifications (HIPAA, PCI, FedRAMP, SOC 2, etc.)
- ❌ Not recommended for production enterprise use
- ✅ Good for: Personal use, learning, non-critical data

For detailed security information, see the [Security section in README](README.md#-security).

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: [Your security contact email]

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

### What to Include

Please include the following information in your report:

- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability, including how an attacker might exploit it

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - Critical: 24-48 hours
  - High: 7 days
  - Medium: 30 days
  - Low: 90 days

### Disclosure Policy

- We will coordinate disclosure timing with you
- We prefer coordinated disclosure after a fix is available
- We will credit you in the CHANGELOG and security advisory (unless you prefer to remain anonymous)

## Automated Security Tooling

TinyVault includes automated security scanning and dependency management:

### Dependabot

**What it does:**
- Automatically checks for dependency updates weekly
- Creates pull requests for security patches
- Monitors Python dependencies (pip)
- Monitors GitHub Actions versions
- Monitors Docker base image updates

**Configuration:** `.github/dependabot.yml`

**Schedule:** Weekly on Mondays at 09:00 UTC

### CodeQL Analysis

**What it does:**
- Automatic code security scanning
- Detects common vulnerabilities (SQL injection, XSS, etc.)
- Runs on every push and pull request
- Weekly scheduled scans

**Configuration:** `.github/workflows/security.yml`

**Coverage:**
- Python code analysis
- Security and quality queries
- Results visible in Security tab

### Dependency Review

**What it does:**
- Reviews new dependencies in pull requests
- Blocks PRs with high-severity vulnerabilities
- Comments on PRs with security findings

**Triggers:** Runs automatically on all pull requests

### Python Security Audit

**What it does:**
- **Safety**: Checks dependencies against vulnerability database
- **Bandit**: Static security analysis for Python code
- Generates security reports as artifacts

**Schedule:** Runs on every push

### Viewing Security Alerts

**GitHub Security Tab:**
1. Go to repository on GitHub
2. Click **Security** tab
3. View:
   - Dependabot alerts
   - CodeQL findings
   - Secret scanning alerts (if enabled)

**Example:** `https://github.com/shawntz/tinyvault/security`

### Responding to Alerts

When Dependabot or CodeQL finds an issue:

1. **Review the alert** in GitHub Security tab
2. **Assess severity** (Critical, High, Medium, Low)
3. **For Dependabot PRs:**
   - Review the PR created by Dependabot
   - Check for breaking changes
   - Merge if safe, or investigate further
4. **For CodeQL alerts:**
   - Review the code flagged
   - Determine if it's a real vulnerability or false positive
   - Fix the issue and push changes

### Limitations

⚠️ **Automated tools don't replace professional audits:**
- Tools only catch **known** vulnerabilities
- May produce false positives
- Won't catch logic bugs or design flaws
- No substitute for security code review

## Security Best Practices

When deploying TinyVault:

### Required

- ✅ Use Google Cloud KMS for key storage (never local storage)
- ✅ Set `ALLOWED_EMAILS` to specific users (don't leave empty/wildcard)
- ✅ Enable Cloud Audit Logs for KMS operations
- ✅ Use HTTPS-only (Cloud Run enforces this by default)
- ✅ Keep dependencies updated (Dependabot helps with this)
- ✅ Review and merge Dependabot PRs promptly

### Recommended

- ✅ Use custom domain with SSL
- ✅ Set up alerting for unusual KMS activity
- ✅ Rotate KMS keys periodically
- ✅ Review Cloud Run logs regularly
- ✅ Use least-privilege IAM roles
- ✅ Enable Cloud Armor for DDoS protection (if high-value target)

### Advanced

- ✅ Require Cloud Run authentication (IAM-based)
- ✅ Implement rate limiting
- ✅ Use VPC Service Controls to restrict KMS access
- ✅ Enable Binary Authorization for container images
- ✅ Use Workload Identity for GKE deployments

## Known Security Considerations

### Google Workspace Access

- TinyVault requires unauthenticated Cloud Run access by default to allow Google Workspace to call the endpoints
- This is by design per the KACLS protocol
- Authorization is handled at the application level via OAuth2 tokens and email allowlists

### Key Security

- Master encryption keys never leave Google Cloud KMS
- All key operations occur within KMS (FIPS 140-2 validated)
- Wrapped keys are safe to store (cannot be decrypted without KMS access)

### Service Account

- Cloud Run service account needs KMS encrypt/decrypt permissions
- Use least-privilege: only grant access to specific key ring/key
- Never use service accounts with broader permissions

## Compliance

### Google Cloud Infrastructure Compliance

The underlying Google Cloud infrastructure TinyVault uses is certified:

**Google Cloud KMS** (key storage):
- **FIPS 140-2 Level 3** validated HSMs
- **ISO/IEC 27001** certified
- **SOC 2/3** compliant
- **HIPAA** eligible (with BAA)
- **PCI DSS** compliant

**Google Cloud Run** (application hosting):
- **ISO 27001** certified
- **SOC 2/3** compliant
- **HIPAA** eligible (with BAA)

### TinyVault Application Compliance

**TinyVault itself is NOT certified or compliant** with:
- ❌ HIPAA
- ❌ PCI DSS
- ❌ FedRAMP
- ❌ SOC 2
- ❌ ISO 27001
- ❌ Any other compliance framework

**Using compliant infrastructure does NOT make TinyVault compliant.**

### What This Means

- ✅ Your encryption keys are stored in FIPS 140-2 validated HSMs (secure)
- ✅ The infrastructure is certified (good foundation)
- ❌ TinyVault application code is NOT audited or certified
- ❌ You CANNOT claim HIPAA/PCI/etc. compliance by using TinyVault
- ❌ Using TinyVault does NOT satisfy compliance requirements

**If you need compliance**:
1. Hire security professionals to audit and harden TinyVault
2. Obtain your own certifications
3. Document security controls
4. Implement compliance procedures
5. OR use a professionally certified CSE partner instead

## Security Updates

Security updates will be released as:
- Patch versions (1.0.x) for security fixes
- Announced in CHANGELOG.md and GitHub releases
- Tagged with "security" label

Subscribe to [GitHub releases](https://github.com/shawntz/tinyvault/releases) to be notified.

## Bug Bounty

We currently do not offer a bug bounty program, but we deeply appreciate responsible disclosure and will credit researchers who report valid vulnerabilities.

---

**Thank you for helping keep TinyVault secure!** 🔐
