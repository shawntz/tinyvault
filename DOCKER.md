# TinyVault

**DIY Google Workspace Client-Side Encryption (CSE) endpoint**

~$0.10/month encryption for personal use and learning.

> ⚠️ **DISCLAIMER**: TinyVault is an unaudited open-source project for personal use. NOT certified for HIPAA, PCI, or other compliance. Use at your own risk. See full disclaimer in README.

## What is TinyVault?

TinyVault is a self-hosted KACLS (Key Access Control List Service) endpoint that enables Google Workspace Client-Side Encryption for individuals and small teams. Instead of paying thousands for enterprise CSE solutions, run your own for pennies per month.

**Best for**: Personal use, learning, non-critical data
**NOT for**: HIPAA/PCI/regulated data, mission-critical enterprise use

## Quick Start with Docker

```bash
docker run -d \
  -p 8080:8080 \
  -e GCP_PROJECT_ID=your-project \
  -e KMS_LOCATION=us-central1 \
  -e KMS_KEYRING=cse-keyring \
  -e KMS_KEY=cse-key \
  -e ALLOWED_EMAILS=your-email@gmail.com \
  --name tinyvault \
  shawnschwartz/tinyvault:latest
```

## What You Need

1. Google Cloud account (free tier works)
2. Google Workspace account (Business Standard+)
3. Google Cloud KMS key (created via setup script)

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GCP_PROJECT_ID` | Yes | Your GCP project ID |
| `KMS_LOCATION` | Yes | KMS region (e.g., `us-central1`) |
| `KMS_KEYRING` | Yes | KMS key ring name |
| `KMS_KEY` | Yes | KMS crypto key name |
| `ALLOWED_EMAILS` | Yes | Comma-separated authorized emails |
| `PORT` | No | Service port (default: 8080) |

## Authentication

The container needs access to Google Cloud KMS. Provide credentials via:

**Service Account Key** (recommended for production):
```bash
docker run -d \
  -v /path/to/service-account.json:/app/key.json \
  -e GOOGLE_APPLICATION_CREDENTIALS=/app/key.json \
  -e GCP_PROJECT_ID=your-project \
  ...
```

**Application Default Credentials** (for testing):
```bash
gcloud auth application-default login
docker run -d \
  -v ~/.config/gcloud:/root/.config/gcloud:ro \
  -e GCP_PROJECT_ID=your-project \
  ...
```

## Production Deployment

**Recommended**: Deploy to Google Cloud Run for:
- Automatic HTTPS
- Auto-scaling
- Free tier (2M requests/month)
- Custom domain support

See the [full documentation](https://github.com/shawntz/tinyvault) for deployment guides.

## Cost Estimate

- **Cloud Run**: Free tier (single user)
- **Cloud KMS**: ~$0.06/month + $0.03 per 10k operations
- **Total**: ~$0.10-0.50/month

## Security

- Uses Google Cloud KMS (FIPS 140-2 validated)
- Keys never leave KMS
- All encryption happens client-side
- OAuth2 token verification
- Audit logging via Cloud Logging

## Links

- **GitHub**: https://github.com/shawntz/tinyvault
- **Documentation**: https://github.com/shawntz/tinyvault#readme
- **Issues**: https://github.com/shawntz/tinyvault/issues
- **License**: MIT

## Support

This is open-source software. For issues and questions, please use GitHub Issues.

---

**Not affiliated with Google.** Google Workspace and Google Cloud are trademarks of Google LLC.
