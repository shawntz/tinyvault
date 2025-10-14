# TinyVault Versioning System

## Overview

TinyVault uses **fully automated date-based semantic versioning** with the format:

```
YYYY.MM.PATCH
```

## Version Components

| Component | Description | Example |
|-----------|-------------|---------|
| **YYYY** | Year | `2025` |
| **MM** | Month (zero-padded) | `01` (January), `10` (October) |
| **PATCH** | Auto-incrementing patch number | `0`, `1`, `2`, etc. |

## Version Examples

```
2025.01.0  →  First release in January 2025
2025.01.1  →  Second release in January 2025
2025.01.2  →  Third release in January 2025
2025.02.0  →  First release in February 2025 (patch resets)
2025.10.0  →  First release in October 2025
```

## How It Works

### Automatic Version Generation

Every push to `main` triggers the GitHub Actions workflow:

1. **Calculate Date**
   ```bash
   YEAR=$(date +%Y)    # e.g., 2025
   MONTH=$(date +%m)   # e.g., 10
   ```

2. **Find Existing Tags**
   ```bash
   git tag -l "2025.10.*"  # Find all tags for current month
   ```

3. **Increment Patch**
   - If no tags exist for current month: `PATCH=0`
   - If tags exist: Find highest patch number and add 1

4. **Create Tag**
   ```bash
   git tag -a "2025.10.0" -m "Release 2025.10.0"
   git push origin "2025.10.0"
   ```

5. **Build & Publish**
   - Build Docker images (multi-arch: amd64, arm64)
   - Push to Docker Hub with version tag
   - Push to Docker Hub with `latest` tag
   - Create GitHub Release with auto-generated notes

## Docker Tags

Every release creates **two tags** on Docker Hub:

```bash
shawnschwartz/tinyvault:2025.10.0   # Specific version
shawnschwartz/tinyvault:latest      # Always latest release
```

### Using Specific Versions

**Docker:**
```bash
# Pull specific version
docker pull shawnschwartz/tinyvault:2025.10.0

# Run specific version
docker run -d shawnschwartz/tinyvault:2025.10.0
```

**Cloud Run:**
```bash
# Deploy specific version
gcloud run deploy cse-kacls \
  --image shawnschwartz/tinyvault:2025.10.0 \
  --region us-central1
```

**Docker Compose:**
```yaml
services:
  tinyvault:
    image: shawnschwartz/tinyvault:2025.10.0  # Pin to version
```

## GitHub Releases

Each version automatically creates a GitHub Release with:

- **Tag name**: Version number (e.g., `2025.10.0`)
- **Release title**: "Release 2025.10.0"
- **Release notes**: Auto-generated with:
  - Timestamp
  - Commit SHA
  - Docker pull commands
  - Deployment instructions
  - Link to CHANGELOG

## Version Timeline

```
Oct 14, 2025  →  2025.10.0  (Initial release)
Oct 15, 2025  →  2025.10.1  (Bug fix)
Oct 20, 2025  →  2025.10.2  (Feature update)
Nov 1, 2025   →  2025.11.0  (New month, patch resets)
Nov 5, 2025   →  2025.11.1  (Update)
```

## Benefits

### ✅ Pros

- **Fully automated** - No manual version management
- **Date-based** - Easy to see when a version was released
- **Predictable** - Clear pattern, no arbitrary numbers
- **Monthly releases** - Patch number shows release frequency
- **No breaking changes** - Every push is treated as a patch

### ⚠️ Considerations

- **No semantic meaning** - Can't tell if it's a feature or bug fix from version
  - Solution: Use CHANGELOG.md to document changes
- **Patch resets monthly** - `2025.01.9` → `2025.02.0`
  - This is intentional and expected
- **Assumes monthly cadence** - Best for projects with regular releases

## Workflow Details

### GitHub Actions Workflow

File: `.github/workflows/docker-publish.yml`

**Triggers:**
- Push to `main` branch
- Pull requests (builds but doesn't publish)

**Steps:**
1. Checkout code (full history)
2. Generate version tag based on date
3. Create and push Git tag
4. Set up Docker Buildx
5. Log in to Docker Hub
6. Build and push Docker images
7. Create GitHub Release
8. Update Docker Hub description

### Environment Variables

Required GitHub Secrets:
- `DOCKER_USERNAME` - Your Docker Hub username
- `DOCKER_PASSWORD` - Docker Hub access token
- `GITHUB_TOKEN` - Auto-provided by GitHub Actions

## Version History

All versions are tracked in:
- **Git tags**: `git tag -l`
- **GitHub Releases**: `https://github.com/shawntz/tinyvault/releases`
- **Docker Hub**: `https://hub.docker.com/r/shawnschwartz/tinyvault/tags`
- **CHANGELOG.md**: Manual documentation of changes

## Migration from Old Versions

If you were using old version format (e.g., `v1.0.0`):

```bash
# Old tags won't conflict with new date-based tags
git tag -l "v*"      # Old tags
git tag -l "20*"     # New date-based tags

# You can keep both or delete old tags:
git tag -d v1.0.0
git push origin :refs/tags/v1.0.0
```

## FAQ

**Q: What if I push multiple times in one day?**
A: Each push increments the patch number (e.g., `2025.10.0` → `2025.10.1` → `2025.10.2`)

**Q: Can I manually create a version?**
A: Yes, but not recommended. The workflow auto-generates versions. If you manually tag, make sure to follow the `YYYY.MM.PATCH` format.

**Q: What happens at the start of a new month?**
A: Patch resets to 0 (e.g., `2025.10.5` → `2025.11.0`)

**Q: Can I skip versions?**
A: No, versions are sequential based on Git tags. Each push increments the patch.

**Q: How do I know what changed between versions?**
A: Check [CHANGELOG.md](CHANGELOG.md) or the GitHub Release notes.

**Q: Can I deploy an old version?**
A: Yes! All versions remain on Docker Hub. Just specify the version tag:
```bash
docker pull shawnschwartz/tinyvault:2025.10.0
```

---

**See Also:**
- [CHANGELOG.md](CHANGELOG.md) - Detailed change history
- [README.md](README.md#-versioning) - Versioning section
- [Releases](https://github.com/shawntz/tinyvault/releases) - All releases
