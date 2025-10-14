# Contributing to TinyVault

Thank you for your interest in contributing to TinyVault! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Assume good intentions

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/shawntz/tinyvault/issues)
2. If not, create a new issue with:
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, GCP region, etc.)
   - Relevant logs or error messages

### Suggesting Features

1. Check [existing issues](https://github.com/shawntz/tinyvault/issues) and [discussions](https://github.com/shawntz/tinyvault/discussions)
2. Create a new discussion or issue with:
   - Clear description of the feature
   - Use case and motivation
   - Potential implementation approach (if you have ideas)

### Pull Requests

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/my-awesome-feature
   ```
3. **Make your changes**:
   - Follow existing code style
   - Add comments for complex logic
   - Update documentation if needed
4. **Test your changes**:
   ```bash
   # Run locally
   python app.py

   # Test endpoints
   ./test_endpoint.sh http://localhost:8080
   ```
5. **Commit** with clear messages:
   ```bash
   git commit -m "Add feature: support for AWS KMS"
   ```
6. **Push** to your fork:
   ```bash
   git push origin feature/my-awesome-feature
   ```
7. **Create Pull Request** on GitHub with:
   - Description of changes
   - Related issue (if applicable)
   - Testing performed
   - Screenshots (if UI changes)

## Development Setup

### Prerequisites

- Python 3.11+
- Google Cloud SDK
- Docker (optional)
- Git

### Local Setup

```bash
# Clone your fork
git clone https://github.com/shawntz/tinyvault.git
cd tinyvault

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install dev dependencies
pip install pytest pytest-flask black flake8

# Copy environment template
cp .env.example .env

# Edit .env with your GCP credentials
nano .env
```

### Running Locally

```bash
# Authenticate with GCP
gcloud auth application-default login

# Run Flask app
python app.py

# In another terminal, test
curl http://localhost:8080/health
```

### Code Style

We use:
- **Black** for code formatting
- **Flake8** for linting

```bash
# Format code
black app.py kms_service.py auth.py

# Lint
flake8 app.py kms_service.py auth.py --max-line-length=100
```

### Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# View coverage report
open htmlcov/index.html
```

## Project Structure

```
tinyvault/
├── app.py              # Main Flask application
├── kms_service.py      # Google Cloud KMS integration
├── auth.py             # Authentication logic
├── requirements.txt    # Python dependencies
├── Dockerfile          # Docker container definition
├── setup.sh            # GCP setup script
├── deploy.sh           # Cloud Run deployment script
├── test_endpoint.sh    # Testing script
├── init_kms.py         # KMS initialization utility
├── .github/
│   └── workflows/
│       └── docker-publish.yml  # Docker Hub CI/CD
├── README.md           # Main documentation
├── DOCKER.md           # Docker-specific docs
├── CONTRIBUTING.md     # This file
└── LICENSE             # MIT License
```

## Areas for Contribution

### High Priority

- [ ] Unit tests for `app.py`, `kms_service.py`, `auth.py`
- [ ] Integration tests for KACLS protocol
- [ ] Terraform/OpenTofu deployment templates
- [ ] Helm chart for Kubernetes deployment
- [ ] AWS KMS support
- [ ] Azure Key Vault support

### Medium Priority

- [ ] Web UI for configuration and monitoring
- [ ] Prometheus metrics endpoint
- [ ] Automated key rotation
- [ ] Multi-key support (per user/department)
- [ ] Rate limiting
- [ ] Request caching

### Low Priority

- [ ] Slack/Discord notifications
- [ ] Dashboard for KMS activity
- [ ] CLI tool for management
- [ ] HashiCorp Vault integration
- [ ] OpenID Connect support

## Commit Message Guidelines

Use clear, descriptive commit messages:

```
Add feature: AWS KMS support

- Implement KMSServiceAWS class
- Add AWS credentials configuration
- Update documentation
- Add tests for AWS integration
```

Format:
- **First line**: Short summary (50 chars or less)
- **Blank line**
- **Body**: Detailed description, bullet points for changes

## Documentation

When adding features:
- Update relevant sections in `README.md`
- Add inline code comments
- Update `DOCKER.md` if Docker-related
- Add examples if applicable

## Security

### Reporting Security Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Instead, email: [Your security email]

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

### Security Best Practices

- Never commit secrets, keys, or credentials
- Use environment variables for sensitive config
- Review code for injection vulnerabilities
- Validate all user input
- Keep dependencies up to date

## Questions?

- **General questions**: [GitHub Discussions](https://github.com/shawntz/tinyvault/discussions)
- **Bug reports**: [GitHub Issues](https://github.com/shawntz/tinyvault/issues)
- **Real-time chat**: [Discord/Slack link if available]

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to TinyVault!** 🔐
