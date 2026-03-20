# Security Policy — TrustCore Sentinel X

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Current |
| < 1.0   | ❌ |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

To report a vulnerability privately:

1. **Email:** security@trustcoreai.io
2. **Subject:** `[SECURITY] Brief description`
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

We will acknowledge receipt within **48 hours** and provide a remediation timeline within **7 days**.

## Scope

This policy covers:
- The FastAPI backend (`backend/`)
- AI service modules (`backend/services/`)
- Docker configuration
- GitHub Actions workflows

**Out of scope:** Third-party dependencies (report to respective upstream maintainers).

## Disclosure Policy

We follow **coordinated disclosure**. We ask that you give us **90 days** to remediate before public disclosure.

## Security Best Practices for Deployers

- Run the container as a non-root user (default in our Dockerfile)
- Place behind a reverse proxy (nginx / Caddy) with TLS in production
- Restrict `/docs` and `/redoc` endpoints in production via `--no-access-log`
- Rotate any API keys or secrets via environment variables, never hardcode
- Monitor `logs/sentinel.log` for anomalous system-level activity
