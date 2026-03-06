# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Argus, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

**Email**: security@tokamak.network

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix (optional)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Critical fix**: Within 7 days
- **Non-critical fix**: Within 30 days

We will coordinate disclosure with you and credit reporters (unless anonymity is preferred).

### Scope

The following components are in scope for security reports:

- Argus core library (`src/`)
- Sentinel real-time detection pipeline
- Autopsy forensic analysis
- Docker image and deployment configurations

### Out of Scope

- Vulnerabilities in upstream dependencies (report to respective maintainers)
- Issues in example/demo code that don't affect the library
- Social engineering attacks
- Denial of service attacks against test/demo infrastructure

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Security Best Practices for Users

- Never expose Sentinel's metrics endpoint (`:9090`) to the public internet without authentication
- Store RPC URLs and API keys in environment variables, not in config files
- Use the Docker image with a non-root user in production
- Keep Argus updated to the latest release
