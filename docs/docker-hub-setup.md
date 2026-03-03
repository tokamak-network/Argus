# Docker Hub Publish Setup

## Prerequisites

1. Docker Hub account with access to `tokamak` organization
2. Docker Hub access token

## GitHub Secrets Configuration

Add these secrets to the Argus repo (`Settings → Secrets and variables → Actions`):

| Secret | Value |
|--------|-------|
| `DOCKERHUB_USERNAME` | Docker Hub username |
| `DOCKERHUB_TOKEN` | Docker Hub access token (not password) |

### Create Docker Hub Access Token

1. Log in to https://hub.docker.com
2. Go to `Account Settings → Security → Access Tokens`
3. Click `New Access Token`
4. Name: `argus-github-actions`
5. Permissions: `Read, Write, Delete`
6. Copy the token

## Triggering a Publish

### Option A: Tag-based (recommended)

```bash
git tag v0.1.0
git push origin v0.1.0
```

This automatically builds and pushes:
- `tokamak/argus-demo:0.1.0`
- `tokamak/argus-demo:0.1`
- `tokamak/argus-demo:latest`

### Option B: Manual

Go to `Actions → Docker Publish → Run workflow`

## Verification

```bash
docker pull tokamak/argus-demo:latest
docker run tokamak/argus-demo
docker run tokamak/argus-demo reentrancy_demo
```
