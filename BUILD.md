# Build Instructions

This document describes how to build deployment packages for the Azure Functions in this repository.

## Overview

The build process creates Linux-compatible deployment packages (`.zip` files) that can be deployed to Azure Functions. The process uses Docker to ensure that Python packages are compiled for the Linux runtime environment, regardless of your local operating system.

## Prerequisites

- **Docker**: Required for building Linux-compatible packages
- **mise**: Task runner and environment manager ([installation guide](https://mise.jdx.dev/getting-started.html))
- **zip**: Command-line zip utility (usually pre-installed on macOS/Linux)

## Local Build

### Using mise (Recommended)

The easiest way to build packages locally is using mise tasks:

```bash
# Build vnet-flow-logs package
mise run build-vnet

# Build nsg-flow-logs package
mise run build-nsg

# Clean build artifacts
mise run clean-build

# Clean all artifacts (test + build)
mise run clean-all

# Run tests
mise run test

# Show all available commands
mise run help
```

### Manual Build

If you prefer to build manually or don't have Make installed:

#### vnet-flow-logs

```bash
cd vnet-flow-logs

# Install dependencies using Docker (ensures Linux compatibility)
docker run --rm \
  -v "$(pwd):/workspace" \
  -w /workspace \
  python:3.11-slim \
  bash -c "pip install --target .python_packages/lib/site-packages -r requirements.txt"

# Create deployment package
zip -r vnet.zip .funcignore .python_packages cortex_function host.json requirements.txt

# The package is now ready: vnet.zip
```

#### nsg-flow-logs

```bash
cd nsg-flow-logs

# Install dependencies using Docker (ensures Linux compatibility)
docker run --rm \
  -v "$(pwd):/workspace" \
  -w /workspace \
  python:3.11-slim \
  bash -c "pip install --target .python_packages/lib/site-packages -r requirements.txt"

# Create deployment package
zip -r nsg.zip .funcignore .python_packages cortex_function host.json requirements.txt

# The package is now ready: nsg.zip
```

## GitHub Actions Build

The repository includes a GitHub Actions workflow that automatically builds packages on:
- Push to `main`, `master`, or `develop` branches
- Pull requests to these branches
- Manual workflow dispatch

### Accessing Build Artifacts

1. Go to the **Actions** tab in your GitHub repository
2. Click on the latest workflow run
3. Scroll down to the **Artifacts** section
4. Download `vnet-flow-logs-package` or `nsg-flow-logs-package`

Artifacts are retained for 30 days.

### Manual Workflow Trigger

You can manually trigger a build from the GitHub Actions tab:
1. Go to **Actions** → **Build Azure Functions**
2. Click **Run workflow**
3. Select the branch and click **Run workflow**

## Why Docker?

The build process uses Docker to install Python packages in a Linux environment. This is important because:

1. **Platform Compatibility**: Azure Functions run on Linux, so packages must be compiled for Linux
2. **Binary Dependencies**: Some Python packages (like those with C extensions) are platform-specific
3. **Consistency**: Ensures the same build output regardless of whether you're on macOS, Windows, or Linux
4. **CI/CD Ready**: The same Docker-based approach works in GitHub Actions and other CI systems

## Package Contents

Each deployment package includes:

- `.funcignore` - Files to exclude from deployment
- `.python_packages/` - Python dependencies installed for Linux
- `cortex_function/` - Function code and configuration
- `host.json` - Azure Functions host configuration
- `requirements.txt` - Python dependencies list

## Troubleshooting

### Docker Permission Issues

If you encounter permission issues with Docker on Linux:

```bash
# The mise task includes ownership fix, but if needed manually:
sudo chown -R $(id -u):$(id -g) .python_packages
```

### mise Not Found

If mise is not installed, follow the [installation guide](https://mise.jdx.dev/getting-started.html):

```bash
# macOS/Linux
curl https://mise.run | sh

# Or via Homebrew (macOS)
brew install mise
```

### Missing Docker

If Docker is not installed:
- **macOS**: Install [Docker Desktop](https://www.docker.com/products/docker-desktop)
- **Linux**: Install Docker Engine via your package manager
- **Windows**: Install [Docker Desktop](https://www.docker.com/products/docker-desktop)

### Zip Command Not Found

- **macOS/Linux**: Usually pre-installed
- **Windows**: Use WSL2 or install via package manager

## Deployment

After building, deploy the package to Azure:

```bash
# Using Azure CLI
az functionapp deployment source config-zip \
  -g <resource-group> \
  -n <function-app-name> \
  --src vnet-flow-logs/vnet.zip
```

Or upload via the Azure Portal:
1. Go to your Function App
2. Navigate to **Deployment Center**
3. Choose **ZIP Deploy**
4. Upload the `.zip` file
