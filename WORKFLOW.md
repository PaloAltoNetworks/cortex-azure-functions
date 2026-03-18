# GitHub Workflow Documentation

## Overview

This repository uses GitHub Actions to automate linting, testing, building, and releasing Azure Functions packages.

## Workflow Triggers

The workflow (`.github/workflows/build.yml`) is triggered by:

1. **Pull Requests** to `main` or `master` branches
2. **Push events** to `main` or `master` branches (after merge)
3. **Manual workflow dispatch** with optional release creation

## Workflow Jobs

### 1. Lint (`lint`)

Runs Python code linting using `ruff` to ensure code quality and consistency.

- **Runs on**: All triggers (PR, push, manual)
- **Command**: `mise run lint-check`
- **Configuration**: See [`ruff.toml`](ruff.toml)

### 2. Test (`test`)

Runs all Python tests using pytest.

- **Runs on**: All triggers (after linting passes)
- **Command**: `mise run test`
- **Dependencies**: Requires `lint` job to pass

### 3. Build (`build`)

Builds deployment packages for both NSG and VNET flow logs.

- **Runs on**: All triggers (after tests pass)
- **Outputs**:
  - `vnet-flow-logs-package` artifact
  - `nsg-flow-logs-package` artifact
- **Dependencies**: Requires `test` job to pass

### 4. Release (`release`)

Creates a GitHub release with versioned artifacts.

- **Runs on**:
  - Automatically after push to `main`/`master` (post-merge)
  - Manually via workflow dispatch when "Create a release" is checked
- **Version Bumping**: Automatically increments the minor version (e.g., `v1.2.0` → `v1.3.0`)
- **Artifacts**:
  - `nsg-<version>.zip` (e.g., `nsg-v1.3.0.zip`)
  - `vnet-<version>.zip` (e.g., `vnet-v1.3.0.zip`)
- **Release Notes**: Uses the last non-merge commit message
- **Dependencies**: Requires `build` job to pass

## Version Bumping Strategy

The workflow automatically bumps the **minor version** number:

- Current version: `v1.2.0`
- New version: `v1.3.0`

If no tags exist, it starts from `v0.1.0`.

## Manual Release Creation

To manually create a release:

1. Go to **Actions** tab in GitHub
2. Select **Build and Release** workflow
3. Click **Run workflow**
4. Check **"Create a release"** option
5. Click **Run workflow** button

## Local Development

### Linting

```bash
# Check linting (no auto-fix)
mise run lint-check

# Lint with auto-fix
mise run lint
```

### Testing

```bash
# Run all tests
mise run test

# Run specific tests
mise run test-vnet
mise run test-nsg
```

### Building

```bash
# Build both packages
mise run build-vnet
mise run build-nsg
```

## Workflow File Structure

```yaml
on:
  pull_request:     # Runs on PRs
  push:             # Runs after merge
  workflow_dispatch: # Manual trigger

jobs:
  lint → test → build → release
```

## Release Artifact Naming

- NSG package: `nsg-<tag>.zip` (e.g., `nsg-v1.3.0.zip`)
- VNET package: `vnet-<tag>.zip` (e.g., `vnet-v1.3.0.zip`)

## Permissions

The release job requires `contents: write` permission to create releases and tags.

## Environment Variables

No special environment variables are required for the workflow. All configuration is handled through the workflow file and mise tasks.
