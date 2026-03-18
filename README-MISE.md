# Mise Setup Guide

This project now uses [mise](https://mise.jdx.dev/) for managing Python versions and running tasks.

## Installation

### Install mise

**macOS:**
```bash
brew install mise
```

**Linux/WSL:**
```bash
curl https://mise.run | sh
```

### Activate mise in your shell

Add to your shell configuration file (`~/.zshrc`, `~/.bashrc`, etc.):

```bash
eval "$(mise activate zsh)"  # or bash, fish, etc.
```

Then reload your shell:
```bash
source ~/.zshrc  # or ~/.bashrc
```

## Setup Python 3.13

Once mise is installed and activated, navigate to the project directory and run:

```bash
mise install
```

This will automatically install Python 3.13 as specified in the configuration files. The Python version is isolated to this project and won't affect your system Python.

## Available Tasks

Run `mise run help` or `mise tasks` to see all available tasks:

- `mise run test` - Run all Python tests
- `mise run test-vnet` - Run vnet-flow-logs tests
- `mise run test-nsg` - Run nsg-flow-logs tests (when available)
- `mise run install` - Install all dependencies
- `mise run install-vnet` - Install vnet-flow-logs dependencies
- `mise run install-nsg` - Install nsg-flow-logs dependencies
- `mise run install-dev` - Install development dependencies (pytest)
- `mise run clean` - Remove test artifacts and cache

## Quick Start

```bash
# Install mise and activate it (one-time setup)
brew install mise
eval "$(mise activate zsh)"

# Install Python 3.13 for this project
mise install

# Install all project dependencies
mise run install

# Run tests
mise run test
```

## Migration from Makefile

The previous Makefile has been converted to mise tasks. All `make` commands now use `mise run`:

| Old Command | New Command |
|-------------|-------------|
| `make help` | `mise run help` or `mise tasks` |
| `make test` | `mise run test` |
| `make test-vnet` | `mise run test-vnet` |
| `make test-nsg` | `mise run test-nsg` |
| `make install` | `mise run install` |
| `make install-vnet` | `mise run install-vnet` |
| `make install-nsg` | `mise run install-nsg` |
| `make install-dev` | `mise run install-dev` |
| `make clean` | `mise run clean` |

## Benefits of mise

- **Isolated Python version**: Python 3.13 is installed and managed per-project, not system-wide
- **Automatic activation**: When you `cd` into the project, the correct Python version is automatically activated
- **Cross-platform**: Works consistently on macOS, Linux, and WSL
- **Task dependencies**: Tasks can depend on other tasks (e.g., `test` depends on `install-dev`)
- **No need for virtualenv**: mise handles Python isolation automatically
