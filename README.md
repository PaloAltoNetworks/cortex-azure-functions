# Cortex Azure Functions

This repository contains Azure Functions for processing network flow logs from Azure.

## Functions

- **vnet-flow-logs**: Processes VNet flow logs
- **nsg-flow-logs**: Processes NSG (Network Security Group) flow logs

## Quick Start

### Building Deployment Packages

The easiest way to build deployment packages is using mise:

```bash
# Build vnet-flow-logs package
mise run build-vnet

# Build nsg-flow-logs package
mise run build-nsg

# Show all available commands
mise run help
```

This will create Linux-compatible deployment packages using Docker, ensuring they work correctly in Azure Functions runtime regardless of your local OS.

### Output

- `vnet-flow-logs/vnet.zip` - Ready to deploy to Azure
- `nsg-flow-logs/nsg.zip` - Ready to deploy to Azure

## Documentation

- **[BUILD.md](BUILD.md)** - Detailed build instructions, troubleshooting, and deployment guide
- **[README-MISE.md](README-MISE.md)** - Development environment setup with mise

## Requirements

- Docker (for building Linux-compatible packages)
- mise (task runner and environment manager)
- Python 3.11+ (for local development)

## CI/CD

GitHub Actions automatically builds deployment packages on push to main branches. Artifacts are available in the Actions tab for 30 days.

## Development

Each function directory contains:
- `CortexFunction/` - Function code
- `requirements.txt` - Python dependencies
- `host.json` - Azure Functions configuration
- `tests/` - Unit tests (vnet-flow-logs)

## License

See individual function directories for specific licensing information.
