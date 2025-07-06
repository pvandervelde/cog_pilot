# CogPilot Technical Specifications

## Overview

CogPilot is a secure Model Context Protocol (MCP) server designed to enable AI agents to safely interact with Rust Cargo commands on local development machines. This specification provides comprehensive documentation for implementing a localhost-only system that prioritizes security, isolation, and controlled access to development tools.

## Quick Start

CogPilot enables AI agents to:

- Execute Cargo commands in isolated environments on the local machine
- Perform dependency security scanning using OSV.dev
- Manage Rust projects with enhanced safety controls
- Integrate with external tools like llvm-cov, audit, deny, mutants, and nextest
- Run securely as a local service without external network access

## Deployment Model

### Local-Only Operation

CogPilot operates exclusively on the local machine as a trusted local service:

- **Localhost Binding**: Server binds only to 127.0.0.1 for security
- **Cross-Platform Support**: Native support for Windows and Linux
- **Deployment Options**: Standalone executable or Docker container
- **User Context**: Runs under the same user context as the calling process
- **No Authentication Required**: Leverages OS-level user permissions

## Security Model

### Core Security Principles

- **Security First**: All operations are subject to security validation
- **Localhost Only**: No external network access or remote connections
- **Least Privilege**: Commands execute with minimal required permissions
- **Defense in Depth**: Multiple layers of protection and validation
- **Working Directory Isolation**: No access to parent directories or system paths
- **No Global Installation**: All tools must be pre-installed and verified

### Key Security Features

- CVE/security scanning for all dependencies
- Strict input validation with regex patterns
- Reduced resource limits (CPU: 300s, Memory: 512MB, Disk I/O: 256MB)
- Enhanced validation for dangerous operations
- Environment variable filtering
- Comprehensive audit logging

## Supported Commands

### Core Cargo Commands

| Command | Risk Level | Description |
|---------|------------|-------------|
| `cargo_build` | LOW | Build the current package |
| `cargo_check` | LOW | Check for compile errors |
| `cargo_clippy` | LOW | Run Clippy lints |
| `cargo_fmt` | LOW | Format code |
| `cargo_test` | MEDIUM | Run tests |
| `cargo_run` | MEDIUM | Run the current package |
| `cargo_add` | HIGH | Add dependencies (enhanced security) |
| `cargo_remove` | MEDIUM | Remove dependencies |
| `cargo_update` | MEDIUM | Update dependencies |
| `cargo_new` | MEDIUM | Create new package |
| `cargo_init` | MEDIUM | Initialize package in current directory |
| `cargo_clean` | LOW | Clean build artifacts |
| `cargo_doc` | LOW | Generate documentation |
| `cargo_search` | LOW | Search for packages |
| `cargo_info` | LOW | Get package information |
| `cargo_metadata` | LOW | Get package metadata |
| `cargo_version` | LOW | Get version information |
| `cargo_tree` | LOW | Display dependency tree |
| `cargo_bench` | MEDIUM | Run benchmarks |

### External Tool Commands

| Command | Risk Level | Tool Required | Description |
|---------|------------|---------------|-------------|
| `cargo_llvm_cov` | MEDIUM | llvm-cov | Generate code coverage |
| `cargo_audit` | LOW | cargo-audit | Security audit |
| `cargo_deny` | LOW | cargo-deny | License and security checks |
| `cargo_mutants` | MEDIUM | cargo-mutants | Mutation testing |
| `cargo_nextest` | MEDIUM | cargo-nextest | Next-generation test runner |

## Documentation Structure

### Application Documents

- **[Overview and Architecture](application/01-overview-and-architecture.md)** - High-level system design and architecture
- **[Security Specification](application/02-security-specification.md)** - Comprehensive security requirements and threat model
- **[API Specification](application/03-api-specification.md)** - Complete JSON-RPC API documentation
- **[Implementation Guide](application/04-implementation-guide.md)** - Developer implementation guidelines
- **[Operations Manual](application/05-operations-manual.md)** - Deployment and operations procedures

### Supplementary Documents

- **[Security Scanning Integration](application/supplementary/security-scanning-integration.md)** - OSV.dev integration details
- **[External Tools Integration](application/supplementary/external-tools-integration.md)** - Tool verification and integration
- **[Sandbox Design](application/supplementary/sandbox-design.md)** - Working directory isolation implementation
- **[Testing Strategy](application/supplementary/testing-strategy.md)** - Comprehensive testing approach

### Reference Documents

- **[Command Reference](application/reference/command-reference.md)** - Quick reference for all commands
- **[Error Codes](application/reference/error-codes.md)** - Complete error code documentation
- **[Configuration Schema](application/reference/configuration-schema.md)** - Configuration file specifications

## Getting Started

1. **Read the Architecture**: Start with the [Overview and Architecture](application/01-overview-and-architecture.md) document
2. **Understand Security**: Review the [Security Specification](application/02-security-specification.md)
3. **Implement the API**: Follow the [API Specification](application/03-api-specification.md)
4. **Deploy Securely**: Use the [Operations Manual](application/05-operations-manual.md)

## Implementation Status

This specification is designed for production implementation. All security requirements are mandatory and must be implemented before deployment.

## Contributing

When contributing to this specification:

1. Follow the security-first design principles
2. Ensure all changes maintain backward compatibility
3. Update relevant reference documents
4. Add appropriate security validations
5. Test all changes thoroughly

## License

This specification is part of the CogPilot project. See the root LICENSE file for details.
