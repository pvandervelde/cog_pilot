# CogPilot API Specification

## Table of Contents

- [Overview](#overview)
- [JSON-RPC 2.0 Protocol](#json-rpc-20-protocol)
- [Authentication](#authentication)
- [Core Cargo Commands](#core-cargo-commands)
- [External Tool Commands](#external-tool-commands)
- [Error Codes](#error-codes)
- [Security Constraints](#security-constraints)
- [Request/Response Examples](#requestresponse-examples)
- [Input Validation Schemas](#input-validation-schemas)

## Overview

CogPilot implements a JSON-RPC 2.0 API that provides secure access to Rust Cargo commands and external development tools. All commands are subject to strict security validation and sandbox execution.

### API Endpoints

**Base URL**: `http://localhost:8080/rpc`

**Protocol**: JSON-RPC 2.0 over HTTP/HTTPS

**Content-Type**: `application/json`

## JSON-RPC 2.0 Protocol

### Request Format

```json
{
  "jsonrpc": "2.0",
  "method": "cargo_build",
  "params": {
    "release": false,
    "target": "x86_64-unknown-linux-gnu"
  },
  "id": 1
}
```

### Response Format

```json
{
  "jsonrpc": "2.0",
  "result": {
    "success": true,
    "stdout": "Compiling my_project v0.1.0",
    "stderr": "",
    "execution_time": 12.5
  },
  "id": 1
}
```

### Error Response Format

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32001,
    "message": "Security violation detected",
    "data": {
      "violation_type": "invalid_package_name",
      "details": "Package name contains invalid characters"
    }
  },
  "id": 1
}
```

## Authentication

### API Key Authentication

**Header**: `Authorization: Bearer <api_key>`

**Example**:

```http
POST /rpc HTTP/1.1
Host: localhost:8080
Content-Type: application/json
Authorization: Bearer cg_1234567890abcdef

{
  "jsonrpc": "2.0",
  "method": "cargo_build",
  "params": {},
  "id": 1
}
```

## Core Cargo Commands

### cargo_build

Build the current package.

**Method**: `cargo_build`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "release": {
      "type": "boolean",
      "description": "Build in release mode"
    },
    "target": {
      "type": "string",
      "pattern": "^[a-zA-Z0-9_\\-]+$",
      "description": "Target architecture"
    },
    "features": {
      "type": "array",
      "items": {
        "type": "string",
        "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$"
      },
      "description": "Features to enable"
    },
    "all_features": {
      "type": "boolean",
      "description": "Enable all features"
    },
    "no_default_features": {
      "type": "boolean",
      "description": "Disable default features"
    }
  },
  "additionalProperties": false
}
```

**Example Request**:

```json
{
  "jsonrpc": "2.0",
  "method": "cargo_build",
  "params": {
    "release": true,
    "features": ["async-std", "json"]
  },
  "id": 1
}
```

**Example Response**:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "success": true,
    "stdout": "Compiling my_project v0.1.0 (file:///path/to/project)\n    Finished release [optimized] target(s) in 12.34s",
    "stderr": "",
    "execution_time": 12.34,
    "exit_code": 0
  },
  "id": 1
}
```

### cargo_check

Check for compile errors without building.

**Method**: `cargo_check`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "target": {
      "type": "string",
      "pattern": "^[a-zA-Z0-9_\\-]+$"
    },
    "features": {
      "type": "array",
      "items": {
        "type": "string",
        "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$"
      }
    },
    "all_features": {
      "type": "boolean"
    },
    "no_default_features": {
      "type": "boolean"
    }
  },
  "additionalProperties": false
}
```

### cargo_clippy

Run Clippy lints.

**Method**: `cargo_clippy`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "fix": {
      "type": "boolean",
      "description": "Apply suggested fixes"
    },
    "deny": {
      "type": "array",
      "items": {
        "type": "string",
        "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$"
      },
      "description": "Lint levels to deny"
    },
    "warn": {
      "type": "array",
      "items": {
        "type": "string",
        "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$"
      },
      "description": "Lint levels to warn"
    }
  },
  "additionalProperties": false
}
```

### cargo_fmt

Format code using rustfmt.

**Method**: `cargo_fmt`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "check": {
      "type": "boolean",
      "description": "Check formatting without making changes"
    },
    "verbose": {
      "type": "boolean",
      "description": "Enable verbose output"
    }
  },
  "additionalProperties": false
}
```

### cargo_test

Run tests.

**Method**: `cargo_test`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "test_name": {
      "type": "string",
      "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$",
      "description": "Specific test to run"
    },
    "release": {
      "type": "boolean",
      "description": "Run tests in release mode"
    },
    "features": {
      "type": "array",
      "items": {
        "type": "string",
        "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$"
      }
    },
    "no_run": {
      "type": "boolean",
      "description": "Compile but don't run tests"
    }
  },
  "additionalProperties": false
}
```

### cargo_run

Run the current package.

**Method**: `cargo_run`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "release": {
      "type": "boolean"
    },
    "target": {
      "type": "string",
      "pattern": "^[a-zA-Z0-9_\\-]+$"
    },
    "features": {
      "type": "array",
      "items": {
        "type": "string",
        "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$"
      }
    },
    "bin": {
      "type": "string",
      "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$",
      "description": "Binary to run"
    },
    "args": {
      "type": "array",
      "items": {
        "type": "string",
        "maxLength": 256
      },
      "maxItems": 50,
      "description": "Arguments to pass to the binary"
    }
  },
  "additionalProperties": false
}
```

### cargo_add

Add dependencies to Cargo.toml.

**Method**: `cargo_add`

**Security Level**: HIGH

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "package": {
      "type": "string",
      "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$",
      "description": "Package name"
    },
    "version": {
      "type": "string",
      "pattern": "^[~^>=<]?[0-9]+(\\.[-9]+)*(-[a-zA-Z0-9\\-]+)?(\\+[a-zA-Z0-9\\-]+)?$",
      "description": "Version specification"
    },
    "features": {
      "type": "array",
      "items": {
        "type": "string",
        "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$"
      },
      "maxItems": 20
    },
    "dev": {
      "type": "boolean",
      "description": "Add as dev dependency"
    },
    "build": {
      "type": "boolean",
      "description": "Add as build dependency"
    },
    "optional": {
      "type": "boolean",
      "description": "Add as optional dependency"
    },
    "git": {
      "type": "string",
      "pattern": "^https://[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,}(/.*)?\.git$",
      "description": "Git repository URL"
    },
    "branch": {
      "type": "string",
      "pattern": "^[a-zA-Z0-9_\\-/]{1,100}$",
      "description": "Git branch"
    },
    "force_insecure": {
      "type": "boolean",
      "description": "Override security warnings"
    }
  },
  "required": ["package"],
  "additionalProperties": false
}
```

**Security Validation**:

1. CVE scanning using OSV.dev
2. License compatibility checking
3. Maintenance status verification
4. Download count validation
5. Yanked version detection

**Example Request**:

```json
{
  "jsonrpc": "2.0",
  "method": "cargo_add",
  "params": {
    "package": "serde",
    "version": "1.0",
    "features": ["derive"]
  },
  "id": 1
}
```

### cargo_remove

Remove dependencies from Cargo.toml.

**Method**: `cargo_remove`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "package": {
      "type": "string",
      "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$",
      "description": "Package name to remove"
    },
    "dev": {
      "type": "boolean",
      "description": "Remove from dev dependencies"
    },
    "build": {
      "type": "boolean",
      "description": "Remove from build dependencies"
    }
  },
  "required": ["package"],
  "additionalProperties": false
}
```

### cargo_update

Update dependencies.

**Method**: `cargo_update`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "package": {
      "type": "string",
      "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$",
      "description": "Specific package to update"
    },
    "aggressive": {
      "type": "boolean",
      "description": "Update to latest compatible versions"
    },
    "dry_run": {
      "type": "boolean",
      "description": "Show what would be updated"
    }
  },
  "additionalProperties": false
}
```

### cargo_new

Create a new package.

**Method**: `cargo_new`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "name": {
      "type": "string",
      "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$",
      "description": "Package name"
    },
    "bin": {
      "type": "boolean",
      "description": "Create binary package"
    },
    "lib": {
      "type": "boolean",
      "description": "Create library package"
    },
    "edition": {
      "type": "string",
      "enum": ["2015", "2018", "2021"],
      "description": "Rust edition"
    }
  },
  "required": ["name"],
  "additionalProperties": false
}
```

### cargo_init

Initialize package in current directory.

**Method**: `cargo_init`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "name": {
      "type": "string",
      "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$",
      "description": "Package name"
    },
    "bin": {
      "type": "boolean",
      "description": "Create binary package"
    },
    "lib": {
      "type": "boolean",
      "description": "Create library package"
    },
    "edition": {
      "type": "string",
      "enum": ["2015", "2018", "2021"],
      "description": "Rust edition"
    }
  },
  "additionalProperties": false
}
```

### cargo_clean

Remove build artifacts.

**Method**: `cargo_clean`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "release": {
      "type": "boolean",
      "description": "Clean release artifacts"
    },
    "target": {
      "type": "string",
      "pattern": "^[a-zA-Z0-9_\\-]+$",
      "description": "Target to clean"
    }
  },
  "additionalProperties": false
}
```

### cargo_doc

Generate documentation.

**Method**: `cargo_doc`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "open": {
      "type": "boolean",
      "description": "Open documentation in browser"
    },
    "no_deps": {
      "type": "boolean",
      "description": "Don't build dependencies"
    },
    "features": {
      "type": "array",
      "items": {
        "type": "string",
        "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$"
      }
    }
  },
  "additionalProperties": false
}
```

### cargo_search

Search for packages.

**Method**: `cargo_search`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "query": {
      "type": "string",
      "pattern": "^[a-zA-Z0-9_\\-\\s]{1,100}$",
      "description": "Search query"
    },
    "limit": {
      "type": "integer",
      "minimum": 1,
      "maximum": 100,
      "description": "Maximum results"
    }
  },
  "required": ["query"],
  "additionalProperties": false
}
```

### cargo_info

Get package information.

**Method**: `cargo_info`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "package": {
      "type": "string",
      "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$",
      "description": "Package name"
    },
    "version": {
      "type": "string",
      "pattern": "^[~^>=<]?[0-9]+(\\.[-9]+)*(-[a-zA-Z0-9\\-]+)?(\\+[a-zA-Z0-9\\-]+)?$",
      "description": "Specific version"
    }
  },
  "required": ["package"],
  "additionalProperties": false
}
```

### cargo_metadata

Get package metadata.

**Method**: `cargo_metadata`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "format_version": {
      "type": "integer",
      "enum": [1],
      "description": "Metadata format version"
    },
    "no_deps": {
      "type": "boolean",
      "description": "Exclude dependencies"
    },
    "features": {
      "type": "array",
      "items": {
        "type": "string",
        "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$"
      }
    }
  },
  "additionalProperties": false
}
```

### cargo_version

Get version information.

**Method**: `cargo_version`

**Parameters**:

```json
{
  "type": "object",
  "properties": {},
  "additionalProperties": false
}
```

### cargo_tree

Display dependency tree.

**Method**: `cargo_tree`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "package": {
      "type": "string",
      "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$",
      "description": "Package to show tree for"
    },
    "features": {
      "type": "array",
      "items": {
        "type": "string",
        "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$"
      }
    },
    "depth": {
      "type": "integer",
      "minimum": 1,
      "maximum": 10,
      "description": "Maximum depth to show"
    }
  },
  "additionalProperties": false
}
```

### cargo_bench

Run benchmarks.

**Method**: `cargo_bench`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "bench_name": {
      "type": "string",
      "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$",
      "description": "Specific benchmark to run"
    },
    "features": {
      "type": "array",
      "items": {
        "type": "string",
        "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$"
      }
    },
    "no_run": {
      "type": "boolean",
      "description": "Compile but don't run benchmarks"
    }
  },
  "additionalProperties": false
}
```

## External Tool Commands

### cargo_llvm_cov

Generate code coverage using llvm-cov.

**Method**: `cargo_llvm_cov`

**Tool Required**: `cargo-llvm-cov`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "html": {
      "type": "boolean",
      "description": "Generate HTML report"
    },
    "lcov": {
      "type": "boolean",
      "description": "Generate LCOV report"
    },
    "json": {
      "type": "boolean",
      "description": "Generate JSON report"
    },
    "output_path": {
      "type": "string",
      "pattern": "^[a-zA-Z0-9_\\-/\\.]{1,200}$",
      "description": "Output file path"
    },
    "ignore_filename_regex": {
      "type": "string",
      "maxLength": 200,
      "description": "Ignore files matching regex"
    }
  },
  "additionalProperties": false
}
```

### cargo_audit

Security audit of dependencies.

**Method**: `cargo_audit`

**Tool Required**: `cargo-audit`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "json": {
      "type": "boolean",
      "description": "Output in JSON format"
    },
    "stale": {
      "type": "boolean",
      "description": "Allow stale database"
    },
    "ignore": {
      "type": "array",
      "items": {
        "type": "string",
        "pattern": "^[A-Z0-9\\-]{1,20}$"
      },
      "description": "Advisory IDs to ignore"
    }
  },
  "additionalProperties": false
}
```

### cargo_deny

License and security checks.

**Method**: `cargo_deny`

**Tool Required**: `cargo-deny`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "check": {
      "type": "string",
      "enum": ["all", "advisories", "bans", "licenses", "sources"],
      "description": "Check type"
    },
    "format": {
      "type": "string",
      "enum": ["human", "json"],
      "description": "Output format"
    }
  },
  "additionalProperties": false
}
```

### cargo_mutants

Mutation testing.

**Method**: `cargo_mutants`

**Tool Required**: `cargo-mutants`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "package": {
      "type": "string",
      "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$",
      "description": "Package to test"
    },
    "timeout": {
      "type": "integer",
      "minimum": 1,
      "maximum": 300,
      "description": "Test timeout in seconds"
    },
    "jobs": {
      "type": "integer",
      "minimum": 1,
      "maximum": 8,
      "description": "Number of parallel jobs"
    }
  },
  "additionalProperties": false
}
```

### cargo_nextest

Next-generation test runner.

**Method**: `cargo_nextest`

**Tool Required**: `cargo-nextest`

**Parameters**:

```json
{
  "type": "object",
  "properties": {
    "run": {
      "type": "boolean",
      "description": "Run tests"
    },
    "list": {
      "type": "boolean",
      "description": "List tests"
    },
    "package": {
      "type": "string",
      "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$",
      "description": "Package to test"
    },
    "features": {
      "type": "array",
      "items": {
        "type": "string",
        "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$"
      }
    }
  },
  "additionalProperties": false
}
```

## Error Codes

### Standard Error Codes

| Code | Name | Description |
|------|------|-------------|
| -32001 | Security Violation | Security validation failed |
| -32002 | Resource Limit Exceeded | Resource limits exceeded |
| -32005 | Timeout Exceeded | Operation timed out |
| -32006 | Sandbox Violation | Sandbox constraints violated |
| -32007 | Input Validation Failed | Input validation failed |
| -32008 | Cargo Command Failed | Cargo command execution failed |
| -32009 | Registry Access Denied | Registry access denied |
| -32010 | Manifest Error | Cargo.toml parsing error |

### Error Response Format

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32001,
    "message": "Security violation detected",
    "data": {
      "violation_type": "cve_detected",
      "package": "vulnerable-package",
      "version": "1.0.0",
      "cve_id": "CVE-2024-1234",
      "severity": "HIGH",
      "recommendation": "Update to version 1.0.1"
    }
  },
  "id": 1
}
```

## Security Constraints

### Input Validation

All API parameters are validated against JSON schemas with strict regex patterns:

- **Package names**: `^[a-zA-Z][a-zA-Z0-9_\-]{0,63}$`
- **Version specifications**: `^[~^>=<]?[0-9]+(\.[0-9]+)*(-[a-zA-Z0-9\-]+)?(\+[a-zA-Z0-9\-]+)?$`
- **Feature names**: `^[a-zA-Z][a-zA-Z0-9_\-]{0,63}$`
- **Git URLs**: `^https://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(/.*)?\.git$`

### Command Restrictions

- **High-risk commands**: `cargo_add`, `cargo_run`, `cargo_new`, `cargo_init`
- **Medium-risk commands**: `cargo_test`, `cargo_bench`, `cargo_remove`, `cargo_update`
- **Low-risk commands**: `cargo_build`, `cargo_check`, `cargo_clippy`, `cargo_fmt`

### Resource Limits

- **CPU Timeout**: 300 seconds
- **Memory Limit**: 2GB
- **Disk I/O Limit**: 1GB
- **Network Timeout**: 30 seconds

## Request/Response Examples

### Successful Build

**Request**:

```json
{
  "jsonrpc": "2.0",
  "method": "cargo_build",
  "params": {
    "release": true
  },
  "id": 1
}
```

**Response**:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "success": true,
    "stdout": "   Compiling my_project v0.1.0\n    Finished release [optimized] target(s) in 5.23s",
    "stderr": "",
    "execution_time": 5.23,
    "exit_code": 0
  },
  "id": 1
}
```

### Security Violation

**Request**:

```json
{
  "jsonrpc": "2.0",
  "method": "cargo_add",
  "params": {
    "package": "vulnerable-package",
    "version": "1.0.0"
  },
  "id": 1
}
```

**Response**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32001,
    "message": "Security violation detected",
    "data": {
      "violation_type": "cve_detected",
      "package": "vulnerable-package",
      "version": "1.0.0",
      "cve_id": "CVE-2024-1234",
      "severity": "HIGH",
      "recommendation": "Update to version 1.0.1 or higher"
    }
  },
  "id": 1
}
```

### Tool Not Available

**Request**:

```json
{
  "jsonrpc": "2.0",
  "method": "cargo_llvm_cov",
  "params": {
    "html": true
  },
  "id": 1
}
```

**Response**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32008,
    "message": "External tool not available",
    "data": {
      "tool": "cargo-llvm-cov",
      "installation_command": "cargo install cargo-llvm-cov",
      "documentation": "https://github.com/taiki-e/cargo-llvm-cov"
    }
  },
  "id": 1
}
```

## Input Validation Schemas

### Common Schemas

```json
{
  "package_name": {
    "type": "string",
    "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$",
    "minLength": 1,
    "maxLength": 64
  },
  "version_spec": {
    "type": "string",
    "pattern": "^[~^>=<]?[0-9]+(\\.[-9]+)*(-[a-zA-Z0-9\\-]+)?(\\+[a-zA-Z0-9\\-]+)?$",
    "minLength": 1,
    "maxLength": 50
  },
  "feature_name": {
    "type": "string",
    "pattern": "^[a-zA-Z][a-zA-Z0-9_\\-]{0,63}$",
    "minLength": 1,
    "maxLength": 64
  },
  "git_url": {
    "type": "string",
    "pattern": "^https://[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,}(/.*)?\.git$",
    "minLength": 10,
    "maxLength": 200
  },
  "target_triple": {
    "type": "string",
    "pattern": "^[a-zA-Z0-9_\\-]+$",
    "minLength": 1,
    "maxLength": 50
  }
}
```

### Validation Rules

1. **Length Limits**: All strings have minimum and maximum length constraints
2. **Character Sets**: Only allow alphanumeric, underscore, and hyphen characters
3. **Format Validation**: Use regex patterns to validate specific formats
4. **Enumeration**: Use enum constraints for limited value sets
5. **Array Limits**: Limit array sizes to prevent resource exhaustion

This API specification ensures secure and controlled access to Cargo commands while maintaining compatibility with the JSON-RPC 2.0 protocol standard.
