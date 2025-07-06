# Command Reference

## Overview

This document provides comprehensive reference information for all CogPilot MCP server commands, including syntax, parameters, security constraints, and usage examples.

## Command Categories

### Build Commands

#### cargo_build

**Description**: Compile a Rust project using Cargo.

**Syntax**:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_build",
    "arguments": {
      "working_directory": "string",
      "release": "boolean",
      "features": "array",
      "target": "string",
      "jobs": "number"
    }
  },
  "id": "string"
}
```

**Parameters**:

| Parameter | Type | Required | Description | Validation |
|-----------|------|----------|-------------|------------|
| `working_directory` | string | Yes | Project directory path | Must be absolute path, sanitized |
| `release` | boolean | No | Build in release mode | Default: false |
| `features` | array | No | Features to enable | Each feature validated against regex |
| `target` | string | No | Target triple | Must match valid target patterns |
| `jobs` | number | No | Number of parallel jobs | Range: 1-16 |

**Security Constraints**:

- Working directory must be within allowed paths
- Maximum build time: 300 seconds
- Memory limit: 512MB (reduced for local use)
- Process limit: 25 concurrent processes (reduced)

**Example Request**:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_build",
    "arguments": {
      "working_directory": "/tmp/my-project",
      "release": true,
      "features": ["default", "serde"],
      "jobs": 4
    }
  },
  "id": "build-123"
}
```

**Example Response**:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "success": true,
    "output": "   Compiling my-project v0.1.0 (/tmp/my-project)\n    Finished release [optimized] target(s) in 12.34s",
    "exit_code": 0,
    "duration": 12.34,
    "resources_used": {
      "max_memory_mb": 1024,
      "cpu_time_seconds": 45.2
    }
  },
  "id": "build-123"
}
```

**Error Codes**:

- `INVALID_DIRECTORY`: Working directory doesn't exist or is not accessible
- `COMPILATION_FAILED`: Build failed with compilation errors
- `RESOURCE_LIMIT_EXCEEDED`: Exceeded memory or time limits
- `SECURITY_VIOLATION`: Security policy violation detected

#### cargo_check

**Description**: Check a Rust project for errors without producing binaries.

**Syntax**:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_check",
    "arguments": {
      "working_directory": "string",
      "all_targets": "boolean",
      "features": "array"
    }
  },
  "id": "string"
}
```

**Parameters**:

| Parameter | Type | Required | Description | Validation |
|-----------|------|----------|-------------|------------|
| `working_directory` | string | Yes | Project directory path | Must be absolute path, sanitized |
| `all_targets` | boolean | No | Check all targets | Default: false |
| `features` | array | No | Features to enable | Each feature validated against regex |

**Security Constraints**:

- Working directory must be within allowed paths
- Maximum check time: 180 seconds
- Memory limit: 1GB
- Process limit: 25 concurrent processes

**Example Request**:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_check",
    "arguments": {
      "working_directory": "/tmp/my-project",
      "all_targets": true
    }
  },
  "id": "check-456"
}
```

### Test Commands

#### cargo_test

**Description**: Run tests for a Rust project.

**Syntax**:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_test",
    "arguments": {
      "working_directory": "string",
      "test_name": "string",
      "release": "boolean",
      "features": "array",
      "no_run": "boolean"
    }
  },
  "id": "string"
}
```

**Parameters**:

| Parameter | Type | Required | Description | Validation |
|-----------|------|----------|-------------|------------|
| `working_directory` | string | Yes | Project directory path | Must be absolute path, sanitized |
| `test_name` | string | No | Specific test to run | Alphanumeric and underscore only |
| `release` | boolean | No | Run tests in release mode | Default: false |
| `features` | array | No | Features to enable | Each feature validated against regex |
| `no_run` | boolean | No | Compile but don't run tests | Default: false |

**Security Constraints**:

- Working directory must be within allowed paths
- Maximum test time: 600 seconds
- Memory limit: 512MB (reduced for local use)
- Process limit: 25 concurrent processes (reduced)
- Network access blocked during tests

**Example Request**:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_test",
    "arguments": {
      "working_directory": "/tmp/my-project",
      "test_name": "integration_tests",
      "features": ["test-utils"]
    }
  },
  "id": "test-789"
}
```

### Documentation Commands

#### cargo_doc

**Description**: Generate documentation for a Rust project.

**Syntax**:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_doc",
    "arguments": {
      "working_directory": "string",
      "open": "boolean",
      "no_deps": "boolean",
      "features": "array"
    }
  },
  "id": "string"
}
```

**Parameters**:

| Parameter | Type | Required | Description | Validation |
|-----------|------|----------|-------------|------------|
| `working_directory` | string | Yes | Project directory path | Must be absolute path, sanitized |
| `open` | boolean | No | Open docs in browser | Always false for security |
| `no_deps` | boolean | No | Don't build dependencies | Default: false |
| `features` | array | No | Features to enable | Each feature validated against regex |

**Security Constraints**:

- Working directory must be within allowed paths
- Maximum documentation time: 300 seconds
- Memory limit: 1GB
- Process limit: 25 concurrent processes
- Browser opening is disabled

### Package Management Commands

#### cargo_install

**Description**: Install a Rust binary crate.

**Syntax**:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_install",
    "arguments": {
      "crate_name": "string",
      "version": "string",
      "features": "array",
      "force": "boolean"
    }
  },
  "id": "string"
}
```

**Parameters**:

| Parameter | Type | Required | Description | Validation |
|-----------|------|----------|-------------|------------|
| `crate_name` | string | Yes | Name of crate to install | Must match crate name regex |
| `version` | string | No | Specific version to install | Must be valid semver |
| `features` | array | No | Features to enable | Each feature validated against regex |
| `force` | boolean | No | Force reinstallation | Default: false |

**Security Constraints**:

- Crate name must be in approved allowlist
- Version must be security-validated
- Installation to sandboxed directory only
- CVE scanning before installation
- Maximum installation time: 600 seconds

**Example Request**:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_install",
    "arguments": {
      "crate_name": "ripgrep",
      "version": "13.0.0",
      "features": ["pcre2"]
    }
  },
  "id": "install-101"
}
```

#### cargo_update

**Description**: Update dependencies in Cargo.lock.

**Syntax**:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_update",
    "arguments": {
      "working_directory": "string",
      "package": "string",
      "precise": "string",
      "dry_run": "boolean"
    }
  },
  "id": "string"
}
```

**Parameters**:

| Parameter | Type | Required | Description | Validation |
|-----------|------|----------|-------------|------------|
| `working_directory` | string | Yes | Project directory path | Must be absolute path, sanitized |
| `package` | string | No | Specific package to update | Must match package name regex |
| `precise` | string | No | Exact version to update to | Must be valid semver |
| `dry_run` | boolean | No | Show what would be updated | Default: false |

**Security Constraints**:

- Working directory must be within allowed paths
- Package names validated against allowlist
- Version updates subject to security scanning
- Maximum update time: 300 seconds

### Information Commands

#### cargo_version

**Description**: Display Cargo version information.

**Syntax**:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_version",
    "arguments": {}
  },
  "id": "string"
}
```

**Parameters**: None

**Security Constraints**: None (read-only operation)

**Example Request**:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_version",
    "arguments": {}
  },
  "id": "version-202"
}
```

**Example Response**:

```json
{
  "jsonrpc": "2.0",
  "result": {
    "success": true,
    "output": "cargo 1.70.0 (7fe40dc9c 2023-04-27)",
    "exit_code": 0,
    "version": "1.70.0"
  },
  "id": "version-202"
}
```

#### cargo_tree

**Description**: Display dependency tree for a project.

**Syntax**:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_tree",
    "arguments": {
      "working_directory": "string",
      "package": "string",
      "features": "array",
      "depth": "number"
    }
  },
  "id": "string"
}
```

**Parameters**:

| Parameter | Type | Required | Description | Validation |
|-----------|------|----------|-------------|------------|
| `working_directory` | string | Yes | Project directory path | Must be absolute path, sanitized |
| `package` | string | No | Specific package to analyze | Must match package name regex |
| `features` | array | No | Features to enable | Each feature validated against regex |
| `depth` | number | No | Maximum depth to display | Range: 1-10 |

**Security Constraints**:

- Working directory must be within allowed paths
- Maximum analysis time: 60 seconds
- Memory limit: 512MB

### Clean Commands

#### cargo_clean

**Description**: Remove build artifacts.

**Syntax**:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_clean",
    "arguments": {
      "working_directory": "string",
      "package": "string",
      "release": "boolean",
      "target": "string"
    }
  },
  "id": "string"
}
```

**Parameters**:

| Parameter | Type | Required | Description | Validation |
|-----------|------|----------|-------------|------------|
| `working_directory` | string | Yes | Project directory path | Must be absolute path, sanitized |
| `package` | string | No | Specific package to clean | Must match package name regex |
| `release` | boolean | No | Clean only release artifacts | Default: false |
| `target` | string | No | Target triple to clean | Must match valid target patterns |

**Security Constraints**:

- Working directory must be within allowed paths
- Can only clean within project target directory
- Maximum clean time: 60 seconds

## Command Validation

### Input Validation Patterns

**Working Directory Validation**:

```regex
^[a-zA-Z0-9/_-]+$
```

- Must be absolute path
- No parent directory traversal (..)
- No special characters except / _ -

**Package Name Validation**:

```regex
^[a-zA-Z0-9_-]+$
```

- Alphanumeric characters, hyphens, underscores
- Length: 1-64 characters
- No leading/trailing hyphens

**Feature Name Validation**:

```regex
^[a-zA-Z0-9_-]+$
```

- Alphanumeric characters, hyphens, underscores
- Length: 1-32 characters
- No leading/trailing hyphens

**Version Validation**:

```regex
^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9_-]+)?$
```

- Semantic versioning format
- Optional pre-release identifier
- No wildcards or ranges

### Security Validation

**Command Injection Prevention**:

```rust
fn validate_command_safety(input: &str) -> Result<(), ValidationError> {
    // Blocked characters and patterns
    let blocked_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\n', '\r'];
    let blocked_patterns = ["&&", "||", ";;", "$(", "`", "exec", "eval"];

    // Check for blocked characters
    for char in blocked_chars {
        if input.contains(char) {
            return Err(ValidationError::BlockedCharacter(char));
        }
    }

    // Check for blocked patterns
    for pattern in blocked_patterns {
        if input.contains(pattern) {
            return Err(ValidationError::BlockedPattern(pattern.to_string()));
        }
    }

    Ok(())
}
```

**Path Traversal Prevention**:

```rust
fn validate_path_safety(path: &str) -> Result<(), ValidationError> {
    // Normalize path and check for traversal
    let normalized = PathBuf::from(path).canonicalize()?;

    // Must be within allowed base directories
    let allowed_bases = ["/tmp", "/var/tmp", "/home/user/projects"];
    let path_allowed = allowed_bases.iter().any(|base| {
        normalized.starts_with(base)
    });

    if !path_allowed {
        return Err(ValidationError::UnauthorizedPath);
    }

    // Check for suspicious path components
    let suspicious = [".", "..", "~", "$HOME", "%USERPROFILE%"];
    for component in normalized.components() {
        if let Some(os_str) = component.as_os_str().to_str() {
            if suspicious.contains(&os_str) {
                return Err(ValidationError::SuspiciousPath);
            }
        }
    }

    Ok(())
}
```

## Error Handling

### Common Error Responses

**Validation Error**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": {
      "field": "working_directory",
      "reason": "Path contains invalid characters",
      "provided": "/tmp/../etc/passwd"
    }
  },
  "id": "request-id"
}
```

**Security Error**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32001,
    "message": "Security violation",
    "data": {
      "violation_type": "command_injection",
      "details": "Command contains blocked characters: ';'"
    }
  },
  "id": "request-id"
}
```

**Resource Error**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32002,
    "message": "Resource limit exceeded",
    "data": {
      "limit_type": "memory",
      "limit_value": "2GB",
      "actual_value": "2.5GB"
    }
  },
  "id": "request-id"
}
```

## Usage Examples

### Basic Project Build

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_build",
    "arguments": {
      "working_directory": "/tmp/hello-world"
    }
  },
  "id": "build-example"
}
```

### Test with Specific Features

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_test",
    "arguments": {
      "working_directory": "/tmp/my-project",
      "features": ["integration", "test-utils"],
      "test_name": "integration_test"
    }
  },
  "id": "test-example"
}
```

### Release Build with Optimizations

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_build",
    "arguments": {
      "working_directory": "/tmp/production-app",
      "release": true,
      "features": ["production", "optimized"],
      "jobs": 8
    }
  },
  "id": "release-example"
}
```

### Documentation Generation

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_doc",
    "arguments": {
      "working_directory": "/tmp/library-project",
      "no_deps": true,
      "features": ["docs"]
    }
  },
  "id": "docs-example"
}
```

## Command Chaining

CogPilot supports sequential command execution through the MCP protocol. Each command must complete before the next can begin.

### Example Workflow

1. **Clean previous build**:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_clean",
    "arguments": {
      "working_directory": "/tmp/my-project"
    }
  },
  "id": "clean-step"
}
```

2. **Build project**:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_build",
    "arguments": {
      "working_directory": "/tmp/my-project",
      "release": true
    }
  },
  "id": "build-step"
}
```

3. **Run tests**:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "cargo_test",
    "arguments": {
      "working_directory": "/tmp/my-project",
      "release": true
    }
  },
  "id": "test-step"
}
```

## Best Practices

### Security Best Practices

1. **Always validate input parameters**
2. **Use absolute paths for working directories**
3. **Enable only necessary features**
4. **Set appropriate resource limits**
5. **Monitor command execution logs**

### Performance Best Practices

1. **Use appropriate job counts for builds**
2. **Clean build artifacts regularly**
3. **Use cargo check for syntax validation**
4. **Enable release mode for production builds**
5. **Limit concurrent operations**

### Error Handling Best Practices

1. **Always check response success field**
2. **Parse error codes for specific handling**
3. **Log security violations for audit**
4. **Implement retry logic for transient failures**
5. **Provide meaningful error messages to users**

This command reference provides comprehensive information for all CogPilot operations, ensuring secure and efficient usage of the Rust Cargo commands through the MCP protocol.
