# Error Codes Reference

## Overview

This document provides a comprehensive reference for all error codes used in CogPilot, including descriptions, causes, and recommended remediation steps.

## Error Code Categories

### JSON-RPC Standard Errors

#### -32700: Parse Error

**Description**: Invalid JSON was received by the server.

**Cause**: The JSON-RPC request is malformed or contains invalid JSON syntax.

**Example**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32700,
    "message": "Parse error",
    "data": {
      "details": "Unexpected character ',' at position 45",
      "received": "{'jsonrpc': '2.0', 'method': 'tools/call',, 'id': 1}"
    }
  },
  "id": null
}
```

**Remediation**:

- Validate JSON syntax before sending requests
- Use proper JSON escaping for string values
- Ensure all braces and brackets are properly closed

#### -32600: Invalid Request

**Description**: The JSON sent is not a valid Request object.

**Cause**: Missing required fields or invalid request structure.

**Example**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32600,
    "message": "Invalid Request",
    "data": {
      "details": "Missing required field 'method'",
      "received": {"jsonrpc": "2.0", "id": 1}
    }
  },
  "id": 1
}
```

**Remediation**:

- Include all required fields: jsonrpc, method, id
- Ensure jsonrpc version is "2.0"
- Use valid method names

#### -32601: Method Not Found

**Description**: The requested method does not exist or is not available.

**Cause**: Invalid method name or method not implemented.

**Example**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32601,
    "message": "Method not found",
    "data": {
      "method": "invalid_method",
      "available_methods": ["tools/call", "tools/list"]
    }
  },
  "id": 1
}
```

**Remediation**:

- Use valid method names from the API specification
- Check method availability in current server version

#### -32602: Invalid Params

**Description**: Invalid method parameter(s).

**Cause**: Missing required parameters, invalid parameter types, or invalid parameter values.

**Example**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": {
      "field": "working_directory",
      "reason": "Path contains invalid characters",
      "provided": "/tmp/../etc/passwd",
      "expected": "Absolute path without traversal"
    }
  },
  "id": 1
}
```

**Remediation**:

- Validate all parameters before sending requests
- Use correct parameter types and formats
- Check parameter constraints in command reference

#### -32603: Internal Error

**Description**: Internal server error.

**Cause**: Unexpected server-side error or system failure.

**Example**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32603,
    "message": "Internal error",
    "data": {
      "error_id": "ERR-2023-001",
      "details": "Database connection failed",
      "timestamp": "2023-07-15T10:30:00Z"
    }
  },
  "id": 1
}
```

**Remediation**:

- Retry the request after a brief delay
- Check server logs for detailed error information
- Contact system administrator if error persists

### CogPilot Security Errors

#### -32001: Security Violation

**Description**: Security policy violation detected.

**Subcodes**:

- `-32001001`: Command injection attempt
- `-32001002`: Path traversal attempt
- `-32001003`: Unauthorized file access
- `-32001004`: Privilege escalation attempt
- `-32001005`: Malicious input detected

**Example**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32001,
    "message": "Security violation",
    "data": {
      "violation_type": "command_injection",
      "subcode": -32001001,
      "details": "Command contains blocked characters: ';'",
      "blocked_input": "cargo build; rm -rf /",
      "security_policy": "command_validation"
    }
  },
  "id": 1
}
```

**Remediation**:

- Review input for malicious patterns
- Use only allowed characters and commands
- Follow security guidelines in documentation

#### -32002: Resource Limit Exceeded

**Description**: System resource limit exceeded.

**Subcodes**:

- `-32002001`: Memory limit exceeded
- `-32002002`: CPU time limit exceeded
- `-32002003`: Process count limit exceeded
- `-32002004`: File descriptor limit exceeded
- `-32002005`: Disk space limit exceeded

**Example**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32002,
    "message": "Resource limit exceeded",
    "data": {
      "limit_type": "memory",
      "subcode": -32002001,
      "limit_value": "2GB",
      "actual_value": "2.5GB",
      "command": "cargo build --release"
    }
  },
  "id": 1
}
```

**Remediation**:

- Optimize build configuration
- Reduce parallel job count
- Clean build artifacts before rebuilding

#### -32003: Authentication Failed

**Description**: Authentication or authorization failure.

**Subcodes**:

- `-32003001`: Invalid credentials
- `-32003002`: Token expired
- `-32003003`: Insufficient permissions
- `-32003004`: Account locked
- `-32003005`: Session timeout

**Example**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32003,
    "message": "Authentication failed",
    "data": {
      "auth_type": "token",
      "subcode": -32003002,
      "details": "Access token expired",
      "expires_at": "2023-07-15T09:00:00Z"
    }
  },
  "id": 1
}
```

**Remediation**:

- Refresh authentication token
- Verify account permissions
- Re-authenticate if session expired

### CogPilot Command Errors

#### -32100: Invalid Directory

**Description**: Working directory is invalid or inaccessible.

**Subcodes**:

- `-32100001`: Directory does not exist
- `-32100002`: Permission denied
- `-32100003`: Not a directory
- `-32100004`: Directory outside allowed paths

**Example**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32100,
    "message": "Invalid directory",
    "data": {
      "subcode": -32100001,
      "path": "/tmp/nonexistent-project",
      "details": "Directory does not exist"
    }
  },
  "id": 1
}
```

**Remediation**:

- Verify directory exists and is accessible
- Check directory permissions
- Use absolute paths within allowed directories

#### -32101: Compilation Failed

**Description**: Rust compilation failed.

**Subcodes**:

- `-32101001`: Syntax errors
- `-32101002`: Type errors
- `-32101003`: Dependency resolution failed
- `-32101004`: Build script failed
- `-32101005`: Linker errors

**Example**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32101,
    "message": "Compilation failed",
    "data": {
      "subcode": -32101001,
      "exit_code": 101,
      "compiler_output": "error: expected `;`, found `}`\n  --> src/main.rs:5:20\n   |\n5  |     println!(\"Hello\")\n   |                    ^ expected `;`",
      "error_count": 1,
      "warning_count": 0
    }
  },
  "id": 1
}
```

**Remediation**:

- Fix syntax errors in source code
- Resolve dependency conflicts
- Check build script configuration

#### -32102: Test Failed

**Description**: Test execution failed.

**Subcodes**:

- `-32102001`: Test compilation failed
- `-32102002`: Test execution failed
- `-32102003`: Test timeout
- `-32102004`: Test panic

**Example**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32102,
    "message": "Test failed",
    "data": {
      "subcode": -32102002,
      "failed_tests": ["integration_test::test_api"],
      "total_tests": 15,
      "passed_tests": 14,
      "failed_tests_count": 1,
      "test_output": "thread 'integration_test::test_api' panicked at 'assertion failed: `(left == right)`'"
    }
  },
  "id": 1
}
```

**Remediation**:

- Fix failing test cases
- Review test assertions
- Check test environment setup

#### -32103: Package Not Found

**Description**: Requested package or crate not found.

**Subcodes**:

- `-32103001`: Package not in registry
- `-32103002`: Version not available
- `-32103003`: Package yanked
- `-32103004`: Registry unavailable

**Example**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32103,
    "message": "Package not found",
    "data": {
      "subcode": -32103001,
      "package_name": "nonexistent-crate",
      "version": "1.0.0",
      "registry": "crates.io"
    }
  },
  "id": 1
}
```

**Remediation**:

- Verify package name spelling
- Check package availability on registry
- Use valid version numbers

### CogPilot System Errors

#### -32200: Sandbox Error

**Description**: Sandbox operation failed.

**Subcodes**:

- `-32200001`: Sandbox initialization failed
- `-32200002`: Sandbox cleanup failed
- `-32200003`: Sandbox escape detected
- `-32200004`: Sandbox resource violation

**Example**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32200,
    "message": "Sandbox error",
    "data": {
      "subcode": -32200001,
      "details": "Failed to create isolated environment",
      "sandbox_id": "sandbox-123",
      "error_details": "Insufficient system resources"
    }
  },
  "id": 1
}
```

**Remediation**:

- Check system resource availability
- Retry operation after cleanup
- Contact system administrator

#### -32201: Tool Not Found

**Description**: Required external tool not found.

**Subcodes**:

- `-32201001`: Cargo not installed
- `-32201002`: Rust toolchain not found
- `-32201003`: Git not available
- `-32201004`: Tool version incompatible

**Example**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32201,
    "message": "Tool not found",
    "data": {
      "subcode": -32201001,
      "tool_name": "cargo",
      "required_version": ">=1.70.0",
      "system_path": "/usr/bin:/usr/local/bin"
    }
  },
  "id": 1
}
```

**Remediation**:

- Install required tools
- Update tool versions
- Check system PATH configuration

#### -32202: Configuration Error

**Description**: Server configuration error.

**Subcodes**:

- `-32202001`: Invalid configuration file
- `-32202002`: Missing configuration
- `-32202003`: Configuration permission denied
- `-32202004`: Configuration validation failed

**Example**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32202,
    "message": "Configuration error",
    "data": {
      "subcode": -32202001,
      "config_file": "/etc/cogpilot/config.yaml",
      "validation_errors": ["Invalid security.sandbox.memory_limit: must be positive integer"]
    }
  },
  "id": 1
}
```

**Remediation**:

- Fix configuration file syntax
- Validate configuration parameters
- Check file permissions

### CogPilot Network Errors

#### -32300: Network Error

**Description**: Network operation failed.

**Subcodes**:

- `-32300001`: Connection timeout
- `-32300002`: Connection refused
- `-32300003`: DNS resolution failed
- `-32300004`: SSL/TLS error
- `-32300005`: Network unreachable

**Example**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32300,
    "message": "Network error",
    "data": {
      "subcode": -32300001,
      "operation": "download_crate",
      "url": "https://crates.io/api/v1/crates/serde",
      "timeout": "30s"
    }
  },
  "id": 1
}
```

**Remediation**:

- Check network connectivity
- Verify URL accessibility
- Review firewall settings

#### -32301: Registry Error

**Description**: Crate registry error.

**Subcodes**:

- `-32301001`: Registry authentication failed
- `-32301002`: Registry rate limit exceeded
- `-32301003`: Registry temporarily unavailable
- `-32301004`: Registry API error

**Example**:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32301,
    "message": "Registry error",
    "data": {
      "subcode": -32301002,
      "registry": "crates.io",
      "rate_limit": "100 requests/hour",
      "retry_after": "3600s"
    }
  },
  "id": 1
}
```

**Remediation**:

- Wait for rate limit reset
- Use authenticated requests if available
- Implement exponential backoff

## Error Handling Best Practices

### Error Response Structure

All CogPilot errors follow this structure:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": "number",
    "message": "string",
    "data": {
      "subcode": "number",
      "details": "string",
      "context": "object",
      "remediation": "string"
    }
  },
  "id": "string|number|null"
}
```

### Client Error Handling

```rust
async fn handle_cogpilot_error(error: &JsonRpcError) -> Result<(), ClientError> {
    match error.code {
        -32001 => {
            // Security violation
            log::error!("Security violation: {}", error.message);
            // Stop execution and alert security team
            return Err(ClientError::SecurityViolation);
        }
        -32002 => {
            // Resource limit exceeded
            log::warn!("Resource limit exceeded: {}", error.message);
            // Retry with reduced resources
            return retry_with_reduced_resources().await;
        }
        -32101 => {
            // Compilation failed
            log::info!("Compilation failed: {}", error.message);
            // Show compilation errors to user
            return display_compilation_errors(error).await;
        }
        -32300..=-32399 => {
            // Network errors
            log::warn!("Network error: {}", error.message);
            // Retry with exponential backoff
            return retry_with_backoff().await;
        }
        _ => {
            // Other errors
            log::error!("Unexpected error: {}", error.message);
            return Err(ClientError::UnexpectedError(error.code));
        }
    }
}
```

### Retry Logic

```rust
async fn retry_with_backoff<F, T, E>(
    operation: F,
    max_retries: u32,
    initial_delay: Duration,
) -> Result<T, E>
where
    F: Fn() -> Result<T, E>,
    E: std::fmt::Debug,
{
    let mut delay = initial_delay;

    for attempt in 0..=max_retries {
        match operation() {
            Ok(result) => return Ok(result),
            Err(e) => {
                if attempt == max_retries {
                    return Err(e);
                }

                log::warn!("Attempt {} failed: {:?}, retrying in {:?}", attempt + 1, e, delay);
                tokio::time::sleep(delay).await;
                delay *= 2; // Exponential backoff
            }
        }
    }

    unreachable!()
}
```

### Error Logging

```rust
fn log_error(error: &JsonRpcError, context: &str) {
    let log_level = match error.code {
        -32001 => log::Level::Error,  // Security violations
        -32002 => log::Level::Warn,   // Resource limits
        -32100..=-32199 => log::Level::Info,  // Command errors
        _ => log::Level::Debug,
    };

    log::log!(log_level,
        "CogPilot error in {}: code={}, message={}, data={:?}",
        context, error.code, error.message, error.data
    );
}
```

## Error Recovery Strategies

### Automatic Recovery

**Resource Limit Exceeded**:

1. Reduce parallel job count
2. Clean build artifacts
3. Retry with lower resource usage

**Network Errors**:

1. Retry with exponential backoff
2. Switch to backup registry
3. Use cached dependencies

**Compilation Errors**:

1. Display errors to user
2. Suggest common fixes
3. Provide documentation links

### Manual Recovery

**Security Violations**:

1. Log incident for audit
2. Notify security team
3. Require manual review

**Authentication Failures**:

1. Prompt for re-authentication
2. Refresh access tokens
3. Verify account status

**Configuration Errors**:

1. Validate configuration
2. Provide fix suggestions
3. Offer configuration wizard

## Error Reporting

### Security Error Reporting

Security errors should be reported to:

- Security team via secure channel
- Audit log for compliance
- Incident response system

### Performance Error Reporting

Performance errors should include:

- Resource usage metrics
- Command execution time
- System load information

### User Error Reporting

User-friendly error messages should:

- Explain what went wrong
- Provide actionable remediation steps
- Link to relevant documentation

This comprehensive error code reference ensures proper error handling and recovery in CogPilot implementations.
