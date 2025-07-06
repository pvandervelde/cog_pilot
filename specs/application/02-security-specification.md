# CogPilot Security Specification

## Table of Contents

- [Executive Summary](#executive-summary)
- [Threat Model and Risk Assessment](#threat-model-and-risk-assessment)
- [Input Validation Rules](#input-validation-rules)
- [Working Directory Isolation](#working-directory-isolation)
- [Resource Limits](#resource-limits)
- [Environment Variable Filtering](#environment-variable-filtering)
- [CVE Scanning Integration](#cve-scanning-integration)
- [Authentication and Authorization](#authentication-and-authorization)
- [Audit and Logging](#audit-and-logging)
- [Security Controls Matrix](#security-controls-matrix)

## Executive Summary

This document defines the comprehensive security requirements for CogPilot, a secure MCP server for Rust Cargo commands. The security model implements defense-in-depth principles with multiple layers of validation, isolation, and monitoring to protect against various attack vectors.

### Security Goals

1. **Prevent Malicious Code Execution**: Block execution of unauthorized or malicious commands
2. **Protect Host System**: Isolate operations from the host system
3. **Secure Dependency Management**: Validate all dependencies for security vulnerabilities
4. **Maintain Audit Trail**: Log all security-relevant events for investigation
5. **Enforce Resource Limits**: Prevent resource exhaustion attacks
6. **Localhost-Only Operation**: Restrict access to local machine only

## Deployment Security Model

### Local-Only Operation

**Design Principle**: CogPilot operates exclusively on the local machine as a trusted local service.

**Security Controls**:

- **Network Binding**: Server binds only to localhost/127.0.0.1
- **Port Restrictions**: Uses local ports (>1024) to avoid privilege escalation
- **Firewall Rules**: Blocks external network access by default
- **User Context**: Runs under the same user context as the calling process

**Benefits**:

- Eliminates network-based attacks
- Reduces authentication complexity
- Leverages OS-level user permissions
- Simplifies security audit scope

### Cross-Platform Deployment

**Supported Platforms**:

- Windows 10/11 (x64)
- Linux (x64) - Ubuntu, CentOS, Debian
- macOS (x64/ARM64) - future consideration

**Deployment Methods**:

- **Standalone Executable**: Single binary with all dependencies
- **Docker Container**: Containerized deployment for consistency
- **Package Managers**: Distribution through cargo, chocolatey, apt

**Security Considerations**:

- Platform-specific security controls
- Consistent behavior across platforms
- Minimal privilege requirements
- Secure defaults for each platform

## Threat Model and Risk Assessment

### Primary Threats

#### T1: Malicious Dependency Injection

**Risk Level**: HIGH

**Description**: Attackers inject malicious dependencies through cargo_add or similar commands

**Attack Vectors**:

- Typosquatting attacks on popular packages
- Supply chain attacks on legitimate packages
- Packages with known CVEs

**Impact**:

- Code execution during build process
- Supply chain compromise
- Data exfiltration
- Backdoor installation

**Mitigation Controls**:

- Pre-execution CVE scanning using OSV.dev
- License compatibility verification
- Maintenance status checking
- Download count validation
- Yanked version detection

#### T2: Directory Traversal Attacks

**Risk Level**: HIGH

**Description**: Attackers attempt to access files outside the working directory

**Attack Vectors**:

- Path traversal using `../` sequences
- Symbolic link attacks
- Absolute path specifications
- Home directory access attempts

**Impact**:

- Sensitive file access
- Configuration file modification
- System file corruption
- Privilege escalation

**Mitigation Controls**:

- Strict path validation
- Canonical path resolution
- Symbolic link detection
- Working directory enforcement

#### T3: Resource Exhaustion

**Risk Level**: MEDIUM

**Description**: Attackers consume excessive system resources

**Attack Vectors**:

- CPU-intensive operations
- Memory exhaustion
- Disk space consumption
- Network bandwidth abuse

**Impact**:

- Denial of service
- System instability
- Performance degradation
- Cost increase

**Mitigation Controls**:

- CPU timeout limits (300 seconds)
- Memory limits (2GB)
- Disk I/O limits (1GB)
- Network rate limiting

#### T4: Command Injection

**Risk Level**: HIGH

**Description**: Attackers inject malicious commands through input parameters

**Attack Vectors**:

- Shell metacharacter injection
- Command chaining
- Environment variable manipulation
- Argument injection

**Impact**:

- Arbitrary code execution
- System compromise
- Data theft
- Privilege escalation

**Mitigation Controls**:

- Strict input validation
- Command whitelisting
- Parameter sanitization
- Execution environment isolation

#### T5: Information Disclosure

**Risk Level**: MEDIUM

**Description**: Attackers extract sensitive information from system

**Attack Vectors**:

- Error message information leakage
- Log file access
- Configuration file exposure
- Environment variable disclosure

**Impact**:

- Credential exposure
- System information disclosure
- Configuration details leakage
- Privacy violations

**Mitigation Controls**:

- Output filtering
- Error message sanitization
- Log access controls
- Environment variable filtering

### Risk Assessment Matrix

| Threat | Likelihood | Impact | Risk Level | Priority |
|--------|------------|--------|------------|----------|
| T1: Malicious Dependency Injection | High | High | HIGH | 1 |
| T2: Directory Traversal | Medium | High | HIGH | 2 |
| T4: Command Injection | Medium | High | HIGH | 3 |
| T3: Resource Exhaustion | Medium | Medium | MEDIUM | 4 |
| T5: Information Disclosure | Low | Medium | MEDIUM | 5 |

## Input Validation Rules

### Package Name Validation

**Regex Pattern**: `^[a-zA-Z][a-zA-Z0-9_\-]{0,63}$`

**Rules**:

- Must start with alphabetic character
- Can contain alphanumeric, underscore, and hyphen
- Maximum 64 characters
- No special characters or whitespace

**Examples**:

- ✅ Valid: `serde`, `tokio-util`, `my_package`
- ❌ Invalid: `123invalid`, `package.name`, `pkg with spaces`

### Version Specification Validation

**Regex Pattern**: `^[~^>=<]?[0-9]+(\.[0-9]+)*(-[a-zA-Z0-9\-]+)?(\+[a-zA-Z0-9\-]+)?$`

**Rules**:

- Optional version operator (`~`, `^`, `>=`, `<`, `>`, `=`)
- Major version required (numeric)
- Optional minor and patch versions
- Optional pre-release identifier
- Optional build metadata

**Examples**:

- ✅ Valid: `1.0.0`, `^2.1`, `~1.2.3-alpha`, `>=1.0.0+build.1`
- ❌ Invalid: `latest`, `1.*.0`, `version-string`

### Feature Name Validation

**Regex Pattern**: `^[a-zA-Z][a-zA-Z0-9_\-]{0,63}$`

**Rules**:

- Must start with alphabetic character
- Can contain alphanumeric, underscore, and hyphen
- Maximum 64 characters
- No special characters or whitespace

**Examples**:

- ✅ Valid: `default`, `async-std`, `feature_name`
- ❌ Invalid: `123feature`, `feature.name`, `feature with spaces`

### Git URL Validation

**Regex Pattern**: `^https://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(/.*)?\.git$`

**Rules**:

- Must use HTTPS protocol
- Valid domain name format
- Must end with `.git`
- No credentials embedded in URL

**Examples**:

- ✅ Valid: `https://github.com/user/repo.git`, `https://gitlab.com/org/project.git`
- ❌ Invalid: `http://github.com/user/repo.git`, `git@github.com:user/repo.git`

### Path Validation

**Rules**:

- No parent directory access (`../`)
- No absolute paths
- No access to hidden directories (`.git/`, `.cargo/`)
- Must be within current working directory
- No symbolic links to restricted areas

**Implementation**:

```rust
fn validate_path(path: &str) -> Result<(), ValidationError> {
    // Reject parent directory traversal
    if path.contains("../") {
        return Err(ValidationError::ParentDirectoryAccess);
    }

    // Reject absolute paths
    if path.starts_with("/") || path.contains(":\\") {
        return Err(ValidationError::AbsolutePath);
    }

    // Reject access to hidden directories
    if path.starts_with(".git/") || path.starts_with(".cargo/") {
        return Err(ValidationError::HiddenDirectoryAccess);
    }

    // Canonicalize and check bounds
    let canonical = std::fs::canonicalize(path)?;
    let working_dir = std::env::current_dir()?;

    if !canonical.starts_with(working_dir) {
        return Err(ValidationError::OutsideWorkingDirectory);
    }

    Ok(())
}
```

## Working Directory Isolation

### Directory Access Rules

#### Allowed Access

- Current working directory and subdirectories
- Files created during execution
- Temporary files in secure temporary directory

#### Forbidden Access

- Parent directories (`../`)
- Home directory (`~/.cargo/`, `~/.config/`)
- System directories (`/etc/`, `/usr/`, `/var/`)
- Hidden directories (`.git/`, `.cargo/`)
- Other user directories

### Path Canonicalization

All paths must be canonicalized before validation:

```rust
fn canonicalize_path(path: &str) -> Result<PathBuf, SecurityError> {
    let canonical = std::fs::canonicalize(path)
        .map_err(|_| SecurityError::InvalidPath)?;

    let working_dir = std::env::current_dir()
        .map_err(|_| SecurityError::WorkingDirectoryError)?;

    if !canonical.starts_with(&working_dir) {
        return Err(SecurityError::DirectoryTraversal);
    }

    Ok(canonical)
}
```

### Symbolic Link Handling

- Symbolic links are resolved during canonicalization
- Links pointing outside working directory are rejected
- Links to system files are blocked
- Circular links are detected and rejected

## Resource Limits

### CPU Limits

**Timeout**: 300 seconds (5 minutes)

**Implementation**:

- Process timeout enforced using system timers
- CPU-intensive operations monitored
- Automatic termination on timeout
- Grace period for cleanup (30 seconds)

### Memory Limits

**Limit**: 512MB per process

**Implementation**:

- Memory usage monitored using system APIs
- Process memory limit enforced
- Automatic termination on limit exceeded
- Memory leak detection and reporting

### Disk I/O Limits

**Limit**: 256MB total I/O

**Implementation**:

- Read/write operations tracked
- Cumulative I/O limit enforced
- Temporary file size limits
- Disk space monitoring

### Network Limits

**Restrictions**:

- Only HTTPS connections allowed
- Rate limiting: 100 requests per minute
- Allowed domains: crates.io, osv.dev, github.com
- Connection timeout: 30 seconds

## Environment Variable Filtering

### Allowed Variables

Environment variables that are passed through to child processes:

```yaml
allowed_env_vars:
  - PATH
  - HOME
  - USER
  - LANG
  - LC_ALL
  - TERM
  - CARGO_HOME
  - RUSTUP_HOME
  - RUST_LOG
```

### Filtered Variables

Environment variables that are blocked or sanitized:

```yaml
blocked_env_vars:
  - AWS_ACCESS_KEY_ID
  - AWS_SECRET_ACCESS_KEY
  - GITHUB_TOKEN
  - DOCKER_PASSWORD
  - KUBERNETES_TOKEN
  - DATABASE_URL
  - API_KEY
  - SECRET_KEY
  - PRIVATE_KEY
```

### Environment Sanitization

```rust
fn sanitize_environment() -> HashMap<String, String> {
    let mut env = HashMap::new();

    for (key, value) in std::env::vars() {
        if is_allowed_env_var(&key) && is_safe_env_value(&value) {
            env.insert(key, value);
        }
    }

    env
}
```

## CVE Scanning Integration

### OSV.dev API Integration

**API Endpoint**: `https://api.osv.dev/v1/query`

**Request Format**:

```json
{
  "package": {
    "name": "package-name",
    "ecosystem": "crates.io"
  },
  "version": "1.0.0"
}
```

**Response Processing**:

- Parse vulnerability data
- Classify severity levels
- Generate security recommendations
- Cache results for performance

### Severity Thresholds

| Severity | Action | Description |
|----------|--------|-------------|
| CRITICAL | BLOCK | Execution blocked, manual override required |
| HIGH | BLOCK | Execution blocked, manual override required |
| MEDIUM | WARN | Warning displayed, confirmation required |
| LOW | LOG | Event logged, execution continues |

### Vulnerability Assessment

```rust
#[derive(Debug, Clone)]
pub struct VulnerabilityAssessment {
    pub package_name: String,
    pub version: String,
    pub vulnerabilities: Vec<Vulnerability>,
    pub severity: SeverityLevel,
    pub recommendation: SecurityRecommendation,
    pub can_proceed: bool,
}

#[derive(Debug, Clone)]
pub enum SecurityRecommendation {
    Block,
    Warn,
    Log,
    Proceed,
}
```

### CVE Scanning Process

1. **Package Identification**: Extract package name and version
2. **API Query**: Query OSV.dev for vulnerability data
3. **Result Processing**: Parse and classify vulnerabilities
4. **Severity Assessment**: Determine overall severity level
5. **Action Determination**: Decide whether to block, warn, or proceed
6. **Result Caching**: Cache results for performance
7. **Audit Logging**: Log all security assessments

## Authentication and Authorization

### Client Authentication

**Method**: API Key Authentication

**Implementation**:

- Unique API keys for each client
- Key rotation support
- Secure key storage
- Key revocation capabilities

### Authorization Levels

| Level | Commands | Risk Assessment |
|-------|----------|----------------|
| READ | `cargo_metadata`, `cargo_version`, `cargo_info` | Low risk |
| BUILD | `cargo_build`, `cargo_check`, `cargo_clippy` | Low risk |
| TEST | `cargo_test`, `cargo_bench` | Medium risk |
| MODIFY | `cargo_add`, `cargo_remove`, `cargo_update` | High risk |
| ADMIN | All commands | High risk |

### Permission Matrix

```yaml
permissions:
  read_only:
    - cargo_metadata
    - cargo_version
    - cargo_info
    - cargo_search
    - cargo_tree

  build_tools:
    - cargo_build
    - cargo_check
    - cargo_clippy
    - cargo_fmt
    - cargo_doc

  test_tools:
    - cargo_test
    - cargo_bench
    - cargo_llvm_cov
    - cargo_nextest

  modify_project:
    - cargo_add
    - cargo_remove
    - cargo_update
    - cargo_new
    - cargo_init

  admin_tools:
    - cargo_clean
    - cargo_audit
    - cargo_deny
    - cargo_mutants
```

## Audit and Logging

### Security Event Logging

All security-relevant events are logged with the following format:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "event_type": "security_validation",
  "severity": "HIGH",
  "client_id": "client-123",
  "command": "cargo_add",
  "parameters": {
    "package": "suspicious-package",
    "version": "1.0.0"
  },
  "validation_result": "BLOCKED",
  "reason": "CVE-2024-1234 detected",
  "threat_indicators": ["high_severity_cve"],
  "remediation": "Update to version 1.0.1"
}
```

### Log Categories

| Category | Description | Retention |
|----------|-------------|-----------|
| SECURITY | Security events, violations, blocks | 2 years |
| AUDIT | Command execution, access attempts | 1 year |
| ERROR | System errors, failures | 6 months |
| DEBUG | Detailed debugging information | 1 month |

### Monitoring and Alerting

**Real-time Monitoring**:

- Security violation detection
- Unusual activity patterns
- Resource usage anomalies
- System health monitoring

**Alert Conditions**:

- Multiple security violations from same client
- High-severity CVE detection
- Resource limit exceeded
- System component failures

## Security Controls Matrix

| Control | Implementation | Validation | Monitoring |
|---------|----------------|------------|------------|
| Input Validation | Regex patterns | Unit tests | Real-time |
| Path Validation | Canonicalization | Integration tests | Per request |
| CVE Scanning | OSV.dev API | Daily scans | Continuous |
| Resource Limits | System enforcement | Load testing | Real-time |
| Access Control | Permission matrix | Security tests | Per request |
| Audit Logging | Structured logs | Log analysis | Continuous |

### Security Testing Requirements

**Unit Tests**:

- Input validation functions
- Path canonicalization
- Permission checking
- Error handling

**Integration Tests**:

- End-to-end security scenarios
- Attack simulation
- Resource limit testing
- Recovery procedures

**Security Tests**:

- Penetration testing
- Vulnerability scanning
- Fuzzing input validation
- Load testing with limits

### Compliance Requirements

**Security Standards**:

- OWASP Top 10 compliance
- NIST Cybersecurity Framework
- ISO 27001 controls
- Industry best practices

**Audit Requirements**:

- Quarterly security reviews
- Annual penetration testing
- Continuous vulnerability scanning
- Incident response testing

## Conclusion

This security specification provides comprehensive protection against identified threats while maintaining system usability. All security controls are mandatory and must be implemented as specified to ensure the safe operation of CogPilot in production environments.

Regular security reviews and updates to this specification are required to address emerging threats and maintain security effectiveness.
