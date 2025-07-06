# Configuration Schema Reference

## Overview

This document provides the complete configuration schema for CogPilot, including all configuration options, validation rules, and examples.

## Configuration File Structure

CogPilot uses YAML configuration files with the following structure:

```yaml
# CogPilot Configuration Schema
server:
  host: "127.0.0.1"      # Localhost only for security
  port: 8080
  max_connections: 10    # Limited for local use
  timeout: 30s

security:
  network:
    localhost_only: true  # Enforce localhost binding
    block_external: true  # Block external connections

  sandbox:
    enabled: true
    memory_limit: "512MB"    # Reduced memory limit
    cpu_limit: "300s"
    process_limit: 25        # Reduced process limit
    disk_limit: "256MB"      # Reduced disk limit

  validation:
    strict_mode: true
    max_input_length: 1024
    blocked_patterns: ["&&", "||", ";", "|"]

tools:
  cargo:
    enabled: true
    version: ">=1.70.0"
    path: "cargo"          # Use system PATH

  rust:
    enabled: true
    version: ">=1.70.0"
    path: "rustc"          # Use system PATH

deployment:
  target_platforms:
    - "windows-x64"
    - "linux-x64"

  package_formats:
    - "executable"
    - "docker"

logging:
  level: "INFO"
  format: "json"
  file: "cogpilot.log"
  max_size: "10MB"         # Reduced log size
  max_files: 3

monitoring:
  metrics:
    enabled: false         # Disabled for local use

  health_checks:
    enabled: true
    interval: "30s"
```

## Configuration Sections

### Server Configuration

**Purpose**: HTTP server settings and connection parameters.

**Schema**:

```yaml
server:
  host: string                    # Server bind address
  port: integer                   # Server port
  max_connections: integer        # Maximum concurrent connections
  timeout: duration               # Request timeout
  tls:
    enabled: boolean              # Enable TLS/SSL
    cert_file: string            # TLS certificate file path
    key_file: string             # TLS private key file path
    ca_file: string              # CA certificate file path
```

**Validation Rules**:

- `host`: Valid IPv4/IPv6 address or hostname
- `port`: Integer between 1024-65535
- `max_connections`: Integer between 1-1000
- `timeout`: Duration string (e.g., "30s", "5m")
- `cert_file`, `key_file`, `ca_file`: Valid file paths

**Example**:

```yaml
server:
  host: "0.0.0.0"
  port: 8443
  max_connections: 200
  timeout: "60s"
  tls:
    enabled: true
    cert_file: "/etc/cogpilot/server.crt"
    key_file: "/etc/cogpilot/server.key"
    ca_file: "/etc/cogpilot/ca.crt"
```

### Security Configuration

**Purpose**: Security policies, authentication, and authorization settings.

#### Authentication

**Schema**:

```yaml
security:
  authentication:
    enabled: boolean              # Enable authentication
    type: string                  # Authentication method
    token_expiry: duration        # Token expiration time
    secret_key: string           # JWT secret key
    issuer: string               # JWT issuer
    audience: string             # JWT audience
```

**Validation Rules**:

- `enabled`: Boolean value
- `type`: One of ["token", "jwt", "basic", "oauth2"]
- `token_expiry`: Duration string
- `secret_key`: Minimum 32 characters
- `issuer`, `audience`: Valid URLs or identifiers

**Example**:

```yaml
security:
  authentication:
    enabled: true
    type: "jwt"
    token_expiry: "8h"
    secret_key: "your-super-secret-key-at-least-32-characters-long"
    issuer: "https://auth.example.com"
    audience: "cogpilot-api"
```

#### Authorization

**Schema**:

```yaml
security:
  authorization:
    enabled: boolean              # Enable authorization
    default_role: string          # Default user role
    roles:                        # Role definitions
      - name: string
        permissions: array
    policies:                     # Access policies
      - resource: string
        actions: array
        roles: array
```

**Validation Rules**:

- `enabled`: Boolean value
- `default_role`: Must exist in roles list
- `roles[].name`: Alphanumeric and underscores only
- `roles[].permissions`: Array of valid permission strings
- `policies[].resource`: Valid resource pattern
- `policies[].actions`: Array of valid action strings
- `policies[].roles`: Array of existing role names

**Example**:

```yaml
security:
  authorization:
    enabled: true
    default_role: "user"
    roles:
      - name: "admin"
        permissions: ["*"]
      - name: "developer"
        permissions: ["cargo:build", "cargo:test", "cargo:check"]
      - name: "user"
        permissions: ["cargo:check"]
    policies:
      - resource: "cargo:*"
        actions: ["execute"]
        roles: ["admin", "developer"]
      - resource: "cargo:check"
        actions: ["execute"]
        roles: ["user"]
```

#### Sandbox Configuration

**Schema**:

```yaml
security:
  sandbox:
    enabled: boolean              # Enable sandboxing
    memory_limit: string          # Memory limit (e.g., "2GB")
    cpu_limit: duration           # CPU time limit
    process_limit: integer        # Max processes
    thread_limit: integer         # Max threads
    file_limit: integer           # Max open files
    network_enabled: boolean      # Allow network access
    allowed_paths: array          # Allowed file paths
    blocked_paths: array          # Blocked file paths
```

**Validation Rules**:

- `enabled`: Boolean value
- `memory_limit`: Memory size string (e.g., "1GB", "512MB")
- `cpu_limit`: Duration string
- `process_limit`: Integer between 1-1000
- `thread_limit`: Integer between 1-10000
- `file_limit`: Integer between 1-100000
- `network_enabled`: Boolean value
- `allowed_paths`: Array of valid directory paths
- `blocked_paths`: Array of valid directory paths

**Example**:

```yaml
security:
  sandbox:
    enabled: true
    memory_limit: "4GB"
    cpu_limit: "600s"
    process_limit: 100
    thread_limit: 200
    file_limit: 2000
    network_enabled: true
    allowed_paths:
      - "/tmp"
      - "/var/tmp"
      - "/home/user/projects"
    blocked_paths:
      - "/etc"
      - "/usr/bin"
      - "/home/user/.ssh"
```

#### Input Validation

**Schema**:

```yaml
security:
  validation:
    strict_mode: boolean          # Enable strict validation
    max_input_length: integer     # Maximum input length
    max_path_length: integer      # Maximum path length
    blocked_patterns: array       # Blocked input patterns
    allowed_patterns: array       # Allowed input patterns
    command_whitelist: array      # Allowed commands
    parameter_validation: object  # Parameter validation rules
```

**Validation Rules**:

- `strict_mode`: Boolean value
- `max_input_length`: Integer between 1-1000000
- `max_path_length`: Integer between 1-4096
- `blocked_patterns`: Array of regex patterns
- `allowed_patterns`: Array of regex patterns
- `command_whitelist`: Array of command names
- `parameter_validation`: Object with validation rules

**Example**:

```yaml
security:
  validation:
    strict_mode: true
    max_input_length: 2048
    max_path_length: 1024
    blocked_patterns:
      - "&&"
      - "||"
      - ";"
      - "|"
      - "`"
      - "$("
    allowed_patterns:
      - "^[a-zA-Z0-9_-]+$"
    command_whitelist:
      - "cargo_build"
      - "cargo_test"
      - "cargo_check"
      - "cargo_clean"
      - "cargo_doc"
    parameter_validation:
      working_directory:
        pattern: "^/tmp/[a-zA-Z0-9_-]+$"
        max_length: 256
      features:
        pattern: "^[a-zA-Z0-9_-]+$"
        max_count: 20
```

### Tools Configuration

**Purpose**: External tool configuration and validation.

**Schema**:

```yaml
tools:
  cargo:
    enabled: boolean              # Enable Cargo tool
    version: string               # Required version
    path: string                  # Executable path
    home: string                  # CARGO_HOME directory
    config: object                # Cargo configuration

  rust:
    enabled: boolean              # Enable Rust compiler
    version: string               # Required version
    path: string                  # Executable path
    target: string                # Default target

  git:
    enabled: boolean              # Enable Git tool
    version: string               # Required version
    path: string                  # Executable path
```

**Validation Rules**:

- `enabled`: Boolean value
- `version`: Valid version constraint (e.g., ">=1.70.0")
- `path`: Valid executable file path
- `home`: Valid directory path
- `config`: Valid tool-specific configuration

**Example**:

```yaml
tools:
  cargo:
    enabled: true
    version: ">=1.70.0"
    path: "/usr/bin/cargo"
    home: "/var/lib/cogpilot/cargo"
    config:
      net:
        retry: 3
        timeout: 30
      build:
        jobs: 4
        target-dir: "target"

  rust:
    enabled: true
    version: ">=1.70.0"
    path: "/usr/bin/rustc"
    target: "x86_64-unknown-linux-gnu"

  git:
    enabled: true
    version: ">=2.30.0"
    path: "/usr/bin/git"
```

### Logging Configuration

**Purpose**: Logging settings and output configuration.

**Schema**:

```yaml
logging:
  level: string                   # Log level
  format: string                  # Log format
  file: string                    # Log file path
  max_size: string                # Maximum log file size
  max_files: integer              # Maximum log files
  rotation: string                # Log rotation policy
  structured: boolean             # Enable structured logging
  destinations: array             # Log destinations
```

**Validation Rules**:

- `level`: One of ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"]
- `format`: One of ["json", "text", "compact"]
- `file`: Valid file path
- `max_size`: Size string (e.g., "100MB")
- `max_files`: Integer between 1-100
- `rotation`: One of ["daily", "hourly", "size"]
- `structured`: Boolean value
- `destinations`: Array of destination configurations

**Example**:

```yaml
logging:
  level: "INFO"
  format: "json"
  file: "/var/log/cogpilot/server.log"
  max_size: "100MB"
  max_files: 10
  rotation: "daily"
  structured: true
  destinations:
    - type: "file"
      path: "/var/log/cogpilot/audit.log"
      filters: ["security.*"]
    - type: "syslog"
      facility: "local0"
      filters: ["error", "warn"]
```

### Monitoring Configuration

**Purpose**: Monitoring, metrics, and health check settings.

**Schema**:

```yaml
monitoring:
  metrics:
    enabled: boolean              # Enable metrics collection
    port: integer                 # Metrics server port
    path: string                  # Metrics endpoint path
    interval: duration            # Collection interval

  health_checks:
    enabled: boolean              # Enable health checks
    interval: duration            # Health check interval
    timeout: duration             # Health check timeout

  tracing:
    enabled: boolean              # Enable distributed tracing
    endpoint: string              # Tracing endpoint
    service_name: string          # Service name
    sample_rate: float            # Sampling rate
```

**Validation Rules**:

- `enabled`: Boolean value
- `port`: Integer between 1024-65535
- `path`: Valid URL path
- `interval`: Duration string
- `timeout`: Duration string
- `endpoint`: Valid URL
- `service_name`: Non-empty string
- `sample_rate`: Float between 0.0-1.0

**Example**:

```yaml
monitoring:
  metrics:
    enabled: true
    port: 9090
    path: "/metrics"
    interval: "15s"

  health_checks:
    enabled: true
    interval: "30s"
    timeout: "5s"

  tracing:
    enabled: true
    endpoint: "http://jaeger:14268/api/traces"
    service_name: "cogpilot"
    sample_rate: 0.1
```

## Configuration Validation

### JSON Schema

The complete configuration schema is available as JSON Schema:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "server": {
      "type": "object",
      "properties": {
        "host": {
          "type": "string",
          "format": "hostname"
        },
        "port": {
          "type": "integer",
          "minimum": 1024,
          "maximum": 65535
        },
        "max_connections": {
          "type": "integer",
          "minimum": 1,
          "maximum": 1000
        },
        "timeout": {
          "type": "string",
          "pattern": "^[0-9]+[smh]$"
        }
      },
      "required": ["host", "port"]
    },
    "security": {
      "type": "object",
      "properties": {
        "authentication": {
          "type": "object",
          "properties": {
            "enabled": {"type": "boolean"},
            "type": {
              "type": "string",
              "enum": ["token", "jwt", "basic", "oauth2"]
            },
            "token_expiry": {
              "type": "string",
              "pattern": "^[0-9]+[smh]$"
            }
          },
          "required": ["enabled", "type"]
        },
        "sandbox": {
          "type": "object",
          "properties": {
            "enabled": {"type": "boolean"},
            "memory_limit": {
              "type": "string",
              "pattern": "^[0-9]+[KMGT]B$"
            },
            "cpu_limit": {
              "type": "string",
              "pattern": "^[0-9]+[smh]$"
            },
            "process_limit": {
              "type": "integer",
              "minimum": 1,
              "maximum": 1000
            }
          },
          "required": ["enabled"]
        }
      },
      "required": ["authentication", "sandbox"]
    }
  },
  "required": ["server", "security"]
}
```

### Validation Functions

**Configuration Validation**:

```rust
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub security: SecurityConfig,
    pub tools: ToolsConfig,
    pub logging: LoggingConfig,
    pub monitoring: MonitoringConfig,
}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.server.validate()?;
        self.security.validate()?;
        self.tools.validate()?;
        self.logging.validate()?;
        self.monitoring.validate()?;
        Ok(())
    }

    pub fn from_file(path: &PathBuf) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Invalid server configuration: {0}")]
    InvalidServer(String),

    #[error("Invalid security configuration: {0}")]
    InvalidSecurity(String),

    #[error("Invalid tools configuration: {0}")]
    InvalidTools(String),

    #[error("File error: {0}")]
    FileError(#[from] std::io::Error),

    #[error("YAML parsing error: {0}")]
    YamlError(#[from] serde_yaml::Error),
}
```

## Configuration Examples

### Development Configuration

```yaml
# Development environment configuration
server:
  host: "127.0.0.1"
  port: 8080
  max_connections: 10
  timeout: "30s"

security:
  authentication:
    enabled: false
    type: "token"

  authorization:
    enabled: false

  sandbox:
    enabled: true
    memory_limit: "1GB"
    cpu_limit: "60s"
    process_limit: 10

  validation:
    strict_mode: false
    max_input_length: 1024

tools:
  cargo:
    enabled: true
    version: ">=1.70.0"
    path: "/usr/bin/cargo"

logging:
  level: "DEBUG"
  format: "text"
  file: "/tmp/cogpilot-dev.log"
  max_size: "10MB"
  max_files: 3

monitoring:
  metrics:
    enabled: false
  health_checks:
    enabled: true
    interval: "60s"
```

### Production Configuration

```yaml
# Production environment configuration
server:
  host: "0.0.0.0"
  port: 8443
  max_connections: 500
  timeout: "60s"
  tls:
    enabled: true
    cert_file: "/etc/cogpilot/server.crt"
    key_file: "/etc/cogpilot/server.key"

security:
  authentication:
    enabled: true
    type: "jwt"
    token_expiry: "8h"
    secret_key: "${JWT_SECRET_KEY}"
    issuer: "https://auth.company.com"
    audience: "cogpilot-api"

  authorization:
    enabled: true
    default_role: "user"
    roles:
      - name: "admin"
        permissions: ["*"]
      - name: "developer"
        permissions: ["cargo:*"]
      - name: "user"
        permissions: ["cargo:check"]

  sandbox:
    enabled: true
    memory_limit: "4GB"
    cpu_limit: "300s"
    process_limit: 50
    network_enabled: true
    allowed_paths:
      - "/tmp/cogpilot"
      - "/var/lib/cogpilot"
    blocked_paths:
      - "/etc"
      - "/usr"
      - "/home"

  validation:
    strict_mode: true
    max_input_length: 2048
    blocked_patterns:
      - "&&"
      - "||"
      - ";"
      - "|"
      - "`"

tools:
  cargo:
    enabled: true
    version: ">=1.70.0"
    path: "/usr/bin/cargo"
    home: "/var/lib/cogpilot/cargo"

  rust:
    enabled: true
    version: ">=1.70.0"
    path: "/usr/bin/rustc"

  git:
    enabled: true
    version: ">=2.30.0"
    path: "/usr/bin/git"

logging:
  level: "INFO"
  format: "json"
  file: "/var/log/cogpilot/server.log"
  max_size: "100MB"
  max_files: 10
  rotation: "daily"
  structured: true
  destinations:
    - type: "file"
      path: "/var/log/cogpilot/audit.log"
      filters: ["security.*"]
    - type: "syslog"
      facility: "local0"

monitoring:
  metrics:
    enabled: true
    port: 9090
    path: "/metrics"
    interval: "15s"

  health_checks:
    enabled: true
    interval: "30s"
    timeout: "5s"

  tracing:
    enabled: true
    endpoint: "http://jaeger:14268/api/traces"
    service_name: "cogpilot"
    sample_rate: 0.1
```

### High-Security Configuration

```yaml
# High-security environment configuration
server:
  host: "127.0.0.1"
  port: 8443
  max_connections: 100
  timeout: "30s"
  tls:
    enabled: true
    cert_file: "/etc/cogpilot/server.crt"
    key_file: "/etc/cogpilot/server.key"
    ca_file: "/etc/cogpilot/ca.crt"

security:
  authentication:
    enabled: true
    type: "jwt"
    token_expiry: "1h"
    secret_key: "${JWT_SECRET_KEY}"
    issuer: "https://auth.secure.com"
    audience: "cogpilot-secure"

  authorization:
    enabled: true
    default_role: "none"
    roles:
      - name: "admin"
        permissions: ["admin:*"]
      - name: "developer"
        permissions: ["cargo:check", "cargo:build"]
      - name: "auditor"
        permissions: ["audit:*"]

  sandbox:
    enabled: true
    memory_limit: "1GB"
    cpu_limit: "120s"
    process_limit: 25
    thread_limit: 50
    file_limit: 500
    network_enabled: false
    allowed_paths:
      - "/tmp/cogpilot-secure"
    blocked_paths:
      - "/etc"
      - "/usr"
      - "/home"
      - "/var"

  validation:
    strict_mode: true
    max_input_length: 512
    max_path_length: 256
    blocked_patterns:
      - "&&"
      - "||"
      - ";"
      - "|"
      - "`"
      - "$("
      - "exec"
      - "eval"
    command_whitelist:
      - "cargo_check"
      - "cargo_build"

tools:
  cargo:
    enabled: true
    version: "=1.70.0"
    path: "/usr/bin/cargo"
    home: "/var/lib/cogpilot/cargo"

  rust:
    enabled: true
    version: "=1.70.0"
    path: "/usr/bin/rustc"

logging:
  level: "WARN"
  format: "json"
  file: "/var/log/cogpilot/secure.log"
  max_size: "50MB"
  max_files: 20
  rotation: "hourly"
  structured: true
  destinations:
    - type: "file"
      path: "/var/log/cogpilot/security.log"
      filters: ["security.*", "error", "warn"]
    - type: "syslog"
      facility: "authpriv"
    - type: "remote"
      endpoint: "https://siem.company.com/api/logs"
      token: "${SIEM_TOKEN}"

monitoring:
  metrics:
    enabled: true
    port: 9090
    path: "/metrics"
    interval: "10s"

  health_checks:
    enabled: true
    interval: "15s"
    timeout: "3s"

  tracing:
    enabled: true
    endpoint: "https://tracing.secure.com/api/traces"
    service_name: "cogpilot-secure"
    sample_rate: 1.0
```

## Environment Variables

Configuration values can be overridden using environment variables:

```bash
# Server configuration
export COGPILOT_SERVER_HOST="0.0.0.0"
export COGPILOT_SERVER_PORT="8443"

# Security configuration
export COGPILOT_SECURITY_AUTH_SECRET_KEY="your-secret-key"
export COGPILOT_SECURITY_SANDBOX_MEMORY_LIMIT="2GB"

# Tools configuration
export COGPILOT_TOOLS_CARGO_PATH="/usr/local/bin/cargo"

# Logging configuration
export COGPILOT_LOGGING_LEVEL="INFO"
export COGPILOT_LOGGING_FILE="/var/log/cogpilot.log"
```

## Configuration Management

### Configuration Validation Tool

```bash
# Validate configuration file
cogpilot config validate --config /etc/cogpilot/config.yaml

# Generate configuration template
cogpilot config template --environment production > config.yaml

# Test configuration
cogpilot config test --config config.yaml
```

### Configuration Hot Reload

```rust
use notify::{Watcher, RecursiveMode, watcher};
use std::sync::mpsc::channel;
use std::time::Duration;

pub struct ConfigWatcher {
    config_path: PathBuf,
    current_config: Arc<RwLock<Config>>,
}

impl ConfigWatcher {
    pub fn new(config_path: PathBuf) -> Result<Self, ConfigError> {
        let config = Config::from_file(&config_path)?;
        Ok(Self {
            config_path,
            current_config: Arc::new(RwLock::new(config)),
        })
    }

    pub fn start_watching(&self) -> Result<(), ConfigError> {
        let (tx, rx) = channel();
        let mut watcher = watcher(tx, Duration::from_secs(1))?;

        watcher.watch(&self.config_path, RecursiveMode::NonRecursive)?;

        loop {
            match rx.recv() {
                Ok(event) => {
                    if let Ok(new_config) = Config::from_file(&self.config_path) {
                        *self.current_config.write().unwrap() = new_config;
                        log::info!("Configuration reloaded successfully");
                    }
                }
                Err(e) => log::error!("Configuration watch error: {}", e),
            }
        }
    }
}
```

This comprehensive configuration schema reference provides all the necessary information for properly configuring CogPilot in various environments while maintaining security and operational requirements.
