# CogPilot Operations Manual

## Table of Contents

- [Overview](#overview)
- [Installation and Setup](#installation-and-setup)
- [Configuration Management](#configuration-management)
- [Deployment Procedures](#deployment-procedures)
- [Monitoring and Alerting](#monitoring-and-alerting)
- [Security Operations](#security-operations)
- [Maintenance and Updates](#maintenance-and-updates)
- [Troubleshooting](#troubleshooting)
- [Disaster Recovery](#disaster-recovery)
- [Compliance and Auditing](#compliance-and-auditing)

## Overview

This operations manual provides comprehensive guidance for deploying, configuring, monitoring, and maintaining CogPilot in production environments. It covers all aspects of operational management from initial setup to ongoing maintenance.

### Operational Principles

- **Security First**: All operations prioritize security over convenience
- **Monitoring Everything**: Comprehensive observability across all components
- **Fail Safe**: Systems fail into secure states
- **Audit Everything**: Complete audit trail for all actions
- **Automate Operations**: Minimize manual intervention

## Installation and Setup

### System Requirements

#### Minimum Requirements

- **CPU**: 2 cores, 2.4 GHz
- **Memory**: 4 GB RAM
- **Storage**: 20 GB available space
- **Network**: Stable internet connection for OSV.dev API
- **OS**: Linux (Ubuntu 20.04+ recommended), macOS 10.15+, Windows 10+

#### Recommended Requirements

- **CPU**: 4 cores, 3.2 GHz
- **Memory**: 8 GB RAM
- **Storage**: 50 GB SSD
- **Network**: High-speed internet connection
- **OS**: Linux (Ubuntu 22.04 LTS recommended)

### Installation Methods

#### Docker Installation (Recommended)

```bash
# Pull the official image
docker pull cogpilot/cog-pilot:latest

# Create configuration directory
mkdir -p /etc/cog_pilot

# Create configuration file
cat > /etc/cog_pilot/config.toml << 'EOF'
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
EOF

# Run container
docker run -d \
  --name cog-pilot \
  --restart unless-stopped \
  -p 8080:8080 \
  -p 9090:9090 \
  -v /etc/cog_pilot:/etc/cog_pilot:ro \
  -v /var/log/cog_pilot:/var/log/cog_pilot \
  cogpilot/cog-pilot:latest
```

#### Binary Installation

```bash
# Download latest release
curl -L https://github.com/cogpilot/cog-pilot/releases/latest/download/cog-pilot-linux-x86_64.tar.gz | tar xz

# Move to system directory
sudo mv cog-pilot /usr/local/bin/
sudo chmod +x /usr/local/bin/cog-pilot

# Create system user
sudo useradd --system --shell /bin/false cogpilot

# Create directories
sudo mkdir -p /etc/cog_pilot /var/log/cog_pilot
sudo chown cogpilot:cogpilot /var/log/cog_pilot

# Install systemd service
sudo tee /etc/systemd/system/cog-pilot.service > /dev/null << 'EOF'
[Unit]
Description=CogPilot MCP Server
After=network.target

[Service]
Type=simple
User=cogpilot
Group=cogpilot
ExecStart=/usr/local/bin/cog-pilot --config /etc/cog_pilot/config.toml
Restart=always
RestartSec=5
KillMode=mixed
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable cog-pilot
sudo systemctl start cog-pilot
```

### Initial Configuration

#### API Key Generation

```bash
# Generate API key
cog-pilot generate-api-key --name "production-key" --permissions "admin"

# Output example:
# API Key: cg_1234567890abcdef1234567890abcdef
# Key ID: key_abc123
# Permissions: admin
```

#### TLS Certificate Setup

```bash
# Generate self-signed certificate (for testing)
openssl req -x509 -newkey rsa:4096 -keyout /etc/cog_pilot/key.pem -out /etc/cog_pilot/cert.pem -days 365 -nodes

# Or use Let's Encrypt for production
certbot certonly --standalone -d cog-pilot.yourdomain.com
cp /etc/letsencrypt/live/cog-pilot.yourdomain.com/fullchain.pem /etc/cog_pilot/cert.pem
cp /etc/letsencrypt/live/cog-pilot.yourdomain.com/privkey.pem /etc/cog_pilot/key.pem
```

### External Tool Installation

#### Required Tools

```bash
# Install Rust and Cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install external tools
cargo install cargo-audit
cargo install cargo-deny
cargo install cargo-llvm-cov
cargo install cargo-mutants
cargo install cargo-nextest

# Verify installations
cargo audit --version
cargo deny --version
cargo llvm-cov --version
cargo mutants --version
cargo nextest --version
```

#### Tool Version Compatibility

| Tool | Minimum Version | Recommended Version |
|------|----------------|-------------------|
| cargo-audit | 0.17.0 | 0.18.0+ |
| cargo-deny | 0.13.0 | 0.14.0+ |
| cargo-llvm-cov | 0.5.0 | 0.6.0+ |
| cargo-mutants | 23.0.0 | 24.0.0+ |
| cargo-nextest | 0.9.0 | 0.9.50+ |

## Configuration Management

### Configuration File Structure

**File**: `/etc/cog_pilot/config.toml`

```toml
# Server configuration
[server]
host = "0.0.0.0"
port = 8080
tls_cert_path = "/etc/cog_pilot/cert.pem"
tls_key_path = "/etc/cog_pilot/key.pem"
max_connections = 1000
request_timeout = 30

# Security configuration
[security]
max_execution_time = 300
max_memory_mb = 2048
max_disk_io_mb = 1024
osv_api_url = "https://api.osv.dev"
osv_timeout = 30
allowed_registries = ["crates.io"]
blocked_packages = []
api_key_file = "/etc/cog_pilot/api_keys.json"

# Logging configuration
[logging]
level = "info"
format = "json"
output = "/var/log/cog_pilot/app.log"
audit_log = "/var/log/cog_pilot/audit.log"
max_file_size = "100MB"
max_files = 10
compress = true

# Monitoring configuration
[monitoring]
metrics_enabled = true
metrics_port = 9090
health_check_path = "/health"
health_check_port = 8080
prometheus_namespace = "cogpilot"

# Cache configuration
[cache]
vulnerability_cache_ttl = 3600  # 1 hour
tool_cache_ttl = 300           # 5 minutes
max_cache_size = 1000
cleanup_interval = 300

# Resource limits
[limits]
max_concurrent_commands = 50
max_request_size = "10MB"
rate_limit_per_minute = 100
burst_limit = 20

# External tools
[tools]
verify_on_startup = true
auto_install = false
tool_timeout = 300
```

### Environment Variables

```bash
# Core configuration
export COGPILOT_CONFIG_FILE="/etc/cog_pilot/config.toml"
export COGPILOT_LOG_LEVEL="info"
export COGPILOT_PORT="8080"

# Security
export COGPILOT_API_KEY_FILE="/etc/cog_pilot/api_keys.json"
export COGPILOT_TLS_CERT="/etc/cog_pilot/cert.pem"
export COGPILOT_TLS_KEY="/etc/cog_pilot/key.pem"

# External services
export COGPILOT_OSV_API_URL="https://api.osv.dev"
export COGPILOT_OSV_TIMEOUT="30"

# Resource limits
export COGPILOT_MAX_MEMORY_MB="2048"
export COGPILOT_MAX_EXECUTION_TIME="300"
export COGPILOT_MAX_DISK_IO_MB="1024"
```

### API Key Management

#### API Key Storage Format

**File**: `/etc/cog_pilot/api_keys.json`

```json
{
  "keys": [
    {
      "id": "key_abc123",
      "key_hash": "sha256:abcdef1234567890...",
      "name": "production-key",
      "permissions": ["admin"],
      "created_at": "2024-01-15T10:00:00Z",
      "expires_at": "2025-01-15T10:00:00Z",
      "last_used": "2024-01-15T11:30:00Z",
      "active": true
    }
  ]
}
```

#### Key Management Commands

```bash
# Generate new API key
cog-pilot generate-api-key --name "client-1" --permissions "build,test"

# List API keys
cog-pilot list-api-keys

# Revoke API key
cog-pilot revoke-api-key --id "key_abc123"

# Rotate API key
cog-pilot rotate-api-key --id "key_abc123"
```

## Deployment Procedures

### Production Deployment Checklist

#### Pre-Deployment

- [ ] Security review completed
- [ ] Load testing performed
- [ ] Backup procedures verified
- [ ] Monitoring configured
- [ ] Log aggregation setup
- [ ] SSL certificates installed
- [ ] API keys generated
- [ ] External tools verified

#### Deployment Steps

1. **Prepare Environment**

   ```bash
   # Create backup of current configuration
   cp -r /etc/cog_pilot /etc/cog_pilot.backup.$(date +%Y%m%d_%H%M%S)

   # Update system packages
   sudo apt update && sudo apt upgrade -y
   ```

2. **Deploy Application**

   ```bash
   # Pull latest image
   docker pull cogpilot/cog-pilot:latest

   # Stop current container
   docker stop cog-pilot

   # Start new container
   docker run -d \
     --name cog-pilot \
     --restart unless-stopped \
     -p 8080:8080 \
     -p 9090:9090 \
     -v /etc/cog_pilot:/etc/cog_pilot:ro \
     -v /var/log/cog_pilot:/var/log/cog_pilot \
     cogpilot/cog-pilot:latest
   ```

3. **Verify Deployment**

   ```bash
   # Check service status
   curl -f http://localhost:8080/health

   # Check metrics endpoint
   curl -f http://localhost:9090/metrics

   # Verify API functionality
   curl -X POST http://localhost:8080/rpc \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer $API_KEY" \
     -d '{"jsonrpc":"2.0","method":"cargo_version","params":{},"id":1}'
   ```

#### Post-Deployment

- [ ] Health checks passing
- [ ] Metrics collection active
- [ ] Log ingestion working
- [ ] API functionality verified
- [ ] Security scanning completed
- [ ] Performance baseline established
- [ ] Backup verification completed

### Blue-Green Deployment

```bash
#!/bin/bash
# Blue-Green deployment script

# Configuration
BLUE_PORT=8080
GREEN_PORT=8081
LOAD_BALANCER_CONFIG="/etc/nginx/sites-available/cog-pilot"

# Deploy to green environment
echo "Deploying to green environment..."
docker run -d \
  --name cog-pilot-green \
  -p $GREEN_PORT:8080 \
  -p 9091:9090 \
  -v /etc/cog_pilot:/etc/cog_pilot:ro \
  -v /var/log/cog_pilot:/var/log/cog_pilot \
  cogpilot/cog-pilot:latest

# Health check green environment
echo "Performing health check..."
for i in {1..30}; do
  if curl -f http://localhost:$GREEN_PORT/health > /dev/null 2>&1; then
    echo "Green environment healthy"
    break
  fi
  echo "Waiting for green environment... ($i/30)"
  sleep 10
done

# Switch traffic to green
echo "Switching traffic to green..."
sed -i "s/proxy_pass http:\/\/localhost:$BLUE_PORT/proxy_pass http:\/\/localhost:$GREEN_PORT/" $LOAD_BALANCER_CONFIG
nginx -s reload

# Stop blue environment
echo "Stopping blue environment..."
docker stop cog-pilot-blue
docker rm cog-pilot-blue

# Rename green to blue
docker rename cog-pilot-green cog-pilot-blue

echo "Deployment complete"
```

## Monitoring and Alerting

### Health Checks

#### Application Health

```bash
# Basic health check
curl -f http://localhost:8080/health

# Expected response:
{
  "status": "healthy",
  "timestamp": "2024-01-15T12:00:00Z",
  "version": "1.0.0",
  "uptime": 3600,
  "checks": {
    "database": "ok",
    "osv_api": "ok",
    "external_tools": "ok"
  }
}
```

#### Detailed Health Check

```bash
# Detailed health check
curl -f http://localhost:8080/health/detailed

# Expected response:
{
  "status": "healthy",
  "timestamp": "2024-01-15T12:00:00Z",
  "version": "1.0.0",
  "uptime": 3600,
  "memory_usage": {
    "used": 512000000,
    "total": 2048000000,
    "percentage": 25.0
  },
  "disk_usage": {
    "used": 1024000000,
    "total": 50000000000,
    "percentage": 2.0
  },
  "external_tools": {
    "cargo-audit": "0.18.0",
    "cargo-deny": "0.14.0",
    "cargo-llvm-cov": "0.6.0",
    "cargo-mutants": "24.0.0",
    "cargo-nextest": "0.9.50"
  },
  "api_connectivity": {
    "osv_dev": "ok",
    "crates_io": "ok"
  }
}
```

### Metrics Collection

#### Prometheus Configuration

**File**: `/etc/prometheus/prometheus.yml`

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'cog-pilot'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 15s
    metrics_path: /metrics

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']
```

#### Key Metrics

| Metric | Description | Type |
|--------|-------------|------|
| `cogpilot_requests_total` | Total requests processed | Counter |
| `cogpilot_request_duration_seconds` | Request processing time | Histogram |
| `cogpilot_security_violations_total` | Security violations detected | Counter |
| `cogpilot_command_executions_total` | Commands executed | Counter |
| `cogpilot_cache_hits_total` | Cache hits/misses | Counter |
| `cogpilot_memory_usage_bytes` | Memory usage | Gauge |
| `cogpilot_cpu_usage_percent` | CPU usage | Gauge |

### Alerting Rules

#### Prometheus Alerting Rules

**File**: `/etc/prometheus/rules/cog-pilot.yml`

```yaml
groups:
  - name: cog-pilot
    rules:
      - alert: CogPilotDown
        expr: up{job="cog-pilot"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "CogPilot service is down"
          description: "CogPilot service has been down for more than 1 minute"

      - alert: HighSecurityViolations
        expr: rate(cogpilot_security_violations_total[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High rate of security violations"
          description: "Security violations rate is {{ $value }} per second"

      - alert: HighMemoryUsage
        expr: cogpilot_memory_usage_bytes / 1024 / 1024 / 1024 > 1.8
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"
          description: "Memory usage is {{ $value }}GB"

      - alert: CommandExecutionTimeout
        expr: rate(cogpilot_command_executions_total{result="timeout"}[5m]) > 0.05
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High command timeout rate"
          description: "Command timeout rate is {{ $value }} per second"

      - alert: OSVAPIDown
        expr: cogpilot_osv_api_status != 1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "OSV.dev API is unreachable"
          description: "Unable to reach OSV.dev API for vulnerability scanning"
```

### Log Management

#### Log Rotation

**File**: `/etc/logrotate.d/cog-pilot`

```bash
/var/log/cog_pilot/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 cogpilot cogpilot
    postrotate
        systemctl reload cog-pilot
    endscript
}
```

#### Log Aggregation

**ELK Stack Configuration**

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/cog_pilot/*.log
    fields:
      service: cog-pilot
      environment: production
    fields_under_root: true
    json.keys_under_root: true
    json.overwrite_keys: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "cog-pilot-%{+yyyy.MM.dd}"

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
```

## Security Operations

### Security Monitoring

#### Real-time Security Monitoring

```bash
# Monitor security events
tail -f /var/log/cog_pilot/audit.log | grep -E "(SECURITY|VIOLATION|BLOCKED)"

# Monitor failed authentication attempts
grep "authentication_failed" /var/log/cog_pilot/audit.log | tail -20

# Monitor suspicious activity
grep -E "(directory_traversal|command_injection|malicious_package)" /var/log/cog_pilot/audit.log
```

#### Security Incident Response

1. **Immediate Response**

   ```bash
   # Block suspicious IP
   iptables -A INPUT -s <suspicious_ip> -j DROP

   # Revoke compromised API key
   cog-pilot revoke-api-key --id <compromised_key_id>

   # Increase logging verbosity
   cog-pilot set-log-level --level debug
   ```

2. **Investigation**

   ```bash
   # Analyze security logs
   grep -A 10 -B 10 "security_violation" /var/log/cog_pilot/audit.log

   # Check system integrity
   aide --check

   # Review active connections
   netstat -an | grep :8080
   ```

3. **Recovery**

   ```bash
   # Restore from backup if needed
   systemctl stop cog-pilot
   rsync -av /backup/cog_pilot/ /etc/cog_pilot/
   systemctl start cog-pilot

   # Update security rules
   cog-pilot update-security-rules
   ```

### Vulnerability Management

#### Regular Security Scans

```bash
#!/bin/bash
# Security scan script

# Run vulnerability scan
trivy image cogpilot/cog-pilot:latest

# Check for outdated dependencies
cargo audit

# Scan configuration files
checkov --framework dockerfile --file Dockerfile

# Check for secrets in logs
truffleHog --regex --entropy=False /var/log/cog_pilot/
```

#### Security Updates

```bash
# Update external tools
cargo install --force cargo-audit
cargo install --force cargo-deny
cargo install --force cargo-llvm-cov
cargo install --force cargo-mutants
cargo install --force cargo-nextest

# Update Docker image
docker pull cogpilot/cog-pilot:latest
docker service update --image cogpilot/cog-pilot:latest cog-pilot
```

## Maintenance and Updates

### Regular Maintenance Tasks

#### Daily Tasks

```bash
#!/bin/bash
# Daily maintenance script

# Check service status
systemctl status cog-pilot

# Verify external tool availability
cog-pilot verify-tools

# Clean up old logs
find /var/log/cog_pilot -name "*.log.gz" -mtime +30 -delete

# Check disk space
df -h | grep -E "(80%|90%|95%)" && echo "Warning: Low disk space"

# Backup configuration
cp -r /etc/cog_pilot /backup/cog_pilot.$(date +%Y%m%d)
```

#### Weekly Tasks

```bash
#!/bin/bash
# Weekly maintenance script

# Update security database
cargo audit --update

# Check for Docker image updates
docker pull cogpilot/cog-pilot:latest

# Rotate API keys older than 90 days
cog-pilot rotate-old-keys --days 90

# Generate security report
cog-pilot generate-security-report --output /var/log/cog_pilot/security-report.$(date +%Y%m%d).json
```

#### Monthly Tasks

```bash
#!/bin/bash
# Monthly maintenance script

# Full system backup
tar -czf /backup/full-backup.$(date +%Y%m%d).tar.gz /etc/cog_pilot /var/log/cog_pilot

# Security audit
cog-pilot security-audit --comprehensive

# Performance review
cog-pilot generate-performance-report --period 30d

# Update documentation
cog-pilot generate-api-docs --output /docs/api-current.md
```

### Update Procedures

#### Minor Updates

```bash
# Pull latest patch version
docker pull cogpilot/cog-pilot:1.0.x

# Rolling update
docker service update --image cogpilot/cog-pilot:1.0.x cog-pilot

# Verify update
curl -f http://localhost:8080/health
```

#### Major Updates

```bash
# Backup current state
systemctl stop cog-pilot
cp -r /etc/cog_pilot /backup/cog_pilot.pre-update
cp -r /var/log/cog_pilot /backup/logs.pre-update

# Update application
docker pull cogpilot/cog-pilot:2.0.0

# Update configuration if needed
cog-pilot migrate-config --from 1.0 --to 2.0

# Start with new version
systemctl start cog-pilot

# Verify functionality
cog-pilot run-integration-tests
```

## Troubleshooting

### Common Issues

#### Service Won't Start

```bash
# Check configuration
cog-pilot validate-config --config /etc/cog_pilot/config.toml

# Check logs
journalctl -u cog-pilot -f

# Check file permissions
ls -la /etc/cog_pilot/
ls -la /var/log/cog_pilot/

# Check port availability
netstat -an | grep :8080
```

#### High Memory Usage

```bash
# Check memory usage
ps aux | grep cog-pilot
free -h

# Check for memory leaks
valgrind --tool=memcheck --leak-check=full cog-pilot

# Restart service
systemctl restart cog-pilot
```

#### API Requests Failing

```bash
# Check API key
cog-pilot validate-api-key --key $API_KEY

# Check rate limiting
grep "rate_limit" /var/log/cog_pilot/app.log

# Check security violations
grep "security_violation" /var/log/cog_pilot/audit.log

# Test API endpoint
curl -v -X POST http://localhost:8080/rpc \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $API_KEY" \
  -d '{"jsonrpc":"2.0","method":"cargo_version","params":{},"id":1}'
```

#### External Tools Not Working

```bash
# Verify tool installation
cargo audit --version
cargo deny --version
cargo llvm-cov --version
cargo mutants --version
cargo nextest --version

# Check PATH
echo $PATH
which cargo-audit

# Reinstall tools
cargo install --force cargo-audit
cargo install --force cargo-deny
cargo install --force cargo-llvm-cov
cargo install --force cargo-mutants
cargo install --force cargo-nextest
```

### Diagnostic Commands

```bash
# Generate diagnostic report
cog-pilot diagnose --output /tmp/diagnostic-report.json

# Check system resources
top
htop
iostat
df -h

# Check network connectivity
ping -c 3 api.osv.dev
curl -I https://crates.io

# Check Docker status
docker ps
docker stats
docker logs cog-pilot
```

## Disaster Recovery

### Backup Strategy

#### Configuration Backup

```bash
#!/bin/bash
# Configuration backup script

BACKUP_DIR="/backup/cog_pilot"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR/$DATE

# Backup configuration
cp -r /etc/cog_pilot $BACKUP_DIR/$DATE/
cp -r /var/log/cog_pilot $BACKUP_DIR/$DATE/

# Backup API keys
cp /etc/cog_pilot/api_keys.json $BACKUP_DIR/$DATE/

# Create archive
tar -czf $BACKUP_DIR/backup_$DATE.tar.gz $BACKUP_DIR/$DATE/

# Remove old backups (keep 30 days)
find $BACKUP_DIR -name "backup_*.tar.gz" -mtime +30 -delete
```

#### Database Backup

```bash
#!/bin/bash
# Database backup script (if using external database)

BACKUP_DIR="/backup/database"
DATE=$(date +%Y%m%d_%H%M%S)

# Create database dump
pg_dump -h localhost -U cogpilot cogpilot_db > $BACKUP_DIR/cogpilot_db_$DATE.sql

# Compress backup
gzip $BACKUP_DIR/cogpilot_db_$DATE.sql

# Remove old backups
find $BACKUP_DIR -name "cogpilot_db_*.sql.gz" -mtime +7 -delete
```

### Recovery Procedures

#### Configuration Recovery

```bash
#!/bin/bash
# Configuration recovery script

BACKUP_FILE="/backup/cog_pilot/backup_20240115_120000.tar.gz"

# Stop service
systemctl stop cog-pilot

# Restore configuration
tar -xzf $BACKUP_FILE -C /tmp/
cp -r /tmp/backup_20240115_120000/etc/cog_pilot/* /etc/cog_pilot/

# Set permissions
chown -R cogpilot:cogpilot /etc/cog_pilot
chmod 600 /etc/cog_pilot/api_keys.json

# Start service
systemctl start cog-pilot

# Verify recovery
curl -f http://localhost:8080/health
```

#### Full System Recovery

```bash
#!/bin/bash
# Full system recovery script

# Install fresh system
apt update && apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Restore configuration
tar -xzf /backup/full-backup.tar.gz -C /

# Set permissions
chown -R cogpilot:cogpilot /etc/cog_pilot /var/log/cog_pilot

# Start service
docker run -d \
  --name cog-pilot \
  --restart unless-stopped \
  -p 8080:8080 \
  -p 9090:9090 \
  -v /etc/cog_pilot:/etc/cog_pilot:ro \
  -v /var/log/cog_pilot:/var/log/cog_pilot \
  cogpilot/cog-pilot:latest

# Verify recovery
sleep 30
curl -f http://localhost:8080/health
```

## Compliance and Auditing

### Audit Logging

#### Audit Log Format

```json
{
  "timestamp": "2024-01-15T12:00:00Z",
  "event_type": "api_request",
  "severity": "info",
  "client_id": "client_123",
  "user_id": "user_456",
  "api_key_id": "key_789",
  "method": "cargo_add",
  "parameters": {
    "package": "serde",
    "version": "1.0"
  },
  "source_ip": "192.168.1.100",
  "user_agent": "CogPilot-Client/1.0.0",
  "result": "success",
  "execution_time": 1.234,
  "security_checks": {
    "cve_scan": "passed",
    "input_validation": "passed",
    "rate_limit": "passed"
  }
}
```

#### Compliance Reports

```bash
# Generate compliance report
cog-pilot generate-compliance-report \
  --start-date 2024-01-01 \
  --end-date 2024-01-31 \
  --format json \
  --output /reports/compliance-2024-01.json

# Generate security audit report
cog-pilot generate-security-audit \
  --period 30d \
  --include-violations \
  --include-blocked-requests \
  --output /reports/security-audit-$(date +%Y%m%d).json
```

### Regulatory Compliance

#### GDPR Compliance

```bash
# Data retention policy
cog-pilot set-retention-policy \
  --logs 2y \
  --audit-logs 7y \
  --user-data 5y

# Data anonymization
cog-pilot anonymize-logs \
  --older-than 90d \
  --preserve-security-events
```

#### SOC 2 Compliance

```bash
# Access control audit
cog-pilot audit-access-controls \
  --output /reports/access-control-audit.json

# Security controls verification
cog-pilot verify-security-controls \
  --output /reports/security-controls-verification.json
```

This operations manual provides comprehensive guidance for successfully deploying and maintaining CogPilot in production environments while ensuring security, reliability, and compliance requirements are met.
