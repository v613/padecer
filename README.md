# Padecer
> **Pa**trol **De**volution of **Cer**tificates

## Overview
Padecer is a Go 1.25 CLI application that searches and monitors X.509 certificates for expiration warnings. *Primary condition* to maintains zero external dependencies, relying only on Go's standard library. This design choice ensures minimal attack surface, predictable behavior, and easy deployment across any Go-supported platform. Currently, there is no interface implementation for different sender types (database, file, etc.) to maintain this zero-dependency requirement, though this could theoretically be changed in the future if needed.

### Key Features
- Certificate Chain Processing
- Concurrent Scanning
- Cross-Platform

## Installation & Build
>On linux machine `releaser.sh` can be used.<br>
>On Windows machine `releaser.bat` can be used.
### Prerequisites
- Go 1.25 or later

### Build Commands

```bash
# Standard build
go build -o padecer .

# Optimized build with reduced binary size
go build -ldflags="-s -w" -o padecer .

# Cross-compilation for multiple platforms
GOOS=linux GOARCH=amd64 go build -o padecer-linux-amd64 .
GOOS=darwin GOARCH=amd64 go build -o padecer-darwin-amd64.exe .
GOOS=windows GOARCH=amd64 go build -o padecer-windows-amd64.exe .
```

## Usage Examples
### Command Line Flags
All available command-line options:

```bash
# Basic usage with default settings (30-day threshold, default paths)
./padecer

# Set expiration threshold
./padecer --days=7

# Replace default paths with custom ones
./padecer --paths="/etc/ssl/certs,/var/lib/kubelet/pki"

# Append additional paths to defaults
./padecer --apaths="/opt/certificates,/home/user/certs"

# Include certificate subject in output
./padecer --include-subject

# Send alerts to monitoring server
./padecer --send-to="http://monitoring.example.com:8080/alerts"

# Use configuration file
./padecer --config=padecer.json

# Set graceful shutdown timeout (default 30s)
./padecer --shutdown-timeout=60s

# Combined example
./padecer --days=14 --include-subject --send-to="http://alerts.company.com/webhook" --apaths="/custom/certs"
```

### Real-World Scenarios

```bash
# Monitor Kubernetes certificates with 7-day warning
./padecer --days=7 --paths="/var/lib/kubelet/pki,/etc/kubernetes/pki"

# Enterprise monitoring with alerting
./padecer --days=30 --include-subject --send-to="https://monitoring.corp.com/api/alerts"

# Quick scan of custom certificate directory
./padecer --days=14 --paths="/opt/ssl-certs" --include-subject

# Comprehensive scan with extended timeout for large directories
./padecer --days=21 --shutdown-timeout=120s --apaths="/mnt/shared-certs,/backup/ssl"
```

## Configuration

### Configuration File Format (padecer.json)
```json
{
  "days": 30,
  "paths": ["/etc/ssl/certs", "/etc/pki", "/var/lib/kubelet/pki"],
  "includeSubject": false,
  "sendTo": "http://monitoring.example.com:8080/alerts",
  "shutdownTimeout": "30s",
  "extensions": [".pem", ".cer", ".crt", ".key"]
}
```

## Output Formats
### STDOUT (Valid Certificates)
JSON format for non-expiring certificates:

```json
{
  "host": "server-01",
  "path": "/etc/ssl/certs/ca-cert.pem",
  "expires": "2024-12-31T23:59:59Z",
  "daysUntilExpiry": 45,
  "subject": "CN=Example CA",
  "serialNumber": "1234567890ABCDEF"
}
```

### STDERR (Warnings & Logs)
Certificate expiration warnings:

```
server-01::/etc/ssl/certs/expiring-cert.pem => 2024-02-01T15:04:05Z07:00
```

Application logs in JSON format:
```json
{"time":"2024-01-15T10:30:00Z","level":"INFO","msg":"Certificate scan configuration","host":"server-01","date":"2024-01-15","days_threshold":30}
```

## HTTP Alert Format

When using `--send-to`, alerts are sent as JSON POST requests:

```json
{
  "host": "server-01",
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "WARN",
  "message": "Certificate expiring soon",
  "path": "/etc/ssl/certs/expiring-cert.pem",
  "expirationDate": "2024-02-01T15:04:05Z",
  "daysUntilExpiry": 17,
  "subject": "CN=Example Certificate",
  "serialNumber": "1234567890ABCDEF"
}
``` 

## Planned Features
- [ ] **Web UI Interface**: Create a web-based user interface that accepts HTTP requests from the `--send-to` flag and displays certificate status in a dashboard format. This UI would provide real-time monitoring capabilities while maintaining the zero-dependency principle for the core application.
- [ ] Adjust format of log records.

## Contributing
For support and questions, please contact the development team or create an issue in the repository.