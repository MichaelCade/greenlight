# GreenLight - Veeam Security Assessment Tool

A lightweight security assessment tool for Veeam Backup & Replication environments that provides a one-time security posture snapshot.

## Features

- **Repository Immutability Check**: Detects immutable repositories and object lock configurations
- **Encryption Assessment**: Evaluates backup job encryption coverage
- **Credential Security**: Analyzes credential usage patterns
- **Network Security**: Checks backup proxy deployment
- **KMS Integration**: Validates enterprise key management setup
- **Web Dashboard**: Interactive HTML report with security scores

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd greenlight
```

2. Initialize Go module and install dependencies:
```bash
go mod init greenlight
go mod tidy
```

3. Set environment variables:
```bash
export VEEAM_URL="https://your-veeam-server:9419"
export VEEAM_USERNAME="your-username"
export VEEAM_PASSWORD="your-password"
```

4. Run the tool:
```bash
go run main.go
```

5. Open your browser to `http://localhost:8080/report`

## Configuration

Configure the tool using environment variables:

- `VEEAM_URL`: Veeam Backup & Replication server URL
- `VEEAM_USERNAME`: Username for API authentication
- `VEEAM_PASSWORD`: Password for API authentication

## Security Checks

1. **Backup Jobs (10 points)**: Verifies backup jobs are configured
2. **Repository Immutability (25 points)**: Checks for immutable storage
3. **Backup Encryption (20 points)**: Evaluates encryption coverage
4. **Credential Security (15 points)**: Analyzes service account usage
5. **Network Security (15 points)**: Validates proxy deployment
6. **KMS Integration (15 points)**: Checks enterprise key management

## API Endpoints

- `GET /report`: HTML dashboard
- `GET /api/report`: JSON report data

## Development

The project is structured as follows:

- `api/`: Veeam API client
- `checks/`: Security check implementations
- `models/`: Data structures
- `web/`: Web server and templates

To add new security checks:

1. Create a new function in the appropriate `checks/` file
2. Add the check to `RunAllChecks()` in `checks/scoring.go`
3. Update the maximum score calculation

## License

MIT License