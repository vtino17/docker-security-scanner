# Docker Security Scanner

[![CI](https://github.com/vtino17/docker-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/vtino17/docker-security-scanner/actions/workflows/ci.yml)

Scan Docker containers and images for security misconfigurations, exposed ports, vulnerable packages, and CIS benchmark violations.

## Install

```bash
pip install docker-security-scanner
```

## Usage

Scan all running containers:

```bash
dss
```

Scan a specific container:

```bash
dss my-container-name
```

Check image age:

```bash
dss --image nginx:latest
```

Generate HTML report:

```bash
dss -o report.html
```

Verbose output (include PASS findings):

```bash
dss -v
```

## Checks

| Check | Severity | Description |
|---|---|---|
| Running as root | HIGH | Containers should run as non-root user |
| Privileged mode | CRITICAL | Privileged mode grants full host access |
| Host network | HIGH | Host network disables network isolation |
| Capabilities | HIGH | Dangerous Linux capabilities added |
| Volume mounts | MEDIUM | Host paths may expose sensitive data |
| Memory limit | MEDIUM | No memory limit can exhaust host |
| Image age | MEDIUM | Old images may have unpatched vulnerabilities |
| CPU limit | LOW | No CPU limit affects other containers |
| Container status | LOW | Stopped containers may be forgotten |
| Restart policy | INFO | Review restart policy choice |
| Exposed ports | INFO | Review exposed ports |

## License

MIT
