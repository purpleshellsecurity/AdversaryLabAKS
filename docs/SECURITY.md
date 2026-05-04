# Security Policy

## Scanning Tools

| Tool | Purpose | Runs On |
|---|---|---|
| PSScriptAnalyzer | PowerShell linting | Every PR and push |
| TruffleHog | Secret scanning | Every PR and push |
| Checkov | IaC misconfiguration | Every PR and push |
| kubeconform | Kubernetes manifest validation | Every PR and push |
| Helm template | Helm values validation | Every PR and push |
| CodeQL | SAST — Python/JavaScript | Every PR and push |
| Trivy | Container/filesystem CVE scanning | Every PR and push |

## Severity Gating Rules

| Severity | Action | SLA |
|---|---|---|
| Critical | Blocks merge immediately | Fix before merge |
| High | Blocks merge immediately | Fix before merge |
| Medium | Warning only | 30-day fix window |
| Low | Informational | 90-day fix window |

## Exception Process

If a finding cannot be remediated within the SLA:

1. Document the accepted risk in `security-exceptions.yaml`
2. Get approval from a maintainer
3. Set an expiration date — maximum 90 days
4. Create a tracking issue

Exceptions are reviewed on every PR. Expired exceptions automatically fail the pipeline.

## Reporting a Vulnerability

If you discover a security vulnerability in this project:

1. **Do not** open a public GitHub issue
2. Email the maintainers directly
3. Include a description of the vulnerability and steps to reproduce
4. Allow 30 days for a response before public disclosure

## Disclaimer

This project intentionally deploys vulnerable workloads for security testing purposes. Do not deploy in production environments or any tenant you do not own.
