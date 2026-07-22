# Security Policy

> This is an **intentionally vulnerable lab**. The pipeline **surfaces findings as
> warnings** rather than hard-blocking — enforcement is deliberately light so the lab
> stays easy to iterate on. Deploy only in an isolated subscription you own, and tear
> it down when finished.

## Scanning Tools

| Tool | Purpose | Runs On | Blocking? |
|---|---|---|---|
| PSScriptAnalyzer | PowerShell linting | Every PR and push | Yes |
| TruffleHog | Verified-secret scanning | Every PR and push | Yes |
| kubeconform | Kubernetes manifest validation | Every PR and push | Yes |
| Helm template | Chart render + custom-rule assertion | Every PR and push | Yes |
| detection-validator | KQL/Falco rule structure | Every PR and push | Yes |
| Bandit | Python SAST (`tools/`) | Every PR and push | Yes |
| Checkov | IaC misconfiguration (Bicep) | Every PR and push | **No — warn only** (`soft_fail`) |
| Trivy | Container CVE scan (Juice Shop) | Every PR and push | **No — warn only** (image is intentionally vulnerable) |

> **SAST is Bandit, not CodeQL.** CodeQL needs GitHub Advanced Security (public repo
> or a GHAS license); the `python-sast` job is wired to switch to CodeQL when that's
> available.

## Severity Handling

Because this is a lab, findings are **surfaced, not gated**:

| Severity | Handling |
|---|---|
| Critical / High | Reported in the run; review before merge (not auto-blocked) |
| Medium | Warning |
| Low | Informational |

The **structural** jobs (lint, manifest/chart/detection validation, verified-secret
scan) do fail the build — they catch broken scaffolding. The **misconfiguration/CVE**
scanners (Checkov, Trivy) warn only, by design: the lab intentionally ships vulnerable
IaC and images, so a hard gate would block every run.

## Exception Process

Accepted risks are documented in [`security-exceptions.yaml`](./security-exceptions.yaml):

1. Add the accepted risk with justification, approver, and (for time-boxed items) an expiration date
2. Get maintainer approval
3. Open a tracking issue for anything meant to be fixed later

The `exception-check` job in `validate.yaml` reads the register on every PR and
**warns** (non-blocking) when a time-boxed exception has passed its expiration date.
Permanent, by-design accepted risks use `expiration_date: none`.

## Reporting a Vulnerability

For a security issue in the lab's *scaffolding* (not the intentionally-vulnerable workloads):

1. **Do not** open a public GitHub issue
2. Email the maintainers directly
3. Include a description and reproduction steps
4. Allow 30 days for a response before public disclosure

## Disclaimer

This project intentionally deploys vulnerable workloads and offensive tooling.
Deploy only in an isolated subscription you own; never in production.
