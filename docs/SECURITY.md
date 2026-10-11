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

## Deployment Workflow Controls

`deploy.yaml` treats every manual-dispatch value as untrusted: it passes values
to shell steps through environment variables and validates action, location,
resource-name prefix, public CIDR, Entra group object ID, and optional workspace
resource ID before Azure login. Falco is a hard gate, so a failed or timed-out
installation prevents the monitoring and workload stages from running; the
runner IP allowlist cleanup remains an `always()` step.

The Azure access model separates two identities. A **bootstrap administrator**
holds the subscription privileges to create the pre-defined lab resource group,
run `tools/bootstrap-policy-definitions.ps1` to provision custom policy
definitions/initiative, manage other subscription-scoped controls, and delete
the group after teardown. The
**GitHub Actions deployment identity** is federated only from the `lab`
Environment and is assigned Contributor, Resource Policy Contributor, and Azure
Kubernetes Service RBAC Cluster Admin (`b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b`)
only on that one resource group. Its User Access Administrator assignment uses
condition version `2.0` to limit role-assignment writes and deletes to only
AcrPull, Monitoring Contributor, Log Analytics Contributor, and
Contributor—the Bicep-required definitions. The bootstrap script grants AKS
RBAC Cluster Admin directly, so the workflow cannot self-assign it. The workflow
first verifies the derived group exists; it never creates or deletes resource
groups, and teardown removes only the AKS cluster and the policy assignment
scoped to the lab group.

The policy bootstrap must precede an OIDC or local lab deployment. `main.bicep`
uses the known ID of the pre-provisioned initiative and creates only its
resource-group-scoped assignment; it does not nest a subscription deployment.
Live validation of `tools/bootstrap-policy-definitions.ps1` is intentionally
unverified: no temporary subscription-policy deployment will run against the
only Azure subscription. Validate it during the retained v2.0.0 deployment by
confirming the expected custom definitions and initiative exist before assigning
the initiative to the lab resource group.

To prevent a generic Entra application name from being reused across independent
deployments, `tools/setup-oidc.ps1` derives its default App Registration display
name after Azure context validation. The derivation uses normalized GitHub
organization/repository text plus a short SHA-256 prefix of the tenant ID,
subscription ID, and normalized `organization/repository`. An explicit
`-AppName` is an operator-controlled override and is reused exactly as supplied.

The setup script also reads the target repository's GitHub OIDC
subject-customization API through authenticated `gh` before it creates or
updates the federated credential. It uses the returned `sub_claim_prefix` plus
the `lab` Environment context and refuses to assume a legacy name-based or
immutable ID-based subject format when that API cannot provide a usable prefix.
Reruns converge a same-named credential whose subject does not match GitHub's
current declaration.

Red-team and victim image references use immutable registry digests. Red-team
release assets downloaded at pod startup are verified against checked-in
SHA-256 values before extraction, installation, or execution. This preserves the
lab's intentional attack behavior while making the selected artifacts
reproducible.

These source controls do **not** configure GitHub itself. A repository
administrator must create and protect the `lab` Environment (required reviewers
and restricted deployment branches), store the Azure OIDC identifiers, and
protect `main` with ruleset/branch-protection requirements for pull requests,
the validation checks, and workflow-file review. This document does not assert
that those external settings are currently in place. For the tenant-neutral
operator sequence—including the external Azure credentials, Entra group, GitHub
Environment plan/reviewer, and repository values—follow the
[GitHub Actions quick start](../README.md#tenant-neutral-deployment-quick-start).

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
