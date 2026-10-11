# AKS Adversary Lab

A production-grade AKS security lab for container threat detection, adversary emulation, and detection engineering — aligned to the [MITRE ATT&CK Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/).

Extension of [Adversary Lab](https://github.com/purpleshellsecurity/adversary_lab) for **Azure Kubernetes Service**.

> ⚠️ **Disclaimer:** This project deploys intentionally vulnerable workloads and offensive tooling. Deploy only in isolated Azure subscriptions you control.

---

## What Gets Deployed

| Component | Details |
|---|---|
| **AKS Cluster** | Azure CNI Overlay + Cilium eBPF dataplane, Entra ID RBAC, no local accounts |
| **Microsoft Sentinel** | 7 container-focused solutions, onboarded to Log Analytics |
| **Log Analytics Workspace** | All 11 AKS diagnostic categories, 90-day retention (or bring your own) |
| **Container Insights** | Pod/node inventory, container logs, metrics via DCR |
| **Defender for Containers** | eBPF sensor for runtime detection (optional) |
| **Azure Policy Initiative** | 10 policies (5 custom + 5 built-in) at subscription scope |
| **Azure Container Registry** | Standard SKU, AcrPull role for AKS kubelet identity |
| **Key Vault** | RBAC auth, soft-delete (7d); public network — accepted lab risk (see docs/security-exceptions.yaml LAB-002) |
| **Falco** | Runtime security via Helm, custom syscall-based rules |
| **Red Team Tools** | kdigger, CDK, Peirates, kubectl, nmap, curl — in `attacker` namespace |
| **Victim Apps** | Juice Shop, DVWA, vulnerable API, intentional misconfigs |

---

## Repository Structure

```
aks-adversary-lab/
├── .github/
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── workflows/
│       ├── validate.yaml          # Runs on every PR and push — never touches Azure
│       └── deploy.yaml            # Manual trigger — deploy or destroy the full stack
│
├── infrastructure/                # Bicep — deploy once, change rarely
│   ├── modules/                   # Layered architecture (Foundation → Compute → Monitoring → Governance)
│   │   ├── log_analytics.bicep
│   │   ├── aks_networking.bicep
│   │   ├── aks_cluster.bicep
│   │   ├── aks_diagnostics.bicep
│   │   ├── container_insights.bicep
│   │   ├── aks_acr.bicep
│   │   ├── aks_acr_role.bicep
│   │   ├── aks_keyvault.bicep
│   │   ├── aks_sentinel.bicep
│   │   ├── aks_policy_defs.bicep  # Subscription-scope policy definitions + initiative
│   │   └── aks_policy.bicep       # Policy assignment at resource group scope
│   ├── main.bicep                 # Resource group orchestrator
│   ├── main_subscription.bicep    # Subscription-scope resources (Defender pricing, activity logs)
│   └── aks_adversary_lab_deploy.ps1  # Local deploy script (alternative to GitHub Actions)
│
├── kubernetes/                    # K8s manifests — applied after cluster is up
│   ├── namespaces/
│   ├── monitoring/
│   ├── network-policies/
│   ├── rbac/
│   ├── red-team/
│   └── victim-apps/
│
├── helm/
│   └── falco/                     # Umbrella chart: pins Falco (Chart.yaml) + values.yaml
│
├── detections/                    # Source of truth for all detection content
│   ├── kql/                       # Microsoft Sentinel analytics rules
│   └── falco/                     # Falco runtime rules (assembled into helm/falco/values.yaml)
│
├── attack-simulations/            # Red team scripts mapped to MITRE ATT&CK
│   ├── token-theft.sh             # T1528
│   └── lateral-movement.sh        # T1550.001
│
├── tools/
│   ├── setup-oidc.ps1             # One-time OIDC setup for GitHub Actions
│   ├── bootstrap-policy-definitions.ps1 # Bootstrap-admin subscription policy provisioning
│   └── detection-validator/       # Python tool — validates KQL + Falco rule structure
│
└── docs/
    ├── SECURITY.md
    ├── security-exceptions.yaml   # Accepted risk register with justification + expiration
    └── KQL_Container_Reference.md
```

---

## CI/CD Pipeline

Every pull request and push to `main` runs `validate.yaml` automatically. You
can also manually run it for an orphan release-candidate branch that has no PR;
it remains CI-only and never accesses Azure. The deploy workflow is always
manual — nothing deploys to Azure without you clicking a button.

> 📖 **New to these workflows?** [`docs/WORKFLOWS-EXPLAINED.md`](docs/WORKFLOWS-EXPLAINED.md) is a line-by-line walkthrough of both workflow files — triggers, jobs, the OIDC auth model, deploy/destroy ordering, and the patterns behind them. The workflow YAML files themselves also carry inline explanatory comments.

### Validation Pipeline (`validate.yaml`)

| Job | Tool | What it checks |
|---|---|---|
| `bicep-validate` | `az bicep build` | Syntax + linting on all Bicep files |
| `powershell-lint` | PSScriptAnalyzer | PowerShell script quality |
| `secret-scan` | TruffleHog | Verified secrets in commit history |
| `k8s-validate` | kubeconform | Kubernetes manifest schema validation |
| `helm-lint` | Helm | Falco values validity |
| `detection-validate` | validate.py | KQL + Falco rule structure |
| `python-sast` | Bandit | Python tooling security scan |
| `iac-scan` | Checkov | Bicep IaC security scan (soft fail) |
| `trivy-scan` | Trivy | Container CVE scan — Juice Shop image |

### Deploy Workflow (`deploy.yaml`)

Triggered manually via `workflow_dispatch`. Every form value is passed to Bash
through an environment variable and validated before Azure login; the workflow
then deploys or destroys the full stack in the correct order. Falco must install
successfully before monitoring, victim, or red-team workloads are applied. The
temporary runner API allowlist entry is still attempted for removal even when a
deployment step fails.

---

## Getting Started

### Prerequisites

| Tool | Install |
|---|---|
| PowerShell 7 | `winget install Microsoft.PowerShell` / `brew install --cask powershell` |
| Azure PowerShell | `Install-Module Az -Force` |
| Azure CLI | `winget install Microsoft.AzureCLI` / `brew install azure-cli` |
| kubectl | `az aks install-cli` |
| Helm | `winget install Helm.Helm` / `brew install helm` |
| gh CLI | `winget install GitHub.cli` / `brew install gh` — setup reads the repository's OIDC subject configuration and sets GitHub secrets |

### Azure Identities and Scope

Use two separate identities:

- **Bootstrap administrator:** an interactive administrator with the
  subscription permissions required to create the lab resource group, configure
  subscription-scoped policy definitions/Defender controls, and remove the
  resource group after teardown.
- **GitHub Actions deployment identity:** the OIDC service principal used by
  `deploy.yaml`. It receives Contributor, Resource Policy Contributor, and
  Azure Kubernetes Service RBAC Cluster Admin
  (`b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b`) only at the single pre-created lab
  resource group. Its User Access Administrator assignment is condition version
  `2.0` constrained to role-assignment writes and deletes for only the AcrPull,
  Monitoring Contributor, Log Analytics Contributor, and Contributor definitions
  required by Bicep. It cannot grant Owner, create/delete resource groups, or
  manage subscription-scoped resources.

The bootstrap administrator also needs an **Entra ID security group** whose
members will get `cluster-admin` on the AKS cluster.

---

## Option A — GitHub Actions (Recommended)

This is the primary path. One-time setup, then spin up and down with a button click.

### Tenant-neutral deployment quick start

Use this sequence for **your own fork or published copy** of the repository. It
does not provision a shared tenant, subscription, GitHub Environment, or
credentials for you.

1. Fork or publish the repository in the GitHub organization that will run the
   lab, then merge the deployment revision into the protected branch you intend
   to deploy from.
2. In your Entra tenant, choose or create a dedicated security group for AKS
   lab administrators. Add only the people who should receive AKS
   `cluster-admin`, and retain its **object ID** for `admin_group_id`.
3. As the bootstrap administrator, choose a lowercase `name_prefix` and
   pre-create `rg-<name_prefix>-aks-lab` in an allowed workflow region. The
   GitHub Actions identity cannot create this resource group.
4. As the bootstrap administrator, run
   [`tools/bootstrap-policy-definitions.ps1`](tools/bootstrap-policy-definitions.ps1)
   once for the subscription to retain the custom policy definitions and
   `aks-adversary-lab-logging-initiative`.
5. Run [`tools/setup-oidc.ps1`](tools/setup-oidc.ps1) with **your** GitHub
   organization, repository, subscription, and pre-created resource group. It
   creates/reuses the deployment identity and configures its
   resource-group-scoped permissions.
6. In **your repository's GitHub settings**, create/protect the `lab`
   Environment, add the required reviewer(s), permit the intended deployment
   branch, and add the `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and
   `AZURE_SUBSCRIPTION_ID` values produced by the OIDC setup.
7. From that permitted branch, manually dispatch **Deploy AKS Adversary Lab**
   with the selected prefix, region, public IPv4 CIDR, and Entra group object
   ID. Approve the `lab` Environment deployment before Azure login.
8. When finished, manually dispatch `destroy` with the same inputs. It removes
   the AKS cluster and lab policy assignment, but retains the resource group;
   the bootstrap administrator reviews remaining resources and removes the
   now-empty group.

**Customer-specific, external configuration:** the Azure subscription and
bootstrap-administrator credentials, Entra group membership, GitHub Environment
reviewers and plan support, permitted deployment branches, and OIDC identifier
values all belong to your tenant or repository. None is committed to the fork.
Required-reviewer protection is a GitHub plan capability; if the plan does not
support it, do not treat the Environment as an approval gate.

The detailed sections below explain the scripts and GitHub settings used in
steps 4–7.

### OIDC setup details (run once)

From your local machine, logged into Azure:

```powershell
Connect-AzAccount

./tools/setup-oidc.ps1 `
  -GitHubOrg  "<your-github-org>" `
  -GitHubRepo "<your-repository>" `
  -ResourceGroupName "rg-<name_prefix>-aks-lab"
```

The script:
- Creates/reuses a deterministic App Registration with a federated credential
  (no client secrets). When `-AppName` is omitted, its display name contains
  normalized GitHub organization/repository text and a 12-character SHA-256
  prefix derived from the tenant ID, subscription ID, and normalized
  `organization/repository`, preventing reuse of a generic identity between
  independent deployments.
- Requires the lab resource group to exist and assigns the deployment identity
  only the required resource-group-scoped roles
- Sets `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` as GitHub secrets through the required authenticated `gh` CLI

Before creating or updating the federated credential, the script reads the
target repository's GitHub OIDC subject-customization API through authenticated
`gh`. It uses GitHub's returned `sub_claim_prefix` plus `:environment:lab`,
rather than assuming a name-based or ID-based subject format. If GitHub cannot
provide that authoritative prefix, setup stops without creating or changing the
federated credential. On rerun, a credential with the same name but a different
subject is updated to the GitHub-declared value.

Pass `-AppName "<your-approved-name>"` only when your tenant's naming policy
requires an explicit display name; that exact value is then reused on later
runs. The derivation inputs are identifiers, not secrets, and are not committed.

Before running the script, the bootstrap administrator must complete the
resource-group and policy-bootstrap steps above. Subscription-scoped controls
remain the bootstrap administrator's responsibility and are not deployed by
the GitHub Actions identity.

### Policy bootstrap details (run once per subscription)

Using the bootstrap administrator's own Azure credentials, provision the custom
policy definitions and `aks-adversary-lab-logging-initiative` before running the
lab deploy workflow:

```powershell
Connect-AzAccount

./tools/bootstrap-policy-definitions.ps1 `
  -SubscriptionId "<subscription-id>" `
  -Location "eastus2"
```

This is a subscription-scoped operation and must be performed before either the
OIDC workflow or local infrastructure deployment. Those deployments retain only
the resource-group-scoped assignment of the pre-provisioned initiative. The
bootstrap administrator remains responsible for subscription-scoped Defender and
Activity Log controls in `infrastructure/main_subscription.bicep`.

> **Operational validation deferred:** No temporary live subscription-policy
> bootstrap has been run against the only Azure subscription. Validate this
> script during the intended retained v2.0.0 deployment, confirming the custom
> policy definitions and `aks-adversary-lab-logging-initiative` exist before the
> lab's resource-group policy assignment is deployed.

### GitHub Environment details

1. Go to **Repo Settings → Environments → New environment**
2. Name it exactly **`lab`**
3. Add one or more **required reviewers** so every deploy/destroy pauses for
   approval before Azure login. Required reviewers require a GitHub plan that
   supports Environment protection rules.
4. Restrict deployment branches/tags to the protected branch you intend to
   deploy from.

### Additional repository protections

The workflow source declares `environment: lab`, but source control cannot create
or protect a GitHub Environment or ruleset. Before enabling deployment, a
repository administrator must configure the following in GitHub:

1. Keep the `lab` environment above with required reviewers and restricted
   deployment branches.
2. Add the three OIDC identifiers (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and
   `AZURE_SUBSCRIPTION_ID`) as environment or repository secrets as appropriate
   for the OIDC setup.
3. Protect `main` with a ruleset or branch protection requiring pull requests
   and the required `validate.yaml` checks; limit bypass and force-push
   permissions to trusted administrators.
4. Require review for `.github/workflows/` changes (for example through the
   repository's CODEOWNERS policy).

These are required external GitHub settings; this repository does not assert
that they are already configured.

### Dispatch and approve deployment

1. Go to **Actions → Deploy AKS Adversary Lab → Run workflow**
2. Fill in the form:

| Field | Description |
|---|---|
| `action` | `deploy` or `destroy` |
| `name_prefix` | Short lowercase prefix for resource names (e.g. `purpleshell`); its derived `rg-<prefix>-aks-lab` resource group must already exist |
| `location` | Azure region |
| `authorized_ip` | Your public IP in CIDR format — `curl ifconfig.me` then append `/32` |
| `admin_group_id` | Object ID of your Entra ID cluster-admin group |
| `existing_workspace_id` | *(Optional)* Resource ID of an existing Log Analytics workspace — leave blank to create a new one |

3. Click **Run workflow**

The workflow deploys in layers — Bicep first, then namespaces, RBAC, network policies, Falco, monitoring, victim apps, red team tools. Falco is a hard deployment gate: a failed or timed-out install stops later workload stages. Red-team and victim image references are pinned to immutable digests, and downloaded red-team release assets are SHA-256 verified before execution. Takes roughly 15–20 minutes end to end.

### Connect

```bash
az aks get-credentials \
  --resource-group rg-<name_prefix>-aks-lab \
  --name <name_prefix>-aks

kubelogin convert-kubeconfig -l azurecli
kubectl get nodes
```

### Tear down

Same workflow, same inputs, change `action` to `destroy`. It deletes the AKS
cluster and the `aks-lab-mitre-logging` policy assignment scoped to the lab
resource group, but deliberately retains the resource group. The bootstrap
administrator must review remaining resources and remove the now-empty resource
group when teardown is complete.

> **Note:** Defender for Cloud pricing tiers and custom policy definitions at
> subscription scope are bootstrap-administrator responsibilities and are not
> managed by the GitHub Actions deployment identity.

---

## Option B — Local PowerShell Deploy

Use this when you want to deploy directly from your machine without the pipeline
— useful for initial testing or when iterating on infrastructure changes. The
same boundaries apply: a bootstrap administrator must first create
`rg-<name_prefix>-aks-lab` in the selected region and run
`tools/bootstrap-policy-definitions.ps1`.

For a first-time interactive run, start the script with no deployment inputs.
After Azure sign-in, it guides you through subscription selection (when needed),
the lowercase name prefix and derived pre-created resource group, Entra
cluster-admin group object ID, public IPv4 API CIDR (offering a detected `/32`),
and supported Azure region. It validates each value and verifies that the
derived resource group already exists in the selected region before prompting
for the final cost confirmation:

```powershell
./infrastructure/aks_adversary_lab_deploy.ps1
```

For automation, use `-NonInteractive`; it never prompts or auto-detects values
and requires `-SubscriptionId`, `-NamePrefix`, `-Location`,
`-AdminGroupObjectId`, `-AuthorizedIpRange`, and explicit `-Approve`.
`-ResourceGroupName` is optional only as the exact derived value
`rg-<name_prefix>-aks-lab`.

```powershell
Connect-AzAccount

./infrastructure/aks_adversary_lab_deploy.ps1 `
  -SubscriptionId       "your-subscription-id" `
  -NamePrefix           "labdemo" `
  -Location             "eastus" `
  -AdminGroupObjectId   "your-entra-group-object-id" `
  -AuthorizedIpRange    "203.0.113.10/32" `
  -Approve `
  -NonInteractive

# With Defender for Containers enabled
./infrastructure/aks_adversary_lab_deploy.ps1 `
  -SubscriptionId       "your-subscription-id" `
  -NamePrefix           "labdemo" `
  -Location             "eastus" `
  -AdminGroupObjectId   "your-entra-group-object-id" `
  -AuthorizedIpRange    "203.0.113.10/32" `
  -EnableDefender       $true `
  -Approve `
  -NonInteractive
```

After the script completes, apply K8s resources manually:

```bash
kubectl apply -f kubernetes/namespaces/
kubectl apply -f kubernetes/rbac/
kubectl apply -f kubernetes/network-policies/
kubectl apply -f kubernetes/monitoring/
kubectl apply -f kubernetes/victim-apps/
kubectl apply -f kubernetes/red-team/

helm repo add falcosecurity https://falcosecurity.github.io/charts
helm dependency update helm/falco
helm upgrade --install falco helm/falco \
  --namespace monitoring \
  --create-namespace
```

> **Falco is a pinned chart dependency.** The version lives declaratively in
> `helm/falco/Chart.yaml` — a single source of truth, not scattered across deploy
> commands. Dependabot watches it and opens a PR when a new version ships; CI renders
> the chart and asserts the custom rules are present. To bump manually, edit `version:`
> in `helm/falco/Chart.yaml`, review the chart's `BREAKING-CHANGES.md`, and let CI validate.

---

## Running Attack Simulations

```bash
# Token theft — T1528
kubectl exec -it -n attacker \
  $(kubectl get pod -n attacker -l app=peirates -o jsonpath='{.items[0].metadata.name}') \
  -- /bin/sh

# Inside the pod:
bash /attack-simulations/token-theft.sh

# Lateral movement — T1550.001
kubectl exec -it -n attacker \
  $(kubectl get pod -n attacker -l app=kubectl -o jsonpath='{.items[0].metadata.name}') \
  -- /bin/sh
```

---

## Verifying Detections

```kql
// AKS API server audit logs — confirm data is flowing
AKSAudit
| where TimeGenerated > ago(1h)
| summarize count() by bin(TimeGenerated, 5m)

// Container stdout/stderr
ContainerLogV2
| where TimeGenerated > ago(1h)
| summarize count() by PodNamespace

// Defender alerts (if enabled)
SecurityAlert
| where TimeGenerated > ago(24h)
| where ProductName has "Defender"
| project TimeGenerated, AlertName, Description, Entities
```

See [docs/KQL_Container_Reference.md](docs/KQL_Container_Reference.md) for the full query reference across all log tables.

---

## Log Tables Reference

| Table | Source | Key Detections |
|---|---|---|
| `AKSAudit` | API server (all ops) | exec, pod creation, secret access, RBAC changes |
| `AKSAuditAdmin` | API server (mutations) | RBAC escalation, daemonset creation, deletions |
| `AKSControlPlane` | guard, scheduler | auth failures, admission denials |
| `ContainerLogV2` | Container stdout/stderr | crypto mining, token access, reverse shells |
| `KubeEvents` | Pod lifecycle | crash loops, image pull failures, OOMKills |
| `KubePodInventory` | Pod metadata | namespace drift, unexpected images |
| `InsightsMetrics` | CPU/memory/network | mining detection via CPU anomalies |
| `SecurityAlert` | Defender | binary drift, web shells, escape attempts |
| `AzureActivity` | ARM operations | resource deletions, policy changes |

---

## Cost Estimate

Approximate monthly cost running 24/7:

| Resource | Cost |
|---|---|
| AKS Standard tier (control plane) | ~$73 |
| 1× D2s_v3 system node | ~$70 |
| 1× D2s_v3 user node | ~$70 |
| Log Analytics (~5 GB/day, 90-day retention) | ~$35 |
| ACR Standard | ~$5 |
| **Total** | **~$253/month** |

For engagements or training sessions, deploy for the session and destroy when done — cost is negligible at a few hours.

```bash
# Pause the cluster between sessions instead of destroying
az aks stop  --resource-group rg-<prefix>-aks-lab --name <prefix>-aks
az aks start --resource-group rg-<prefix>-aks-lab --name <prefix>-aks
```

---

## Detection Content

Detection rules in `detections/` are the source of truth — version controlled, validated in CI, reviewed in PRs like code.

| Location | Format | Purpose |
|---|---|---|
| `detections/kql/` | `.kql` | Microsoft Sentinel analytics rules |
| `detections/falco/` | `.yaml` | Falco runtime rules |

Falco rules are assembled from `detections/falco/` into `helm/falco/values.yaml` for deployment. The standalone files exist for validation, diffing, and easier review.

Every detection is mapped to a MITRE technique and a trigger script in the
[detection coverage matrix](docs/DETECTION-COVERAGE.md) (with a color-coded
[ATT&CK Navigator layer](docs/attack-navigator-layer.json)). New to the detections?
Start with the [beginner's walkthrough](docs/DETECTIONS-FOR-BEGINNERS.md).

---

## Additional Resources

- [MITRE ATT&CK Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/)
- [Microsoft Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
- [Defender for Containers](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction)
- [Falco Documentation](https://falco.org/docs/)
- [KQL Container Reference](docs/KQL_Container_Reference.md)



---

## License

MIT License
